import Foundation

/// App-side and CLI-side wrapper around `NSXPCConnection`.
///
/// The Objective-C protocol uses completion handlers; this client wraps each
/// call in a `withCheckedContinuation` so callers get a clean `async`
/// surface. The underlying `NSXPCConnection` is re-created lazily after
/// invalidation, so callers can keep this client alive across daemon restarts.
///
/// In-flight calls are tracked in a registry. When the connection invalidates
/// or interrupts mid-call (the Mach service disappears, the daemon crashes,
/// etc.) the registry is drained and every pending call's error path fires.
/// That closes the "leaked continuation" hole - `NSXPCConnection`'s per-proxy
/// error handler from `remoteObjectProxyWithErrorHandler` is not a complete
/// guarantee on its own.
public final class DaemonXPCClient: @unchecked Sendable {
    public enum Endpoint: Sendable {
        case machService(String)
        case listener(NSXPCListenerEndpoint)
    }

    private let endpoint: Endpoint
    private let queue = DispatchQueue(label: "ssh-keychain.xpc.client")
    private var connection: NSXPCConnection?
    private var pendingCalls: [ObjectIdentifier: any XPCErrorReceiver] = [:]

    public init(endpoint: Endpoint) {
        self.endpoint = endpoint
    }

    // MARK: - Public API

    /// Returns the daemon's current status, or `nil` if the agent is
    /// unreachable (Mach service not registered, daemon crashed, etc).
    public func status() async -> DaemonStatus? {
        await call(failureValue: nil as DaemonStatus?) { proxy, result in
            proxy.status { result.fireSuccess($0) }
        }
    }

    public func reload() async throws {
        try await throwingCall { (proxy, result: XPCCallResult<Void>) in
            proxy.reload { ok, error in
                if let error { result.fireError(error) }
                else if ok { result.fireSuccess(()) }
                else { result.fireError(DaemonXPCError.unreachable) }
            }
        }
    }

    public func lockAll() async -> Bool {
        await call(failureValue: false) { proxy, result in
            proxy.lockAll { result.fireSuccess($0) }
        }
    }

    public func recentActivity(limit: Int) async -> [ActivityEvent] {
        await call(failureValue: []) { proxy, result in
            proxy.recentActivity(limit: limit) { result.fireSuccess($0) }
        }
    }

    public func listSourceCandidates(backend: String) async throws -> [String] {
        try await throwingCall { proxy, result in
            proxy.listSourceCandidates(backend: backend) { names, error in
                if let error { result.fireError(error) }
                else { result.fireSuccess(names) }
            }
        }
    }

    /// Invalidate the underlying connection; the next call will re-establish.
    public func disconnect() {
        let toFire: [any XPCErrorReceiver] = queue.sync {
            connection?.invalidate()
            connection = nil
            let fired = Array(pendingCalls.values)
            pendingCalls.removeAll()
            return fired
        }
        for call in toFire { call.fireUnreachable() }
    }

    // MARK: - Generic call shape

    /// Bridges Apple's reply-block XPC protocol into Swift Concurrency. The
    /// `body` closure receives the proxy and an `XPCCallResult` it can route
    /// the reply through; if the connection fails before the reply (or the
    /// proxy itself errors), the result is fired with `.unreachable`.
    private func call<T: Sendable>(
        failureValue: T,
        body: @escaping @Sendable (any DaemonXPC, XPCCallResult<T>) -> Void
    ) async -> T {
        await withCheckedContinuation { (cont: CheckedContinuation<T, Never>) in
            let contBox = ContBox<T, Never>(cont)
            let result = XPCCallResult<T>(
                onSuccess: { value in contBox.resume(value) },
                onError: { _ in contBox.resume(failureValue) }
            )
            invoke(result: result, body: body)
        }
    }

    private func throwingCall<T: Sendable>(
        body: @escaping @Sendable (any DaemonXPC, XPCCallResult<T>) -> Void
    ) async throws -> T {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, Error>) in
            let contBox = ContBox<T, Error>(cont)
            let result = XPCCallResult<T>(
                onSuccess: { value in contBox.resume(returning: value) },
                onError: { error in contBox.resume(throwing: error) }
            )
            invoke(result: result, body: body)
        }
    }

    private func invoke<T: Sendable>(
        result: XPCCallResult<T>,
        body: @escaping @Sendable (any DaemonXPC, XPCCallResult<T>) -> Void
    ) {
        // Register the call so invalidation can drain it.
        let removeFromRegistry: @Sendable () -> Void = { [weak self] in
            guard let self else { return }
            self.queue.async {
                self.pendingCalls.removeValue(forKey: ObjectIdentifier(result))
            }
        }
        result.setRemoveFromRegistry(removeFromRegistry)
        queue.sync { pendingCalls[ObjectIdentifier(result)] = result }

        let conn = ensureConnection()
        guard let remote = conn.remoteObjectProxyWithErrorHandler({ error in
            result.fireError(error)
        }) as? DaemonXPC else {
            result.fireError(DaemonXPCError.unreachable)
            return
        }
        body(remote, result)
    }

    // MARK: NSXPCConnection plumbing

    private func ensureConnection() -> NSXPCConnection {
        queue.sync {
            if let existing = connection { return existing }
            let conn: NSXPCConnection
            switch endpoint {
            case .machService(let name):
                conn = NSXPCConnection(machServiceName: name, options: [])
            case .listener(let endpoint):
                conn = NSXPCConnection(listenerEndpoint: endpoint)
            }
            conn.remoteObjectInterface = NSXPCInterface(with: DaemonXPC.self)
            let allowedClasses: [AnyClass] = [DaemonStatus.self, LoadedIdentity.self, ActivityEvent.self, NSArray.self, NSString.self, NSDate.self, NSError.self, NSDictionary.self]
            let allowedSet = NSSet(array: allowedClasses) as! Set<AnyHashable>
            conn.remoteObjectInterface?.setClasses(
                allowedSet,
                for: #selector(DaemonXPC.status(reply:)),
                argumentIndex: 0,
                ofReply: true
            )
            let weakSelf = WeakBox(self)
            let drainPending: @Sendable () -> Void = {
                guard let me = weakSelf.value else { return }
                let toFire: [any XPCErrorReceiver] = me.queue.sync {
                    me.connection = nil
                    let fired = Array(me.pendingCalls.values)
                    me.pendingCalls.removeAll()
                    return fired
                }
                for call in toFire { call.fireUnreachable() }
            }
            conn.invalidationHandler = drainPending
            conn.interruptionHandler = drainPending
            conn.resume()
            connection = conn
            return conn
        }
    }
}

public enum DaemonXPCError: Error, Equatable {
    case unreachable
}

// MARK: - Internals

/// Tracks an in-flight XPC call. Both the XPC reply block and any error
/// (per-proxy error handler or connection-level invalidation) route through
/// here. Exactly one of `fireSuccess` / `fireError` ever wins; subsequent
/// calls are no-ops. After firing, the call removes itself from the client's
/// pending registry so the registry doesn't grow unboundedly.
final class XPCCallResult<T: Sendable>: @unchecked Sendable, XPCErrorReceiver {
    private let lock = NSLock()
    private var fired = false
    private let onSuccess: (T) -> Void
    private let onError: (Error) -> Void
    private var removeFromRegistry: (@Sendable () -> Void)?

    init(onSuccess: @escaping (T) -> Void, onError: @escaping (Error) -> Void) {
        self.onSuccess = onSuccess
        self.onError = onError
    }

    func setRemoveFromRegistry(_ remove: @escaping @Sendable () -> Void) {
        lock.lock(); defer { lock.unlock() }
        removeFromRegistry = remove
    }

    func fireSuccess(_ value: T) {
        lock.lock()
        if fired { lock.unlock(); return }
        fired = true
        let remove = removeFromRegistry
        removeFromRegistry = nil
        lock.unlock()
        remove?()
        onSuccess(value)
    }

    func fireError(_ error: Error) {
        lock.lock()
        if fired { lock.unlock(); return }
        fired = true
        let remove = removeFromRegistry
        removeFromRegistry = nil
        lock.unlock()
        remove?()
        onError(error)
    }

    /// Type-erased entry point used by the registry drain path so the client
    /// doesn't need to know `T` to cancel a pending call.
    func fireUnreachable() {
        fireError(DaemonXPCError.unreachable)
    }
}

/// Type-erased view of `XPCCallResult<T>` for the registry.
protocol XPCErrorReceiver: AnyObject, Sendable {
    func fireUnreachable()
}

/// `CheckedContinuation` doesn't conform to Sendable across all toolchains;
/// wrap in an `@unchecked Sendable` box so we can capture it inside the XPC
/// completion handlers, which Apple's API gives us as plain non-Sendable
/// closures. Marked unchecked because XPC reply blocks are guaranteed to be
/// invoked at most once - and `XPCCallResult` enforces this on our side too.
private final class ContBox<T: Sendable, E: Error>: @unchecked Sendable {
    private let cont: CheckedContinuation<T, E>
    init(_ cont: CheckedContinuation<T, E>) { self.cont = cont }
    func resume(_ value: T) { cont.resume(returning: value) }
    func resume(returning value: T) { cont.resume(returning: value) }
    func resume(throwing error: Error) { cont.resume(throwing: error as! E) }
}

private final class WeakBox<T: AnyObject>: @unchecked Sendable {
    weak var value: T?
    init(_ value: T) { self.value = value }
}
