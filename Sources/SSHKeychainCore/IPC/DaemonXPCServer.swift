import Foundation

/// Hosts the `DaemonXPCService` on an `NSXPCListener`.
///
/// In production the listener is registered with a Mach service name from the
/// launch agent plist (`MachServices`). For in-process tests we use
/// `NSXPCListener.anonymous()` and hand the endpoint to clients directly.
public final class DaemonXPCServer: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    public let listener: NSXPCListener
    private let service: DaemonXPCService

    /// Construct an anonymous server. The endpoint is on `listener.endpoint`
    /// and must be communicated to clients out-of-band (tests use this).
    public init(anonymousServing service: DaemonXPCService) {
        self.listener = NSXPCListener.anonymous()
        self.service = service
        super.init()
        listener.delegate = self
        listener.resume()
    }

    /// Construct a server bound to a Mach service name. Used by the launch
    /// agent; the daemon's plist's `MachServices` key must include this name.
    public init(machServiceName: String, service: DaemonXPCService) {
        self.listener = NSXPCListener(machServiceName: machServiceName)
        self.service = service
        super.init()
        listener.delegate = self
        listener.resume()
    }

    public func invalidate() {
        listener.invalidate()
    }

    // MARK: NSXPCListenerDelegate

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        // Audit-session / team-id checking lands in phase 30 (codesigning); for
        // now we accept all connections to the anonymous listener. The Mach
        // service variant is implicitly restricted to peers in the same audit
        // session by launchd's matching rules.
        newConnection.exportedInterface = NSXPCInterface(with: DaemonXPC.self)
        let allowedClasses: [AnyClass] = [DaemonStatus.self, LoadedIdentity.self, ActivityEvent.self, NSArray.self, NSDictionary.self, NSString.self, NSDate.self, NSError.self]
        let allowedSet = NSSet(array: allowedClasses) as! Set<AnyHashable>
        newConnection.exportedInterface?.setClasses(
            allowedSet,
            for: #selector(DaemonXPC.status(reply:)),
            argumentIndex: 0,
            ofReply: true
        )
        newConnection.exportedObject = service
        newConnection.resume()
        return true
    }
}
