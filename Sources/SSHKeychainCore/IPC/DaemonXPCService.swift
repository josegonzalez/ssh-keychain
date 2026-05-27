import Foundation

/// Daemon-side implementation of the XPC protocol. Owned by the running
/// `AgentService` and exposed to the app via an `NSXPCListener`.
///
/// Each XPC method bridges from completion handlers into Swift Concurrency,
/// calls into the actor, and hands the result back on the XPC thread. The
/// daemon serializes everything through the agent actor so concurrent app
/// requests can't interleave with in-flight signing.
public final class DaemonXPCService: NSObject, DaemonXPC, @unchecked Sendable {
    private let agent: AgentService
    private let socketPath: String
    private let configPath: String?

    public init(agent: AgentService, socketPath: String, configPath: String?) {
        self.agent = agent
        self.socketPath = socketPath
        self.configPath = configPath
    }

    // MARK: DaemonXPC

    public func status(reply: @escaping (DaemonStatus) -> Void) {
        let box = SendableReply(reply)
        Task { [agent, socketPath, configPath] in
            let identities = await agent.loadedIdentities()
            let lastReload = await agent.lastReloadAt
            let status = DaemonStatus(
                running: true,
                version: SSHKeychain.version,
                socketPath: socketPath,
                configPath: configPath,
                lastReloadAt: lastReload,
                identities: identities
            )
            box.call(status)
        }
    }

    public func reload(reply: @escaping (Bool, NSError?) -> Void) {
        let box = SendableReply2(reply)
        Task { [agent] in
            do {
                try await agent.reload()
                box.call(true, nil)
            } catch {
                box.call(false, error.asNSError())
            }
        }
    }

    public func lockAll(reply: @escaping (Bool) -> Void) {
        let box = SendableReply(reply)
        Task { [agent] in
            await agent.flushCache()
            box.call(true)
        }
    }

    public func recentActivity(limit: Int, reply: @escaping ([ActivityEvent]) -> Void) {
        let box = SendableReply(reply)
        Task { [agent] in
            let events = await agent.recentActivity(limit: limit)
            box.call(events)
        }
    }

    public func listSourceCandidates(backend: String, reply: @escaping ([String], NSError?) -> Void) {
        let box = SendableReply2(reply)
        Task { [agent] in
            do {
                let names = try await agent.listBackendCandidates(backend: backend)
                box.call(names, nil)
            } catch {
                box.call([], error.asNSError())
            }
        }
    }

    public func testBackend(configJSON: Data, reply: @escaping (Bool, NSError?) -> Void) {
        _ = configJSON
        reply(false, NSError(domain: "ssh-keychain", code: -1, userInfo: [
            NSLocalizedDescriptionKey: "testBackend is not implemented in this build (phase 23)"
        ]))
    }
}

/// Wraps a non-Sendable Objective-C completion handler in an `@unchecked
/// Sendable` reference so we can cross actor boundaries safely. XPC reply
/// blocks are guaranteed to be invoked exactly once, so the unchecked
/// concurrency annotation is sound here.
private final class SendableReply<T>: @unchecked Sendable {
    private let reply: (T) -> Void
    init(_ reply: @escaping (T) -> Void) { self.reply = reply }
    func call(_ value: T) { reply(value) }
}

private final class SendableReply2<A, B>: @unchecked Sendable {
    private let reply: (A, B) -> Void
    init(_ reply: @escaping (A, B) -> Void) { self.reply = reply }
    func call(_ a: A, _ b: B) { reply(a, b) }
}

private extension Error {
    func asNSError() -> NSError {
        if let ns = self as NSError? { return ns }
        return NSError(domain: "ssh-keychain", code: -1, userInfo: [NSLocalizedDescriptionKey: String(describing: self)])
    }
}
