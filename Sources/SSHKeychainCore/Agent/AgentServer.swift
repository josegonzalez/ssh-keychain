import Foundation
import NIOCore
import NIOPosix

/// SwiftNIO Unix-socket SSH-agent server.
///
/// Binds to `socketPath`, dispatches each accepted connection to an
/// `AgentHandler`, and stays running until `shutdown()` is called.
public final class AgentServer: @unchecked Sendable {
    public let socketPath: String
    private let service: AgentService
    private let group: MultiThreadedEventLoopGroup
    private var serverChannel: Channel?
    private let activeConnections: ActiveConnectionsTracker

    public init(socketPath: String, service: AgentService) {
        self.socketPath = (socketPath as NSString).expandingTildeInPath
        self.service = service
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.activeConnections = ActiveConnectionsTracker()
    }

    public func start() async throws {
        try cleanupStaleSocket()
        try ensureSocketDirectory()

        // 0o077 umask -> socket created with 0o600 permissions.
        let previousUmask = umask(0o077)
        defer { umask(previousUmask) }

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [service, activeConnections] channel in
                activeConnections.opened()
                channel.closeFuture.whenComplete { _ in activeConnections.closed() }
                return channel.pipeline.addHandler(AgentHandler(service: service))
            }

        let channel = try await bootstrap.bind(unixDomainSocketPath: socketPath).get()
        self.serverChannel = channel
    }

    /// Launches a background task that shuts the server down after `idle`
    /// seconds with no live connections. Used by `--once` mode so the
    /// short-lived agent reaps itself.
    public func enableIdleTimeout(_ idle: TimeInterval) {
        Task { [activeConnections, weak self] in
            while true {
                try? await Task.sleep(for: .seconds(idle))
                if activeConnections.shouldExit(idle: idle) {
                    try? await self?.shutdown()
                    return
                }
            }
        }
    }

    /// Blocks the current task until the server channel closes.
    public func awaitShutdown() async throws {
        guard let channel = serverChannel else { return }
        try await channel.closeFuture.get()
    }

    public func shutdown() async throws {
        if let channel = serverChannel {
            try? await channel.close().get()
            serverChannel = nil
        }
        try? await group.shutdownGracefully()
        if FileManager.default.fileExists(atPath: socketPath) {
            try? FileManager.default.removeItem(atPath: socketPath)
        }
    }

    private func cleanupStaleSocket() throws {
        guard FileManager.default.fileExists(atPath: socketPath) else { return }
        // Try to connect. If it succeeds, another agent owns the socket -
        // bail rather than clobber it. If it fails with ECONNREFUSED, the
        // socket is stale and safe to remove.
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { throw AgentServerError.socketBindFailed("socket() failed") }
        defer { close(s) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count <= maxLen else {
            throw AgentServerError.socketBindFailed("socket path too long")
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { dest in
            dest.withMemoryRebound(to: CChar.self, capacity: maxLen) { destBytes in
                _ = pathBytes.withUnsafeBufferPointer { src in
                    memcpy(destBytes, src.baseAddress, pathBytes.count)
                }
            }
        }
        let addrSize = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(s, sockaddrPtr, addrSize)
            }
        }
        if connectResult == 0 {
            throw AgentServerError.socketInUse(socketPath)
        }
        // connect failed (ECONNREFUSED or similar) -> stale socket, remove it.
        try FileManager.default.removeItem(atPath: socketPath)
    }

    private func ensureSocketDirectory() throws {
        let parent = (socketPath as NSString).deletingLastPathComponent
        if !FileManager.default.fileExists(atPath: parent) {
            try FileManager.default.createDirectory(
                atPath: parent,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
    }
}

public enum AgentServerError: Error, Equatable {
    case socketBindFailed(String)
    case socketInUse(String)
}

/// Tracks open connections so the idle-timeout sweeper knows when it's safe to exit.
final class ActiveConnectionsTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var openCount = 0
    private var lastActivity = Date()

    func opened() {
        lock.lock()
        defer { lock.unlock() }
        openCount += 1
        lastActivity = Date()
    }

    func closed() {
        lock.lock()
        defer { lock.unlock() }
        openCount = max(0, openCount - 1)
        lastActivity = Date()
    }

    /// True if no connections are open AND the last close was at least `idle` seconds ago.
    func shouldExit(idle: TimeInterval) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return openCount == 0 && Date().timeIntervalSince(lastActivity) >= idle
    }
}
