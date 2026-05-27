import ArgumentParser
import Foundation
import SSHKeychainCore

struct StatusCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Show the running agent's status via XPC."
    )

    @Option(name: .long, help: "Mach service name the daemon registered (must match the daemon's --mach-service).")
    var machService: String = "com.josegonzalez.ssh-keychain.daemon"

    func run() async throws {
        let client = DaemonXPCClient(endpoint: .machService(machService))
        defer { client.disconnect() }
        guard let status = await client.status() else {
            throw ValidationError("daemon not reachable on Mach service \(machService) (is it running with `--mach-service \(machService)`?)")
        }

        print("ssh-keychain \(status.version)\(status.running ? " (running)" : " (stopped)")")
        print("  socket: \(status.socketPath)")
        if let path = status.configPath {
            print("  config: \(path)")
        }
        if let when = status.lastReloadAt {
            print("  last reload: \(formatter.string(from: when))")
        }
        print("  identities: \(status.identities.count)")
        for id in status.identities {
            let mark = id.cached ? "✓" : (id.biometric ? "⚿" : "·")
            print("    \(mark) \(id.backend):\(id.key)  \(id.fingerprint)")
        }
    }

    private var formatter: DateFormatter {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .medium
        return f
    }
}
