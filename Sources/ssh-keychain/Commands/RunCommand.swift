import ArgumentParser
import Foundation
import SSHKeychainCore

struct RunCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "run",
        abstract: "Run a command with an ephemeral ssh-agent serving the chosen key.",
        discussion: """
            The wrapped command receives SSH_AUTH_SOCK pointing at an in-memory
            ssh-keychain agent that serves only the requested key. The socket and
            its parent directory are removed when the command exits.

              ssh-keychain run --source=keychain:gh -- ssh user@host
              ssh-keychain run --source=file:work -- git clone git@github.com:org/repo
            """
    )

    @Option(name: .long, help: "Backend and key: BACKEND:KEY (single key required).")
    var source: String

    @Argument(parsing: .captureForPassthrough, help: "Command to run (everything after `--`).")
    var command: [String] = []

    func run() async throws {
        let spec = try SourceSpec.parse(source)
        guard spec.singleKey != nil else {
            throw ValidationError("--source must name exactly one key")
        }
        // ArgumentParser's `.captureForPassthrough` doesn't always strip the
        // leading `--` separator; drop it if present.
        var rawCommand = command
        if rawCommand.first == "--" { rawCommand.removeFirst() }
        guard !rawCommand.isEmpty else {
            throw ValidationError("specify the command to run after `--`")
        }
        let command = rawCommand

        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        // sockaddr_un.sun_path is 104 bytes on macOS. Keep the path short
        // by using a single-char socket name ("s") under a short tempdir.
        let socketPath = tempDir.appending(path: "s").path

        installCleanupSignalHandlers(tempDir: tempDir)

        let exec = CommandLine.arguments[0]
        let forwarded = [
            "--socket=\(socketPath)",
            "--source=\(source)",
            "--idle-timeout=60",
        ]
        let spawnStatus = try OnceLauncher.spawnAndWait(
            executablePath: exec,
            forwardedArgs: forwarded,
            socketPath: socketPath,
            readyTimeout: 5.0
        )
        guard spawnStatus == 0 else {
            throw ValidationError("could not start ephemeral agent (status \(spawnStatus))")
        }

        let process = Process()
        process.executableURL = try resolveExecutable(command[0])
        process.arguments = Array(command.dropFirst())
        var env = ProcessInfo.processInfo.environment
        env["SSH_AUTH_SOCK"] = socketPath
        process.environment = env
        process.standardInput = FileHandle.standardInput
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError

        try process.run()
        process.waitUntilExit()

        // Tell the ephemeral agent to shut down so we don't wait for idle timeout.
        sendShutdown(socketPath: socketPath)

        let status = process.terminationStatus
        throw ExitCode(status)
    }

    // MARK: helpers

    private func makeTempDirectory() throws -> URL {
        // Use /tmp directly (short prefix, ~5 chars) instead of /var/folders/.../T
        // (~30 chars). The socket path budget is 104 bytes; we need every byte we can keep.
        let suffix = String(UUID().uuidString.prefix(8))
        let dir = URL(fileURLWithPath: "/tmp/ssk-\(suffix)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return dir
    }

    private func resolveExecutable(_ name: String) throws -> URL {
        if name.contains("/") {
            return URL(fileURLWithPath: name)
        }
        let pathEnv = ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin"
        for dir in pathEnv.split(separator: ":") {
            let candidate = URL(fileURLWithPath: String(dir)).appending(path: name)
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
        }
        throw ValidationError("\(name) not found in PATH")
    }

    /// Best-effort shutdown of the ephemeral agent. We send SIGTERM via the
    /// socket path's owning process if we can determine it - otherwise we
    /// just let the idle timer reap.
    private func sendShutdown(socketPath: String) {
        // The agent doesn't expose its pid; we simply remove the socket file
        // and rely on the next accept failure to trigger orderly shutdown.
        // Idle-timeout (60s above) will pick up the slack in the worst case.
        try? FileManager.default.removeItem(atPath: socketPath)
    }
}

/// Process-scoped list of paths to wipe if we die from a fatal signal.
private nonisolated(unsafe) var runCleanupSources: [DispatchSourceSignal] = []

private func installCleanupSignalHandlers(tempDir: URL) {
    let queue = DispatchQueue(label: "ssh-keychain.run.cleanup")
    let path = tempDir.path

    func makeSource(_ sig: Int32) -> DispatchSourceSignal {
        let src = DispatchSource.makeSignalSource(signal: sig, queue: queue)
        src.setEventHandler {
            try? FileManager.default.removeItem(atPath: path)
            // Re-raise with default disposition so the process actually exits.
            signal(sig, SIG_DFL)
            kill(getpid(), sig)
        }
        src.resume()
        return src
    }

    for sig in [SIGINT, SIGTERM, SIGHUP] {
        signal(sig, SIG_IGN)
        runCleanupSources.append(makeSource(sig))
    }
}
