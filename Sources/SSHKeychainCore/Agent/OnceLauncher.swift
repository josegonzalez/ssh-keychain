import Foundation

/// Race-free spawn of a child `ssh-keychain agent` process for `--once` mode.
///
/// Pattern:
///   1. Parent posix_spawns the child with the same flags but `--__once-child`.
///   2. Parent polls for the socket file to appear at `socketPath`.
///   3. When the socket exists, the parent exits 0. `Match exec` then evaluates
///      `IdentityAgent` and `ssh` dials a socket that's guaranteed bound.
///
/// If the child fails to bind within the deadline, the parent returns a non-zero
/// status and the child is sent SIGTERM.
public enum OnceLauncher {
    public static func spawnAndWait(
        executablePath: String,
        forwardedArgs: [String],
        socketPath: String,
        readyTimeout: TimeInterval = 5.0
    ) throws -> Int32 {
        let resolvedSocket = (socketPath as NSString).expandingTildeInPath

        // If the socket already exists, defer to AgentServer's stale-socket logic
        // for the actual decision - but if we can connect, exit early.
        if FileManager.default.fileExists(atPath: resolvedSocket),
           Self.socketAcceptsConnections(resolvedSocket)
        {
            // Already running. ssh will pick up the existing socket.
            return 0
        }

        let argv = [executablePath, "agent", "--__once-child"] + forwardedArgs
        let cArgv: [UnsafeMutablePointer<CChar>?] =
            argv.map { strdup($0) } + [nil]
        defer { for p in cArgv where p != nil { free(p) } }

        let environment: [String: String] = ProcessInfo.processInfo.environment
        let cEnv: [UnsafeMutablePointer<CChar>?] =
            environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { for p in cEnv where p != nil { free(p) } }

        var pid: pid_t = 0
        let result = posix_spawn(
            &pid,
            executablePath,
            nil,
            nil,
            cArgv,
            cEnv
        )
        guard result == 0 else {
            throw OnceLauncherError.spawnFailed(errno: result)
        }

        let deadline = Date().addingTimeInterval(readyTimeout)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: resolvedSocket),
               Self.socketAcceptsConnections(resolvedSocket)
            {
                return 0
            }
            // Detect early child crash before the deadline.
            var status: Int32 = 0
            let waited = waitpid(pid, &status, WNOHANG)
            if waited == pid {
                // Child exited before binding. Surface its exit code.
                let exitCode = (status & 0xff00) >> 8
                return Int32(exitCode != 0 ? exitCode : 1)
            }
            Thread.sleep(forTimeInterval: 0.02)
        }
        // Timed out: signal the child so we don't leak a daemon.
        kill(pid, SIGTERM)
        return 1
    }

    private static func socketAcceptsConnections(_ path: String) -> Bool {
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { return false }
        defer { close(s) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = path.utf8CString
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        guard bytes.count <= maxLen else { return false }
        withUnsafeMutablePointer(to: &addr.sun_path) { dest in
            dest.withMemoryRebound(to: CChar.self, capacity: maxLen) { destBytes in
                _ = bytes.withUnsafeBufferPointer { src in
                    memcpy(destBytes, src.baseAddress, bytes.count)
                }
            }
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(s, sockaddrPtr, size)
            }
        }
        return connected == 0
    }
}

public enum OnceLauncherError: Error, Equatable {
    case spawnFailed(errno: Int32)
}
