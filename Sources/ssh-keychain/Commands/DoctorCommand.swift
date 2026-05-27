import ArgumentParser
import Foundation
import SSHKeychainCore

struct DoctorCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "doctor",
        abstract: "Diagnose configuration, ssh_config, codesigning, and launch agent state."
    )

    func run() async throws {
        var problems: [String] = []
        var notes: [String] = []

        // Config file
        let configURL = Config.defaultPath
        if FileManager.default.fileExists(atPath: configURL.path) {
            do {
                let cfg = try ConfigStore.load(from: configURL)
                check("config file parses (version \(cfg.version))")
                check("\(cfg.backends.count) backend(s), \(cfg.sources.count) source(s)")
            } catch {
                problems.append("config file at \(configURL.path) does not parse: \(error)")
            }
        } else {
            notes.append("no config file at \(configURL.path) (CLI-only use)")
        }

        // ssh_config
        let sshConfigPath = (NSHomeDirectory() as NSString).appendingPathComponent(".ssh/config")
        if FileManager.default.fileExists(atPath: sshConfigPath) {
            let content = (try? String(contentsOfFile: sshConfigPath, encoding: .utf8)) ?? ""
            if content.contains("IdentityAgent") {
                check("~/.ssh/config has at least one IdentityAgent directive")
            } else {
                notes.append("~/.ssh/config has no IdentityAgent directive yet")
            }
        } else {
            notes.append("no ~/.ssh/config")
        }

        // Daemon reachable via XPC?
        let machService = "com.josegonzalez.ssh-keychain.daemon"
        let client = DaemonXPCClient(endpoint: .machService(machService))
        defer { client.disconnect() }
        if let status = await client.status() {
            check("daemon reachable via Mach service \(machService) (\(status.identities.count) identities loaded)")
        } else {
            notes.append("daemon not reachable on Mach service \(machService) (run `ssh-keychain agent --mach-service \(machService)`)")
        }

        // Codesigning
        let exec = CommandLine.arguments[0]
        check("binary path: \(exec)")
        if let identity = codesignIdentity(of: exec) {
            check("binary signed by: \(identity)")
        } else {
            notes.append("binary is unsigned or ad-hoc (Secure Enclave persistence requires Developer ID + entitlements)")
        }

        // Output
        for note in notes { print("info: \(note)") }
        for problem in problems { print("problem: \(problem)") }
        if problems.isEmpty {
            print("doctor: \(notes.isEmpty ? "all checks passed" : "\(notes.count) note(s); no problems")")
        } else {
            throw ExitCode(1)
        }
    }

    private func check(_ message: String) {
        print("ok: \(message)")
    }

    private func codesignIdentity(of path: String) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = ["-dv", "--verbose=4", path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch { return nil }
        process.waitUntilExit()
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        for line in output.split(separator: "\n") {
            if line.hasPrefix("Authority=") { return String(line.dropFirst("Authority=".count)) }
        }
        return nil
    }

}
