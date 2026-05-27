import SSHKeychainCore
import SwiftUI

/// Detects `Host` blocks in `~/.ssh/config` that lack an `IdentityAgent`
/// directive and offers to add one. Writes a timestamped backup before any
/// mutation.
struct SSHConfigTab: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var hosts: [SSHConfigInspector.HostBlock] = []
    @State private var status: String?

    var body: some View {
        VStack(alignment: .leading) {
            Text("ssh_config").font(.title2)
            Text("Hosts in `~/.ssh/config` that don't yet route through ssh-keychain.")
                .foregroundStyle(.secondary)

            if hosts.isEmpty {
                Text(status ?? "All hosts already use IdentityAgent.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(hosts) { host in
                    HStack {
                        Text(host.pattern).font(.body.monospaced())
                        Spacer()
                        Button("Add IdentityAgent") { addIdentityAgent(for: host) }
                    }
                }
                Button("Add IdentityAgent to all") { addIdentityAgentToAll() }
            }
            if let status {
                Text(status).foregroundStyle(.secondary).padding(.top, 4)
            }
        }
        .padding()
        .onAppear { refresh() }
    }

    private func refresh() {
        let inspector = SSHConfigInspector(socketPath: coordinator.configVM.config.agent.socketPath)
        do {
            hosts = try inspector.findHostsMissingIdentityAgent()
            status = nil
        } catch {
            status = "could not read ~/.ssh/config: \(error)"
            hosts = []
        }
    }

    private func addIdentityAgent(for host: SSHConfigInspector.HostBlock) {
        let inspector = SSHConfigInspector(socketPath: coordinator.configVM.config.agent.socketPath)
        do {
            try inspector.addIdentityAgent(toHostsMatching: [host.pattern])
            status = "Added IdentityAgent to \(host.pattern). Backup at \(inspector.lastBackupPath ?? "?")."
            refresh()
        } catch {
            status = "failed: \(error)"
        }
    }

    private func addIdentityAgentToAll() {
        let inspector = SSHConfigInspector(socketPath: coordinator.configVM.config.agent.socketPath)
        do {
            try inspector.addIdentityAgent(toHostsMatching: hosts.map(\.pattern))
            status = "Added IdentityAgent to \(hosts.count) host(s). Backup at \(inspector.lastBackupPath ?? "?")."
            refresh()
        } catch {
            status = "failed: \(error)"
        }
    }
}

/// Lightweight ssh_config inspector. Doesn't pretend to be a full parser - we
/// only care about top-level `Host` blocks and detecting whether each has an
/// `IdentityAgent` directive somewhere before the next `Host`/`Match`.
final class SSHConfigInspector {
    let configPath: String
    let socketPath: String
    private(set) var lastBackupPath: String?

    init(configPath: String = ("~/.ssh/config" as NSString).expandingTildeInPath,
         socketPath: String)
    {
        self.configPath = configPath
        self.socketPath = socketPath
    }

    struct HostBlock: Identifiable {
        var id: String { pattern }
        let pattern: String
    }

    func findHostsMissingIdentityAgent() throws -> [HostBlock] {
        guard FileManager.default.fileExists(atPath: configPath) else { return [] }
        let lines = try String(contentsOfFile: configPath, encoding: .utf8).split(separator: "\n", omittingEmptySubsequences: false)

        var hosts: [HostBlock] = []
        var currentHostPatterns: [String] = []
        var currentHasIdentityAgent = false

        func closeCurrent() {
            for pat in currentHostPatterns where !currentHasIdentityAgent && pat != "*" {
                hosts.append(HostBlock(pattern: pat))
            }
            currentHostPatterns = []
            currentHasIdentityAgent = false
        }

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let lower = trimmed.lowercased()
            if lower.hasPrefix("host ") {
                closeCurrent()
                currentHostPatterns = trimmed
                    .split(separator: " ", omittingEmptySubsequences: true)
                    .dropFirst()
                    .map(String.init)
            } else if lower.hasPrefix("match ") {
                closeCurrent()
            } else if lower.hasPrefix("identityagent ") {
                currentHasIdentityAgent = true
            }
        }
        closeCurrent()
        return hosts
    }

    func addIdentityAgent(toHostsMatching patterns: [String]) throws {
        if !FileManager.default.fileExists(atPath: configPath) {
            try "".write(toFile: configPath, atomically: true, encoding: .utf8)
        }
        let timestamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let backupPath = configPath + ".backup-" + timestamp
        try FileManager.default.copyItem(atPath: configPath, toPath: backupPath)
        self.lastBackupPath = backupPath

        let raw = try String(contentsOfFile: configPath, encoding: .utf8)
        let lines = raw.components(separatedBy: "\n")
        var currentHostPatterns: [String] = []
        var currentHasIdentityAgent = false
        var output: [String] = []
        let want = Set(patterns)
        let directive = "  IdentityAgent \(socketPath)"

        func emitCurrentClose() {
            if !currentHostPatterns.isEmpty,
               currentHostPatterns.contains(where: { want.contains($0) }),
               !currentHasIdentityAgent
            {
                output.append(directive)
            }
            currentHostPatterns = []
            currentHasIdentityAgent = false
        }

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let lower = trimmed.lowercased()
            if lower.hasPrefix("host ") || lower.hasPrefix("match ") {
                emitCurrentClose()
                if lower.hasPrefix("host ") {
                    currentHostPatterns = trimmed
                        .split(separator: " ", omittingEmptySubsequences: true)
                        .dropFirst()
                        .map(String.init)
                }
            } else if lower.hasPrefix("identityagent ") {
                currentHasIdentityAgent = true
            }
            output.append(line)
        }
        emitCurrentClose()

        try output.joined(separator: "\n").write(toFile: configPath, atomically: true, encoding: .utf8)
    }
}
