import SwiftUI
import SSHKeychainCore

/// Menu-bar drop-down. Shows the running state, loaded keys, and quick actions.
struct MenuBarContent: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if !coordinator.daemonReachable {
            Text("SSH Keychain · daemon offline")
                .foregroundStyle(.secondary)
            Text("(reconnecting…)")
                .foregroundStyle(.secondary)
            Divider()
            settingsButton
            Button("Quit") { NSApplication.shared.terminate(nil) }
                .keyboardShortcut("q")
        } else if let status = coordinator.daemonStatus {
            statusHeader(status)
            Divider()
            identitiesSection(status)
            Divider()
            actionsSection
            Divider()
            footerSection
        }
    }

    @ViewBuilder
    private func statusHeader(_ status: DaemonStatus) -> some View {
        Text("SSH Keychain \(status.version) · \(status.running ? "running" : "stopped")")
    }

    @ViewBuilder
    private func identitiesSection(_ status: DaemonStatus) -> some View {
        if status.identities.isEmpty {
            Text("No keys loaded").foregroundStyle(.secondary)
        } else {
            ForEach(status.identities, id: \.fingerprint) { id in
                Text("\(symbol(for: id)) \(id.backend):\(id.key)")
                    .help(id.fingerprint)
            }
        }
    }

    private var actionsSection: some View {
        Group {
            Button("Reload sources") { coordinator.reload() }
                .keyboardShortcut("r")
                .help("Re-read the config file and rebuild the agent's identity map")
            Button("Lock all keys") { coordinator.lockAll() }
                .keyboardShortcut("l")
                .help("Flush the in-memory key cache; next sign re-prompts Touch ID")
        }
    }

    private var footerSection: some View {
        Group {
            settingsButton
            Button("Activity…") { openWindow(id: "activity") }
                .keyboardShortcut("a", modifiers: [.command, .shift])
                .help("Recent sign-event log")
            Button("Onboarding…") { openWindow(id: "onboarding") }
                .help("Re-run the first-launch setup")
            Button("Quit") { NSApplication.shared.terminate(nil) }
                .keyboardShortcut("q")
        }
    }

    /// SettingsLink (macOS 14+) is the canonical way to open the `Settings { }`
    /// scene from anywhere in the view hierarchy. Unlike sending stringly-typed
    /// selectors, it knows about the scene by structural identity.
    private var settingsButton: some View {
        SettingsLink {
            Text("Settings…")
        }
        .keyboardShortcut(",")
    }

    private func symbol(for id: LoadedIdentity) -> String {
        if id.cached { return "✓" }
        if id.biometric { return "⚿" }
        return "·"
    }
}
