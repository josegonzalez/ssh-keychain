import SSHKeychainCore
import SwiftUI

struct AdvancedTab: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var cliInstalled: Bool = false
    @State private var message: String?

    private let symlinkPath = "/usr/local/bin/ssh-keychain"

    var body: some View {
        Form {
            Section("Launch agent") {
                LaunchAgentRow()
                    .environmentObject(coordinator)
            }

            Section("Command-line tool") {
                HStack {
                    Text(cliInstalled ? "Installed at \(symlinkPath)" : "Not installed")
                        .foregroundStyle(cliInstalled ? .primary : .secondary)
                    Spacer()
                    if cliInstalled {
                        Button("Remove…") { remove() }
                            .help("Print the command to remove the /usr/local/bin/ssh-keychain symlink")
                    } else {
                        Button("Install command-line tool…") { install() }
                            .help("Print the command to symlink /usr/local/bin/ssh-keychain to the bundled binary")
                    }
                }
                Text("Creates a symlink at \(symlinkPath) pointing at the binary inside this app bundle. Requires admin authentication on first install.")
                    .foregroundStyle(.secondary)
                    .font(.callout)
            }

            Section("Config file") {
                HStack {
                    Text(coordinator.configVM.url.path).font(.callout.monospaced())
                    Spacer()
                    Button("Reveal in Finder") { revealConfig() }
                        .help("Show the config file in Finder")
                    Button("Open in editor") { openConfig() }
                        .help("Open the config file in your default JSON editor")
                }
            }
            if let message {
                Text(message).foregroundStyle(.secondary)
            }
        }
        .padding()
        .onAppear { refresh() }
    }

    private func refresh() {
        cliInstalled = FileManager.default.fileExists(atPath: symlinkPath)
    }

    private func install() {
        let bundlePath = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/ssh-keychain").path
        message = "Run in Terminal: sudo ln -sf '\(bundlePath)' '\(symlinkPath)'"
    }

    private func remove() {
        message = "Run in Terminal: sudo rm '\(symlinkPath)'"
    }

    private func revealConfig() {
        if FileManager.default.fileExists(atPath: coordinator.configVM.url.path) {
            NSWorkspace.shared.activateFileViewerSelecting([coordinator.configVM.url])
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([coordinator.configVM.url.deletingLastPathComponent()])
        }
    }

    private func openConfig() {
        if !FileManager.default.fileExists(atPath: coordinator.configVM.url.path) {
            coordinator.configVM.saveOrSurfaceError()
        }
        NSWorkspace.shared.open(coordinator.configVM.url)
    }
}

/// Single launch-agent control row reused in Settings and Onboarding.
struct LaunchAgentRow: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var working: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: iconName)
                    .foregroundStyle(iconColor)
                Text(statusText)
                    .font(.body.bold())
                Spacer()
                actionButtons
            }
            Text(detailText)
                .font(.callout)
                .foregroundStyle(.secondary)
            if let err = coordinator.launchAgent.lastErrorMessage {
                Text(err).font(.callout).foregroundStyle(.red)
            }
        }
    }

    private var iconName: String {
        switch coordinator.launchAgent.state {
        case .enabled: return "checkmark.circle.fill"
        case .requiresApproval: return "exclamationmark.triangle.fill"
        case .notRegistered, .notFound: return "circle"
        case .unknown: return "questionmark.circle"
        }
    }

    private var iconColor: Color {
        switch coordinator.launchAgent.state {
        case .enabled: return .green
        case .requiresApproval: return .orange
        case .notRegistered, .notFound: return .secondary
        case .unknown: return .secondary
        }
    }

    private var statusText: String {
        switch coordinator.launchAgent.state {
        case .enabled: return "Enabled (running)"
        case .requiresApproval: return "Approval required"
        case .notRegistered: return "Not enabled"
        case .notFound: return "Plist missing from bundle"
        case .unknown(let raw): return "Unknown status (raw \(raw))"
        }
    }

    private var detailText: String {
        switch coordinator.launchAgent.state {
        case .enabled:
            return "The agent will start automatically at login and stay running in the background."
        case .requiresApproval:
            return "You denied or deferred the approval prompt. Open Login Items in System Settings to enable us."
        case .notRegistered:
            return "Enable to register us as a login item. macOS may show an approval prompt the first time."
        case .notFound:
            return "Reinstall the app: Contents/Library/LaunchAgents/\(LaunchAgentManager.plistName) is missing."
        case .unknown:
            return "macOS reported a status we don't recognize. Try refreshing."
        }
    }

    @ViewBuilder
    private var actionButtons: some View {
        switch coordinator.launchAgent.state {
        case .enabled:
            Button("Disable") {
                working = true
                Task {
                    await coordinator.launchAgent.disable()
                    working = false
                }
            }
            .disabled(working)
            .help("Unregister the launch agent. ssh will stop being able to dial the agent socket.")
        case .requiresApproval:
            Button("Open Login Items…") {
                coordinator.launchAgent.openLoginItemsSettings()
            }
            .help("Open System Settings → Login Items so you can approve the agent")
            Button("Refresh") {
                coordinator.launchAgent.refresh()
            }
        case .notRegistered, .notFound, .unknown:
            Button("Enable…") {
                coordinator.launchAgent.enable()
            }
            .help("Register the launch agent with macOS so it starts at login.")
        }
    }
}
