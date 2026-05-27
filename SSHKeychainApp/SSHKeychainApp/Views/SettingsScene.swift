import SwiftUI
import SSHKeychainCore

/// Settings window with the tabs called out in the plan. Each tab is a
/// placeholder for now; phases 23-25 fill in the real UI.
struct SettingsScene: View {
    @EnvironmentObject var coordinator: AppCoordinator

    var body: some View {
        TabView {
            BackendsTab()
                .tabItem { Label("Backends", systemImage: "tray.full") }
            SourcesTab()
                .tabItem { Label("Sources", systemImage: "key.fill") }
            AgentTab()
                .tabItem { Label("Agent", systemImage: "gear") }
            SSHConfigTab()
                .tabItem { Label("ssh_config", systemImage: "doc.text") }
            AdvancedTab()
                .tabItem { Label("Advanced", systemImage: "wrench.and.screwdriver") }
            AboutTab()
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(minWidth: 560, minHeight: 380)
        .padding()
    }
}

struct AboutTab: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @EnvironmentObject var updateController: UpdateController
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("SSH Keychain").font(.title)
            Text("Version \(coordinator.daemonStatus?.version ?? SSHKeychain.version)")
                .foregroundStyle(.secondary)
            Text("Dynamic SSH key retrieval from pluggable backends.")
            Spacer()
            HStack {
                CheckForUpdatesMenuItem(controller: updateController)
                    .help("Ask Sparkle to fetch the appcast and check for a newer version")
                Spacer()
                Link("GitHub",
                     destination: URL(string: "https://github.com/josegonzalez/ssh-keychain")!)
            }
        }
    }
}
