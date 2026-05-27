import SSHKeychainCore
import SwiftUI

struct AgentTab: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var socketPath: String = ""
    @State private var cacheTTL: Double = 0
    @State private var cacheMaxKeys: Double = 32

    var body: some View {
        Form {
            Section("Agent socket") {
                HStack {
                    TextField("Socket path", text: $socketPath)
                        .help("Where the agent binds. Put this same path in your ssh_config IdentityAgent directive.")
                    Button("Reveal in Finder") { revealSocket() }
                        .disabled(socketPath.isEmpty)
                        .help("Open Finder at the directory containing the socket file")
                }
            }
            Section("Key cache") {
                HStack {
                    Slider(value: $cacheTTL, in: 0...3600, step: 60)
                    Text(cacheTTL == 0 ? "off" : "\(Int(cacheTTL))s TTL")
                        .frame(width: 100, alignment: .trailing)
                }
                HStack {
                    Slider(value: $cacheMaxKeys, in: 1...128, step: 1)
                    Text("\(Int(cacheMaxKeys)) max")
                        .frame(width: 100, alignment: .trailing)
                }
                Text("Caching keeps unlocked signers in memory after Touch ID. With TTL=0, every Sign re-prompts.")
                    .foregroundStyle(.secondary)
                    .font(.callout)
            }
            HStack {
                Spacer()
                Button("Apply") { apply() }
                    .keyboardShortcut(.defaultAction)
                    .help("Write the agent settings to the config file; the daemon picks them up via its FSEvents watcher")
            }
        }
        .padding()
        .onAppear { hydrateFromConfig() }
    }

    private func hydrateFromConfig() {
        let agent = coordinator.configVM.config.agent
        socketPath = agent.socketPath
        cacheTTL = agent.cacheTTL
        cacheMaxKeys = Double(agent.cacheMaxKeys)
    }

    private func apply() {
        coordinator.configVM.config.agent.socketPath = socketPath
        coordinator.configVM.config.agent.cacheTTL = cacheTTL
        coordinator.configVM.config.agent.cacheMaxKeys = Int(cacheMaxKeys)
        coordinator.configVM.saveOrSurfaceError()
        coordinator.reload()
    }

    private func revealSocket() {
        let expanded = (socketPath as NSString).expandingTildeInPath
        // Sockets aren't selectable in Finder; we reveal the parent dir instead.
        let parent = (expanded as NSString).deletingLastPathComponent
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: expanded.isEmpty ? parent : expanded)])
    }
}
