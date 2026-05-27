import SwiftUI
import SSHKeychainCore

@main
struct SSHKeychainAppMain: App {
    @StateObject private var coordinator = AppCoordinator()
    @StateObject private var updateController = UpdateController()

    var body: some Scene {
        MenuBarExtra {
            MenuBarContent()
                .environmentObject(coordinator)
        } label: {
            Image(systemName: coordinator.menuBarIconName)
        }
        .menuBarExtraStyle(.menu)

        Settings {
            SettingsScene()
                .environmentObject(coordinator)
                .environmentObject(updateController)
        }

        Window("Activity", id: "activity") {
            ActivityView()
                .environmentObject(coordinator)
        }
        .defaultSize(width: 760, height: 420)
        .defaultPosition(.center)
        .keyboardShortcut("a", modifiers: [.command, .shift])

        Window("Welcome", id: "onboarding") {
            OnboardingView()
                .environmentObject(coordinator)
                .onDisappear { coordinator.onboardingComplete = true }
        }
        .defaultSize(width: 560, height: 440)
        .defaultPosition(.center)
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About SSH Keychain") {
                    NSApp.orderFrontStandardAboutPanel(options: [
                        .applicationName: "SSH Keychain",
                        .applicationVersion: SSHKeychain.version,
                        NSApplication.AboutPanelOptionKey(rawValue: "Copyright"):
                            "Dynamic SSH key retrieval from pluggable backends.",
                    ])
                }
            }
            CommandGroup(after: .appInfo) {
                CheckForUpdatesMenuItem(controller: updateController)
                Divider()
            }
            CommandGroup(replacing: .help) {
                Link("SSH Keychain Help",
                     destination: URL(string: "https://github.com/josegonzalez/ssh-keychain#readme")!)
                Link("Report an Issue…",
                     destination: URL(string: "https://github.com/josegonzalez/ssh-keychain/issues")!)
            }
        }
    }
}
