import SSHKeychainCore
import SwiftUI

/// First-launch wizard that walks the user through:
///   1. Welcome
///   2. Pick a primary backend (keychain / file / 1Password / Vault)
///   3. Import existing `~/.ssh/id_*` keys (if discovered)
///   4. Generate a Secure-Enclave key (if no imports happened)
///   5. ssh_config IdentityAgent
///   6. Enable launch agent
///   7. Done
///
/// The state is held in a view model so individual step views stay small.
struct OnboardingView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @Environment(\.dismiss) private var dismiss

    @State private var step: Step = .welcome

    enum Step: Int, CaseIterable {
        case welcome, pickBackend, importExisting, generate, sshConfig, launchAgent, done
    }

    var body: some View {
        VStack(alignment: .leading) {
            ProgressView(value: Double(step.rawValue), total: Double(Step.allCases.count - 1))
                .padding(.bottom, 12)

            Group {
                switch step {
                case .welcome: WelcomeStep(next: advance)
                case .pickBackend: PickBackendStep(next: advance)
                case .importExisting: ImportExistingStep(next: advance)
                case .generate: GenerateStep(next: advance)
                case .sshConfig: SSHConfigStep(next: advance)
                case .launchAgent: LaunchAgentStep(next: advance)
                case .done: DoneStep(close: { dismiss() })
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            HStack {
                if step.rawValue > 0 {
                    Button("Back") { back() }
                }
                Spacer()
                Button("Skip") { dismiss() }
                    .opacity(step == .done ? 0 : 1)
            }
        }
        .padding(24)
        .frame(width: 520, height: 420)
    }

    private func advance() {
        if let next = Step(rawValue: step.rawValue + 1) {
            step = next
        }
    }

    private func back() {
        if let prev = Step(rawValue: step.rawValue - 1) {
            step = prev
        }
    }
}

// MARK: step views

private struct WelcomeStep: View {
    let next: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Welcome to ssh-keychain").font(.title)
            Text("This wizard sets up the SSH-agent so your private keys can live in the macOS Keychain, 1Password, or HashiCorp Vault instead of as plaintext files in ~/.ssh/.")
            Spacer()
            Button("Get started") { next() }
                .keyboardShortcut(.defaultAction)
        }
    }
}

private struct PickBackendStep: View {
    @EnvironmentObject var coordinator: AppCoordinator
    let next: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Pick a primary backend").font(.title2)
            Text("We'll start with one - you can add more later.")
            VStack(alignment: .leading) {
                BackendChoice(type: "keychain", title: "macOS Keychain (recommended)",
                              detail: "Keys protected by Touch ID; new keys can live in the Secure Enclave.")
                BackendChoice(type: "file", title: "Plain files",
                              detail: "Files on disk under ~/Library/Application Support/. Lower security.")
                BackendChoice(type: "op", title: "1Password CLI",
                              detail: "Use existing keys from your 1Password 8 vault. Requires `op` CLI.")
                BackendChoice(type: "vault", title: "HashiCorp Vault",
                              detail: "KV-v2 secrets from a Vault server.")
            }
            Spacer()
            Button("Continue") { next() }
                .keyboardShortcut(.defaultAction)
        }
    }
}

private struct BackendChoice: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @Environment(\.appearsActive) private var appearsActive: Bool
    @State private var hovering: Bool = false
    let type: String
    let title: String
    let detail: String

    var body: some View {
        Button {
            ensure(type: type)
        } label: {
            VStack(alignment: .leading) {
                Text(title).font(.headline)
                Text(detail).font(.callout).foregroundStyle(.secondary)
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(hoverBackground)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(outlineColor, lineWidth: alreadyConfigured ? 2 : 1)
            )
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(detail)
    }

    private var outlineColor: Color {
        // De-emphasize in inactive windows: per HIG, only the key window's
        // controls should be tinted.
        let base: Color = alreadyConfigured ? .accentColor : .secondary
        return appearsActive ? base : base.opacity(0.4)
    }

    private var hoverBackground: Color {
        guard hovering, appearsActive else { return .clear }
        return Color.primary.opacity(0.05)
    }

    private var alreadyConfigured: Bool {
        coordinator.configVM.config.backends.values.contains { $0.type == type }
    }

    private func ensure(type: String) {
        if alreadyConfigured { return }
        let name: String
        switch type {
        case "keychain": name = "primary"
        case "file": name = "files"
        case "op": name = "work-1p"
        case "vault": name = "vault"
        default: name = type
        }
        coordinator.configVM.addBackend(name: name, config: BackendConfig(type: type))
    }
}

private struct ImportExistingStep: View {
    @EnvironmentObject var coordinator: AppCoordinator
    let next: () -> Void
    @State private var detected: [URL] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Existing keys").font(.title2)
            if detected.isEmpty {
                Text("We didn't find any key files in ~/.ssh/. Skip ahead to generate a fresh key.")
                    .foregroundStyle(.secondary)
            } else {
                Text("We found \(detected.count) key file(s) in ~/.ssh/. The full per-key import flow lives in Settings → Sources.")
                    .foregroundStyle(.secondary)
                List(detected, id: \.self) { url in
                    Text(url.lastPathComponent).font(.body.monospaced())
                }
                .frame(maxHeight: 160)
            }
            Spacer()
            Button("Continue") { next() }
                .keyboardShortcut(.defaultAction)
        }
        .onAppear { scan() }
    }

    private func scan() {
        let sshDir = (("~/.ssh") as NSString).expandingTildeInPath
        guard let entries = try? FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: sshDir), includingPropertiesForKeys: nil) else { return }
        detected = entries.filter {
            let name = $0.lastPathComponent
            return name.hasPrefix("id_") && !name.hasSuffix(".pub") && !name.hasSuffix("_sk")
        }
    }
}

private struct GenerateStep: View {
    let next: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Generate a new key").font(.title2)
            Text("Apple Silicon Macs can store ECDSA P-256 keys inside the Secure Enclave - they sign without ever leaving hardware.")
            Text("Use Settings → Sources → Generate new key after you finish onboarding. Production builds add a one-click button here once Developer ID codesigning is in place.")
                .foregroundStyle(.secondary)
                .font(.callout)
            Spacer()
            Button("Continue") { next() }
                .keyboardShortcut(.defaultAction)
        }
    }
}

private struct SSHConfigStep: View {
    let next: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Configure SSH").font(.title2)
            Text("Add an `IdentityAgent` directive to ~/.ssh/config so ssh dials our agent socket.")
            Text("Settings → ssh_config detects hosts that still use file-based identities and offers to convert them. We back up your config before any change.")
                .foregroundStyle(.secondary)
                .font(.callout)
            Spacer()
            Button("Continue") { next() }
                .keyboardShortcut(.defaultAction)
        }
    }
}

private struct LaunchAgentStep: View {
    @EnvironmentObject var coordinator: AppCoordinator
    let next: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Enable launch agent").font(.title2)
            Text("The agent runs in the background via SMAppService. macOS will ask for approval the first time you enable it.")
            LaunchAgentRow()
                .environmentObject(coordinator)
                .padding(.vertical, 4)
            Spacer()
            Button(coordinator.launchAgent.state == .enabled ? "Continue" : "Continue without enabling") {
                next()
            }
            .keyboardShortcut(.defaultAction)
        }
    }
}

private struct DoneStep: View {
    let close: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("All set").font(.title)
            Text("ssh-keychain lives in your menu bar. Use Settings to add more backends or wire up additional sources.")
            Spacer()
            Button("Done") { close() }
                .keyboardShortcut(.defaultAction)
        }
    }
}
