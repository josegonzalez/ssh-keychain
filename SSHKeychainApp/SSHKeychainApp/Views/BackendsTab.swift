import SSHKeychainCore
import SwiftUI

/// Lists configured backends and lets the user add/edit/remove/test them.
/// Mutations go through `ConfigViewModel`, which writes the config file
/// atomically and triggers the daemon's `ConfigWatcher` to reload.
struct BackendsTab: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var showingAddSheet = false
    @State private var editingBackend: BackendEntry?

    /// Sorted view of the configured backends (the underlying dictionary
    /// isn't naturally ordered, and `ForEach` needs identifiable items).
    private var entries: [BackendEntry] {
        coordinator.configVM.config.backends
            .map { BackendEntry(name: $0.key, config: $0.value) }
            .sorted { $0.name < $1.name }
    }

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Backends").font(.title2)
                Spacer()
                Button {
                    showingAddSheet = true
                } label: {
                    Label("Add Backend", systemImage: "plus")
                }
                .help("Register a new backend instance the daemon can read keys from")
            }

            if entries.isEmpty {
                VStack(spacing: 12) {
                    Text("No backends configured yet.")
                        .foregroundStyle(.secondary)
                    Text("Add one to start serving keys through the agent.")
                        .foregroundStyle(.secondary)
                        .font(.callout)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(entries) {
                    TableColumn("Name") { Text($0.name).monospaced() }
                    TableColumn("Type") { Text($0.config.type) }
                    TableColumn("Detail", value: \.detailSummary)
                    TableColumn("") { entry in
                        HStack {
                            Button("Edit") { editingBackend = entry }
                                .help("Edit this backend's connectivity settings")
                            Button("Remove", role: .destructive) {
                                coordinator.configVM.removeBackend(name: entry.name)
                            }
                            .help("Remove this backend and any source entries that reference it")
                            Button("Test") {
                                coordinator.lastError = "test backend: not implemented in this build"
                            }
                            .help("Ask the daemon to verify it can reach this backend")
                        }
                    }
                    .width(min: 220)
                }
            }
        }
        .padding()
        .sheet(isPresented: $showingAddSheet) {
            BackendEditorSheet(mode: .add) { name, cfg in
                coordinator.configVM.addBackend(name: name, config: cfg)
            }
        }
        .sheet(item: $editingBackend) { entry in
            BackendEditorSheet(mode: .edit(name: entry.name, config: entry.config)) { name, cfg in
                if name != entry.name {
                    coordinator.configVM.removeBackend(name: entry.name)
                }
                coordinator.configVM.updateBackend(name: name, config: cfg)
            }
        }
    }
}

struct BackendEntry: Identifiable {
    let name: String
    let config: BackendConfig
    var id: String { name }

    var detailSummary: String {
        switch config.type {
        case "file": return config.path ?? "(default path)"
        case "keychain": return "macOS Keychain"
        case "vault": return [config.address, config.mount, config.prefix].compactMap { $0 }.joined(separator: " · ")
        case "op": return "\(config.account ?? "(default account)") · \(config.vault ?? "?")"
        case "opvault": return config.path ?? "?"
        default: return ""
        }
    }
}

// MARK: editor sheet

struct BackendEditorSheet: View {
    enum Mode {
        case add
        case edit(name: String, config: BackendConfig)
    }

    let mode: Mode
    let onCommit: (String, BackendConfig) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var name: String = ""
    @State private var type: String = "file"
    @State private var path: String = ""
    @State private var address: String = ""
    @State private var mount: String = "secret"
    @State private var prefix: String = "ssh"
    @State private var tokenRef: String = ""
    @State private var account: String = ""
    @State private var vault: String = "Personal"
    @State private var masterRef: String = ""
    @State private var lockAfter: Double = 900

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(isAdd ? "Add Backend" : "Edit Backend").font(.title2)
            Form {
                TextField("Name", text: $name)
                    .disableAutocorrection(true)
                Picker("Type", selection: $type) {
                    Text("File").tag("file")
                    Text("macOS Keychain").tag("keychain")
                    Text("HashiCorp Vault").tag("vault")
                    Text("1Password CLI (op)").tag("op")
                    Text("1Password OPVault").tag("opvault")
                }
                .pickerStyle(.menu)

                switch type {
                case "file":
                    TextField("Root path (optional)", text: $path)
                case "keychain":
                    Text("No additional configuration required.").foregroundStyle(.secondary)
                case "vault":
                    TextField("Address (https://vault.example:8200)", text: $address)
                    TextField("Mount", text: $mount)
                    TextField("Prefix", text: $prefix)
                    TextField("Token (secretref)", text: $tokenRef)
                        .help("e.g. keychain:vault-prod-token  or  env:VAULT_TOKEN")
                case "op":
                    TextField("Account (optional)", text: $account)
                    TextField("Vault name", text: $vault)
                case "opvault":
                    TextField("Path to .opvault directory", text: $path)
                    TextField("Master password (secretref)", text: $masterRef)
                        .help("e.g. keychain:opvault-master or prompt:")
                    HStack {
                        Slider(value: $lockAfter, in: 60...3600, step: 60)
                        Text("\(Int(lockAfter))s lock-after")
                    }
                default:
                    EmptyView()
                }
            }
            Spacer()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button(isAdd ? "Add" : "Save") {
                    onCommit(name, buildConfig())
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(name.isEmpty)
            }
        }
        .padding()
        .frame(minWidth: 460, minHeight: 360)
        .onAppear { hydrateFromMode() }
    }

    private var isAdd: Bool {
        if case .add = mode { return true } else { return false }
    }

    private func hydrateFromMode() {
        if case .edit(let n, let c) = mode {
            name = n
            type = c.type
            path = c.path ?? ""
            address = c.address ?? ""
            mount = c.mount ?? "secret"
            prefix = c.prefix ?? "ssh"
            tokenRef = c.auth?.tokenRef ?? ""
            account = c.account ?? ""
            vault = c.vault ?? "Personal"
            masterRef = c.masterRef ?? ""
            lockAfter = c.lockAfter ?? 900
        }
    }

    private func buildConfig() -> BackendConfig {
        var cfg = BackendConfig(type: type)
        switch type {
        case "file":
            if !path.isEmpty { cfg.path = path }
        case "vault":
            cfg.address = address
            cfg.mount = mount
            cfg.prefix = prefix
            cfg.auth = AuthConfig(type: "static", tokenRef: tokenRef.isEmpty ? nil : tokenRef)
        case "op":
            cfg.account = account.isEmpty ? nil : account
            cfg.vault = vault
        case "opvault":
            cfg.path = path
            cfg.masterRef = masterRef.isEmpty ? nil : masterRef
            cfg.lockAfter = lockAfter
        default:
            break
        }
        return cfg
    }
}
