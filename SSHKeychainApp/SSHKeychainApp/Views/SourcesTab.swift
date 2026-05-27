import AppKit
import SSHKeychainCore
import SwiftUI
import UniformTypeIdentifiers

/// Sources tab: lists `--source` entries, with three ways to add (Generate /
/// Import from file / Pick from backend). Drag-and-drop key files lands here.
struct SourcesTab: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var showingAddSheet = false
    @State private var dropTargeted = false
    @State private var importPreloadPath: String?

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Sources").font(.title2)
                Spacer()
                Menu {
                    Button("Generate new key…") { showAdd(.generate) }
                        .help("Create a new key in a writable backend (Secure Enclave for keychain)")
                    Button("Import from file…") { showAdd(.importFromFile(path: nil)) }
                        .help("Import an existing private key file (~/.ssh/id_ed25519, etc)")
                    Button("Import from clipboard") { importFromClipboard() }
                        .help("Detect a PEM-armored key in the clipboard and import it")
                    Divider()
                    Button("Pick existing from backend…") { showAdd(.pickExisting) }
                        .help("Reference a key that already lives in a configured backend")
                } label: {
                    Label("Add Source", systemImage: "plus")
                }
                .help("Add a new key source the agent should serve")
            }

            List {
                ForEach(Array(coordinator.configVM.config.sources.enumerated()), id: \.offset) { idx, entry in
                    SourceRow(entry: entry)
                        .contextMenu {
                            Button("Remove", role: .destructive) {
                                coordinator.configVM.removeSource(at: IndexSet(integer: idx))
                            }
                        }
                }
                .onMove { from, to in
                    coordinator.configVM.moveSource(from: from, to: to)
                }
                .onDelete { offsets in
                    coordinator.configVM.removeSource(at: offsets)
                }
            }
            .listStyle(.plain)
            .overlay(alignment: .center) {
                if coordinator.configVM.config.sources.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "key.viewfinder")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("Drop a private key file here, or use Add Source.")
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .padding()
        .background(dropHighlight)
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first else { return false }
            showAdd(.importFromFile(path: url.path))
            return true
        } isTargeted: { dropTargeted = $0 }
        .sheet(isPresented: $showingAddSheet) {
            AddSourceSheet(preloadedImportPath: importPreloadPath)
                .environmentObject(coordinator)
        }
    }

    private enum AddMode {
        case generate, importFromFile(path: String?), pickExisting
    }

    private func showAdd(_ mode: AddMode) {
        switch mode {
        case .importFromFile(let path): importPreloadPath = path
        default: importPreloadPath = nil
        }
        showingAddSheet = true
    }

    /// Drop-zone tint that respects window state - dims when the window is
    /// inactive so an out-of-focus window doesn't pulse accent color.
    @Environment(\.appearsActive) private var windowAppearsActive: Bool

    private var dropHighlight: Color {
        guard dropTargeted else { return .clear }
        return windowAppearsActive ? Color.accentColor.opacity(0.08) : Color.gray.opacity(0.04)
    }

    private func importFromClipboard() {
        guard let text = NSPasteboard.general.string(forType: .string),
              text.contains("-----BEGIN") else {
            coordinator.lastError = "clipboard does not contain a recognizable private key"
            return
        }
        // Write the clipboard contents to a temp file and feed it to the import flow.
        // We can't pass raw bytes to the import sheet without bigger refactoring; the
        // temp file lives only for the duration of the import.
        let tempURL = FileManager.default.temporaryDirectory
            .appending(path: "ssh-keychain-clipboard-\(UUID().uuidString)")
        do {
            try text.write(to: tempURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tempURL.path)
        } catch {
            coordinator.lastError = "could not write clipboard contents: \(error)"
            return
        }
        showAdd(.importFromFile(path: tempURL.path))
    }
}

struct SourceRow: View {
    let entry: SourceEntry

    var body: some View {
        HStack {
            Image(systemName: "key.fill").foregroundStyle(.secondary)
            VStack(alignment: .leading) {
                Text("\(entry.backend):\(entry.key)").font(.body.monospaced())
                if let item = entry.item {
                    Text("item: \(item)").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
    }
}

// MARK: add-source sheet

struct AddSourceSheet: View {
    let preloadedImportPath: String?
    @EnvironmentObject var coordinator: AppCoordinator
    @Environment(\.dismiss) private var dismiss

    enum Tab: String, CaseIterable, Identifiable {
        case generate = "Generate"
        case importFile = "Import from File"
        case pick = "Pick Existing"
        var id: String { rawValue }
    }

    @State private var tab: Tab = .importFile
    @State private var backend: String = ""
    @State private var keyName: String = ""
    @State private var requireBiometric: Bool = false
    @State private var importPath: String = ""
    @State private var importPassphrase: String = ""
    @State private var importFingerprint: String?
    @State private var actionMessage: String?

    private var writableBackends: [String] {
        coordinator.configVM.config.backends
            .filter { ["file", "keychain"].contains($0.value.type) }
            .keys
            .sorted()
    }

    var body: some View {
        VStack(alignment: .leading) {
            Picker("Method", selection: $tab) {
                ForEach(Tab.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)

            Divider()

            switch tab {
            case .generate: generateForm
            case .importFile: importForm
            case .pick: pickForm
            }

            Spacer()
            if let msg = actionMessage {
                Text(msg).foregroundStyle(.secondary).font(.callout)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button(commitLabel) { commit() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canCommit)
            }
        }
        .padding()
        .frame(minWidth: 520, minHeight: 380)
        .onAppear {
            if let preloadedImportPath {
                importPath = preloadedImportPath
                tab = .importFile
                Task { await refreshImportFingerprint() }
            }
            if backend.isEmpty {
                backend = writableBackends.first ?? ""
            }
        }
        .onChange(of: importPath) {
            Task { await refreshImportFingerprint() }
        }
    }

    private var commitLabel: String {
        switch tab {
        case .generate: return "Generate"
        case .importFile: return "Import"
        case .pick: return "Add Source"
        }
    }

    private var canCommit: Bool {
        switch tab {
        case .generate, .importFile:
            return !backend.isEmpty && !keyName.isEmpty
        case .pick:
            return !backend.isEmpty && !keyName.isEmpty
        }
    }

    // MARK: generate

    private var generateForm: some View {
        Form {
            Picker("Backend", selection: $backend) {
                ForEach(writableBackends, id: \.self) { Text($0).tag($0) }
            }
            TextField("Key name", text: $keyName)
            Toggle("Require Touch ID for each signing", isOn: $requireBiometric)
            Text("Phase 23: keychain backends in v1 generate ECDSA P-256 keys inside the Secure Enclave. Apple Silicon required.")
                .foregroundStyle(.secondary)
                .font(.callout)
        }
    }

    // MARK: import

    private var importForm: some View {
        Form {
            Picker("Backend", selection: $backend) {
                ForEach(writableBackends, id: \.self) { Text($0).tag($0) }
            }
            TextField("Key name", text: $keyName)
            HStack {
                TextField("Path", text: $importPath)
                Button("Browse…") { pickFile() }
            }
            SecureField("Passphrase (if encrypted)", text: $importPassphrase)
            if let fp = importFingerprint {
                Text("Fingerprint: \(fp)").font(.callout.monospaced())
            }
            Toggle("Require Touch ID for each signing", isOn: $requireBiometric)
        }
    }

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.data]
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url {
            importPath = url.path
        }
    }

    /// Cheap pre-commit fingerprint preview - parses the file with KeyParser
    /// and shows the result. Encrypted keys (without passphrase decryption,
    /// which is phase 3b) fall through with a friendly message.
    private func refreshImportFingerprint() async {
        guard !importPath.isEmpty, FileManager.default.fileExists(atPath: importPath) else {
            importFingerprint = nil
            return
        }
        let path = importPath
        let fp: String? = await Task.detached { () -> String? in
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
            guard let parsed = try? KeyParser.parsePrivateKey(data) else { return nil }
            return parsed.publicKey.sshKeyBlob.sha256Fingerprint
        }.value
        await MainActor.run {
            self.importFingerprint = fp
            if fp == nil && keyName.isEmpty {
                self.actionMessage = "Couldn't parse this file (encrypted keys not yet supported in v1)."
            } else {
                self.actionMessage = nil
            }
        }
    }

    // MARK: pick existing

    @State private var candidateKeys: [String] = []
    @State private var pickedKey: String = ""

    private var pickForm: some View {
        Form {
            Picker("Backend", selection: $backend) {
                ForEach(allBackends, id: \.self) { Text($0).tag($0) }
            }
            .onChange(of: backend) { _, newValue in
                Task { await refreshCandidates(for: newValue) }
            }
            if candidateKeys.isEmpty {
                Text(backend.isEmpty ? "Pick a backend" : "No keys available (daemon offline or backend empty).")
                    .foregroundStyle(.secondary)
            } else {
                Picker("Key", selection: $pickedKey) {
                    ForEach(candidateKeys, id: \.self) { Text($0).tag($0) }
                }
                .onChange(of: pickedKey) { _, newValue in keyName = newValue }
            }
        }
    }

    private var allBackends: [String] {
        coordinator.configVM.config.backends.keys.sorted()
    }

    private func refreshCandidates(for backend: String) async {
        guard !backend.isEmpty else { candidateKeys = []; return }
        let keys = (try? await coordinator.client.listSourceCandidates(backend: backend)) ?? []
        await MainActor.run {
            self.candidateKeys = keys
            if let first = keys.first {
                self.pickedKey = first
                self.keyName = first
            }
        }
    }

    // MARK: commit

    private func commit() {
        let entry = SourceEntry(backend: backend, key: keyName)
        switch tab {
        case .generate:
            actionMessage = "Generate flow: call `ssh-keychain gen --source=\(backend):\(keyName) --algorithm=ecdsa-p256 --secure-enclave\(requireBiometric ? " --require-biometric" : "")` from a codesigned binary. Secure-Enclave persistence needs Developer ID."
            // We still add the source entry so the agent will try to load it.
            coordinator.configVM.addSource(entry)
        case .importFile:
            actionMessage = "Import flow: call `ssh-keychain add --source=\(backend):\(keyName) --file=\(importPath)\(requireBiometric ? " --require-biometric" : "")` (passphrase support lands in phase 3b)."
            coordinator.configVM.addSource(entry)
        case .pick:
            coordinator.configVM.addSource(entry)
        }
        coordinator.reload()
        dismiss()
    }
}

import Crypto

private extension Data {
    var sha256Fingerprint: String {
        let digest = Crypto.SHA256.hash(data: self)
        let b64 = Data(digest).base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))
        return "SHA256:\(b64)"
    }
}
