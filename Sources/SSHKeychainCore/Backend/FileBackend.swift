import Foundation
import NIOSSH

/// A `Backend` that stores SSH private keys as 0600-mode files on disk, with
/// public keys in `.pub` sidecars (mode 0644) for ACL-free enumeration.
///
/// Default root: `~/Library/Application Support/com.josegonzalez.ssh-keychain/file-backend/`.
public actor FileBackend: Backend {
    public nonisolated let name: String
    private let root: URL

    public init(name: String = "file", root: URL? = nil) throws {
        self.name = name
        if let root {
            self.root = root
        } else {
            let appSupport = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            )
            self.root = appSupport
                .appending(path: "com.josegonzalez.ssh-keychain", directoryHint: .isDirectory)
                .appending(path: "file-backend", directoryHint: .isDirectory)
        }
        try Self.ensureRoot(self.root)
    }

    private static func ensureRoot(_ root: URL) throws {
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        // createDirectory only sets perms on directories it created. Re-apply
        // to be safe (the user may have pre-existing dirs with wider perms).
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: root.path
        )
    }

    public func get(key: String) async throws -> Item {
        let privateURL = url(for: key)
        guard FileManager.default.fileExists(atPath: privateURL.path) else {
            throw BackendError.notFound
        }
        let pem = try Data(contentsOf: privateURL)
        let parsed = try KeyParser.parsePrivateKey(pem)
        let signer = PEMSSHSigner(parsed: parsed)
        let sidecarComment = (try? readSidecarComment(for: key)) ?? nil
        return Item(
            key: key,
            publicKey: parsed.publicKey,
            signer: signer,
            comment: sidecarComment ?? parsed.comment
        )
    }

    private func readSidecarComment(for key: String) throws -> String? {
        let url = pubURL(for: key)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let line = try String(contentsOf: url, encoding: .utf8)
        return parseComment(from: line)
    }

    public func put(key: String, pem: Data, options: PutOptions) async throws {
        try validateKey(key)
        let privateURL = url(for: key)
        let publicURL = pubURL(for: key)

        let exists = FileManager.default.fileExists(atPath: privateURL.path)
        if exists && !options.overwrite {
            throw BackendError.exists
        }

        let parsed = try KeyParser.parsePrivateKey(pem)
        try writeAtomic(data: pem, to: privateURL, mode: 0o600)
        let publicLine = try renderPublicKeyLine(parsed.publicKey, comment: options.comment ?? parsed.comment ?? key)
        try writeAtomic(data: Data(publicLine.utf8), to: publicURL, mode: 0o644)
    }

    public func list(options: ListOptions) async throws -> [PublicItem] {
        guard FileManager.default.fileExists(atPath: root.path) else { return [] }
        let entries = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
        var items: [PublicItem] = []
        for entry in entries where entry.pathExtension == "pub" {
            let key = entry.deletingPathExtension().lastPathComponent
            do {
                let line = try String(contentsOf: entry, encoding: .utf8)
                let publicKey = try NIOSSHPublicKey(openSSHPublicKey: line)
                let comment = parseComment(from: line)
                items.append(PublicItem(key: key, publicKey: publicKey, comment: comment))
            } catch {
                // Ignore malformed .pub sidecars - we'd rather list other keys
                // than fail the whole `list` operation.
                continue
            }
        }
        items.sort { $0.key < $1.key }
        _ = options
        return items
    }

    public func remove(key: String) async throws {
        try validateKey(key)
        let privateURL = url(for: key)
        let publicURL = pubURL(for: key)
        let privExists = FileManager.default.fileExists(atPath: privateURL.path)
        let pubExists = FileManager.default.fileExists(atPath: publicURL.path)
        if !privExists && !pubExists { throw BackendError.notFound }
        if privExists { try FileManager.default.removeItem(at: privateURL) }
        if pubExists { try FileManager.default.removeItem(at: publicURL) }
    }

    // MARK: - helpers

    private func url(for key: String) -> URL {
        root.appending(path: key)
    }

    private func pubURL(for key: String) -> URL {
        root.appending(path: "\(key).pub")
    }

    private func validateKey(_ key: String) throws {
        guard !key.isEmpty else { throw BackendError.unsupported("empty key name") }
        guard !key.contains("/") && !key.contains("\\") && key != "." && key != ".." else {
            throw BackendError.unsupported("invalid characters in key name: \(key)")
        }
    }

    private func renderPublicKeyLine(_ publicKey: NIOSSHPublicKey, comment: String) throws -> String {
        let core = String(openSSHPublicKey: publicKey)  // "algo base64-blob"
        return "\(core) \(comment)\n"
    }

    private func parseComment(from line: String) -> String? {
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count == 3 else { return nil }
        let raw = parts[2].trimmingCharacters(in: .whitespacesAndNewlines)
        return raw.isEmpty ? nil : raw
    }

    private func writeAtomic(data: Data, to url: URL, mode: Int) throws {
        let tempURL = url.appendingPathExtension("tmp-\(UUID().uuidString)")
        try data.write(to: tempURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: tempURL.path)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        try FileManager.default.moveItem(at: tempURL, to: url)
    }
}
