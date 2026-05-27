import Foundation

/// 1Password 8+ CLI backend.
///
/// Shells out to the `op` binary to fetch keys via `op read op://...`. Trusts
/// `op`'s own session handling - if the vault is locked, `op` prompts for the
/// master password (and we surface its stderr).
///
/// Read-only. Users who want to add or rotate keys do so directly in the
/// 1Password app.
public actor OPBackend: Backend {
    public nonisolated let name: String
    private let account: String?
    private let vault: String
    private let defaultField: String
    private let opPath: String

    public init(
        name: String,
        account: String?,
        vault: String,
        defaultField: String = "private_key",
        opPath: String = "/usr/local/bin/op"
    ) {
        self.name = name
        self.account = account
        self.vault = vault
        self.defaultField = defaultField
        self.opPath = opPath
    }

    public func get(key: String) async throws -> Item {
        let pem = try runOpRead(item: key, field: defaultField)
        let parsed = try KeyParser.parsePrivateKey(pem)
        return Item(
            key: key,
            publicKey: parsed.publicKey,
            signer: PEMSSHSigner(parsed: parsed),
            comment: parsed.comment
        )
    }

    public func put(key: String, pem: Data, options: PutOptions) async throws {
        throw BackendError.readOnly
    }

    public func remove(key: String) async throws {
        throw BackendError.readOnly
    }

    public func list(options: ListOptions) async throws -> [PublicItem] {
        // `op item list --vault=... --format=json` returns an array of items;
        // we keep only those that have a `private_key` field. For phase 16 we
        // surface the titles; pubkeys are derived on first `get`.
        let raw = try runOpListItems()
        guard let array = try JSONSerialization.jsonObject(with: raw) as? [[String: Any]] else {
            throw OPError.invalidJSON
        }
        var items: [PublicItem] = []
        for entry in array {
            guard let title = entry["title"] as? String else { continue }
            guard let item = try? await get(key: title) else { continue }
            items.append(PublicItem(key: title, publicKey: item.publicKey, comment: item.comment ?? title))
        }
        return items
    }

    // MARK: helpers

    private func opURL(item: String, field: String) -> String {
        var components = "op://"
        if let account { components += "\(account)/" }
        components += "\(vault)/\(item)/\(field)"
        return components
    }

    private func runOpRead(item: String, field: String) throws -> Data {
        let url = opURL(item: item, field: field)
        let result = try runOp(arguments: ["read", url])
        // `op read` returns the raw field value with no trailing newline; some
        // shells/CRLFs might add one, so trim.
        var data = result
        while let last = data.last, last == 0x0a || last == 0x0d {
            data.removeLast()
        }
        return data
    }

    private func runOpListItems() throws -> Data {
        var args = ["item", "list", "--format=json", "--vault", vault]
        if let account { args.append(contentsOf: ["--account", account]) }
        return try runOp(arguments: args)
    }

    private func runOp(arguments: [String]) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: opPath)
        process.arguments = arguments
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        do {
            try process.run()
        } catch {
            throw OPError.notInstalled(opPath, error)
        }
        process.waitUntilExit()
        let stdoutData = stdout.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderr.fileHandleForReading.readDataToEndOfFile()

        if process.terminationStatus != 0 {
            let errMsg = String(data: stderrData, encoding: .utf8) ?? ""
            // Translate "isn't an item" / "doesn't exist" stderr to notFound.
            if errMsg.contains("isn't an item") || errMsg.contains("doesn't exist") || errMsg.contains("no item found") {
                throw BackendError.notFound
            }
            throw OPError.commandFailed(status: process.terminationStatus, stderr: errMsg)
        }
        return stdoutData
    }
}

public enum OPError: Error {
    case notInstalled(String, Error)
    case commandFailed(status: Int32, stderr: String)
    case invalidJSON
}
