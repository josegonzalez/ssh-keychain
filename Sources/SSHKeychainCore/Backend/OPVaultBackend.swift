import Crypto
import Foundation
import NIOSSH

/// Reads SSH private keys out of a 1Password OPVault directory (the legacy
/// 1Password 4-7 export format).
///
/// Read-only: 1Password owns writes. Items are matched by title; the configured
/// field name (default `private_key`) selects which field of the item's
/// `details` JSON contains the PEM bytes. For Secure Note items containing the
/// key in the `notesPlain` field, set `field: notesPlain` in the source override.
public actor OPVaultBackend: Backend {
    public nonisolated let name: String
    private let vaultPath: URL
    private let masterSource: any SecretSource
    private let defaultField: String

    private var unlocked: UnlockedState?
    private let lockAfter: TimeInterval?
    private var lastUnlockAt: Date?

    private struct UnlockedState {
        let masterEnc: Data
        let masterMAC: Data
        let overviewEnc: Data
        let overviewMAC: Data
        var index: [String: BandEntry]   // title -> entry
    }

    private struct BandEntry {
        let title: String
        let detailsBlob: Data
        let itemEnc: Data
        let itemMAC: Data
    }

    public init(
        name: String,
        vaultPath: URL,
        masterSource: any SecretSource,
        defaultField: String = "private_key",
        lockAfter: TimeInterval? = 900
    ) {
        self.name = name
        self.vaultPath = vaultPath
        self.masterSource = masterSource
        self.defaultField = defaultField
        self.lockAfter = lockAfter
    }

    // MARK: Backend

    public func get(key: String) async throws -> Item {
        let state = try await ensureUnlocked()
        guard let entry = state.index[key] else { throw BackendError.notFound }
        let detailsBytes = try OPVaultCrypto.decryptOPData01(
            entry.detailsBlob,
            encryptionKey: entry.itemEnc,
            macKey: entry.itemMAC
        )
        let details = try parseJSON(detailsBytes)
        let pemString: String
        if let direct = details[defaultField] as? String {
            pemString = direct
        } else if let sections = details["sections"] as? [[String: Any]] {
            // Custom fields live inside `sections[].fields[]` for Login/Secure Note items.
            pemString = try findSectionField(sections, named: defaultField, fallbackTitle: key)
        } else if defaultField == "notesPlain", let notes = details["notesPlain"] as? String {
            pemString = notes
        } else {
            throw OPVaultError.fieldMissing(defaultField)
        }
        let pem = Data(pemString.utf8)
        let parsed = try KeyParser.parsePrivateKey(pem)
        return Item(
            key: key,
            publicKey: parsed.publicKey,
            signer: PEMSSHSigner(parsed: parsed),
            comment: parsed.comment ?? entry.title
        )
    }

    public func put(key: String, pem: Data, options: PutOptions) async throws {
        throw BackendError.readOnly
    }

    public func remove(key: String) async throws {
        throw BackendError.readOnly
    }

    public func list(options: ListOptions) async throws -> [PublicItem] {
        let state = try await ensureUnlocked()
        var items: [PublicItem] = []
        for (title, _) in state.index {
            // Best-effort: each get() does its own crypto, so listing decrypts
            // every item to derive a public key. This matches the plan and
            // mirrors how the Vault backend handles `list`.
            if let item = try? await get(key: title) {
                items.append(PublicItem(key: title, publicKey: item.publicKey, comment: item.comment))
            }
        }
        return items
    }

    // MARK: unlock

    private func ensureUnlocked() async throws -> UnlockedState {
        if let state = unlocked, !isStale() {
            return state
        }
        try await unlock()
        return unlocked!
    }

    private func isStale() -> Bool {
        guard let lockAfter, let last = lastUnlockAt else { return false }
        return Date().timeIntervalSince(last) > lockAfter
    }

    private func unlock() async throws {
        let profile = try parseProfile()
        let password = try await masterSource.fetch()
        defer { /* TODO: zero password buffer */ }

        let (derivedEnc, derivedMAC) = try OPVaultCrypto.deriveKeys(
            password: password,
            salt: profile.salt,
            iterations: profile.iterations
        )
        let masterPlain = try OPVaultCrypto.decryptOPData01(
            profile.masterKey,
            encryptionKey: derivedEnc,
            macKey: derivedMAC
        )
        // The 1Password spec specifies that the decrypted master key is the
        // SHA-512 of the actual 64-byte material; the first 32 bytes of the
        // digest are the encryption key, the last 32 are the MAC key.
        let masterDigest = Crypto.SHA512.hash(data: masterPlain)
        let masterDigestBytes = Data(masterDigest)
        let masterEnc = masterDigestBytes.prefix(32)
        let masterMAC = masterDigestBytes.suffix(32)

        let overviewPlain = try OPVaultCrypto.decryptOPData01(
            profile.overviewKey,
            encryptionKey: derivedEnc,
            macKey: derivedMAC
        )
        let overviewDigest = Data(Crypto.SHA512.hash(data: overviewPlain))
        let overviewEnc = overviewDigest.prefix(32)
        let overviewMAC = overviewDigest.suffix(32)

        let index = try buildIndex(masterEnc: Data(masterEnc), masterMAC: Data(masterMAC),
                                   overviewEnc: Data(overviewEnc), overviewMAC: Data(overviewMAC))

        self.unlocked = UnlockedState(
            masterEnc: Data(masterEnc),
            masterMAC: Data(masterMAC),
            overviewEnc: Data(overviewEnc),
            overviewMAC: Data(overviewMAC),
            index: index
        )
        self.lastUnlockAt = Date()
    }

    // MARK: vault parsing

    private struct Profile {
        let salt: Data
        let iterations: Int
        let masterKey: Data
        let overviewKey: Data
    }

    private func parseProfile() throws -> Profile {
        let url = vaultPath.appending(path: "default/profile.js")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw OPVaultError.profileNotFound(url.path)
        }
        let raw = try String(contentsOf: url, encoding: .utf8)
        let stripped = stripJSONP(raw, prefix: "var profile=", suffix: ";")
        guard let data = stripped.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw OPVaultError.malformed("profile.js JSON parse") }

        guard
            let saltB64 = json["salt"] as? String,
            let iter = json["iterations"] as? Int,
            let masterKeyB64 = json["masterKey"] as? String,
            let overviewKeyB64 = json["overviewKey"] as? String,
            let salt = Data(base64Encoded: saltB64),
            let masterKey = Data(base64Encoded: masterKeyB64),
            let overviewKey = Data(base64Encoded: overviewKeyB64)
        else { throw OPVaultError.malformed("profile.js missing required fields") }

        return Profile(salt: salt, iterations: iter, masterKey: masterKey, overviewKey: overviewKey)
    }

    private func buildIndex(
        masterEnc: Data, masterMAC: Data,
        overviewEnc: Data, overviewMAC: Data
    ) throws -> [String: BandEntry] {
        var index: [String: BandEntry] = [:]
        let bandDir = vaultPath.appending(path: "default")
        let entries = try FileManager.default.contentsOfDirectory(at: bandDir, includingPropertiesForKeys: nil)
        for entry in entries where entry.lastPathComponent.hasPrefix("band_") && entry.pathExtension == "js" {
            let raw = try String(contentsOf: entry, encoding: .utf8)
            let stripped = stripJSONP(raw, prefix: "ld(", suffix: ");")
            guard let data = stripped.data(using: .utf8),
                  let bandJSON = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { continue }
            for (_, value) in bandJSON {
                guard let item = value as? [String: Any] else { continue }
                guard
                    let kB64 = item["k"] as? String,
                    let oB64 = item["o"] as? String,
                    let dB64 = item["d"] as? String,
                    let kBlob = Data(base64Encoded: kB64),
                    let oBlob = Data(base64Encoded: oB64),
                    let dBlob = Data(base64Encoded: dB64)
                else { continue }

                let (itemEnc, itemMAC): (Data, Data)
                do {
                    let pair = try OPVaultCrypto.decryptItemKey(kBlob, encryptionKey: masterEnc, macKey: masterMAC)
                    itemEnc = pair.itemEnc
                    itemMAC = pair.itemMAC
                } catch {
                    continue
                }
                guard let overviewBytes = try? OPVaultCrypto.decryptOPData01(oBlob, encryptionKey: overviewEnc, macKey: overviewMAC) else { continue }
                guard let overview = try? parseJSON(overviewBytes), let title = overview["title"] as? String else { continue }
                index[title] = BandEntry(title: title, detailsBlob: dBlob, itemEnc: itemEnc, itemMAC: itemMAC)
            }
        }
        return index
    }

    private func stripJSONP(_ raw: String, prefix: String, suffix: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix(prefix) { s.removeFirst(prefix.count) }
        if s.hasSuffix(suffix) { s.removeLast(suffix.count) }
        return s
    }

    private func parseJSON(_ data: Data) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw OPVaultError.malformed("non-object JSON")
        }
        return object
    }

    private func findSectionField(_ sections: [[String: Any]], named: String, fallbackTitle: String) throws -> String {
        for section in sections {
            guard let fields = section["fields"] as? [[String: Any]] else { continue }
            for field in fields {
                let fieldName = field["t"] as? String ?? field["n"] as? String ?? ""
                if fieldName == named, let value = field["v"] as? String { return value }
            }
        }
        throw OPVaultError.fieldMissing("\(named) (in item \(fallbackTitle))")
    }
}
