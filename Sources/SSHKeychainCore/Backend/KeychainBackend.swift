#if canImport(Security)
import Foundation
import LocalAuthentication
import NIOSSH
import Security

/// A `Backend` that stores SSH private keys in the macOS Keychain as
/// `kSecClassGenericPassword` items, with a `.pub` sidecar item per key so
/// `list` never triggers a biometric prompt.
///
/// Each logical key produces two keychain items:
///
/// - Private item: `account=<key>`, value=raw OpenSSH PEM bytes,
///   optional `kSecAttrAccessControl` (Touch ID / passcode).
/// - Public sidecar: `account=<key>.pub`, value=`authorized_keys`-format
///   bytes, no ACL.
///
/// Both items share `kSecAttrService = serviceName` so they're discoverable
/// together and won't collide with user-stored passwords.
public actor KeychainBackend: Backend, GeneratingBackend {
    public nonisolated let name: String
    private let serviceName: String

    /// - Parameters:
    ///   - name: How this backend appears in `--source` (e.g. "keychain").
    ///   - serviceName: The `kSecAttrService` namespace. Tests pass a unique
    ///     UUID-tagged service to isolate from production items.
    public init(name: String = "keychain", serviceName: String = "com.josegonzalez.ssh-keychain") {
        self.name = name
        self.serviceName = serviceName
    }

    // MARK: - Backend

    public func get(key: String) async throws -> Item {
        try validateKey(key)

        // Mode B first: a Secure-Enclave-backed `kSecClassKey` item exists if
        // the key was created via `generate(...)`. If not, fall through to
        // Mode A (generic-password storage of raw PEM bytes).
        if let secKey = try lookupSecKey(applicationTag: key) {
            let publicKey = try nioPublicKey(fromSecKey: secKey)
            let comment = try? pubLineComment(for: key)
            return Item(
                key: key,
                publicKey: publicKey,
                signer: SecureEnclaveSigner(privateKey: secKey, publicKey: publicKey),
                comment: comment
            )
        }

        let pem = try fetchData(account: key, withACLPrompt: true)
        let parsed: ParsedKey
        do {
            parsed = try KeyParser.parsePrivateKey(pem)
        } catch {
            throw BackendError.unsupported("keychain item \(key) is not a parseable SSH key: \(error)")
        }
        let comment = try? pubLineComment(for: key)
        return Item(
            key: key,
            publicKey: parsed.publicKey,
            signer: PEMSSHSigner(parsed: parsed),
            comment: comment ?? parsed.comment
        )
    }

    public func generate(key: String, options: GenerateOptions) async throws -> Item {
        try validateKey(key)
        guard options.algorithm == .ecdsaP256 else {
            throw BackendError.unsupported("only ecdsa-p256 is supported in v1 (got \(options.algorithm.rawValue))")
        }
        guard options.secureEnclave else {
            throw BackendError.unsupported("keychain `gen` requires --secure-enclave in v1")
        }

        let exists = try secKeyExists(applicationTag: key) || itemExists(account: key)
        if exists && !options.overwrite {
            throw BackendError.exists
        }
        if exists {
            _ = try? deleteSecKey(applicationTag: key)
            _ = try? deleteItem(account: key)
            _ = try? deleteItem(account: "\(key).pub")
        }

        let acl = try makeSecureEnclaveACL(requireBiometric: options.requireBiometric)
        let appTag = applicationTagData(forKey: key)
        let label = "ssh-keychain: \(key)"

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: appTag,
                kSecAttrAccessControl as String: acl,
                kSecAttrLabel as String: label,
            ] as [String: Any],
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let cf = error?.takeRetainedValue() {
                throw SecureEnclaveError.keyGeneration(cf)
            }
            throw SecureEnclaveError.keyGenerationGeneric
        }

        let publicKey = try nioPublicKey(fromSecKey: privateKey)
        let pubLine = renderPublicKeyLine(publicKey, comment: options.comment ?? key)
        try upsertItem(
            account: "\(key).pub",
            data: Data(pubLine.utf8),
            label: "\(label).pub",
            accessControl: nil,
            allowOverwrite: true
        )

        return Item(
            key: key,
            publicKey: publicKey,
            signer: SecureEnclaveSigner(privateKey: privateKey, publicKey: publicKey),
            comment: options.comment ?? key
        )
    }

    public func put(key: String, pem: Data, options: PutOptions) async throws {
        try validateKey(key)
        let parsed: ParsedKey
        do {
            parsed = try KeyParser.parsePrivateKey(pem)
        } catch {
            throw BackendError.unsupported("not a parseable SSH key: \(error)")
        }

        let exists = try itemExists(account: key)
        if exists && !options.overwrite { throw BackendError.exists }

        let label = "ssh-keychain: \(key)"
        let pubLine = renderPublicKeyLine(parsed.publicKey, comment: options.comment ?? parsed.comment ?? key)

        // Public sidecar first - if writing the private item fails (e.g. the
        // user denies the biometric ACL setup), the next `list` won't show a
        // half-loaded key.
        try upsertItem(
            account: "\(key).pub",
            data: Data(pubLine.utf8),
            label: "\(label).pub",
            accessControl: nil,
            allowOverwrite: options.overwrite || exists
        )

        do {
            try upsertItem(
                account: key,
                data: pem,
                label: label,
                accessControl: try options.requireBiometric ? makeBiometricACL() : nil,
                allowOverwrite: options.overwrite || exists
            )
        } catch {
            // Roll back the sidecar if private write fails
            _ = try? deleteItem(account: "\(key).pub")
            throw error
        }
    }

    public func list(options: ListOptions) async throws -> [PublicItem] {
        // Two-phase enumeration to work around the legacy-keychain restriction
        // that disallows combining `kSecMatchLimitAll` with both attributes and
        // data in one call (errSecParam / -50):
        //   1. Query attributes only to discover `.pub` sidecar accounts.
        //   2. Fetch each sidecar's data with a targeted single-item query.
        // This also keeps private items entirely out of the listing path - no
        // chance of a biometric ACL prompt firing during `list`.
        var query = baseQuery()
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnAttributes as String] = true

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else {
            throw KeychainError.osStatus("SecItemCopyMatching", status)
        }
        guard let items = result as? [[String: Any]] else { return [] }

        var output: [PublicItem] = []
        for entry in items {
            guard let account = entry[kSecAttrAccount as String] as? String,
                  account.hasSuffix(".pub")
            else { continue }
            guard let data = try? fetchData(account: account, withACLPrompt: false),
                  let line = String(data: data, encoding: .utf8)
            else { continue }
            let key = String(account.dropLast(".pub".count))
            do {
                let pubKey = try NIOSSHPublicKey(openSSHPublicKey: line)
                let comment = parseComment(from: line)
                output.append(PublicItem(key: key, publicKey: pubKey, comment: comment))
            } catch {
                // Malformed sidecar - skip silently so one bad entry doesn't
                // sink the whole listing.
                continue
            }
        }
        output.sort { $0.key < $1.key }
        _ = options
        return output
    }

    public func remove(key: String) async throws {
        try validateKey(key)
        let secExists = try secKeyExists(applicationTag: key)
        let privExists = try itemExists(account: key)
        let pubExists = try itemExists(account: "\(key).pub")
        if !secExists && !privExists && !pubExists { throw BackendError.notFound }
        if secExists { _ = try deleteSecKey(applicationTag: key) }
        if privExists { _ = try deleteItem(account: key) }
        if pubExists { _ = try deleteItem(account: "\(key).pub") }
    }

    // MARK: - helpers

    private func baseQuery() -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
        ]
    }

    private func itemExists(account: String) throws -> Bool {
        var query = baseQuery()
        query[kSecAttrAccount as String] = account
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = false
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess: return true
        case errSecItemNotFound: return false
        default: throw KeychainError.osStatus("SecItemCopyMatching(exists)", status)
        }
    }

    private func fetchData(account: String, withACLPrompt: Bool) throws -> Data {
        var query = baseQuery()
        query[kSecAttrAccount as String] = account
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true

        if withACLPrompt {
            let context = LAContext()
            context.localizedReason = "ssh-keychain wants to use key \"\(account)\" to sign"
            query[kSecUseAuthenticationContext as String] = context
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { throw BackendError.notFound }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError.osStatus("SecItemCopyMatching(\(account))", status)
        }
        return data
    }

    private func upsertItem(account: String, data: Data, label: String, accessControl: SecAccessControl?, allowOverwrite: Bool) throws {
        let exists = try itemExists(account: account)
        if exists {
            if !allowOverwrite { throw BackendError.exists }
            try updateItem(account: account, data: data, label: label, accessControl: accessControl)
        } else {
            try addItem(account: account, data: data, label: label, accessControl: accessControl)
        }
    }

    private func addItem(account: String, data: Data, label: String, accessControl: SecAccessControl?) throws {
        var query = baseQuery()
        query[kSecAttrAccount as String] = account
        query[kSecAttrLabel as String] = label
        query[kSecValueData as String] = data
        if let accessControl {
            query[kSecAttrAccessControl as String] = accessControl
        } else {
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.osStatus("SecItemAdd(\(account))", status)
        }
    }

    private func updateItem(account: String, data: Data, label: String, accessControl: SecAccessControl?) throws {
        var query = baseQuery()
        query[kSecAttrAccount as String] = account
        var update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrLabel as String: label,
        ]
        if let accessControl {
            update[kSecAttrAccessControl as String] = accessControl
        }
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        guard status == errSecSuccess else {
            throw KeychainError.osStatus("SecItemUpdate(\(account))", status)
        }
    }

    private func deleteItem(account: String) throws -> Bool {
        var query = baseQuery()
        query[kSecAttrAccount as String] = account
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecItemNotFound { return false }
        guard status == errSecSuccess else {
            throw KeychainError.osStatus("SecItemDelete(\(account))", status)
        }
        return true
    }

    // MARK: SecKey (Secure Enclave) helpers

    private func applicationTagData(forKey key: String) -> Data {
        Data("\(serviceName):\(key)".utf8)
    }

    private func secKeyQuery(applicationTag tag: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: applicationTagData(forKey: tag),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        ]
    }

    private func secKeyExists(applicationTag tag: String) throws -> Bool {
        var query = secKeyQuery(applicationTag: tag)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess: return true
        case errSecItemNotFound: return false
        default: throw KeychainError.osStatus("SecItemCopyMatching(secKey exists)", status)
        }
    }

    private func lookupSecKey(applicationTag tag: String) throws -> SecKey? {
        var query = secKeyQuery(applicationTag: tag)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnRef as String] = true
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            // Force-cast OK: queries for SecKey class always return SecKey on success.
            return (result as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.osStatus("SecItemCopyMatching(secKey lookup)", status)
        }
    }

    private func deleteSecKey(applicationTag tag: String) throws -> Bool {
        let query = secKeyQuery(applicationTag: tag)
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecItemNotFound { return false }
        guard status == errSecSuccess else {
            throw KeychainError.osStatus("SecItemDelete(secKey)", status)
        }
        return true
    }

    private func makeSecureEnclaveACL(requireBiometric: Bool) throws -> SecAccessControl {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requireBiometric {
            flags.insert(.biometryCurrentSet)
            flags.insert(.or)
            flags.insert(.devicePasscode)
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            if let cf = error?.takeRetainedValue() {
                throw KeychainError.accessControlCreate(cf)
            }
            throw KeychainError.accessControlCreateGeneric
        }
        return access
    }

    /// Derive a `NIOSSHPublicKey` from a Secure-Enclave `SecKey`.
    /// `SecKeyCopyExternalRepresentation` returns the uncompressed EC point
    /// (`0x04 || X || Y`, 65 bytes for P-256). We assemble the SSH wire
    /// format `ecdsa-sha2-nistp256` blob and let NIOSSH parse it.
    private func nioPublicKey(fromSecKey secKey: SecKey) throws -> NIOSSHPublicKey {
        guard let publicSecKey = SecKeyCopyPublicKey(secKey) else {
            throw SecureEnclaveError.publicKeyExtraction
        }
        var error: Unmanaged<CFError>?
        guard let representation = SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data? else {
            throw SecureEnclaveError.publicKeyExtraction
        }
        // representation is `0x04 || X(32) || Y(32)` for P-256 = 65 bytes.
        var blob = SSHWireWriter()
        blob.writeString("ecdsa-sha2-nistp256")
        blob.writeString("nistp256")
        blob.writeString(representation)
        let openSSHLine = "ecdsa-sha2-nistp256 \(blob.buffer.base64EncodedString())"
        return try NIOSSHPublicKey(openSSHPublicKey: openSSHLine)
    }

    // MARK: Generic-password helpers

    private func makeBiometricACL() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet, .or, .devicePasscode],
            &error
        ) else {
            if let cf = error?.takeRetainedValue() {
                throw KeychainError.accessControlCreate(cf)
            }
            throw KeychainError.accessControlCreateGeneric
        }
        return access
    }

    private func pubLineComment(for key: String) throws -> String? {
        guard let data = try? fetchData(account: "\(key).pub", withACLPrompt: false),
              let line = String(data: data, encoding: .utf8) else { return nil }
        return parseComment(from: line)
    }

    private func renderPublicKeyLine(_ publicKey: NIOSSHPublicKey, comment: String) -> String {
        let core = String(openSSHPublicKey: publicKey)
        return "\(core) \(comment)\n"
    }

    private func parseComment(from line: String) -> String? {
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count == 3 else { return nil }
        let raw = parts[2].trimmingCharacters(in: .whitespacesAndNewlines)
        return raw.isEmpty ? nil : raw
    }

    private func validateKey(_ key: String) throws {
        guard !key.isEmpty else { throw BackendError.unsupported("empty key name") }
        guard !key.hasSuffix(".pub") else {
            throw BackendError.unsupported("key name may not end with .pub (reserved for sidecar)")
        }
    }
}

public enum KeychainError: Error {
    case osStatus(String, OSStatus)
    case accessControlCreate(CFError)
    case accessControlCreateGeneric
}

#endif
