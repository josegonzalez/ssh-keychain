import Foundation
#if canImport(Security)
import Security
#endif

/// Caches `Credential`s returned by `AuthProvider`s.
///
/// Default behavior: in-memory only, cleared on daemon shutdown.
///
/// With `persistToKeychain=true`: each credential is also written to a
/// keychain item under the reserved service namespace
/// `com.josegonzalez.ssh-keychain.auth` (separate from the SSH-key namespace
/// so user-named keys can't collide with cached tokens). Biometric ACL on
/// the cache item means each refresh-read still prompts Touch ID.
public actor TokenCache {
    private struct InMemoryEntry {
        var credential: Credential
    }

    private var inMemory: [String: InMemoryEntry] = [:]
    public let persistToKeychain: Bool

    public init(persistToKeychain: Bool = false) {
        self.persistToKeychain = persistToKeychain
    }

    /// Fetches a token via `provider`. Returns a cached value if still valid;
    /// otherwise calls `provider.token()` and caches the result.
    public func token(for provider: any AuthProvider) async throws -> Credential {
        if let cached = inMemory[provider.name], cached.credential.expiresAt > Date() {
            return cached.credential
        }
        if persistToKeychain, let keyed = try keychainLookup(for: provider.name),
           keyed.expiresAt > Date()
        {
            inMemory[provider.name] = InMemoryEntry(credential: keyed)
            return keyed
        }
        let fresh = try await provider.token()
        inMemory[provider.name] = InMemoryEntry(credential: fresh)
        if persistToKeychain {
            try? keychainStore(name: provider.name, credential: fresh)
        }
        return fresh
    }

    /// Force re-auth on the next `token(for:)` call. Backends call this on 403
    /// to handle token revocation mid-session.
    public func invalidate(for providerName: String) {
        inMemory.removeValue(forKey: providerName)
        if persistToKeychain {
            try? keychainDelete(name: providerName)
        }
    }

    public func flushAll() {
        for name in inMemory.keys {
            if persistToKeychain { try? keychainDelete(name: name) }
        }
        inMemory.removeAll()
    }

    // MARK: keychain persistence (macOS only)

    #if canImport(Security)
    private static let cacheService = "com.josegonzalez.ssh-keychain.auth"

    private func keychainLookup(for providerName: String) throws -> Credential? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.cacheService,
            kSecAttrAccount as String: providerName,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return try? JSONDecoder().decode(StoredCredential.self, from: data).toCredential()
    }

    private func keychainStore(name providerName: String, credential: Credential) throws {
        let payload = try JSONEncoder().encode(StoredCredential(credential))
        try? keychainDelete(name: providerName)
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.cacheService,
            kSecAttrAccount as String: providerName,
            kSecValueData as String: payload,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        if status != errSecSuccess {
            throw AuthError.sourceUnavailable("token cache SecItemAdd failed: \(status)")
        }
    }

    private func keychainDelete(name providerName: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.cacheService,
            kSecAttrAccount as String: providerName,
        ]
        SecItemDelete(query as CFDictionary)
    }

    #else
    private func keychainLookup(for providerName: String) throws -> Credential? { nil }
    private func keychainStore(name providerName: String, credential: Credential) throws {}
    private func keychainDelete(name providerName: String) throws {}
    #endif
}

private struct StoredCredential: Codable {
    let token: String
    let expiresAt: Date
    let metadata: [String: String]

    init(_ c: Credential) {
        self.token = c.token
        self.expiresAt = c.expiresAt
        self.metadata = c.metadata
    }

    func toCredential() -> Credential {
        Credential(token: token, expiresAt: expiresAt, metadata: metadata)
    }
}
