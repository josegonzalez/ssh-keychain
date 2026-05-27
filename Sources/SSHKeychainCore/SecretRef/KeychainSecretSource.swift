#if canImport(Security)
import Foundation
import Security

/// Reads a generic-password keychain item dedicated to secret-ref storage.
///
/// Uses a distinct service namespace (`com.josegonzalez.ssh-keychain.secrets`)
/// so secretref items don't collide with the keychain backend's SSH keys nor
/// with cached auth tokens.
public struct KeychainSecretSource: SecretSource {
    public let account: String
    public let service: String

    public init(account: String, service: String = "com.josegonzalez.ssh-keychain.secrets") {
        self.account = account
        self.service = service
    }

    public func fetch() async throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            throw SecretRefError.fetchFailed("keychain:\(account) not found in service \(service)")
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw SecretRefError.fetchFailed("keychain lookup failed: OSStatus \(status)")
        }
        return data
    }
}
#endif
