import Foundation

/// Reads a long-lived token from a `SecretSource` and returns it as a
/// `Credential` with a far-future expiry.
///
/// This is the "I'll manage rotation myself" auth path - typical for
/// development and small deployments. Production Vault setups typically pair
/// this backend with a Vault token issued via OIDC (v1.1).
public struct StaticAuthProvider: AuthProvider {
    public let name: String
    private let source: any SecretSource

    public init(name: String = "static", source: any SecretSource) {
        self.name = name
        self.source = source
    }

    public func token() async throws -> Credential {
        let bytes: Data
        do {
            bytes = try await source.fetch()
        } catch {
            throw AuthError.sourceUnavailable(String(describing: error))
        }
        guard let str = String(data: bytes, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines), !str.isEmpty else {
            throw AuthError.sourceUnavailable("static token source returned empty/non-utf8")
        }
        // Static tokens have no published expiry; we use distantFuture so the
        // TokenCache never proactively evicts them. Backends that get a 403
        // can force a refresh via `forceRefresh`.
        return Credential(token: str, expiresAt: .distantFuture)
    }
}
