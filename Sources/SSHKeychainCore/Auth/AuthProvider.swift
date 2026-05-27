import Foundation

/// Yields short-lived credentials for backends that authenticate to external
/// services (Vault primarily). The provider implementations decide where the
/// credential comes from: static config, OIDC browser flow (v1.1), AWS SSO
/// (v1.1), etc.
public protocol AuthProvider: Sendable {
    var name: String { get }
    func token() async throws -> Credential
}

public struct Credential: Sendable {
    public let token: String
    public let expiresAt: Date
    public let metadata: [String: String]

    public init(token: String, expiresAt: Date, metadata: [String: String] = [:]) {
        self.token = token
        self.expiresAt = expiresAt
        self.metadata = metadata
    }
}

public enum AuthError: Error, Sendable {
    /// The provider doesn't implement the requested operation yet (e.g. OIDC stub).
    case unsupported(String)
    /// The IdP or token endpoint rejected our request.
    case authenticationFailed(String)
    /// A cached token has expired; the provider needs to re-authenticate.
    case tokenExpired
    /// Unable to read the configured token source.
    case sourceUnavailable(String)
}
