import Foundation

/// v1.1 stub for browser-driven OIDC PKCE auth (Okta, Azure AD, Google, etc).
///
/// The shape is locked in so v1.1 implementation slots in without changes to
/// callers. The eventual implementation will:
///   - Open `ASWebAuthenticationSession` pointing at the IdP's authorization endpoint.
///   - Bind a loopback `127.0.0.1` HTTP listener to receive the code.
///   - Exchange the code + PKCE verifier at the token endpoint.
///   - Exchange the resulting ID token at Vault's `/v1/auth/oidc/login` for a Vault token.
public struct OIDCAuthProvider: AuthProvider {
    public let name: String
    public let issuer: URL
    public let clientID: String
    public let scopes: [String]
    public let vaultMount: String

    public init(name: String, issuer: URL, clientID: String, scopes: [String] = ["openid", "email"], vaultMount: String = "oidc") {
        self.name = name
        self.issuer = issuer
        self.clientID = clientID
        self.scopes = scopes
        self.vaultMount = vaultMount
    }

    public func token() async throws -> Credential {
        throw AuthError.unsupported("OIDC AuthProvider is a v1.1 stub; configure --vault-auth=static for now")
    }
}
