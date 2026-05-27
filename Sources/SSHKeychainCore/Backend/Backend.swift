import Foundation
import NIOSSH

/// A pluggable source of SSH private keys.
///
/// Implementations include the macOS Keychain, plain files, HashiCorp Vault,
/// 1Password (OPVault and `op` CLI). Backends may be read-only.
public protocol Backend: Sendable {
    /// User-assigned name of this backend instance (e.g. "primary", "work-vault").
    var name: String { get }

    /// Fetch a key by its user-assigned label. Returned `Item` carries a usable
    /// `SSHSigner`. May prompt the user (biometric ACL, OPVault unlock, etc.).
    func get(key: String) async throws -> Item

    /// Store a key. Backends that don't support writes throw `.readOnly`.
    func put(key: String, pem: Data, options: PutOptions) async throws

    /// Enumerate keys without exposing private material. Used by the agent to
    /// build its identity map at startup and on `SIGHUP`.
    func list(options: ListOptions) async throws -> [PublicItem]

    /// Delete a key. Read-only backends throw `.readOnly`.
    func remove(key: String) async throws
}

/// Optional capability: backends that can generate new keys in place (e.g.
/// keychain backend generating an ECDSA P-256 key inside the Secure Enclave).
public protocol GeneratingBackend: Backend {
    func generate(key: String, options: GenerateOptions) async throws -> Item
}

/// A key that exists in a backend, with material available for signing.
public struct Item: Sendable {
    public let key: String
    public let publicKey: NIOSSHPublicKey
    public let signer: any SSHSigner
    public let comment: String?

    public init(key: String, publicKey: NIOSSHPublicKey, signer: any SSHSigner, comment: String? = nil) {
        self.key = key
        self.publicKey = publicKey
        self.signer = signer
        self.comment = comment
    }
}

/// A key advertised by a backend, without private material. Used for `list` and
/// the agent's `RequestIdentities` response.
public struct PublicItem: Sendable {
    public let key: String
    public let publicKey: NIOSSHPublicKey
    public let comment: String?

    public init(key: String, publicKey: NIOSSHPublicKey, comment: String? = nil) {
        self.key = key
        self.publicKey = publicKey
        self.comment = comment
    }
}

public struct PutOptions: Sendable {
    public var requireBiometric: Bool
    public var overwrite: Bool
    public var comment: String?

    public init(requireBiometric: Bool = false, overwrite: Bool = false, comment: String? = nil) {
        self.requireBiometric = requireBiometric
        self.overwrite = overwrite
        self.comment = comment
    }
}

public struct ListOptions: Sendable {
    /// When true, the backend must not materialize private bytes or signer
    /// handles. Defaults to `true` (the safe path).
    public var publicKeysOnly: Bool

    public init(publicKeysOnly: Bool = true) {
        self.publicKeysOnly = publicKeysOnly
    }
}

public struct GenerateOptions: Sendable {
    public var algorithm: KeyAlgorithm
    public var secureEnclave: Bool
    public var requireBiometric: Bool
    public var overwrite: Bool
    public var comment: String?

    public init(
        algorithm: KeyAlgorithm = .ecdsaP256,
        secureEnclave: Bool = true,
        requireBiometric: Bool = false,
        overwrite: Bool = false,
        comment: String? = nil
    ) {
        self.algorithm = algorithm
        self.secureEnclave = secureEnclave
        self.requireBiometric = requireBiometric
        self.overwrite = overwrite
        self.comment = comment
    }
}

public enum KeyAlgorithm: String, Sendable, CaseIterable {
    case ecdsaP256 = "ecdsa-p256"
    case ed25519 = "ed25519"
    case rsa4096 = "rsa-4096"
}

public enum BackendError: Error, Sendable, Equatable {
    /// No key with the given label exists in this backend.
    case notFound
    /// A key with the given label already exists and `overwrite` was false.
    case exists
    /// The operation is not supported on this platform or by this backend.
    case unsupported(String)
    /// The backend does not accept writes (1Password, Vault in read-only mode).
    case readOnly
}
