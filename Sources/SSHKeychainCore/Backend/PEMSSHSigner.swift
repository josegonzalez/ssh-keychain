import Crypto
import Foundation
import NIOSSH

/// An `SSHSigner` backed by an in-memory parsed private key.
///
/// Used by every backend except the keychain Secure-Enclave path (which uses
/// `SecureEnclaveSigner`). The wrapped CryptoKit primitive signs directly; we
/// don't go through NIOSSH because its signing surface is internal-only.
public struct PEMSSHSigner: SSHSigner {
    public let publicKey: NIOSSHPublicKey
    public let parsed: ParsedKey

    public init(parsed: ParsedKey) {
        self.publicKey = parsed.publicKey
        self.parsed = parsed
    }

    public func sign(data: Data) async throws -> Data {
        try SignatureEncoding.sshSignature(material: parsed.privateKey, data: data)
    }
}
