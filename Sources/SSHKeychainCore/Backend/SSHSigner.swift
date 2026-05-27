import Foundation
import NIOSSH

/// Produces SSH signatures over arbitrary data using a private key the signer
/// owns. The private material may live in process memory (`PEMSSHSigner`) or
/// inside hardware (`SecureEnclaveSigner` - implemented in the keychain backend).
///
/// The agent calls `sign(data:)` once per `SignRequest` message. Signers are
/// expected to be reusable; the daemon's key cache holds them for the
/// configured TTL.
public protocol SSHSigner: Sendable {
    var publicKey: NIOSSHPublicKey { get }

    /// Produces an SSH wire-format signature over `data` (already hashed by the
    /// caller per the algorithm's expectations - the signer applies the
    /// algorithm-specific transformation and wraps the output in the SSH
    /// signature framing).
    func sign(data: Data) async throws -> Data
}
