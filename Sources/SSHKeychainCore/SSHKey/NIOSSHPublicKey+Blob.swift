import Foundation
import NIOSSH

extension NIOSSHPublicKey {
    /// The SSH wire-format key blob - the binary that goes on the wire in
    /// `IDENTITIES_ANSWER` and that clients send in `SIGN_REQUEST`. This is
    /// what's base64-encoded in the standard `~/.ssh/*.pub` format.
    public var sshKeyBlob: Data {
        let line = String(openSSHPublicKey: self)
        let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard parts.count >= 2,
              let decoded = Data(base64Encoded: String(parts[1]), options: .ignoreUnknownCharacters)
        else { return Data() }
        return decoded
    }
}
