import Crypto
import Foundation

/// Converts CryptoKit signatures into SSH wire-format signature blobs.
///
/// SSH agent protocol returns signatures in the format:
///
///     string  algorithm_identifier   ("ssh-ed25519", "ecdsa-sha2-nistp256", ...)
///     string  signature_blob          (algorithm-specific encoding)
///
/// For ed25519, `signature_blob` is the raw 64-byte signature.
/// For ECDSA, `signature_blob` is two mpints: `r` and `s`.
public enum SignatureEncoding {
    public static func sshSignature(material: PrivateKeyMaterial, data: Data) throws -> Data {
        switch material {
        case .ed25519(let key):
            let raw = try key.signature(for: data)
            return encodeEd25519(raw)
        case .ecdsaP256(let key):
            let sig = try key.signature(for: data)
            return encodeECDSA(algorithm: "ecdsa-sha2-nistp256", rawRS: sig.rawRepresentation)
        case .ecdsaP384(let key):
            let sig = try key.signature(for: data)
            return encodeECDSA(algorithm: "ecdsa-sha2-nistp384", rawRS: sig.rawRepresentation)
        case .ecdsaP521(let key):
            let sig = try key.signature(for: data)
            return encodeECDSA(algorithm: "ecdsa-sha2-nistp521", rawRS: sig.rawRepresentation)
        }
    }

    private static func encodeEd25519(_ raw: Data) -> Data {
        var w = SSHWireWriter()
        w.writeString("ssh-ed25519")
        w.writeString(raw)
        return w.buffer
    }

    /// CryptoKit's `rawRepresentation` for ECDSA signatures is `r || s` with
    /// each component padded to the curve's byte length. For SSH wire format we
    /// split it back into `r` and `s` and write each as an mpint.
    private static func encodeECDSA(algorithm: String, rawRS: Data) -> Data {
        let half = rawRS.count / 2
        let r = rawRS.prefix(half)
        let s = rawRS.suffix(half)

        var inner = SSHWireWriter()
        inner.writeMPInt(Data(r))
        inner.writeMPInt(Data(s))

        var w = SSHWireWriter()
        w.writeString(algorithm)
        w.writeString(inner.buffer)
        return w.buffer
    }
}
