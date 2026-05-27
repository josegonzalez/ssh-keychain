#if canImport(Security)
import Foundation
import NIOSSH
import Security

/// `SSHSigner` whose private key is held inside the Secure Enclave.
///
/// Signing goes through `SecKeyCreateSignature(... messageX962SHA256 ...)`,
/// which returns a DER-encoded ECDSA signature; we parse it into `(r, s)` and
/// reformat as an SSH wire-format signature (`mpint r` + `mpint s`) under the
/// `ecdsa-sha2-nistp256` algorithm.
///
/// The `SecKey` is reference-counted by Apple; ARC handles its lifetime
/// because `Box` retains it for as long as this signer (or its caller-cached
/// copy in `KeyCache`) is alive.
public struct SecureEnclaveSigner: SSHSigner {
    public let publicKey: NIOSSHPublicKey
    private let box: SecKeyBox

    public init(privateKey: SecKey, publicKey: NIOSSHPublicKey) {
        self.publicKey = publicKey
        self.box = SecKeyBox(value: privateKey)
    }

    public func sign(data: Data) async throws -> Data {
        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(
            box.value,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        )
        guard let sig = signature as Data? else {
            if let cf = error?.takeRetainedValue() {
                throw SecureEnclaveError.signing(cf)
            }
            throw SecureEnclaveError.signingGeneric
        }
        let (r, s) = try DERSignature.parseECDSA(sig)

        var inner = SSHWireWriter()
        inner.writeMPInt(r)
        inner.writeMPInt(s)

        var outer = SSHWireWriter()
        outer.writeString("ecdsa-sha2-nistp256")
        outer.writeString(inner.buffer)
        return outer.buffer
    }
}

/// Wraps an Apple `SecKey` reference so it can cross actor / Sendable
/// boundaries. `SecKey` is documented as thread-safe by Apple.
private final class SecKeyBox: @unchecked Sendable {
    let value: SecKey
    init(value: SecKey) { self.value = value }
}

public enum SecureEnclaveError: Error {
    case signing(CFError)
    case signingGeneric
    case keyGeneration(CFError)
    case keyGenerationGeneric
    case publicKeyExtraction
}

#endif
