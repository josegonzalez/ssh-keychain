import Crypto
import Foundation
import NIOSSH

/// Parses OpenSSH-format private keys ("-----BEGIN OPENSSH PRIVATE KEY-----")
/// into `NIOSSHPrivateKey` + `NIOSSHPublicKey` instances.
///
/// Supported in v1: ed25519, ECDSA P-256/P-384/P-521 (unencrypted only).
/// Encrypted keys and the legacy PEM formats (PKCS#1 RSA, PKCS#8) are deferred
/// to phase 3b - they throw `unsupported` with a descriptive message.
public enum KeyParser {
    public static func parsePrivateKey(_ pem: Data) throws -> ParsedKey {
        guard let pemString = String(data: pem, encoding: .utf8) else {
            throw KeyParseError.malformed("not valid UTF-8")
        }
        let normalized = pemString.replacingOccurrences(of: "\r\n", with: "\n")

        if normalized.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
            return try parseOpenSSH(pemString: normalized)
        }
        if normalized.contains("-----BEGIN RSA PRIVATE KEY-----") {
            throw KeyParseError.unsupported("legacy PKCS#1 RSA PEM keys are not supported in v1; convert with `ssh-keygen -p -m RFC4716 -f <key>`")
        }
        if normalized.contains("-----BEGIN EC PRIVATE KEY-----")
            || normalized.contains("-----BEGIN PRIVATE KEY-----")
            || normalized.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        {
            throw KeyParseError.unsupported("legacy PEM private key formats are not supported in v1; convert with `ssh-keygen -p -m RFC4716 -f <key>`")
        }
        throw KeyParseError.malformed("not a recognized SSH private key format")
    }

    private static func parseOpenSSH(pemString: String) throws -> ParsedKey {
        let body = try stripPEMArmor(pemString, expectedLabel: "OPENSSH PRIVATE KEY")
        guard let decoded = Data(base64Encoded: body, options: .ignoreUnknownCharacters) else {
            throw KeyParseError.malformed("base64 decode failed")
        }

        var reader = SSHWireReader(decoded)

        let magic = "openssh-key-v1\0"
        let magicBytes = Array(magic.utf8)
        guard decoded.count >= magicBytes.count else {
            throw KeyParseError.malformed("truncated openssh blob")
        }
        for (i, b) in magicBytes.enumerated() where decoded[decoded.startIndex + i] != b {
            throw KeyParseError.malformed("missing openssh-key-v1 magic")
        }
        reader = SSHWireReader(decoded.dropFirst(magicBytes.count))

        let cipherName = try reader.readASCIIString()
        let kdfName = try reader.readASCIIString()
        let kdfOptions = try reader.readString()
        _ = kdfOptions

        if cipherName != "none" || kdfName != "none" {
            throw KeyParseError.encryptedKey
        }

        let numKeys = try reader.readUInt32()
        guard numKeys == 1 else {
            throw KeyParseError.unsupported("openssh keyfiles with multiple keys are not supported (got \(numKeys))")
        }

        let publicKeyBlob = try reader.readString()
        let encrypted = try reader.readString()

        // Padded private list (since cipher is "none", "encrypted" is plaintext):
        //   uint32  checkint
        //   uint32  checkint (same value)
        //   string  keytype
        //   ... key-specific fields ...
        //   string  comment
        //   padding 1, 2, 3, ...
        var pr = SSHWireReader(encrypted)
        let checkint1 = try pr.readUInt32()
        let checkint2 = try pr.readUInt32()
        guard checkint1 == checkint2 else {
            throw KeyParseError.malformed("openssh checkint mismatch")
        }

        let keyType = try pr.readASCIIString()
        let parsed: ParsedKey
        switch keyType {
        case "ssh-ed25519":
            parsed = try parseEd25519(privateReader: &pr, publicKeyBlob: publicKeyBlob)
        case "ecdsa-sha2-nistp256":
            parsed = try parseECDSA(curve: .p256, privateReader: &pr, publicKeyBlob: publicKeyBlob)
        case "ecdsa-sha2-nistp384":
            parsed = try parseECDSA(curve: .p384, privateReader: &pr, publicKeyBlob: publicKeyBlob)
        case "ecdsa-sha2-nistp521":
            parsed = try parseECDSA(curve: .p521, privateReader: &pr, publicKeyBlob: publicKeyBlob)
        case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
            throw KeyParseError.unsupported("RSA keys are not supported in v1; use ed25519 or ECDSA")
        default:
            throw KeyParseError.unsupported("unsupported key type: \(keyType)")
        }
        return parsed
    }

    private static func parseEd25519(privateReader: inout SSHWireReader, publicKeyBlob: Data) throws -> ParsedKey {
        let publicKeyBytes = try privateReader.readString()
        guard publicKeyBytes.count == 32 else {
            throw KeyParseError.malformed("ed25519 public key wrong length")
        }
        let privateAndPublic = try privateReader.readString()
        // OpenSSH stores ed25519 as the 64-byte concatenation of seed (32) + pubkey (32).
        guard privateAndPublic.count == 64 else {
            throw KeyParseError.malformed("ed25519 private key wrong length")
        }
        let seed = privateAndPublic.prefix(32)

        let cryptoKey: Curve25519.Signing.PrivateKey
        do {
            cryptoKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        } catch {
            throw KeyParseError.malformed("ed25519 seed rejected by CryptoKit: \(error)")
        }

        let publicKey: NIOSSHPublicKey
        do {
            publicKey = try NIOSSHPublicKey(openSSHPublicKey: try openSSHPublicKeyLine(blob: publicKeyBlob, type: "ssh-ed25519"))
        } catch {
            throw KeyParseError.malformed("could not roundtrip ed25519 public key: \(error)")
        }
        return ParsedKey(
            publicKey: publicKey,
            comment: try readTrailingComment(&privateReader),
            privateKey: .ed25519(cryptoKey)
        )
    }

    private static func parseECDSA(curve: ECCurve, privateReader: inout SSHWireReader, publicKeyBlob: Data) throws -> ParsedKey {
        let curveName = try privateReader.readASCIIString()
        guard curveName == curve.curveName else {
            throw KeyParseError.malformed("ecdsa curve name mismatch: \(curveName)")
        }
        let q = try privateReader.readString()      // public point (uncompressed)
        _ = q
        let d = try privateReader.readMPInt()       // private scalar

        let material: PrivateKeyMaterial
        do {
            switch curve {
            case .p256:
                material = .ecdsaP256(try P256.Signing.PrivateKey(rawRepresentation: d))
            case .p384:
                material = .ecdsaP384(try P384.Signing.PrivateKey(rawRepresentation: d))
            case .p521:
                material = .ecdsaP521(try P521.Signing.PrivateKey(rawRepresentation: d))
            }
        } catch {
            throw KeyParseError.malformed("ecdsa private scalar rejected by CryptoKit: \(error)")
        }

        let publicKey: NIOSSHPublicKey
        do {
            publicKey = try NIOSSHPublicKey(openSSHPublicKey: try openSSHPublicKeyLine(blob: publicKeyBlob, type: curve.sshKeyType))
        } catch {
            throw KeyParseError.malformed("could not roundtrip ecdsa public key: \(error)")
        }
        return ParsedKey(
            publicKey: publicKey,
            comment: try readTrailingComment(&privateReader),
            privateKey: material
        )
    }

    private static func readTrailingComment(_ r: inout SSHWireReader) throws -> String? {
        guard r.remaining >= 4 else { return nil }
        let str = try r.readASCIIString()
        return str.isEmpty ? nil : str
    }

    private static func openSSHPublicKeyLine(blob: Data, type: String) throws -> String {
        return "\(type) \(blob.base64EncodedString())"
    }

    private enum ECCurve {
        case p256, p384, p521
        var curveName: String {
            switch self {
            case .p256: return "nistp256"
            case .p384: return "nistp384"
            case .p521: return "nistp521"
            }
        }
        var sshKeyType: String {
            switch self {
            case .p256: return "ecdsa-sha2-nistp256"
            case .p384: return "ecdsa-sha2-nistp384"
            case .p521: return "ecdsa-sha2-nistp521"
            }
        }
    }

    private static func stripPEMArmor(_ pem: String, expectedLabel: String) throws -> String {
        let begin = "-----BEGIN \(expectedLabel)-----"
        let end = "-----END \(expectedLabel)-----"
        guard let beginRange = pem.range(of: begin),
              let endRange = pem.range(of: end),
              beginRange.upperBound < endRange.lowerBound
        else {
            throw KeyParseError.malformed("missing PEM armor for \(expectedLabel)")
        }
        let body = pem[beginRange.upperBound ..< endRange.lowerBound]
        return body.replacingOccurrences(of: "\n", with: "")
                   .replacingOccurrences(of: " ", with: "")
    }
}

public struct ParsedKey: Sendable {
    public let publicKey: NIOSSHPublicKey
    public let comment: String?
    public let privateKey: PrivateKeyMaterial
}

/// Algorithm-specific private key material, kept as CryptoKit types so the
/// signer can call into them directly. NIOSSH wraps these one-way for handshake
/// use, but the agent server needs to call `sign(for:)` on the raw primitives.
public enum PrivateKeyMaterial: Sendable {
    case ed25519(Curve25519.Signing.PrivateKey)
    case ecdsaP256(P256.Signing.PrivateKey)
    case ecdsaP384(P384.Signing.PrivateKey)
    case ecdsaP521(P521.Signing.PrivateKey)
}

public enum KeyParseError: Error, Equatable {
    case malformed(String)
    case unsupported(String)
    /// The key file is encrypted with a passphrase. Caller should re-invoke
    /// with a passphrase source (phase 3b will implement decryption).
    case encryptedKey
}
