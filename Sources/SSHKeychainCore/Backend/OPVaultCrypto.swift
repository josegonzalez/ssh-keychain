import Crypto
import CommonCrypto
import Foundation

/// Low-level crypto primitives used by the OPVault format.
///
/// Spec: https://support.1password.com/opvault-design/
///
/// Pieces:
///   - PBKDF2-HMAC-SHA512: derive 64 bytes from the master password.
///   - opdata01 envelope: `"opdata01" || uint64_le(plaintextLen) || iv(16) || ct || hmac(32)`,
///     decrypted with AES-256-CBC and authenticated with HMAC-SHA256.
///   - Item-key envelope: `iv(16) || ct(64) || hmac(32)`, no "opdata01" magic.
enum OPVaultCrypto {
    // MARK: PBKDF2

    static func deriveKeys(password: Data, salt: Data, iterations: Int) throws -> (encryption: Data, mac: Data) {
        var derived = Data(count: 64)
        let result = derived.withUnsafeMutableBytes { derivedPtr -> Int32 in
            password.withUnsafeBytes { passwordPtr in
                salt.withUnsafeBytes { saltPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordPtr.baseAddress, password.count,
                        saltPtr.baseAddress, salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        UInt32(iterations),
                        derivedPtr.baseAddress, 64
                    )
                }
            }
        }
        guard result == kCCSuccess else {
            throw OPVaultError.pbkdf2Failed(Int(result))
        }
        return (derived.prefix(32), derived.suffix(32))
    }

    // MARK: opdata01

    /// Decrypts an opdata01-framed payload.
    static func decryptOPData01(_ payload: Data, encryptionKey: Data, macKey: Data) throws -> Data {
        guard payload.count > 8 + 8 + 16 + 32 else { throw OPVaultError.malformed("opdata01 too short") }
        guard payload.prefix(8) == Data("opdata01".utf8) else { throw OPVaultError.malformed("missing opdata01 magic") }

        let macLen = 32
        let hmacRange = (payload.count - macLen)..<payload.count
        let signedRange = 0..<(payload.count - macLen)

        let signed = payload[signedRange]
        let expectedMAC = payload[hmacRange]
        try verifyHMAC(signed: signed, expected: expectedMAC, macKey: macKey)

        let plaintextLen = signed.subdata(in: 8..<16).withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
        let iv = signed.subdata(in: 16..<32)
        let ct = signed.subdata(in: 32..<signed.count)

        let plaintext = try aesDecryptCBCNoPad(ciphertext: ct, key: encryptionKey, iv: iv)
        guard plaintext.count >= Int(plaintextLen) else {
            throw OPVaultError.malformed("opdata01 declared length exceeds plaintext")
        }
        // Strip random padding prefix from front: opdata01 plaintext is padded
        // *at the start* to align to AES block size; the declared length tells
        // us how many real bytes follow.
        return Data(plaintext.suffix(Int(plaintextLen)))
    }

    // MARK: Item-key envelope (no opdata01 magic, fixed 64-byte payload)

    /// Decrypts a per-item key blob (the `k` field of band entries).
    /// Format: `iv(16) || ct(64) || hmac(32)`.
    static func decryptItemKey(_ payload: Data, encryptionKey: Data, macKey: Data) throws -> (itemEnc: Data, itemMAC: Data) {
        guard payload.count == 16 + 64 + 32 else {
            throw OPVaultError.malformed("item key blob wrong length \(payload.count)")
        }
        let signed = payload.prefix(16 + 64)
        let expectedMAC = payload.suffix(32)
        try verifyHMAC(signed: signed, expected: expectedMAC, macKey: macKey)

        let iv = signed.prefix(16)
        let ct = signed.suffix(64)
        let plaintext = try aesDecryptCBCNoPad(ciphertext: ct, key: encryptionKey, iv: Data(iv))
        guard plaintext.count == 64 else {
            throw OPVaultError.malformed("item key plaintext wrong length")
        }
        return (Data(plaintext.prefix(32)), Data(plaintext.suffix(32)))
    }

    // MARK: low-level helpers

    private static func verifyHMAC(signed: Data, expected: Data, macKey: Data) throws {
        let symKey = SymmetricKey(data: macKey)
        let actual = HMAC<Crypto.SHA256>.authenticationCode(for: signed, using: symKey)
        let actualData = Data(actual)
        // Constant-time compare.
        guard actualData.count == expected.count else { throw OPVaultError.macMismatch }
        var diff: UInt8 = 0
        for i in 0..<actualData.count {
            diff |= actualData[i] ^ expected[expected.startIndex + i]
        }
        guard diff == 0 else { throw OPVaultError.macMismatch }
    }

    private static func aesDecryptCBCNoPad(ciphertext: Data, key: Data, iv: Data) throws -> Data {
        let outCapacity = ciphertext.count + kCCBlockSizeAES128
        var out = Data(count: outCapacity)
        var outLen = 0
        let status = out.withUnsafeMutableBytes { outPtr in
            ciphertext.withUnsafeBytes { ctPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),                        // no PKCS7 - OPVault pre-pads manually
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            ctPtr.baseAddress, ciphertext.count,
                            outPtr.baseAddress, outCapacity,
                            &outLen
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw OPVaultError.aesFailed(Int(status)) }
        out.count = outLen
        return out
    }
}

public enum OPVaultError: Error {
    case pbkdf2Failed(Int)
    case aesFailed(Int)
    case macMismatch
    case malformed(String)
    case profileNotFound(String)
    case itemNotFound(String)
    case fieldMissing(String)
}
