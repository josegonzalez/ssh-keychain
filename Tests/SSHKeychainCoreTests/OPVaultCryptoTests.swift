import Crypto
import CommonCrypto
import Foundation
import XCTest
@testable import SSHKeychainCore

/// Unit tests for the OPVault crypto primitives. Because we don't have a real
/// `.opvault` file in tree (would require 1Password to generate), we exercise
/// the format by *constructing* opdata01 blobs ourselves and decrypting them
/// back. This confirms the AES-CBC + HMAC-SHA256 plumbing matches the spec.
final class OPVaultCryptoTests: XCTestCase {
    func testPBKDF2DerivesSixtyFourBytes() throws {
        let (enc, mac) = try OPVaultCrypto.deriveKeys(
            password: Data("hunter2".utf8),
            salt: Data((0..<16).map { UInt8($0) }),
            iterations: 1000
        )
        XCTAssertEqual(enc.count, 32)
        XCTAssertEqual(mac.count, 32)
        XCTAssertNotEqual(enc, mac, "encryption and mac halves should differ")
    }

    func testPBKDF2IsDeterministic() throws {
        let password = Data("master".utf8)
        let salt = Data(repeating: 0xab, count: 16)
        let a = try OPVaultCrypto.deriveKeys(password: password, salt: salt, iterations: 5000)
        let b = try OPVaultCrypto.deriveKeys(password: password, salt: salt, iterations: 5000)
        XCTAssertEqual(a.encryption, b.encryption)
        XCTAssertEqual(a.mac, b.mac)
    }

    func testOPData01RoundTrip() throws {
        let encKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let macKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let plaintext = Data("hello, opvault, this is a test payload".utf8)

        let blob = try makeOPData01(plaintext: plaintext, encryptionKey: encKey, macKey: macKey)
        let recovered = try OPVaultCrypto.decryptOPData01(blob, encryptionKey: encKey, macKey: macKey)
        XCTAssertEqual(recovered, plaintext)
    }

    func testOPData01MACMismatchFails() throws {
        let encKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let macKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        var blob = try makeOPData01(plaintext: Data("payload".utf8), encryptionKey: encKey, macKey: macKey)
        blob[blob.startIndex] ^= 0x01    // corrupt magic
        XCTAssertThrowsError(try OPVaultCrypto.decryptOPData01(blob, encryptionKey: encKey, macKey: macKey))
    }

    // MARK: helpers

    /// Build a synthetic opdata01 blob: magic || uint64_le(len) || iv || aes-cbc-no-pad(padded plaintext) || hmac.
    /// Padding rule per OPVault: random bytes at the *front* to bring total to a 16-byte multiple.
    private func makeOPData01(plaintext: Data, encryptionKey: Data, macKey: Data) throws -> Data {
        let blockSize = 16
        let padding = (blockSize - (plaintext.count % blockSize)) % blockSize
        var padded = Data((0..<padding).map { _ in UInt8.random(in: 0...255) })
        padded.append(plaintext)
        if padded.count % blockSize != 0 {
            // If plaintext length was already a multiple, add a full block of padding so
            // ciphertext is at least one block.
            let extra = blockSize
            padded = Data((0..<extra).map { _ in UInt8.random(in: 0...255) }) + padded
        }

        let iv = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let ct = try aesEncrypt(plaintext: padded, key: encryptionKey, iv: iv)

        var signed = Data()
        signed.append("opdata01".data(using: .ascii)!)
        var lenLE = UInt64(plaintext.count).littleEndian
        signed.append(Data(bytes: &lenLE, count: 8))
        signed.append(iv)
        signed.append(ct)

        let symKey = SymmetricKey(data: macKey)
        let hmac = HMAC<Crypto.SHA256>.authenticationCode(for: signed, using: symKey)
        var blob = signed
        blob.append(Data(hmac))
        return blob
    }

    private func aesEncrypt(plaintext: Data, key: Data, iv: Data) throws -> Data {
        let outCapacity = plaintext.count + kCCBlockSizeAES128
        var out = Data(count: outCapacity)
        var outLen = 0
        let status = out.withUnsafeMutableBytes { outPtr in
            plaintext.withUnsafeBytes { ptPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            ptPtr.baseAddress, plaintext.count,
                            outPtr.baseAddress, outCapacity,
                            &outLen
                        )
                    }
                }
            }
        }
        XCTAssertEqual(Int(status), kCCSuccess)
        out.count = outLen
        return out
    }
}
