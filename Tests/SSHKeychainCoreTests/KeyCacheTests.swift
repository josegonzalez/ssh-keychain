import Foundation
import NIOSSH
import XCTest
@testable import SSHKeychainCore

final class KeyCacheTests: XCTestCase {
    func testHitAfterPut() async throws {
        let cache = KeyCache(ttl: 60, maxEntries: 4)
        let signer = await makeSigner()
        let blob = Data([1, 2, 3])
        await cache.put(blob: blob, signer: signer)
        let cached = await cache.get(blob: blob)
        XCTAssertNotNil(cached)
    }

    func testMissForUnknownBlob() async throws {
        let cache = KeyCache(ttl: 60, maxEntries: 4)
        let cached = await cache.get(blob: Data([9, 9, 9]))
        XCTAssertNil(cached)
    }

    func testExpiry() async throws {
        let cache = KeyCache(ttl: 0.05, maxEntries: 4)   // 50ms
        let signer = await makeSigner()
        let blob = Data([7])
        await cache.put(blob: blob, signer: signer)
        try await Task.sleep(nanoseconds: 100_000_000)   // 100ms
        let cached = await cache.get(blob: blob)
        XCTAssertNil(cached)
    }

    func testTTLZeroDisablesCache() async throws {
        let cache = KeyCache(ttl: 0, maxEntries: 4)
        let signer = await makeSigner()
        let blob = Data([1])
        await cache.put(blob: blob, signer: signer)
        let cached = await cache.get(blob: blob)
        XCTAssertNil(cached, "ttl=0 should be a no-op put")
    }

    func testLRUEviction() async throws {
        let cache = KeyCache(ttl: 60, maxEntries: 2)
        let s1 = await makeSigner()
        let s2 = await makeSigner()
        let s3 = await makeSigner()
        await cache.put(blob: Data([1]), signer: s1)
        await cache.put(blob: Data([2]), signer: s2)
        // Touch blob 1 so blob 2 becomes the LRU victim
        _ = await cache.get(blob: Data([1]))
        await cache.put(blob: Data([3]), signer: s3)
        let got1 = await cache.get(blob: Data([1]))
        let got2 = await cache.get(blob: Data([2]))
        let got3 = await cache.get(blob: Data([3]))
        XCTAssertNotNil(got1)
        XCTAssertNil(got2)
        XCTAssertNotNil(got3)
    }

    func testFlushAll() async throws {
        let cache = KeyCache(ttl: 60, maxEntries: 4)
        let signer = await makeSigner()
        await cache.put(blob: Data([1]), signer: signer)
        await cache.put(blob: Data([2]), signer: signer)
        await cache.flushAll()
        let got1 = await cache.get(blob: Data([1]))
        let got2 = await cache.get(blob: Data([2]))
        XCTAssertNil(got1)
        XCTAssertNil(got2)
    }

    // MARK: helpers

    private func makeSigner() async -> any SSHSigner {
        // Use a fresh ed25519 key just so we have a valid signer to cache.
        let pem = try! generateEd25519PEM()
        let parsed = try! KeyParser.parsePrivateKey(pem)
        return PEMSSHSigner(parsed: parsed)
    }

    private func generateEd25519PEM() throws -> Data {
        let dir = FileManager.default.temporaryDirectory
            .appending(path: "keycache-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let keyURL = dir.appending(path: "k")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        p.arguments = ["-t", "ed25519", "-f", keyURL.path, "-N", "", "-C", "test"]
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        try p.run()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else {
            throw NSError(domain: "KeyCacheTests", code: Int(p.terminationStatus))
        }
        return try Data(contentsOf: keyURL)
    }
}
