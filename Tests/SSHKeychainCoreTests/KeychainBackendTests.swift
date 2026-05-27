#if canImport(Security)
import Foundation
import NIOSSH
import Security
import XCTest
@testable import SSHKeychainCore

/// Exercises the macOS Keychain backend against a uniquely-prefixed service
/// name so it can run alongside the real user's keychain without colliding.
/// Every test cleans up via `tearDown`.
final class KeychainBackendTests: XCTestCase {
    var service: String!

    override func setUp() async throws {
        service = "ssh-keychain-test-\(UUID().uuidString)"
    }

    override func tearDown() async throws {
        // Belt-and-suspenders cleanup in case a test fails mid-flight.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service!,
        ]
        SecItemDelete(query as CFDictionary)
    }

    func testPutListGetRemoveRoundTrip() async throws {
        let backend = KeychainBackend(name: "test", serviceName: service)
        let pem = try generateEd25519PEM()

        try await backend.put(key: "alice", pem: pem, options: PutOptions(comment: "alice@host"))
        let items = try await backend.list(options: ListOptions(publicKeysOnly: true))
        XCTAssertEqual(items.map(\.key), ["alice"])
        XCTAssertEqual(items.first?.comment, "alice@host")

        let item = try await backend.get(key: "alice")
        XCTAssertEqual(item.key, "alice")
        XCTAssertEqual(item.comment, "alice@host")

        try await backend.remove(key: "alice")
        let empty = try await backend.list(options: ListOptions(publicKeysOnly: true))
        XCTAssertEqual(empty.count, 0)
    }

    func testListOmitsBareSidecarsAndUnrelatedItems() async throws {
        let backend = KeychainBackend(name: "test", serviceName: service)
        let pem = try generateEd25519PEM()
        try await backend.put(key: "k1", pem: pem, options: PutOptions())
        try await backend.put(key: "k2", pem: pem, options: PutOptions())
        let items = try await backend.list(options: ListOptions(publicKeysOnly: true))
        XCTAssertEqual(Set(items.map(\.key)), ["k1", "k2"])
    }

    func testPutRejectsDuplicateWithoutOverwrite() async throws {
        let backend = KeychainBackend(name: "test", serviceName: service)
        let pem = try generateEd25519PEM()
        try await backend.put(key: "k", pem: pem, options: PutOptions())
        do {
            try await backend.put(key: "k", pem: pem, options: PutOptions())
            XCTFail("expected exists")
        } catch let error as BackendError {
            XCTAssertEqual(error, .exists)
        }
    }

    func testPutAcceptsOverwrite() async throws {
        let backend = KeychainBackend(name: "test", serviceName: service)
        let pem1 = try generateEd25519PEM()
        let pem2 = try generateEd25519PEM()
        try await backend.put(key: "k", pem: pem1, options: PutOptions(comment: "v1"))
        try await backend.put(key: "k", pem: pem2, options: PutOptions(overwrite: true, comment: "v2"))
        let item = try await backend.get(key: "k")
        XCTAssertEqual(item.comment, "v2")
    }

    func testRemoveOnMissingThrowsNotFound() async throws {
        let backend = KeychainBackend(name: "test", serviceName: service)
        do {
            try await backend.remove(key: "nonexistent")
            XCTFail("expected notFound")
        } catch let error as BackendError {
            XCTAssertEqual(error, .notFound)
        }
    }

    func testKeyNameEndingInPubRejected() async throws {
        let backend = KeychainBackend(name: "test", serviceName: service)
        let pem = try generateEd25519PEM()
        do {
            try await backend.put(key: "evil.pub", pem: pem, options: PutOptions())
            XCTFail("expected unsupported")
        } catch let error as BackendError {
            if case .unsupported = error {} else {
                XCTFail("wrong error: \(error)")
            }
        }
    }

    // MARK: helpers

    private func generateEd25519PEM() throws -> Data {
        let dir = FileManager.default.temporaryDirectory
            .appending(path: "keychain-test-\(UUID().uuidString)")
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
            throw NSError(domain: "KeychainBackendTests", code: Int(p.terminationStatus))
        }
        return try Data(contentsOf: keyURL)
    }
}
#endif
