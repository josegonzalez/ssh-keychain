import Foundation
import NIOSSH
import XCTest
@testable import SSHKeychainCore

final class FileBackendTests: XCTestCase {
    var tempRoot: URL!

    override func setUp() async throws {
        tempRoot = FileManager.default.temporaryDirectory
            .appending(path: "ssh-keychain-test-\(UUID().uuidString)", directoryHint: .isDirectory)
    }

    override func tearDown() async throws {
        if FileManager.default.fileExists(atPath: tempRoot.path) {
            try FileManager.default.removeItem(at: tempRoot)
        }
    }

    func testPutGetRoundTripEd25519() async throws {
        let backend = try FileBackend(name: "test", root: tempRoot)
        let pem = try generateEd25519PEM()

        try await backend.put(key: "alice", pem: pem, options: PutOptions(comment: "alice@host"))
        let item = try await backend.get(key: "alice")
        XCTAssertEqual(item.key, "alice")
        XCTAssertEqual(item.comment, "alice@host")
    }

    func testListPublicOnlyDoesNotMaterializePrivate() async throws {
        let backend = try FileBackend(name: "test", root: tempRoot)
        let pem = try generateEd25519PEM()
        try await backend.put(key: "k1", pem: pem, options: PutOptions(comment: "k1"))
        try await backend.put(key: "k2", pem: pem, options: PutOptions(comment: "k2"))
        let items = try await backend.list(options: ListOptions(publicKeysOnly: true))
        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(items.map(\.key).sorted(), ["k1", "k2"])
    }

    func testRemove() async throws {
        let backend = try FileBackend(name: "test", root: tempRoot)
        let pem = try generateEd25519PEM()
        try await backend.put(key: "doomed", pem: pem, options: PutOptions())
        try await backend.remove(key: "doomed")
        do {
            _ = try await backend.get(key: "doomed")
            XCTFail("expected notFound")
        } catch let error as BackendError {
            XCTAssertEqual(error, .notFound)
        }
    }

    func testPutRejectsDuplicateWithoutOverwrite() async throws {
        let backend = try FileBackend(name: "test", root: tempRoot)
        let pem = try generateEd25519PEM()
        try await backend.put(key: "k", pem: pem, options: PutOptions())
        do {
            try await backend.put(key: "k", pem: pem, options: PutOptions())
            XCTFail("expected exists")
        } catch let error as BackendError {
            XCTAssertEqual(error, .exists)
        }
    }

    func testPutAcceptsDuplicateWithOverwrite() async throws {
        let backend = try FileBackend(name: "test", root: tempRoot)
        let pem = try generateEd25519PEM()
        try await backend.put(key: "k", pem: pem, options: PutOptions(comment: "v1"))
        try await backend.put(key: "k", pem: pem, options: PutOptions(overwrite: true, comment: "v2"))
        let item = try await backend.get(key: "k")
        XCTAssertEqual(item.comment, "v2")
    }

    func testKeyNameWithSlashRejected() async throws {
        let backend = try FileBackend(name: "test", root: tempRoot)
        let pem = try generateEd25519PEM()
        do {
            try await backend.put(key: "../escape", pem: pem, options: PutOptions())
            XCTFail("expected unsupported")
        } catch let error as BackendError {
            if case .unsupported = error {} else { XCTFail("wrong error: \(error)") }
        }
    }

    // MARK: helpers

    /// Shells out to `ssh-keygen` to produce a known-good OpenSSH-format
    /// private key for round-trip testing.
    private func generateEd25519PEM() throws -> Data {
        let dir = FileManager.default.temporaryDirectory
            .appending(path: "keygen-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let keyURL = dir.appending(path: "k")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = ["-t", "ed25519", "-f", keyURL.path, "-N", "", "-C", "test"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "FileBackendTests", code: Int(process.terminationStatus))
        }
        return try Data(contentsOf: keyURL)
    }
}
