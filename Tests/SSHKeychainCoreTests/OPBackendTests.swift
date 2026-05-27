import Foundation
import XCTest
@testable import SSHKeychainCore

/// `op` CLI backend tests use a fake `op` shell script we drop into a temp
/// dir. The script logs its argv to a file we can inspect, and prints either
/// canned key bytes (for `read`) or canned JSON (for `item list`).
final class OPBackendTests: XCTestCase {
    var tempDir: URL!
    var samplePEM: Data!

    override func setUp() async throws {
        tempDir = FileManager.default.temporaryDirectory
            .appending(path: "op-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        samplePEM = try generateEd25519PEM()
    }

    override func tearDown() async throws {
        if let dir = tempDir { try? FileManager.default.removeItem(at: dir) }
    }

    func testReadEmitsExpectedArgv() async throws {
        let argvFile = tempDir.appending(path: "argv.log")
        let fakeOP = try writeFakeOP(
            argvLog: argvFile,
            readOutput: String(data: samplePEM, encoding: .utf8)!
        )
        let backend = OPBackend(name: "test", account: "my-team", vault: "Personal", opPath: fakeOP)
        let item = try await backend.get(key: "ssh-github")
        XCTAssertEqual(item.key, "ssh-github")

        let argv = try String(contentsOf: argvFile, encoding: .utf8)
        XCTAssertTrue(argv.contains("read"), "argv: \(argv)")
        XCTAssertTrue(argv.contains("op://my-team/Personal/ssh-github/private_key"), "argv: \(argv)")
    }

    func testReadOmitsAccountWhenNil() async throws {
        let argvFile = tempDir.appending(path: "argv.log")
        let fakeOP = try writeFakeOP(
            argvLog: argvFile,
            readOutput: String(data: samplePEM, encoding: .utf8)!
        )
        let backend = OPBackend(name: "test", account: nil, vault: "Personal", opPath: fakeOP)
        _ = try await backend.get(key: "ssh-github")
        let argv = try String(contentsOf: argvFile, encoding: .utf8)
        XCTAssertTrue(argv.contains("op://Personal/ssh-github/private_key"), "argv: \(argv)")
    }

    func testPutThrowsReadOnly() async throws {
        let fakeOP = try writeFakeOP(argvLog: tempDir.appending(path: "x.log"), readOutput: "")
        let backend = OPBackend(name: "test", account: nil, vault: "Personal", opPath: fakeOP)
        do {
            try await backend.put(key: "x", pem: Data(), options: PutOptions())
            XCTFail("expected readOnly")
        } catch let err as BackendError {
            XCTAssertEqual(err, .readOnly)
        }
    }

    func testNonZeroExitMappedToCommandFailed() async throws {
        let argvLog = tempDir.appending(path: "argv.log")
        let script = """
            #!/bin/sh
            echo "[\\"$@\\"]" >> "\(argvLog.path)"
            echo "vault is locked" 1>&2
            exit 1
            """
        let fakeOP = tempDir.appending(path: "op").path
        try script.write(toFile: fakeOP, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fakeOP)

        let backend = OPBackend(name: "test", account: nil, vault: "Personal", opPath: fakeOP)
        do {
            _ = try await backend.get(key: "missing")
            XCTFail("expected commandFailed")
        } catch let err as OPError {
            if case .commandFailed(_, let stderr) = err {
                XCTAssertTrue(stderr.contains("vault is locked"))
            } else {
                XCTFail("wrong error: \(err)")
            }
        }
    }

    // MARK: helpers

    private func writeFakeOP(argvLog: URL, readOutput: String) throws -> String {
        // Heredoc-escaped to avoid shell expanding $@.
        let script = """
            #!/bin/sh
            echo "[\\"$@\\"]" >> "\(argvLog.path)"
            cat <<'EOF'
            \(readOutput)
            EOF
            """
        let path = tempDir.appending(path: "op").path
        try script.write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
        return path
    }

    private func generateEd25519PEM() throws -> Data {
        let dir = FileManager.default.temporaryDirectory
            .appending(path: "op-keygen-\(UUID().uuidString)")
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
        return try Data(contentsOf: keyURL)
    }
}
