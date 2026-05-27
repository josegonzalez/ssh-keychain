import Foundation
import XCTest
@testable import SSHKeychainCore

final class SecretRefTests: XCTestCase {
    func testParseEnvScheme() throws {
        let s = try SecretRef.parse("env:MY_VAR")
        XCTAssertTrue(s is EnvSecretSource)
        XCTAssertEqual((s as? EnvSecretSource)?.variable, "MY_VAR")
    }

    func testParseFileScheme() throws {
        let s = try SecretRef.parse("file:/etc/secrets/x")
        XCTAssertTrue(s is FileSecretSource)
        XCTAssertEqual((s as? FileSecretSource)?.path, "/etc/secrets/x")
    }

    func testParsePromptScheme() throws {
        let s = try SecretRef.parse("prompt:Enter X")
        XCTAssertTrue(s is PromptSecretSource)
        XCTAssertEqual((s as? PromptSecretSource)?.message, "Enter X")
    }

    func testParsePromptWithoutMessage() throws {
        let s = try SecretRef.parse("prompt:")
        XCTAssertTrue(s is PromptSecretSource)
        XCTAssertEqual((s as? PromptSecretSource)?.message, "Enter secret")
    }

    func testMissingScheme() {
        XCTAssertThrowsError(try SecretRef.parse("no-colon")) { error in
            XCTAssertEqual(error as? SecretRefError, .missingScheme("no-colon"))
        }
    }

    func testUnknownScheme() {
        XCTAssertThrowsError(try SecretRef.parse("vault:foo")) { error in
            if case .unknownScheme = error as? SecretRefError {} else {
                XCTFail("wrong error: \(error)")
            }
        }
    }

    func testEnvSourceFetchesValue() async throws {
        setenv("SSK_TEST_SECRET", "deadbeef", 1)
        defer { unsetenv("SSK_TEST_SECRET") }
        let source = EnvSecretSource(variable: "SSK_TEST_SECRET")
        let bytes = try await source.fetch()
        XCTAssertEqual(bytes, Data("deadbeef".utf8))
    }

    func testEnvSourceMissingVarThrows() async {
        let source = EnvSecretSource(variable: "SSK_TEST_DEFINITELY_NOT_SET")
        do {
            _ = try await source.fetch()
            XCTFail("expected fetchFailed")
        } catch let err as SecretRefError {
            if case .fetchFailed = err {} else { XCTFail("wrong error: \(err)") }
        } catch {
            XCTFail("wrong error type: \(error)")
        }
    }

    func testFileSourceReadsAndTrimsNewline() async throws {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "ssk-secret-\(UUID().uuidString)")
        try "topsecret\n".write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        defer { try? FileManager.default.removeItem(at: url) }

        let bytes = try await FileSecretSource(path: url.path).fetch()
        XCTAssertEqual(bytes, Data("topsecret".utf8))
    }

    func testFileSourceRejectsLoosePerms() async throws {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "ssk-secret-loose-\(UUID().uuidString)")
        try "x".write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        defer { try? FileManager.default.removeItem(at: url) }

        do {
            _ = try await FileSecretSource(path: url.path).fetch()
            XCTFail("expected fetchFailed (insecure permissions)")
        } catch let err as SecretRefError {
            if case .fetchFailed(let msg) = err {
                XCTAssertTrue(msg.contains("insecure"), "got message: \(msg)")
            } else {
                XCTFail("wrong error: \(err)")
            }
        } catch {
            XCTFail("wrong error type: \(error)")
        }
    }
}
