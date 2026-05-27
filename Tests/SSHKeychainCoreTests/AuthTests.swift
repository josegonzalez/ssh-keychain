import Foundation
import XCTest
@testable import SSHKeychainCore

final class AuthTests: XCTestCase {
    func testStaticProviderReadsTokenFromEnv() async throws {
        setenv("SSK_TEST_AUTH_TOKEN", "hvs.abc123", 1)
        defer { unsetenv("SSK_TEST_AUTH_TOKEN") }
        let provider = StaticAuthProvider(source: EnvSecretSource(variable: "SSK_TEST_AUTH_TOKEN"))
        let cred = try await provider.token()
        XCTAssertEqual(cred.token, "hvs.abc123")
    }

    func testStaticProviderTrimsWhitespace() async throws {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "ssk-token-\(UUID().uuidString)")
        try "hvs.token-with-newline\n".write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        defer { try? FileManager.default.removeItem(at: url) }

        let provider = StaticAuthProvider(source: FileSecretSource(path: url.path))
        let cred = try await provider.token()
        XCTAssertEqual(cred.token, "hvs.token-with-newline")
    }

    func testOIDCProviderStubThrowsUnsupported() async throws {
        let provider = OIDCAuthProvider(name: "test", issuer: URL(string: "https://idp.example.com")!, clientID: "abc")
        do {
            _ = try await provider.token()
            XCTFail("expected unsupported")
        } catch AuthError.unsupported {
            // OK
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testTokenCacheHitDoesNotCallProviderAgain() async throws {
        let provider = CountingProvider()
        let cache = TokenCache(persistToKeychain: false)
        _ = try await cache.token(for: provider)
        _ = try await cache.token(for: provider)
        let calls = await provider.calls
        XCTAssertEqual(calls, 1)
    }

    func testTokenCacheInvalidateForcesRefresh() async throws {
        let provider = CountingProvider()
        let cache = TokenCache(persistToKeychain: false)
        _ = try await cache.token(for: provider)
        await cache.invalidate(for: provider.name)
        _ = try await cache.token(for: provider)
        let calls = await provider.calls
        XCTAssertEqual(calls, 2)
    }

    func testTokenCacheRespectsExpiry() async throws {
        let provider = ExpiringProvider()
        let cache = TokenCache(persistToKeychain: false)
        _ = try await cache.token(for: provider)
        try await Task.sleep(nanoseconds: 100_000_000)
        _ = try await cache.token(for: provider)
        let calls = await provider.calls
        XCTAssertEqual(calls, 2, "expired token should force second call")
    }
}

/// Test provider that hands out a static long-lived token, counting calls.
actor CountingProvider: AuthProvider {
    nonisolated let name: String = "counting-provider"
    private(set) var calls = 0

    nonisolated func token() async throws -> Credential {
        await bumpCalls()
        return Credential(token: "tok", expiresAt: .distantFuture)
    }

    private func bumpCalls() { calls += 1 }
}

/// Provider whose tokens expire 50ms after issue.
actor ExpiringProvider: AuthProvider {
    nonisolated let name: String = "expiring-provider"
    private(set) var calls = 0

    nonisolated func token() async throws -> Credential {
        await bumpCalls()
        return Credential(token: "tok", expiresAt: Date().addingTimeInterval(0.05))
    }

    private func bumpCalls() { calls += 1 }
}
