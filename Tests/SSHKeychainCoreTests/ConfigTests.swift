import Foundation
import XCTest
@testable import SSHKeychainCore

final class ConfigTests: XCTestCase {
    var tempURL: URL!

    override func setUp() async throws {
        tempURL = FileManager.default.temporaryDirectory
            .appending(path: "ssh-keychain-config-\(UUID().uuidString).json")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: tempURL)
    }

    func testRoundTrip() throws {
        var config = Config()
        config.backends["primary"] = BackendConfig(type: "keychain")
        var workVault = BackendConfig(type: "vault")
        workVault.address = "https://vault.internal:8200"
        workVault.mount = "secret"
        workVault.auth = AuthConfig(type: "static", tokenRef: "keychain:vault-token")
        config.backends["work-vault"] = workVault
        config.sources = [
            SourceEntry(backend: "primary", key: "*"),
            {
                var s = SourceEntry(backend: "work-vault", key: "db-readonly")
                s.vaultPath = "secret/data/ssh/db-readonly"
                return s
            }(),
        ]
        try ConfigStore.save(config, to: tempURL)
        let loaded = try ConfigStore.load(from: tempURL)
        XCTAssertEqual(loaded, config)
    }

    func testRejectsUnknownVersion() throws {
        let badJSON = """
        { "version": 99, "agent": { "socketPath": "x", "cacheTTL": 0, "cacheMaxKeys": 32, "cacheTokensToKeychain": false }, "backends": {}, "sources": [] }
        """
        try badJSON.write(to: tempURL, atomically: true, encoding: .utf8)
        do {
            _ = try ConfigStore.load(from: tempURL)
            XCTFail("expected unsupportedVersion")
        } catch ConfigError.unsupportedVersion(let v) {
            XCTAssertEqual(v, 99)
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testMissingFile() {
        do {
            _ = try ConfigStore.load(from: tempURL)
            XCTFail("expected fileNotFound")
        } catch ConfigError.fileNotFound {
            // OK
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testFilePermissionsOnSave() throws {
        let config = Config()
        try ConfigStore.save(config, to: tempURL)
        let attrs = try FileManager.default.attributesOfItem(atPath: tempURL.path)
        let perms = attrs[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
    }
}

final class ConfigWatcherTests: XCTestCase {
    var tempURL: URL!

    override func setUp() async throws {
        tempURL = FileManager.default.temporaryDirectory
            .appending(path: "ssh-keychain-watch-\(UUID().uuidString).json")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: tempURL)
    }

    func testFiresOnInitialLoad() async throws {
        try ConfigStore.save(Config(), to: tempURL)
        let exp = expectation(description: "initial load")
        let watcher = ConfigWatcher(
            url: tempURL,
            onChange: { _ in exp.fulfill() },
            onError: { _ in }
        )
        watcher.start()
        defer { watcher.stop() }
        await fulfillment(of: [exp], timeout: 2.0)
    }

    func testFiresOnAtomicRewrite() async throws {
        var config = Config()
        try ConfigStore.save(config, to: tempURL)

        let firstLoad = expectation(description: "first load")
        let secondLoad = expectation(description: "rewrite delivered")
        let counter = Counter()
        let watcher = ConfigWatcher(
            url: tempURL,
            onChange: { newConfig in
                let n = counter.next()
                if n == 1 { firstLoad.fulfill() }
                if n == 2, newConfig.agent.cacheTTL == 900 { secondLoad.fulfill() }
            },
            onError: { _ in }
        )
        watcher.start()
        defer { watcher.stop() }
        await fulfillment(of: [firstLoad], timeout: 2.0)

        config.agent.cacheTTL = 900
        try ConfigStore.save(config, to: tempURL)
        await fulfillment(of: [secondLoad], timeout: 5.0)
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = 0
    var value: Int {
        lock.lock(); defer { lock.unlock() }
        return _value
    }
    func next() -> Int {
        lock.lock(); defer { lock.unlock() }
        _value += 1
        return _value
    }
}
