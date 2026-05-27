import Foundation

/// The on-disk JSON schema for `~/Library/Application Support/com.josegonzalez.ssh-keychain/config.json`.
///
/// The daemon reads this at startup, watches it via `ConfigWatcher`, and
/// reloads when it changes. Invalid configs are surfaced via thrown errors;
/// the daemon never moves to a half-loaded state.
public struct Config: Codable, Sendable, Equatable {
    public var version: Int
    public var agent: AgentSettings
    public var backends: [String: BackendConfig]
    public var sources: [SourceEntry]

    public init(
        version: Int = 1,
        agent: AgentSettings = .init(),
        backends: [String: BackendConfig] = [:],
        sources: [SourceEntry] = []
    ) {
        self.version = version
        self.agent = agent
        self.backends = backends
        self.sources = sources
    }
}

public struct AgentSettings: Codable, Sendable, Equatable {
    public var socketPath: String
    public var cacheTTL: Double
    public var cacheMaxKeys: Int
    public var cacheTokensToKeychain: Bool

    public init(
        socketPath: String = "~/.ssh/ssh-keychain.sock",
        cacheTTL: Double = 0,
        cacheMaxKeys: Int = 32,
        cacheTokensToKeychain: Bool = false
    ) {
        self.socketPath = socketPath
        self.cacheTTL = cacheTTL
        self.cacheMaxKeys = cacheMaxKeys
        self.cacheTokensToKeychain = cacheTokensToKeychain
    }
}

/// Per-backend connectivity configuration. The `type` discriminator picks
/// which fields are valid; we use a flat representation rather than an
/// enum-of-cases so the JSON stays human-friendly.
public struct BackendConfig: Codable, Sendable, Equatable {
    public var type: String

    // Common
    public var path: String?           // file, opvault: filesystem path

    // Vault
    public var address: String?
    public var mount: String?
    public var prefix: String?
    public var auth: AuthConfig?

    // OPVault
    public var masterRef: String?      // secretref
    public var lockAfter: Double?

    // op (1Password CLI)
    public var account: String?
    public var vault: String?

    public init(type: String) {
        self.type = type
    }
}

public struct AuthConfig: Codable, Sendable, Equatable {
    public var type: String            // "static" | "oidc" (v1.1)
    public var tokenRef: String?       // secretref for "static"

    public init(type: String, tokenRef: String? = nil) {
        self.type = type
        self.tokenRef = tokenRef
    }
}

/// One `--source` equivalent line in the config: backend name + key(s) +
/// optional per-source overrides.
public struct SourceEntry: Codable, Sendable, Equatable {
    public var backend: String
    public var key: String             // user label, or "*" for wildcard

    // 1Password backends
    public var item: String?
    public var field: String?

    // Vault backend
    public var vaultPath: String?
    public var vaultField: String?

    public init(backend: String, key: String) {
        self.backend = backend
        self.key = key
    }
}

public enum ConfigError: Error, Equatable {
    case fileNotFound(String)
    case parseError(String)
    case unsupportedVersion(Int)
}

extension Config {
    /// Standard config path. Test code overrides this via explicit URLs to
    /// avoid touching the user's real config.
    public static var defaultPath: URL {
        let appSupport = (try? FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: false
        )) ?? URL(fileURLWithPath: NSHomeDirectory()).appending(path: "Library/Application Support")
        return appSupport
            .appending(path: "com.josegonzalez.ssh-keychain")
            .appending(path: "config.json")
    }
}
