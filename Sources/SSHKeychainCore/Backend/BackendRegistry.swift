import Foundation

/// Resolves backend names (as they appear in `--source=NAME:KEY`) to live
/// `Backend` instances.
///
/// In phase 3 the registry knows only the implicit `file` backend. Phase 12
/// (Config schema) extends it to load configured backend instances by name
/// from `~/Library/Application Support/com.josegonzalez.ssh-keychain/config.json`.
public actor BackendRegistry {
    private var backends: [String: any Backend] = [:]
    private var configuredBackends: [String: BackendConfig] = [:]

    public init() {}

    /// Register a named backend instance from the config file. The agent calls
    /// this once per `backends.*` entry before resolving any source specs.
    public func register(name: String, config: BackendConfig) async {
        configuredBackends[name] = config
        backends.removeValue(forKey: name)   // force re-construction next resolve
    }

    public func resolve(_ name: String) async throws -> any Backend {
        if let existing = backends[name] {
            return existing
        }
        let created = try await create(name: name)
        backends[name] = created
        return created
    }

    private func create(name: String) async throws -> any Backend {
        if let cfg = configuredBackends[name] {
            return try await createFromConfig(name: name, config: cfg)
        }
        // Implicit backends (no config file): "file" and "keychain".
        switch name {
        case "file":
            return try FileBackend(name: "file")
        case "keychain":
            #if canImport(Security)
            return KeychainBackend(name: "keychain")
            #else
            throw RegistryError.unknownBackend(name)
            #endif
        default:
            throw RegistryError.unknownBackend(name)
        }
    }

    private func createFromConfig(name: String, config: BackendConfig) async throws -> any Backend {
        switch config.type {
        case "file":
            let root = config.path.map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath) }
            return try FileBackend(name: name, root: root)
        case "keychain":
            #if canImport(Security)
            return KeychainBackend(name: name)
            #else
            throw RegistryError.unknownBackend("keychain not available on this platform")
            #endif
        case "vault":
            return try await makeVaultBackend(name: name, config: config)
        case "op":
            return try makeOPBackend(name: name, config: config)
        case "opvault":
            return try makeOPVaultBackend(name: name, config: config)
        default:
            throw RegistryError.unsupportedBackendType(config.type)
        }
    }
}

public enum RegistryError: Error, Equatable {
    case unknownBackend(String)
    case unsupportedBackendType(String)
    case invalidBackendConfig(String)
}

extension BackendRegistry {
    /// Construct an `OPVaultBackend` from a config entry. `path` and `masterRef` are required.
    func makeOPVaultBackend(name: String, config: BackendConfig) throws -> any Backend {
        guard let path = config.path else {
            throw RegistryError.invalidBackendConfig("opvault backend \(name) is missing `path`")
        }
        guard let masterRef = config.masterRef else {
            throw RegistryError.invalidBackendConfig("opvault backend \(name) is missing `masterRef`")
        }
        let source = try SecretRef.parse(masterRef)
        let expanded = (path as NSString).expandingTildeInPath
        return OPVaultBackend(
            name: name,
            vaultPath: URL(fileURLWithPath: expanded),
            masterSource: source,
            lockAfter: config.lockAfter ?? 900
        )
    }

    /// Construct an `OPBackend` from a config entry. `vault` is required.
    func makeOPBackend(name: String, config: BackendConfig) throws -> any Backend {
        guard let vault = config.vault else {
            throw RegistryError.invalidBackendConfig("op backend \(name) is missing `vault`")
        }
        let opPath = resolveOPPath()
        return OPBackend(
            name: name,
            account: config.account,
            vault: vault,
            opPath: opPath
        )
    }

    /// Resolve the `op` binary path. Defaults to the canonical Homebrew
    /// location and falls back to a PATH lookup. The chosen path is plumbed
    /// through to `OPBackend` so the actor doesn't repeat the lookup per call.
    private func resolveOPPath() -> String {
        let candidates = ["/opt/homebrew/bin/op", "/usr/local/bin/op", "/usr/bin/op"]
        for c in candidates where FileManager.default.isExecutableFile(atPath: c) {
            return c
        }
        // Last resort: rely on PATH at runtime.
        return "op"
    }

    /// Construct a `VaultBackend` from a config entry, wiring up the auth
    /// provider as specified.
    func makeVaultBackend(name: String, config: BackendConfig) async throws -> any Backend {
        guard let addressString = config.address,
              let address = URL(string: addressString)
        else {
            throw RegistryError.invalidBackendConfig("vault backend \(name) is missing `address`")
        }
        guard let mount = config.mount else {
            throw RegistryError.invalidBackendConfig("vault backend \(name) is missing `mount`")
        }
        let auth = config.auth ?? AuthConfig(type: "static")
        let provider: any AuthProvider
        switch auth.type {
        case "static":
            let tokenSource: any SecretSource
            if let tokenRef = auth.tokenRef {
                tokenSource = try SecretRef.parse(tokenRef)
            } else {
                // Fall back to the standard VAULT_TOKEN env var.
                tokenSource = EnvSecretSource(variable: "VAULT_TOKEN")
            }
            provider = StaticAuthProvider(name: "\(name).static", source: tokenSource)
        case "oidc":
            throw RegistryError.unsupportedBackendType("vault auth=oidc lands in v1.1")
        default:
            throw RegistryError.invalidBackendConfig("unknown auth type: \(auth.type)")
        }
        let cache = TokenCache(persistToKeychain: false)
        return VaultBackend(
            name: name,
            address: address,
            mount: mount,
            prefix: config.prefix,
            provider: provider,
            tokenCache: cache
        )
    }
}
