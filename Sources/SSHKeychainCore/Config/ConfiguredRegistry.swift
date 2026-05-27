import Foundation

/// Build a `BackendRegistry` populated from the user's config file if one
/// exists. Falls back to the empty registry (which still serves the implicit
/// `file` and `keychain` backends) when no config is present.
///
/// Use from CLI commands that need to resolve user-named backends (`primary`,
/// `work-vault`, etc.). The daemon constructs its own registry directly.
public enum ConfiguredRegistry {
    public static func loadDefault() async throws -> BackendRegistry {
        let registry = BackendRegistry()
        let url = Config.defaultPath
        guard FileManager.default.fileExists(atPath: url.path) else {
            return registry
        }
        let config = try ConfigStore.load(from: url)
        for (name, backendConfig) in config.backends {
            await registry.register(name: name, config: backendConfig)
        }
        return registry
    }
}
