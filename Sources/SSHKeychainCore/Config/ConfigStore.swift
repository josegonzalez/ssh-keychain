import Foundation

/// Atomic load/save of `Config` JSON.
public enum ConfigStore {
    public static func load(from url: URL) throws -> Config {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw ConfigError.fileNotFound(url.path)
        }
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw ConfigError.parseError("could not read \(url.path): \(error)")
        }
        let decoder = JSONDecoder()
        do {
            let config = try decoder.decode(Config.self, from: data)
            guard config.version == 1 else {
                throw ConfigError.unsupportedVersion(config.version)
            }
            return config
        } catch let e as ConfigError {
            throw e
        } catch {
            throw ConfigError.parseError("JSON decode failed: \(error)")
        }
    }

    /// Atomic write via `Data.write(to:options:.atomic)`, which uses a temp
    /// file + rename so readers never see a half-written config.
    public static func save(_ config: Config, to url: URL) throws {
        let parent = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: parent,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(config)
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
