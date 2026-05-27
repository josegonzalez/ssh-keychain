import Foundation

public struct FileSecretSource: SecretSource {
    public let path: String

    public init(path: String) {
        self.path = path
    }

    public func fetch() async throws -> Data {
        guard FileManager.default.fileExists(atPath: path) else {
            throw SecretRefError.fetchFailed("file:\(path) does not exist")
        }
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        if let mode = attrs[.posixPermissions] as? Int, (mode & 0o077) != 0 {
            throw SecretRefError.fetchFailed("file:\(path) has insecure permissions \(String(mode, radix: 8)); must be 0600 or stricter")
        }
        let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
        // Strip trailing newlines (common pattern: secrets written with `echo`).
        var trimmed = bytes
        while let last = trimmed.last, last == 0x0a || last == 0x0d {
            trimmed.removeLast()
        }
        return trimmed
    }
}
