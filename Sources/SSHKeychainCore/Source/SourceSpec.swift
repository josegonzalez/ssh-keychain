import Foundation

/// A parsed `--source=BACKEND:KEY[,KEY...]` specifier.
///
/// Grammar (whitespace not allowed):
///
///     spec    = backend ":" keyList
///     keyList = "*" | key ("," key)*
///     key     = any non-empty string not containing "," or ":"
public struct SourceSpec: Sendable, Equatable {
    public let backend: String
    public let keys: Selection

    public enum Selection: Sendable, Equatable {
        case wildcard
        case explicit([String])
    }

    public init(backend: String, keys: Selection) {
        self.backend = backend
        self.keys = keys
    }

    public static func parse(_ raw: String) throws -> SourceSpec {
        guard let colon = raw.firstIndex(of: ":") else {
            throw SourceSpecError.missingColon(raw)
        }
        let backend = String(raw[..<colon])
        let keysPart = String(raw[raw.index(after: colon)...])
        guard !backend.isEmpty else { throw SourceSpecError.emptyBackend(raw) }
        guard !keysPart.isEmpty else { throw SourceSpecError.emptyKeys(raw) }

        if keysPart == "*" {
            return SourceSpec(backend: backend, keys: .wildcard)
        }
        let keys = keysPart.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        for k in keys where k.isEmpty {
            throw SourceSpecError.emptyKey(raw)
        }
        return SourceSpec(backend: backend, keys: .explicit(keys))
    }

    /// The single key referenced by this spec, or `nil` if the spec is a
    /// wildcard or names multiple keys. Used by single-source CLI commands
    /// (`add`, `gen`, `get`, `remove`, `load`, `run`).
    public var singleKey: String? {
        if case .explicit(let keys) = self.keys, keys.count == 1 {
            return keys.first
        }
        return nil
    }
}

public enum SourceSpecError: Error, Equatable {
    case missingColon(String)
    case emptyBackend(String)
    case emptyKeys(String)
    case emptyKey(String)
}
