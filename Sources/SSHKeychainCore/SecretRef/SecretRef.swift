import Foundation

/// Produces the bytes of a secret on demand. Used by backends that need
/// credentials (Vault token, OPVault master password) but want to avoid
/// holding the secret in memory longer than the operation requires.
public protocol SecretSource: Sendable {
    func fetch() async throws -> Data
}

/// Parser for the secretref DSL.
///
/// Supported schemes:
///
///   keychain:NAME           macOS keychain generic-password item under our service.
///   file:/path/to/secret    0600-permissioned file containing the raw secret.
///   env:VAR_NAME            Read from a process environment variable.
///   prompt:[message]        Prompt on the controlling TTY (no-echo). CLI only -
///                            errors when invoked from the daemon (no controlling TTY).
public enum SecretRef {
    public static func parse(_ ref: String) throws -> any SecretSource {
        guard let colon = ref.firstIndex(of: ":") else {
            throw SecretRefError.missingScheme(ref)
        }
        let scheme = String(ref[..<colon])
        let rest = String(ref[ref.index(after: colon)...])
        switch scheme {
        case "keychain":
            guard !rest.isEmpty else { throw SecretRefError.emptyTarget(ref) }
            #if canImport(Security)
            return KeychainSecretSource(account: rest)
            #else
            throw SecretRefError.unknownScheme("keychain (not available on this platform)")
            #endif
        case "file":
            guard !rest.isEmpty else { throw SecretRefError.emptyTarget(ref) }
            return FileSecretSource(path: (rest as NSString).expandingTildeInPath)
        case "env":
            guard !rest.isEmpty else { throw SecretRefError.emptyTarget(ref) }
            return EnvSecretSource(variable: rest)
        case "prompt":
            return PromptSecretSource(message: rest.isEmpty ? "Enter secret" : rest)
        default:
            throw SecretRefError.unknownScheme(scheme)
        }
    }
}

public enum SecretRefError: Error, Equatable {
    case missingScheme(String)
    case unknownScheme(String)
    case emptyTarget(String)
    case fetchFailed(String)
    case noTTY
}
