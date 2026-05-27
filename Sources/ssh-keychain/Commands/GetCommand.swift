import ArgumentParser
import Foundation
import NIOSSH
import SSHKeychainCore

struct GetCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "get",
        abstract: "Export a public key from a backend to stdout or a file."
    )

    @Option(name: .long, help: "Backend and key: BACKEND:KEY (single key required).")
    var source: String

    @Option(name: .long, help: "Write the public key to this path instead of stdout.")
    var output: String?

    func run() async throws {
        let spec = try SourceSpec.parse(source)
        guard let keyName = spec.singleKey else {
            throw ValidationError("--source must name exactly one key (no wildcards, no commas)")
        }

        let registry = try await ConfiguredRegistry.loadDefault()
        let backend = try await registry.resolve(spec.backend)

        // Phase 3 `get` writes only the public key. Private export (the
        // `--output=<file>` case for full PEM) is intentionally deferred until
        // we have a per-backend "expose private bytes" capability check - many
        // backends (Secure Enclave, future YubiKey) physically cannot expose
        // private material. See phase 9.
        let items = try await backend.list(options: ListOptions(publicKeysOnly: true))
        guard let item = items.first(where: { $0.key == keyName }) else {
            throw BackendError.notFound
        }

        var line = String(openSSHPublicKey: item.publicKey)
        if let comment = item.comment {
            line += " \(comment)"
        }
        line += "\n"

        if let output {
            try line.write(toFile: output, atomically: true, encoding: .utf8)
        } else {
            print(line, terminator: "")
        }
    }
}
