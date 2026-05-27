import ArgumentParser
import Foundation
import SSHKeychainCore

struct AddCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "add",
        abstract: "Import an existing SSH private key into a backend."
    )

    @Option(name: .long, help: "Backend and key: BACKEND:KEY (single key required).")
    var source: String

    @Option(name: .long, help: "Path to the private key file to import.")
    var file: String

    @Option(name: .long, help: "Optional descriptive comment to store with the key.")
    var comment: String?

    @Flag(name: .long, help: "Require Touch ID / biometric on every signing operation.")
    var requireBiometric: Bool = false

    @Flag(name: .long, help: "Overwrite an existing key with the same name.")
    var overwrite: Bool = false

    func run() async throws {
        let spec = try SourceSpec.parse(source)
        guard let keyName = spec.singleKey else {
            throw ValidationError("--source must name exactly one key (no wildcards, no commas)")
        }

        let pem: Data
        do {
            pem = try Data(contentsOf: URL(fileURLWithPath: file))
        } catch {
            throw ValidationError("cannot read \(file): \(error.localizedDescription)")
        }

        let registry = try await ConfiguredRegistry.loadDefault()
        let backend = try await registry.resolve(spec.backend)
        let options = PutOptions(
            requireBiometric: requireBiometric,
            overwrite: overwrite,
            comment: comment
        )
        try await backend.put(key: keyName, pem: pem, options: options)
        print("imported \(spec.backend):\(keyName)")
    }
}
