import ArgumentParser
import SSHKeychainCore

struct RemoveCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "remove",
        abstract: "Remove a key from a backend."
    )

    @Option(name: .long, help: "Backend and key: BACKEND:KEY (single key required).")
    var source: String

    func run() async throws {
        let spec = try SourceSpec.parse(source)
        guard let keyName = spec.singleKey else {
            throw ValidationError("--source must name exactly one key (no wildcards, no commas)")
        }
        let registry = try await ConfiguredRegistry.loadDefault()
        let backend = try await registry.resolve(spec.backend)
        try await backend.remove(key: keyName)
        print("removed \(spec.backend):\(keyName)")
    }
}
