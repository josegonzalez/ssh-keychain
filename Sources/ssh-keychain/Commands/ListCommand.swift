import ArgumentParser
import Foundation
import NIOSSH
import SSHKeychainCore

struct ListCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "List keys available in one or more backends."
    )

    @Option(name: .long, help: "Backend (with optional :KEY or :* filter).")
    var source: String

    func run() async throws {
        let spec = try SourceSpec.parse(source)
        let registry = try await ConfiguredRegistry.loadDefault()
        let backend = try await registry.resolve(spec.backend)
        let items = try await backend.list(options: ListOptions(publicKeysOnly: true))
        let filtered: [PublicItem]
        switch spec.keys {
        case .wildcard:
            filtered = items
        case .explicit(let names):
            let want = Set(names)
            filtered = items.filter { want.contains($0.key) }
        }
        for item in filtered {
            let line = String(openSSHPublicKey: item.publicKey)
            let comment = item.comment.map { " \($0)" } ?? ""
            print("\(spec.backend):\(item.key)\t\(line)\(comment)")
        }
    }
}
