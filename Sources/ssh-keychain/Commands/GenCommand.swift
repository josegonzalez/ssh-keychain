import ArgumentParser
import Foundation
import NIOSSH
import SSHKeychainCore

struct GenCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "gen",
        abstract: "Generate a new SSH key in a backend (Secure Enclave for keychain)."
    )

    @Option(name: .long, help: "Backend and key: BACKEND:KEY (single key required).")
    var source: String

    @Option(name: .long, help: "Algorithm. v1 supports only ecdsa-p256.")
    var algorithm: String = "ecdsa-p256"

    @Flag(name: .long, help: "Store the new key in the Secure Enclave (required for keychain in v1).")
    var secureEnclave: Bool = false

    @Flag(name: .long, help: "Require Touch ID / biometric on every signing operation.")
    var requireBiometric: Bool = false

    @Flag(name: .long, help: "Overwrite an existing key with the same name.")
    var overwrite: Bool = false

    @Option(name: .long, help: "Optional descriptive comment to store on the public key.")
    var comment: String?

    func run() async throws {
        let spec = try SourceSpec.parse(source)
        guard let keyName = spec.singleKey else {
            throw ValidationError("--source must name exactly one key")
        }
        guard let algo = KeyAlgorithm(rawValue: algorithm) else {
            throw ValidationError("unsupported algorithm: \(algorithm). v1 supports ecdsa-p256")
        }
        guard algo == .ecdsaP256, secureEnclave else {
            throw ValidationError("v1 `gen` requires --algorithm=ecdsa-p256 and --secure-enclave")
        }

        let registry = try await ConfiguredRegistry.loadDefault()
        let backend = try await registry.resolve(spec.backend)
        guard let generating = backend as? any GeneratingBackend else {
            throw ValidationError("backend \(spec.backend) does not support key generation")
        }
        let options = GenerateOptions(
            algorithm: algo,
            secureEnclave: secureEnclave,
            requireBiometric: requireBiometric,
            overwrite: overwrite,
            comment: comment
        )
        let item = try await generating.generate(key: keyName, options: options)
        print("generated \(spec.backend):\(keyName)")
        print(String(openSSHPublicKey: item.publicKey) + " " + (item.comment ?? keyName))
    }
}
