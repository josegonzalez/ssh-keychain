import ArgumentParser
import Foundation
import SSHKeychainCore

struct LoadCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "load",
        abstract: "Push a key from a backend into the running $SSH_AUTH_SOCK agent."
    )

    @Option(name: .long, help: "Backend and key: BACKEND:KEY (single key required).")
    var source: String

    @Option(name: .long, help: "Override $SSH_AUTH_SOCK with an explicit socket path.")
    var sshAuthSock: String?

    func run() async throws {
        let spec = try SourceSpec.parse(source)
        guard let keyName = spec.singleKey else {
            throw ValidationError("--source must name exactly one key (no wildcards, no commas)")
        }

        let socketPath = sshAuthSock ?? ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"]
        guard let socketPath, !socketPath.isEmpty else {
            throw ValidationError("$SSH_AUTH_SOCK is not set; pass --ssh-auth-sock=PATH or start an agent first")
        }

        let registry = try await ConfiguredRegistry.loadDefault()
        let backend = try await registry.resolve(spec.backend)
        let item = try await backend.get(key: keyName)

        // `load` requires raw key bytes to hand to the remote agent. Hardware-
        // bound backends (Secure Enclave, future YubiKey) can't satisfy this;
        // those users should configure `IdentityAgent` against our own daemon.
        guard let pemSigner = item.signer as? PEMSSHSigner else {
            throw ValidationError("`load` cannot export hardware-bound keys; use IdentityAgent against our daemon for \(spec.backend):\(keyName)")
        }

        let client = AgentClient(socketPath: socketPath)
        let existing = try client.listIdentities()
        let ourBlob = pemSigner.parsed.publicKey.sshKeyBlob
        if existing.contains(ourBlob) {
            print("\(spec.backend):\(keyName) already loaded in $SSH_AUTH_SOCK; skipping")
            return
        }

        let success = try client.addIdentity(parsed: pemSigner.parsed, comment: item.comment ?? "\(spec.backend):\(keyName)")
        if success {
            print("loaded \(spec.backend):\(keyName) into $SSH_AUTH_SOCK")
        } else {
            throw ValidationError("agent at \(socketPath) refused the AddIdentity request")
        }
    }
}
