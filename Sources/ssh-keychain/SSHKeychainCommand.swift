import ArgumentParser
import SSHKeychainCore

@main
struct SSHKeychainCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ssh-keychain",
        abstract: "Dynamic SSH key retrieval from pluggable backends.",
        version: SSHKeychain.version,
        subcommands: [
            AddCommand.self,
            GenCommand.self,
            ListCommand.self,
            RemoveCommand.self,
            GetCommand.self,
            LoadCommand.self,
            RunCommand.self,
            AgentCommand.self,
            StatusCommand.self,
            DoctorCommand.self,
        ]
    )
}
