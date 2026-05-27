import Foundation

public struct EnvSecretSource: SecretSource {
    public let variable: String

    public init(variable: String) {
        self.variable = variable
    }

    public func fetch() async throws -> Data {
        guard let value = ProcessInfo.processInfo.environment[variable] else {
            throw SecretRefError.fetchFailed("env:\(variable) is not set")
        }
        return Data(value.utf8)
    }
}
