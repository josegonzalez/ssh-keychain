import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Reads a secret from the controlling TTY with terminal echo disabled.
///
/// Daemon mode has no controlling TTY; this source errors with `.noTTY` so
/// the caller can suggest a `keychain:` or `file:` alternative.
public struct PromptSecretSource: SecretSource {
    public let message: String

    public init(message: String) {
        self.message = message
    }

    public func fetch() async throws -> Data {
        // isatty(0) returns 1 if stdin is a terminal. Daemonized processes
        // have stdin redirected to /dev/null, so this is the canonical check.
        guard isatty(0) == 1 else {
            throw SecretRefError.noTTY
        }
        FileHandle.standardError.write(Data("\(message): ".utf8))
        let line = readPassword()
        return Data(line.utf8)
    }

    private func readPassword() -> String {
        // Save current terminal attributes, disable echo, read line, restore.
        var oldFlags = termios()
        tcgetattr(0, &oldFlags)
        var newFlags = oldFlags
        newFlags.c_lflag &= ~UInt(ECHO)
        tcsetattr(0, TCSANOW, &newFlags)
        defer {
            tcsetattr(0, TCSANOW, &oldFlags)
            FileHandle.standardError.write(Data("\n".utf8))
        }
        return readLine(strippingNewline: true) ?? ""
    }
}
