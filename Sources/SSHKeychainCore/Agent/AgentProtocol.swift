import Foundation
import NIOCore

/// SSH agent protocol wire format (PROTOCOL.agent in the OpenSSH source tree).
///
/// All messages are length-prefixed: `uint32 length; byte type; payload[length-1]`.
public enum AgentProtocol {
    public enum MessageType: UInt8 {
        // Client requests
        case requestIdentities = 11
        case signRequest = 13
        case addIdentity = 17
        case removeIdentity = 18
        case removeAllIdentities = 19
        case lock = 22
        case unlock = 23
        case addIDConstrained = 25
        case addSmartcardKey = 20
        case removeSmartcardKey = 21
        case addSmartcardKeyConstrained = 26
        case requestExtension = 27

        // Server responses
        case failure = 5
        case success = 6
        case extensionFailure = 28
        case identitiesAnswer = 12
        case signResponse = 14
    }

    public struct IdentitiesAnswer: Sendable {
        public let keys: [Identity]
        public struct Identity: Sendable {
            public let keyBlob: Data
            public let comment: String
            public init(keyBlob: Data, comment: String) {
                self.keyBlob = keyBlob
                self.comment = comment
            }
        }
        public init(keys: [Identity]) { self.keys = keys }
    }

    public struct SignRequest: Sendable {
        public let keyBlob: Data
        public let data: Data
        public let flags: UInt32
        public init(keyBlob: Data, data: Data, flags: UInt32) {
            self.keyBlob = keyBlob
            self.data = data
            self.flags = flags
        }
    }
}

extension AgentProtocol.IdentitiesAnswer {
    public func encode() -> Data {
        var w = SSHWireWriter()
        w.writeByte(AgentProtocol.MessageType.identitiesAnswer.rawValue)
        w.writeUInt32(UInt32(keys.count))
        for k in keys {
            w.writeString(k.keyBlob)
            w.writeString(k.comment)
        }
        return AgentProtocol.frame(w.buffer)
    }
}

extension AgentProtocol {
    public static func parseSignRequest(_ body: Data) throws -> SignRequest {
        var r = SSHWireReader(body)
        let keyBlob = try r.readString()
        let data = try r.readString()
        let flags = try r.readUInt32()
        return SignRequest(keyBlob: keyBlob, data: data, flags: flags)
    }

    public static func encodeSignResponse(signatureBlob: Data) -> Data {
        var w = SSHWireWriter()
        w.writeByte(MessageType.signResponse.rawValue)
        w.writeString(signatureBlob)
        return frame(w.buffer)
    }

    public static func encodeFailure() -> Data {
        return frame(Data([MessageType.failure.rawValue]))
    }

    public static func encodeSuccess() -> Data {
        return frame(Data([MessageType.success.rawValue]))
    }

    /// Prepend the 4-byte length prefix that wraps every agent message.
    internal static func frame(_ payload: Data) -> Data {
        var out = Data()
        var w = SSHWireWriter()
        w.writeUInt32(UInt32(payload.count))
        out.append(w.buffer)
        out.append(payload)
        return out
    }

    /// Sign-request flags (RFC draft-miller-ssh-agent §3.6.1).
    public enum SignFlags: UInt32 {
        case rsaSHA2_256 = 0x01
        case rsaSHA2_512 = 0x02
    }
}
