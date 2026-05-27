import Foundation

/// Synchronous SSH-agent client over a Unix domain socket.
///
/// Used by `ssh-keychain load` to push a key into the user's running agent
/// (`$SSH_AUTH_SOCK`) and to query what's already loaded for deduplication.
///
/// This is a thin blocking implementation; we don't need NIO here because the
/// CLI is one-shot and serializes against a single socket.
public struct AgentClient {
    public let socketPath: String

    public init(socketPath: String) {
        self.socketPath = (socketPath as NSString).expandingTildeInPath
    }

    /// List public-key blobs of the identities the remote agent currently holds.
    public func listIdentities() throws -> [Data] {
        let conn = try connect()
        defer { close(conn) }
        try send(byte: AgentProtocol.MessageType.requestIdentities.rawValue, on: conn)

        let response = try readFrame(on: conn)
        var r = SSHWireReader(response)
        let type = try r.readByte()
        guard type == AgentProtocol.MessageType.identitiesAnswer.rawValue else {
            throw AgentClientError.unexpectedResponse(type)
        }
        let count = try r.readUInt32()
        var blobs: [Data] = []
        for _ in 0..<count {
            blobs.append(try r.readString())
            _ = try r.readString()    // comment - ignored here
        }
        return blobs
    }

    /// Adds an identity to the remote agent. Returns whether the agent
    /// acknowledged success.
    public func addIdentity(parsed: ParsedKey, comment: String) throws -> Bool {
        let body = try buildAddIdentityBody(parsed: parsed, comment: comment)

        let conn = try connect()
        defer { close(conn) }
        try sendFrame(body, on: conn)

        let response = try readFrame(on: conn)
        guard !response.isEmpty else { return false }
        return response[response.startIndex] == AgentProtocol.MessageType.success.rawValue
    }

    // MARK: - encoding

    private func buildAddIdentityBody(parsed: ParsedKey, comment: String) throws -> Data {
        var w = SSHWireWriter()
        w.writeByte(AgentProtocol.MessageType.addIdentity.rawValue)
        switch parsed.privateKey {
        case .ed25519(let key):
            let pubRaw = key.publicKey.rawRepresentation
            // ssh-agent ed25519 private bytes are concatenated `seed || pub` = 64 bytes.
            var privBytes = key.rawRepresentation
            privBytes.append(pubRaw)
            w.writeString("ssh-ed25519")
            w.writeString(pubRaw)
            w.writeString(privBytes)
        case .ecdsaP256(let key):
            w.writeString("ecdsa-sha2-nistp256")
            w.writeString("nistp256")
            w.writeString(key.publicKey.x963Representation)
            w.writeMPInt(key.rawRepresentation)
        case .ecdsaP384, .ecdsaP521:
            throw AgentClientError.unsupported("ecdsa-p384/p521 add-identity not implemented in v1")
        }
        w.writeString(comment)
        return w.buffer
    }

    // MARK: - transport

    private func connect() throws -> Int32 {
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { throw AgentClientError.socketCreate(errno) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = socketPath.utf8CString
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        guard bytes.count <= maxLen else {
            close(s)
            throw AgentClientError.socketPathTooLong
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { dest in
            dest.withMemoryRebound(to: CChar.self, capacity: maxLen) { destBytes in
                _ = bytes.withUnsafeBufferPointer { src in
                    memcpy(destBytes, src.baseAddress, bytes.count)
                }
            }
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                Darwin.connect(s, sockaddrPtr, size)
            }
        }
        if result != 0 {
            let err = errno
            close(s)
            throw AgentClientError.connectFailed(err)
        }
        return s
    }

    private func send(byte: UInt8, on fd: Int32) throws {
        try sendFrame(Data([byte]), on: fd)
    }

    private func sendFrame(_ payload: Data, on fd: Int32) throws {
        var length = UInt32(payload.count).bigEndian
        try writeAll(fd: fd, bytes: Data(bytes: &length, count: 4))
        try writeAll(fd: fd, bytes: payload)
    }

    private func readFrame(on fd: Int32) throws -> Data {
        let lengthBytes = try readExact(fd: fd, count: 4)
        var length: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &length) { lengthBytes.copyBytes(to: $0) }
        length = UInt32(bigEndian: length)
        guard length > 0, length < 1_000_000 else {
            throw AgentClientError.framingError(Int(length))
        }
        return try readExact(fd: fd, count: Int(length))
    }

    private func writeAll(fd: Int32, bytes: Data) throws {
        var remaining = bytes
        while !remaining.isEmpty {
            let written = remaining.withUnsafeBytes { buf -> Int in
                write(fd, buf.baseAddress, remaining.count)
            }
            if written < 0 { throw AgentClientError.writeFailed(errno) }
            if written == 0 { throw AgentClientError.shortWrite }
            remaining = remaining.dropFirst(written)
        }
    }

    private func readExact(fd: Int32, count: Int) throws -> Data {
        var out = Data(count: count)
        var filled = 0
        while filled < count {
            let chunk = out.withUnsafeMutableBytes { buf -> Int in
                let base = buf.baseAddress!.advanced(by: filled)
                return read(fd, base, count - filled)
            }
            if chunk < 0 { throw AgentClientError.readFailed(errno) }
            if chunk == 0 { throw AgentClientError.shortRead }
            filled += chunk
        }
        return out
    }
}

public enum AgentClientError: Error, Equatable {
    case socketCreate(Int32)
    case socketPathTooLong
    case connectFailed(Int32)
    case writeFailed(Int32)
    case readFailed(Int32)
    case shortWrite
    case shortRead
    case framingError(Int)
    case unexpectedResponse(UInt8)
    case unsupported(String)
}
