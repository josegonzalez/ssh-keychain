import Foundation

/// Reader for SSH wire format primitives over a `Data` buffer.
///
/// SSH wire format (RFC 4251 §5):
/// - `byte`: 1 byte
/// - `uint32`: 4 bytes, big-endian
/// - `string`: uint32 length prefix followed by that many bytes
/// - `mpint`: same as string, but encodes an arbitrary-precision two's-complement integer
struct SSHWireReader {
    let buffer: Data
    private(set) var offset: Int = 0

    init(_ buffer: Data) {
        self.buffer = buffer
    }

    var remaining: Int { buffer.count - offset }

    mutating func readByte() throws -> UInt8 {
        guard offset < buffer.count else { throw SSHWireError.truncated }
        defer { offset += 1 }
        return buffer[buffer.startIndex + offset]
    }

    mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else { throw SSHWireError.truncated }
        let start = buffer.startIndex + offset
        let value = (UInt32(buffer[start]) << 24)
            | (UInt32(buffer[start + 1]) << 16)
            | (UInt32(buffer[start + 2]) << 8)
            | UInt32(buffer[start + 3])
        offset += 4
        return value
    }

    mutating func readString() throws -> Data {
        let length = Int(try readUInt32())
        guard remaining >= length else { throw SSHWireError.truncated }
        let start = buffer.startIndex + offset
        let slice = buffer[start ..< (start + length)]
        offset += length
        return Data(slice)
    }

    /// Reads a string and decodes it as UTF-8.
    mutating func readASCIIString() throws -> String {
        let bytes = try readString()
        guard let s = String(data: bytes, encoding: .utf8) else {
            throw SSHWireError.malformed("non-utf8 string")
        }
        return s
    }

    /// Read an `mpint` and return the magnitude bytes (no leading zero pad byte).
    mutating func readMPInt() throws -> Data {
        var bytes = try readString()
        // SSH mpints positive numbers may have a leading 0x00 to disambiguate from
        // negative two's-complement; strip it for downstream consumers.
        if let first = bytes.first, first == 0x00, bytes.count > 1 {
            bytes.removeFirst()
        }
        return bytes
    }
}

/// Writer for SSH wire format primitives, producing a `Data` buffer.
struct SSHWireWriter {
    private(set) var buffer = Data()

    mutating func writeByte(_ b: UInt8) {
        buffer.append(b)
    }

    mutating func writeUInt32(_ v: UInt32) {
        buffer.append(UInt8(truncatingIfNeeded: v >> 24))
        buffer.append(UInt8(truncatingIfNeeded: v >> 16))
        buffer.append(UInt8(truncatingIfNeeded: v >> 8))
        buffer.append(UInt8(truncatingIfNeeded: v))
    }

    mutating func writeString(_ bytes: Data) {
        writeUInt32(UInt32(bytes.count))
        buffer.append(bytes)
    }

    mutating func writeString(_ s: String) {
        writeString(Data(s.utf8))
    }

    /// Write `bytes` as an `mpint`. Pads with a leading 0x00 if the high bit is set.
    mutating func writeMPInt(_ bytes: Data) {
        // Strip leading zero bytes (canonical form), but keep at least one byte for 0.
        var trimmed = bytes
        while trimmed.count > 1 && trimmed.first == 0x00 {
            trimmed.removeFirst()
        }
        if let first = trimmed.first, first & 0x80 != 0 {
            writeUInt32(UInt32(trimmed.count + 1))
            buffer.append(0x00)
            buffer.append(trimmed)
        } else {
            writeUInt32(UInt32(trimmed.count))
            buffer.append(trimmed)
        }
    }
}

enum SSHWireError: Error, Equatable {
    case truncated
    case malformed(String)
}
