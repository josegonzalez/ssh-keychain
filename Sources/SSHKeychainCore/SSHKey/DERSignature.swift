import Foundation

/// Parses the ASN.1 DER encoding of an ECDSA signature, as produced by
/// `SecKeyCreateSignature` with `kSecKeyAlgorithmECDSASignatureMessage*`.
///
/// Format:
///
///     SEQUENCE {
///         INTEGER r
///         INTEGER s
///     }
public enum DERSignature {
    public static func parseECDSA(_ der: Data) throws -> (r: Data, s: Data) {
        var reader = ByteReader(der)
        let tag = try reader.readByte()
        guard tag == 0x30 else { throw DERError.notASequence }
        let seqLength = try reader.readLength()
        guard reader.remaining >= seqLength else { throw DERError.truncated }

        let r = try readInteger(&reader)
        let s = try readInteger(&reader)
        return (r, s)
    }

    private static func readInteger(_ reader: inout ByteReader) throws -> Data {
        let tag = try reader.readByte()
        guard tag == 0x02 else { throw DERError.notAnInteger }
        let length = try reader.readLength()
        guard reader.remaining >= length else { throw DERError.truncated }
        let bytes = try reader.readBytes(length)
        return bytes
    }

    private struct ByteReader {
        let data: Data
        var offset: Int = 0

        init(_ data: Data) { self.data = data }

        var remaining: Int { data.count - offset }

        mutating func readByte() throws -> UInt8 {
            guard offset < data.count else { throw DERError.truncated }
            defer { offset += 1 }
            return data[data.startIndex + offset]
        }

        mutating func readBytes(_ count: Int) throws -> Data {
            guard remaining >= count else { throw DERError.truncated }
            let start = data.startIndex + offset
            let slice = data[start ..< (start + count)]
            offset += count
            return Data(slice)
        }

        /// ASN.1 DER length: short form (one byte, 0..127) or long form
        /// (high bit set, followed by N length bytes).
        mutating func readLength() throws -> Int {
            let first = try readByte()
            if first & 0x80 == 0 {
                return Int(first)
            }
            let count = Int(first & 0x7f)
            guard count > 0, count <= 4 else { throw DERError.lengthOverflow }
            var value: Int = 0
            for _ in 0..<count {
                value = (value << 8) | Int(try readByte())
            }
            return value
        }
    }
}

public enum DERError: Error, Equatable {
    case truncated
    case notASequence
    case notAnInteger
    case lengthOverflow
}
