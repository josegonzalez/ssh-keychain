import Foundation
import XCTest
@testable import SSHKeychainCore

final class DERSignatureTests: XCTestCase {
    func testParseSimpleSignature() throws {
        // SEQUENCE { INTEGER 0x01..0x20 r, INTEGER 0x21..0x40 s }
        let r = Data((0x01...0x20).map { UInt8($0) })
        let s = Data((0x21...0x40).map { UInt8($0) })
        let der = encodeDER(r: r, s: s)
        let (parsedR, parsedS) = try DERSignature.parseECDSA(der)
        XCTAssertEqual(parsedR, r)
        XCTAssertEqual(parsedS, s)
    }

    func testParseWithLeadingZeroByte() throws {
        // r with a leading 0x00 (DER's way to disambiguate positive vs negative)
        var r = Data([0x00])
        r.append(Data((0x80...0x9f).map { UInt8($0) }))
        let s = Data((0x21...0x40).map { UInt8($0) })
        let der = encodeDER(r: r, s: s)
        let (parsedR, parsedS) = try DERSignature.parseECDSA(der)
        XCTAssertEqual(parsedR, r)
        XCTAssertEqual(parsedS, s)
    }

    func testParseLongFormLength() throws {
        // r large enough to trigger long-form length encoding.
        let r = Data(repeating: 0x42, count: 200)
        let s = Data(repeating: 0x43, count: 32)
        let der = encodeDER(r: r, s: s)
        let (parsedR, parsedS) = try DERSignature.parseECDSA(der)
        XCTAssertEqual(parsedR, r)
        XCTAssertEqual(parsedS, s)
    }

    func testRejectsNonSequence() {
        let bogus = Data([0x02, 0x01, 0x00])
        XCTAssertThrowsError(try DERSignature.parseECDSA(bogus)) { error in
            XCTAssertEqual(error as? DERError, .notASequence)
        }
    }

    // MARK: helpers

    private func encodeDER(r: Data, s: Data) -> Data {
        var inner = Data()
        inner.append(0x02); inner.append(encodeLength(r.count)); inner.append(r)
        inner.append(0x02); inner.append(encodeLength(s.count)); inner.append(s)
        var out = Data([0x30])
        out.append(encodeLength(inner.count))
        out.append(inner)
        return out
    }

    private func encodeLength(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var bytes: [UInt8] = []
        var x = n
        while x > 0 { bytes.insert(UInt8(x & 0xff), at: 0); x >>= 8 }
        return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
    }
}
