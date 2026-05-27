import XCTest
@testable import SSHKeychainCore

final class SourceSpecTests: XCTestCase {
    func testSingleKey() throws {
        let spec = try SourceSpec.parse("file:my-key")
        XCTAssertEqual(spec.backend, "file")
        XCTAssertEqual(spec.keys, .explicit(["my-key"]))
        XCTAssertEqual(spec.singleKey, "my-key")
    }

    func testMultipleKeys() throws {
        let spec = try SourceSpec.parse("keychain:gh,prod,staging")
        XCTAssertEqual(spec.backend, "keychain")
        XCTAssertEqual(spec.keys, .explicit(["gh", "prod", "staging"]))
        XCTAssertNil(spec.singleKey)
    }

    func testWildcard() throws {
        let spec = try SourceSpec.parse("keychain:*")
        XCTAssertEqual(spec.backend, "keychain")
        XCTAssertEqual(spec.keys, .wildcard)
        XCTAssertNil(spec.singleKey)
    }

    func testMissingColon() {
        XCTAssertThrowsError(try SourceSpec.parse("file")) { error in
            XCTAssertEqual(error as? SourceSpecError, .missingColon("file"))
        }
    }

    func testEmptyBackend() {
        XCTAssertThrowsError(try SourceSpec.parse(":key")) { error in
            XCTAssertEqual(error as? SourceSpecError, .emptyBackend(":key"))
        }
    }

    func testEmptyKeys() {
        XCTAssertThrowsError(try SourceSpec.parse("file:")) { error in
            XCTAssertEqual(error as? SourceSpecError, .emptyKeys("file:"))
        }
    }

    func testEmptyKeyInList() {
        XCTAssertThrowsError(try SourceSpec.parse("file:a,,b")) { error in
            XCTAssertEqual(error as? SourceSpecError, .emptyKey("file:a,,b"))
        }
    }
}
