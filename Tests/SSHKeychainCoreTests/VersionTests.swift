import XCTest
@testable import SSHKeychainCore

final class VersionTests: XCTestCase {
    func testVersionIsNotEmpty() {
        XCTAssertFalse(SSHKeychain.version.isEmpty)
    }
}
