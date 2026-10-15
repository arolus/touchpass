import XCTest
@testable import TouchPassCore

final class VersionTests: XCTestCase {
    func testNumericComparison() {
        XCTAssertTrue(isNewerVersion("1.1.10", than: "1.1.9"))
        XCTAssertTrue(isNewerVersion("1.2", than: "1.1.99"))
        XCTAssertTrue(isNewerVersion("2.0.0", than: "1.9.9"))
        XCTAssertFalse(isNewerVersion("1.1.1", than: "1.1.1"))
        XCTAssertFalse(isNewerVersion("1.1", than: "1.1.0"))
        XCTAssertFalse(isNewerVersion("1.0.16", than: "1.1.1"))
    }

    func testVersionFromReleaseRedirect() {
        XCTAssertEqual(versionFromReleaseLocation("https://github.com/arolus/touchpass/releases/tag/v1.2.3"), "1.2.3")
        XCTAssertNil(versionFromReleaseLocation("https://github.com/arolus/touchpass/releases"))
        XCTAssertNil(versionFromReleaseLocation("https://github.com/arolus/touchpass/releases/tag/vnext"))
        XCTAssertNil(versionFromReleaseLocation("https://github.com/arolus/touchpass/releases/tag/v1..2"))
    }
}
