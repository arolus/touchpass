import Foundation
import XCTest

final class SafariExtensionTests: XCTestCase {
    /// Safari shows an extension's context menu items only where the extension has
    /// access to the page: with "contextMenus" alone it creates them without any
    /// error and never displays them. "activeTab" is the lightest grant that works.
    func testManifestGrantsWhatTheContextMenuNeeds() throws {
        let manifestURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("SafariExtension/Resources/manifest.json")
        let manifest = try JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as? [String: Any]
        let permissions = manifest?["permissions"] as? [String] ?? []
        XCTAssertTrue(permissions.contains("contextMenus"))
        XCTAssertTrue(permissions.contains("activeTab"))
    }
}
