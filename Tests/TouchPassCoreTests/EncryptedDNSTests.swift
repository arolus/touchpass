import TouchPassCore
import XCTest

final class EncryptedDNSTests: XCTestCase {
    func testSwitchRoundTripsThroughTheRule() {
        for on in [true, false] {
            XCTAssertEqual(encryptedDNSIsOn(rules: [onDemandAction(on: on)], onDemandEnabled: true), on)
        }
    }

    func testWithoutRulesTheSettingsAlwaysApply() {
        XCTAssertTrue(encryptedDNSIsOn(rules: [], onDemandEnabled: true))
        XCTAssertTrue(encryptedDNSIsOn(rules: [.disconnect], onDemandEnabled: false))
    }

    func testStateFromTheSavedConfiguration() {
        XCTAssertEqual(EncryptedDNSState(installed: false, systemEnabled: false, rulesOn: true), .notSetUp)
        XCTAssertEqual(EncryptedDNSState(installed: true, systemEnabled: false, rulesOn: true), .needsApproval(on: true))
        XCTAssertEqual(EncryptedDNSState(installed: true, systemEnabled: true, rulesOn: true), .on)
        XCTAssertEqual(EncryptedDNSState(installed: true, systemEnabled: true, rulesOn: false), .off)
    }

    func testMenuShowsOnOnlyWhenTheSettingsApply() {
        XCTAssertEqual(EncryptedDNSState.on.menuTitle, "Encrypted DNS: On")
        XCTAssertEqual(EncryptedDNSState.off.menuTitle, "Encrypted DNS: Off")
        XCTAssertTrue(EncryptedDNSState.needsApproval(on: true).menuTitle.contains("System Settings"))
        XCTAssertTrue(EncryptedDNSState.on.isActive)
        XCTAssertFalse(EncryptedDNSState.needsApproval(on: true).isActive)
        XCTAssertFalse(EncryptedDNSState.on.targetOnClick)
        XCTAssertTrue(EncryptedDNSState.off.targetOnClick)
        XCTAssertTrue(EncryptedDNSState.notSetUp.targetOnClick)
    }

    func testServerIsAnIPAddress() {
        // dns.google is blocked by SNI: the URL must not carry a name.
        let host = URL(string: EncryptedDNSConfig.serverURL)?.host ?? ""
        XCTAssertTrue(EncryptedDNSConfig.servers.contains(host))
    }
}
