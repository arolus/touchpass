import XCTest
@testable import TouchPassCore

final class TOTPVectorTests: XCTestCase {
    // RFC 6238 appendix B: the seeds are ASCII digits repeated to the hash's block size.
    private let sha1Key = Data("12345678901234567890".utf8)
    private let sha256Key = Data("12345678901234567890123456789012".utf8)
    private let sha512Key = Data((String(repeating: "1234567890", count: 6) + "1234").utf8)

    private let vectors: [(time: TimeInterval, sha1: String, sha256: String, sha512: String)] = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ]

    func testRFC6238SHA1() {
        for v in vectors {
            XCTAssertEqual(TOTP.code(key: sha1Key, time: v.time, algorithm: .sha1, digits: 8), v.sha1, "T=\(v.time)")
        }
    }

    func testRFC6238SHA256() {
        for v in vectors {
            XCTAssertEqual(TOTP.code(key: sha256Key, time: v.time, algorithm: .sha256, digits: 8), v.sha256, "T=\(v.time)")
        }
    }

    func testRFC6238SHA512() {
        for v in vectors {
            XCTAssertEqual(TOTP.code(key: sha512Key, time: v.time, algorithm: .sha512, digits: 8), v.sha512, "T=\(v.time)")
        }
    }

    func testAccountUsesBase32KeyAndSixDigits() throws {
        // The SHA-1 seed in base32; 6 digits are the last six of the 8-digit RFC value.
        let account = try OTPAccount(secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        let (code, left) = account.code(at: Date(timeIntervalSince1970: 59))
        XCTAssertEqual(code, "287082")
        XCTAssertEqual(left, 1)
        XCTAssertEqual(account.code(at: Date(timeIntervalSince1970: 60)).secondsLeft, 30)
    }
}

final class Base32Tests: XCTestCase {
    func testRoundTrip() throws {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let data = Data(s.utf8)
            XCTAssertEqual(try? Base32.decode(Base32.encode(data)), s.isEmpty ? nil : data, s)
        }
        XCTAssertEqual(Base32.encode(Data("foobar".utf8)), "MZXW6YTBOI")
    }

    func testTolerantOfHowSitesPrintKeys() throws {
        let expected = try Base32.decode("JBSWY3DPEHPK3PXP")
        XCTAssertEqual(try Base32.decode("jbsw y3dp ehpk 3pxp"), expected)
        XCTAssertEqual(try Base32.decode("JBSW-Y3DP-EHPK-3PXP"), expected)
        XCTAssertEqual(try Base32.decode("MZXW6YTBOI======"), Data("foobar".utf8))
    }

    func testRejectsGarbage() {
        XCTAssertThrowsError(try Base32.decode("JBSWY3DP1")) { XCTAssertEqual($0 as? OTPError, .invalidBase32) }
        XCTAssertThrowsError(try Base32.decode("  ")) { XCTAssertEqual($0 as? OTPError, .emptySecret) }
        XCTAssertThrowsError(try OTPAccount(secret: "not a key!"))
    }
}

final class OTPAuthURITests: XCTestCase {
    func testTypicalWordPressStyleURI() throws {
        let uri = try OTPAuthURI("otpauth://totp/WordPress.org:alice?secret=JBSWY3DPEHPK3PXP&issuer=WordPress.org")
        XCTAssertEqual(uri.issuer, "WordPress.org")
        XCTAssertEqual(uri.accountName, "alice")
        XCTAssertEqual(uri.suggestedName, "WordPress.org: alice")
        XCTAssertEqual(uri.account.secret, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(uri.account.algorithm, .sha1)
        XCTAssertEqual(uri.account.digits, 6)
        XCTAssertEqual(uri.account.period, 30)
    }

    func testParametersAndPercentEncoding() throws {
        let uri = try OTPAuthURI("otpauth://totp/ACME%20Co:john%40example.com?secret=jbswy3dpehpk3pxp"
                                 + "&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60")
        XCTAssertEqual(uri.suggestedName, "ACME Co: john@example.com")
        XCTAssertEqual(uri.account.algorithm, .sha256)
        XCTAssertEqual(uri.account.digits, 8)
        XCTAssertEqual(uri.account.period, 60)
        XCTAssertEqual(uri.account.secret, "JBSWY3DPEHPK3PXP")
    }

    func testIssuerFromLabelOnlyOrNoIssuer() throws {
        XCTAssertEqual(try OTPAuthURI("otpauth://totp/GitHub:bob?secret=JBSWY3DPEHPK3PXP").suggestedName, "GitHub: bob")
        XCTAssertEqual(try OTPAuthURI("otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP").suggestedName, "bob")
        XCTAssertEqual(try OTPAuthURI("otpauth://totp/?secret=JBSWY3DPEHPK3PXP&issuer=X").suggestedName, "X")
    }

    func testRejectsWhatItCannotGenerate() {
        XCTAssertThrowsError(try OTPAuthURI("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1")) {
            XCTAssertEqual($0 as? OTPError, .notTOTP("hotp"))
        }
        XCTAssertThrowsError(try OTPAuthURI("otpauth://totp/x?issuer=X")) { XCTAssertEqual($0 as? OTPError, .missingSecret) }
        XCTAssertThrowsError(try OTPAuthURI("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"))
        XCTAssertThrowsError(try OTPAuthURI("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4"))
        XCTAssertThrowsError(try OTPAuthURI("https://example.com")) { XCTAssertEqual($0 as? OTPError, .notOTPAuthURI) }
    }

    func testManualInputAcceptsKeyOrURI() throws {
        let bare = try parseSecretInput(" jbsw y3dp ehpk 3pxp ")
        XCTAssertEqual(bare.account.secret, "JBSWY3DPEHPK3PXP")
        XCTAssertNil(bare.suggestedName)
        let uri = try parseSecretInput("otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(uri.suggestedName, "X: y")
    }

    func testAccountJSONRoundTrip() throws {
        let a = try OTPAccount(secret: "JBSWY3DPEHPK3PXP", algorithm: .sha512, digits: 8, period: 60,
                               issuer: "X", backupCodes: "1111 2222")
        let b = try JSONDecoder().decode(OTPAccount.self, from: JSONEncoder().encode(a))
        XCTAssertEqual(a, b)
    }

    func testFormatCode() {
        XCTAssertEqual(formatCode("123456"), "123 456")
        XCTAssertEqual(formatCode("12345678"), "1234 5678")
    }
}

final class FolderTests: XCTestCase {
    func testGroupsLooseFirstThenFoldersSorted() {
        let g = groupByFolder([
            OTPEntry(name: "WordPress.org: zed", folder: "WordPress.org"),
            OTPEntry(name: "GitHub: me", folder: nil),
            OTPEntry(name: "WordPress.org: alice", folder: "WordPress.org"),
            OTPEntry(name: "aws", folder: "  "),
            OTPEntry(name: "Stripe", folder: "Billing"),
        ])
        XCTAssertEqual(g.loose, ["aws", "GitHub: me"])
        XCTAssertEqual(g.folders.map(\.name), ["Billing", "WordPress.org"])
        XCTAssertEqual(g.folders[1].accounts, ["WordPress.org: alice", "WordPress.org: zed"])
    }

    func testBlankFolderMeansTopLevel() {
        XCTAssertNil(OTPEntry(name: "x", folder: " ").folder)
        XCTAssertEqual(OTPEntry(name: "x", folder: " Work ").folder, "Work")
    }

    func testDisplayNameDropsTheFolderPrefix() {
        XCTAssertEqual(displayName("WordPress.org: alice", inFolder: "WordPress.org"), "alice")
        XCTAssertEqual(displayName("wordpress.org:bob", inFolder: "WordPress.org"), "bob")
        XCTAssertEqual(displayName("GitHub: me", inFolder: "WordPress.org"), "GitHub: me")
        XCTAssertEqual(displayName("WordPress.org: ", inFolder: "WordPress.org"), "WordPress.org: ")
        XCTAssertEqual(displayName("alice", inFolder: nil), "alice")
    }
}
