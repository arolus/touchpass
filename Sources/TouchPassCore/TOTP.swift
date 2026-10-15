// TOTP (RFC 6238) codes, base32 keys and otpauth:// URIs — the pure part of
// TouchPass's 2FA codes, kept apart from AppKit so it can be unit-tested.

import CryptoKit
import Foundation

public enum OTPAlgorithm: String, Codable, CaseIterable, Sendable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"

    public init?(uriValue: String) {
        let v = uriValue.uppercased().replacingOccurrences(of: "-", with: "")
        guard let a = OTPAlgorithm(rawValue: v) else { return nil }
        self = a
    }
}

public enum OTPError: Error, Equatable, CustomStringConvertible {
    case invalidBase32
    case emptySecret
    case notOTPAuthURI
    case notTOTP(String)
    case missingSecret
    case unsupported(String)

    public var description: String {
        switch self {
        case .invalidBase32: return "The key is not valid base32 (letters A–Z and digits 2–7)."
        case .emptySecret: return "The key is empty."
        case .notOTPAuthURI: return "Not an otpauth:// link."
        case .notTOTP(let kind): return "Only time-based codes (totp) are supported, not \(kind)."
        case .missingSecret: return "The link has no secret."
        case .unsupported(let what): return "Unsupported parameter: \(what)."
        }
    }
}

public enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    private static let values: [Character: UInt8] = {
        var m: [Character: UInt8] = [:]
        for (i, c) in alphabet.enumerated() { m[c] = UInt8(i) }
        return m
    }()

    /// Upper-cases and strips what sites add for readability: spaces, dashes, padding.
    public static func normalize(_ s: String) -> String {
        String(s.uppercased().filter { !" \t\n\r-=".contains($0) })
    }

    public static func decode(_ s: String) throws -> Data {
        let clean = normalize(s)
        guard !clean.isEmpty else { throw OTPError.emptySecret }
        var out = Data()
        var buffer: UInt32 = 0
        var bits = 0
        for c in clean {
            guard let v = values[c] else { throw OTPError.invalidBase32 }
            buffer = (buffer << 5) | UInt32(v)
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((buffer >> UInt32(bits)) & 0xff))
            }
        }
        return out
    }

    public static func encode(_ data: Data) -> String {
        var out = ""
        var buffer: UInt32 = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[Int((buffer >> UInt32(bits)) & 0x1f)])
            }
        }
        if bits > 0 { out.append(alphabet[Int((buffer << UInt32(5 - bits)) & 0x1f)]) }
        return out
    }
}

/// One 2FA account as stored in the Keychain (as JSON, in the item's data).
public struct OTPAccount: Codable, Equatable, Sendable {
    public var secret: String          // normalized base32
    public var algorithm: OTPAlgorithm
    public var digits: Int
    public var period: Int
    public var issuer: String?
    public var backupCodes: String?

    public init(secret: String, algorithm: OTPAlgorithm = .sha1, digits: Int = 6, period: Int = 30,
                issuer: String? = nil, backupCodes: String? = nil) throws {
        let clean = Base32.normalize(secret)
        let key = try Base32.decode(clean)
        guard !key.isEmpty else { throw OTPError.emptySecret }
        guard (6...8).contains(digits) else { throw OTPError.unsupported("digits=\(digits)") }
        guard (1...300).contains(period) else { throw OTPError.unsupported("period=\(period)") }
        self.secret = clean
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.issuer = issuer
        self.backupCodes = backupCodes
    }

    /// The code valid at `date` and the seconds it has left.
    public func code(at date: Date = Date()) -> (code: String, secondsLeft: Int) {
        let t = date.timeIntervalSince1970
        // A secret is validated in init, so decoding cannot fail here.
        let key = (try? Base32.decode(secret)) ?? Data()
        let code = TOTP.code(key: key, counter: UInt64(max(0, t) / Double(period)),
                             algorithm: algorithm, digits: digits)
        let left = period - Int(max(0, t).truncatingRemainder(dividingBy: Double(period)))
        return (code, left)
    }
}

public enum TOTP {
    /// HOTP (RFC 4226) over the TOTP counter: HMAC, dynamic truncation, modulo 10^digits.
    public static func code(key: Data, counter: UInt64, algorithm: OTPAlgorithm, digits: Int) -> String {
        var big = counter.bigEndian
        let message = Data(bytes: &big, count: 8)
        let mac: [UInt8]
        let symmetric = SymmetricKey(data: key)
        switch algorithm {
        case .sha1: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetric))
        case .sha256: mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: symmetric))
        case .sha512: mac = Array(HMAC<SHA512>.authenticationCode(for: message, using: symmetric))
        }
        let o = Int(mac[mac.count - 1] & 0x0f)
        let bin = (UInt32(mac[o] & 0x7f) << 24) | (UInt32(mac[o + 1]) << 16)
            | (UInt32(mac[o + 2]) << 8) | UInt32(mac[o + 3])
        var mod: UInt32 = 1
        for _ in 0..<digits { mod *= 10 }
        let s = String(bin % mod)
        return String(repeating: "0", count: max(0, digits - s.count)) + s
    }

    public static func code(key: Data, time: TimeInterval, period: Int = 30,
                            algorithm: OTPAlgorithm = .sha1, digits: Int = 6) -> String {
        code(key: key, counter: UInt64(time / Double(period)), algorithm: algorithm, digits: digits)
    }
}

/// What an otpauth://totp/ link (the content of a 2FA setup QR code) carries.
public struct OTPAuthURI: Equatable, Sendable {
    public var account: OTPAccount
    public var issuer: String?
    public var accountName: String?

    /// A name for the TouchPass menu: "Issuer: account", or whichever part exists.
    public var suggestedName: String {
        switch (issuer, accountName) {
        case let (i?, a?) where !i.isEmpty && !a.isEmpty: return "\(i): \(a)"
        case let (i?, _) where !i.isEmpty: return i
        case let (_, a?) where !a.isEmpty: return a
        default: return "Account"
        }
    }

    public static func looksLikeURI(_ s: String) -> Bool {
        s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("otpauth://")
    }

    public init(_ text: String) throws {
        let raw = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard OTPAuthURI.looksLikeURI(raw), let comps = URLComponents(string: raw) else {
            throw OTPError.notOTPAuthURI
        }
        let kind = (comps.host ?? "").lowercased()
        guard kind == "totp" else { throw OTPError.notTOTP(kind.isEmpty ? "?" : kind) }

        var query: [String: String] = [:]
        for item in comps.queryItems ?? [] { query[item.name.lowercased()] = item.value ?? "" }
        guard let secret = query["secret"], !secret.isEmpty else { throw OTPError.missingSecret }

        var algorithm = OTPAlgorithm.sha1
        if let a = query["algorithm"], !a.isEmpty {
            guard let parsed = OTPAlgorithm(uriValue: a) else { throw OTPError.unsupported("algorithm=\(a)") }
            algorithm = parsed
        }
        func int(_ key: String, _ fallback: Int) throws -> Int {
            guard let v = query[key], !v.isEmpty else { return fallback }
            guard let n = Int(v) else { throw OTPError.unsupported("\(key)=\(v)") }
            return n
        }
        let digits = try int("digits", 6)
        let period = try int("period", 30)

        // The label is "Issuer:account" or just "account" (path, percent-decoded).
        var label = comps.path
        if label.hasPrefix("/") { label.removeFirst() }
        var labelIssuer: String?
        var accountName: String? = label.isEmpty ? nil : label
        if let colon = label.firstIndex(of: ":") {
            labelIssuer = String(label[..<colon]).trimmingCharacters(in: .whitespaces)
            accountName = String(label[label.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        }
        let issuer = (query["issuer"].flatMap { $0.isEmpty ? nil : $0 }) ?? labelIssuer

        self.issuer = issuer
        self.accountName = accountName
        self.account = try OTPAccount(secret: secret, algorithm: algorithm, digits: digits,
                                      period: period, issuer: issuer)
    }
}

/// Parses what a person pastes into "Add manually": a bare base32 key or a full otpauth:// link.
public func parseSecretInput(_ text: String) throws -> (account: OTPAccount, suggestedName: String?) {
    if OTPAuthURI.looksLikeURI(text) {
        let uri = try OTPAuthURI(text)
        return (uri.account, uri.suggestedName)
    }
    return (try OTPAccount(secret: text), nil)
}

/// Groups a code for display: "123 456", "1234 5678".
public func formatCode(_ code: String) -> String {
    guard code.count >= 6 else { return code }
    let mid = code.index(code.startIndex, offsetBy: code.count / 2)
    return "\(code[..<mid]) \(code[mid...])"
}

// MARK: - Folders

/// A 2FA account as the menu lists it: its name and the folder it sits in (nil = top level).
public struct OTPEntry: Equatable, Sendable {
    public var name: String
    public var folder: String?

    public init(name: String, folder: String?) {
        self.name = name
        let f = folder?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.folder = (f?.isEmpty ?? true) ? nil : f
    }
}

/// The menu layout: loose accounts first, then folders, both sorted case-insensitively.
public func groupByFolder(_ entries: [OTPEntry]) -> (loose: [String], folders: [(name: String, accounts: [String])]) {
    func sorted(_ xs: [String]) -> [String] {
        xs.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }
    var byFolder: [String: [String]] = [:]
    var loose: [String] = []
    for e in entries {
        if let f = e.folder { byFolder[f, default: []].append(e.name) } else { loose.append(e.name) }
    }
    return (sorted(loose), sorted(Array(byFolder.keys)).map { ($0, sorted(byFolder[$0]!)) })
}

/// Inside folder "WordPress.org", "WordPress.org: alice" reads as just "alice".
public func displayName(_ name: String, inFolder folder: String?) -> String {
    guard let folder = folder, !folder.isEmpty else { return name }
    for sep in [": ", ":", " - ", " — ", " / ", "/"] {
        let prefix = folder + sep
        guard name.range(of: prefix, options: [.anchored, .caseInsensitive]) != nil else { continue }
        let rest = name.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces)
        if !rest.isEmpty { return rest }
    }
    return name
}
