// Encrypted DNS (DNS over HTTPS to Google) as an on/off switch — the pure part:
// the server settings and how the on/off state maps onto on-demand rules.
//
// Why: the ISP drops plain DNS queries for some names (Instagram's CDN hosts),
// whatever resolver they go to. DoH hides them. The URL is an IP because the
// name dns.google is blocked too (by DNS and by TLS SNI). Google rather than
// Cloudflare because Google passes the client subnet (ECS), so CDNs answer with
// nearby nodes.
//
// The configuration is saved once with NEDNSSettingsManager and enabled once by
// the person in System Settings; after that the switch only rewrites its
// on-demand rule (connect = on, disconnect = off), which needs no new approval.

import Foundation

public enum EncryptedDNSConfig {
    public static let serverURL = "https://8.8.8.8/dns-query"
    public static let servers = ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"]
    public static let name = "TouchPass Encrypted DNS (Google)"
}

/// The action of an on-demand rule, without NetworkExtension types.
public enum OnDemandAction: Equatable, Sendable {
    case connect, disconnect, evaluateConnection, ignore
}

/// The single rule the switch writes.
public func onDemandAction(on: Bool) -> OnDemandAction { on ? .connect : .disconnect }

/// Whether the saved rules apply the settings. No rules (or on-demand off) means
/// the settings always apply while the configuration is enabled; otherwise the
/// first rule decides, as it matches every interface.
public func encryptedDNSIsOn(rules: [OnDemandAction], onDemandEnabled: Bool) -> Bool {
    guard onDemandEnabled, let first = rules.first else { return true }
    return first == .connect || first == .evaluateConnection
}

/// What the menu shows.
public enum EncryptedDNSState: Equatable, Sendable {
    case unknown                    // not loaded yet, or the load failed
    case notSetUp                   // no configuration saved yet
    case needsApproval(on: Bool)    // saved, but not enabled in System Settings
    case on, off

    public init(installed: Bool, systemEnabled: Bool, rulesOn: Bool) {
        if !installed { self = .notSetUp }
        else if !systemEnabled { self = .needsApproval(on: rulesOn) }
        else { self = rulesOn ? .on : .off }
    }

    public var menuTitle: String {
        switch self {
        case .unknown: return "Encrypted DNS"
        case .notSetUp: return "Encrypted DNS: Off"
        case .needsApproval: return "Encrypted DNS: Off (enable in System Settings…)"
        case .on: return "Encrypted DNS: On"
        case .off: return "Encrypted DNS: Off"
        }
    }

    /// The checkmark: only a configuration that actually applies counts as on.
    public var isActive: Bool { self == .on }

    /// What a click asks for: a configuration that does not apply gets turned on.
    public var targetOnClick: Bool { self != .on }
}
