// The Encrypted DNS switch on top of NEDNSSettingsManager. The pure mapping
// (state ↔ rules, menu titles) is TouchPassCore/EncryptedDNS.swift.

import AppKit
import NetworkExtension
import TouchPassCore

enum EncryptedDNS {
    /// Where the person enables a DNS configuration: System Settings → Network → Filters
    /// (macOS 26; "VPN & Filters" on macOS 15). The NetworkExtensionSettingsUI pane opens
    /// the VPN list instead, where DNS configurations are not shown, so open Network itself.
    static let settingsURL = URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension")!

    private static var manager: NEDNSSettingsManager { .shared() }

    /// The saved state. Calls back on the main thread.
    static func load(_ done: @escaping (EncryptedDNSState) -> Void) {
        manager.loadFromPreferences { error in
            DispatchQueue.main.async {
                if let error = error {
                    log("Encrypted DNS: load failed: \(error.localizedDescription)")
                    done(.unknown)
                    return
                }
                done(state(of: manager))
            }
        }
    }

    private static func state(of m: NEDNSSettingsManager) -> EncryptedDNSState {
        let rules = (m.onDemandRules ?? []).map(action(of:))
        return EncryptedDNSState(installed: m.dnsSettings != nil, systemEnabled: m.isEnabled,
                                 rulesOn: encryptedDNSIsOn(rules: rules, onDemandEnabled: true))
    }

    private static func action(of rule: NEOnDemandRule) -> OnDemandAction {
        switch rule.action {
        case .connect: return .connect
        case .disconnect: return .disconnect
        case .evaluateConnection: return .evaluateConnection
        default: return .ignore
        }
    }

    private static func rule(on: Bool) -> NEOnDemandRule {
        let r: NEOnDemandRule = onDemandAction(on: on) == .connect ? NEOnDemandRuleConnect() : NEOnDemandRuleDisconnect()
        r.interfaceTypeMatch = .any
        return r
    }

    /// Saves the configuration with the rule for `on`. The first save adds the
    /// configuration (the person then enables it in System Settings); later saves
    /// only swap the rule. Calls back on the main thread with the new state.
    static func set(on: Bool, _ done: @escaping (Result<EncryptedDNSState, Error>) -> Void) {
        manager.loadFromPreferences { error in
            if let error = error { DispatchQueue.main.async { done(.failure(error)) }; return }
            let m = manager
            let settings = NEDNSOverHTTPSSettings(servers: EncryptedDNSConfig.servers)
            settings.serverURL = URL(string: EncryptedDNSConfig.serverURL)
            m.dnsSettings = settings
            m.localizedDescription = EncryptedDNSConfig.name
            m.onDemandRules = [rule(on: on)]
            m.saveToPreferences { error in
                DispatchQueue.main.async {
                    if let error = error {
                        log("Encrypted DNS: save failed: \(error.localizedDescription)")
                        done(.failure(error))
                    } else {
                        log("Encrypted DNS: saved \(on ? "on" : "off").")
                        done(.success(state(of: m)))
                    }
                }
            }
        }
    }

    /// Deletes the configuration altogether.
    static func remove(_ done: @escaping (Error?) -> Void) {
        manager.loadFromPreferences { _ in
            manager.removeFromPreferences { error in DispatchQueue.main.async { done(error) } }
        }
    }

    static func openSettings() { NSWorkspace.shared.open(settingsURL) }
}

/// `touchpass --dns status|on|off|remove` — the switch from a terminal (and for tests).
func runDNSCommand(_ command: String) -> Int32 {
    var code: Int32 = 0
    var finished = false
    func finish(_ message: String, _ c: Int32 = 0) { print(message); code = c; finished = true }
    switch command {
    case "status":
        EncryptedDNS.load { finish($0.menuTitle + " [\($0)]", $0 == .unknown ? 1 : 0) }
    case "on", "off":
        EncryptedDNS.set(on: command == "on") { result in
            switch result {
            case .success(let s): finish(s.menuTitle + " [\(s)]")
            case .failure(let e): finish("Encrypted DNS: \(e.localizedDescription)", 1)
            }
        }
    case "remove":
        EncryptedDNS.remove { e in finish(e.map { "Encrypted DNS: \($0.localizedDescription)" } ?? "Encrypted DNS: removed", e == nil ? 0 : 1) }
    default:
        finish("usage: touchpass --dns status|on|off|remove", 2)
    }
    while !finished { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
    return code
}
