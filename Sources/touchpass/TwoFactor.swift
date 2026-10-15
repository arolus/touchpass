// 2FA codes: TOTP accounts kept in the Keychain, typed into the focused field
// after Touch ID — the same gate and the same keystroke path as the password.
//
// Adding an account: "Scan QR code…" reads the setup QR straight off the screen
// (ScreenCaptureKit + Vision, needs Screen Recording) or, without that
// permission, from a screenshot on the clipboard (Cmd-Ctrl-Shift-4); "Add
// manually…" takes the text key or the otpauth:// link. Right after saving, the
// current code is shown, copied and can be typed, to finish the site's setup.
//
// Storage: one Keychain item per account (service `otpKeychainService`,
// in iCloud Keychain when the app is team-signed — see OTPKeychain —
// account = the name shown in the menu, data = JSON OTPAccount incl. backup
// codes, folder = the item's comment attribute). Names and folders are item
// attributes, readable without unlocking any data, so the menu needs no file
// on disk and moving accounts between folders needs no Touch ID; nothing
// secret is logged. A folder exists while some account is in it.

import AppKit
import Foundation
import ScreenCaptureKit
import TouchPassCore
import Vision

let otpKeychainService = "com.arsidian.touchpass.otp"

/// A code with fewer seconds left than this is not typed: the site would likely
/// get it after it expired. TouchPass waits for the next one instead.
let otpMinSecondsLeft = 3

/// The clipboard copy of a code is wiped after this long, unless something else was copied since.
let otpClipboardLifetime: TimeInterval = 45

// MARK: - Keychain

/// The 2FA accounts, one generic-password item each; every read of the data
/// happens behind `Biometrics.authenticate()`.
///
/// Team-signed builds (Developer ID + profile, with a keychain access group)
/// keep them in the data-protection keychain as synchronizable items, so iCloud
/// Keychain carries them to the person's other Macs — and back after losing
/// one. Ad-hoc builds cannot (errSecMissingEntitlement) and fall back to the
/// login keychain of this Mac (WhenUnlockedThisDeviceOnly, like the password).
/// The password itself stays local in both cases.
enum OTPKeychain {
    /// Decided once: a probe of the data-protection keychain.
    static let syncsWithICloud: Bool = {
        guard CodeSigning.isTeamSigned else { return false }
        let probe: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: otpKeychainService,
                                      kSecUseDataProtectionKeychain: true,
                                      kSecAttrSynchronizable: kSecAttrSynchronizableAny]
        let status = SecItemCopyMatching(probe as CFDictionary, nil)
        if status != errSecSuccess && status != errSecItemNotFound {
            log("⚠️ 2FA: iCloud Keychain unavailable (\(keychainErrorName(status))) — keeping accounts on this Mac.")
            return false
        }
        return true
    }()

    /// `adding`: an item being created needs a concrete synchronizable flag;
    /// searches match both, so nothing written either way gets lost.
    private static func query(_ name: String? = nil, adding: Bool = false) -> [CFString: Any] {
        var q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: otpKeychainService]
        if syncsWithICloud {
            q[kSecUseDataProtectionKeychain] = true
            q[kSecAttrSynchronizable] = adding ? kCFBooleanTrue! : kSecAttrSynchronizableAny
        }
        if let name = name { q[kSecAttrAccount] = name }
        return q
    }

    /// Every account with its folder. Attributes only — no data is read.
    static func entries() -> [OTPEntry] {
        var q = query()
        q[kSecMatchLimit] = kSecMatchLimitAll
        q[kSecReturnAttributes] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            if status != errSecItemNotFound { log("⚠️ 2FA: listing accounts failed: \(keychainErrorName(status)).") }
            return []
        }
        return items.compactMap { item in
            (item[kSecAttrAccount as String] as? String).map {
                OTPEntry(name: $0, folder: item[kSecAttrComment as String] as? String)
            }
        }
    }

    /// Account names, sorted.
    static func names() -> [String] {
        entries().map(\.name).sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    /// Every folder (with accounts or created empty), sorted.
    static func folders() -> [String] { layout().folders.map(\.name) }

    static func layout() -> (loose: [String], folders: [(name: String, accounts: [String])]) {
        groupByFolder(entries(), emptyFolders: OTPFolders.created)
    }

    /// Moves an account into a folder (nil or blank = top level). Attributes only.
    @discardableResult
    static func setFolder(_ name: String, _ folder: String?) -> Bool {
        let clean = OTPEntry(name: name, folder: folder).folder ?? ""
        let status = SecItemUpdate(query(name) as CFDictionary, [kSecAttrComment: clean] as CFDictionary)
        if status != errSecSuccess { log("⚠️ 2FA: moving \"\(name)\" failed: \(keychainErrorName(status)).") }
        return status == errSecSuccess
    }

    static func exists(_ name: String) -> Bool {
        SecItemCopyMatching(query(name) as CFDictionary, nil) == errSecSuccess
    }

    /// Writes the account's data. An existing item is updated in place, so its
    /// folder stays; a new one is created at the top level.
    @discardableResult
    static func save(_ name: String, _ account: OTPAccount) -> Bool {
        guard let data = try? JSONEncoder().encode(account) else { return false }
        if exists(name) {
            let status = SecItemUpdate(query(name) as CFDictionary, [kSecValueData: data] as CFDictionary)
            if status != errSecSuccess { log("⚠️ 2FA: updating \"\(name)\" failed: \(keychainErrorName(status)).") }
            return status == errSecSuccess
        }
        var attrs = query(name, adding: true)
        attrs[kSecValueData] = data
        attrs[kSecAttrLabel] = "TouchPass 2FA: \(name)"
        // A synced item cannot be ThisDeviceOnly.
        attrs[kSecAttrAccessible] = syncsWithICloud
            ? kSecAttrAccessibleWhenUnlocked : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(attrs as CFDictionary, nil)
        if status != errSecSuccess { log("⚠️ 2FA: saving \"\(name)\" failed: \(keychainErrorName(status)).") }
        return status == errSecSuccess
    }

    /// Reads one account. Call ONLY after a successful Biometrics.authenticate().
    static func read(_ name: String) -> OTPAccount? {
        var q = query(name)
        q[kSecReturnData] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            log("⚠️ 2FA: Keychain did not return \"\(name)\": \(keychainErrorName(status)).")
            return nil
        }
        return try? JSONDecoder().decode(OTPAccount.self, from: data)
    }

    @discardableResult
    static func delete(_ name: String) -> Bool {
        let status = SecItemDelete(query(name) as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}

// MARK: - Empty folders

/// Folders made with "Add Folder" before anything is moved into them. A folder
/// that has accounts needs no record (it comes from the items' comment
/// attribute, which syncs with them); this list is only the menu's memory of
/// empty ones, in UserDefaults — folder names, nothing secret, this Mac only.
enum OTPFolders {
    private static let key = "otpFolders"

    static var created: [String] {
        get { UserDefaults.standard.stringArray(forKey: key) ?? [] }
        set { UserDefaults.standard.set(Array(Set(newValue)).sorted(), forKey: key) }
    }

    static func add(_ name: String) { created.append(name) }
    static func remove(_ name: String) { created.removeAll { $0 == name } }
    static func rename(_ old: String, to new: String) {
        if created.contains(old) { created = created.filter { $0 != old } + [new] }
    }
}

// MARK: - Clipboard

enum CodeClipboard {
    /// Marks the entry as a secret for clipboard managers (nspasteboard.org convention).
    private static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")

    /// Copies the code and wipes it later unless the clipboard changed meanwhile. Main thread.
    static func copy(_ code: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(code, forType: .string)
        pb.setString(code, forType: concealed)
        let stamp = pb.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + otpClipboardLifetime) {
            if NSPasteboard.general.changeCount == stamp { NSPasteboard.general.clearContents() }
        }
    }
}

// MARK: - QR codes

enum QRScanner {
    /// otpauth:// links found in QR codes in the image.
    static func otpauthLinks(in image: CGImage) -> [String] {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        do {
            try VNImageRequestHandler(cgImage: image, options: [:]).perform([request])
        } catch {
            log("⚠️ 2FA: QR detection failed: \(error.localizedDescription).")
            return []
        }
        let found = (request.results ?? []).compactMap { $0.payloadStringValue }
        var seen = Set<String>()
        return found.filter { OTPAuthURI.looksLikeURI($0) && seen.insert($0).inserted }
    }

    /// Captures every display (ScreenCaptureKit). Needs Screen Recording.
    static func captureScreens() async throws -> [CGImage] {
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        var images: [CGImage] = []
        for display in content.displays {
            let filter = SCContentFilter(display: display, excludingWindows: [])
            let config = SCStreamConfiguration()
            // Points → pixels: a small QR on a Retina screen needs the full resolution.
            let scale = NSScreen.screens.first { screenNumber($0) == display.displayID }?.backingScaleFactor ?? 2
            config.width = Int(CGFloat(display.width) * scale)
            config.height = Int(CGFloat(display.height) * scale)
            config.showsCursor = false
            images.append(try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: config))
        }
        return images
    }

    private static func screenNumber(_ screen: NSScreen) -> CGDirectDisplayID? {
        (screen.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value
    }

    /// An otpauth:// link on the clipboard: as text, or inside a screenshot image.
    static func clipboardLinks() -> [String] {
        let pb = NSPasteboard.general
        if let text = pb.string(forType: .string), OTPAuthURI.looksLikeURI(text) {
            return [text.trimmingCharacters(in: .whitespacesAndNewlines)]
        }
        guard let image = (pb.readObjects(forClasses: [NSImage.self]) as? [NSImage])?.first,
              let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else { return [] }
        return otpauthLinks(in: cg)
    }
}

// MARK: - Screen Recording permission

enum ScreenRecording {
    static var isAllowed: Bool { CGPreflightScreenCaptureAccess() }

    /// Same trick as Accessibility.resetAndRequest(): an ad-hoc signature changes
    /// with every build, so a stale TCC entry is dropped first to get a fresh prompt.
    static func resetAndRequest() {
        CodeSigning.resetTCCUnlessGranted("ScreenCapture", granted: isAllowed)
        CGRequestScreenCaptureAccess()
    }

    static func openSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture") {
            NSWorkspace.shared.open(url)
        }
    }
}

// MARK: - Controller

/// The "OTP" submenu and everything behind it. UI on the main thread;
/// Touch ID and typing on a background thread, as in Typer.
final class TwoFactorController: NSObject {
    private let lock = NSLock()
    private var busy = false

    private func begin() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if busy { return false }
        busy = true
        return true
    }
    private func end() { lock.lock(); busy = false; lock.unlock() }

    // MARK: Menu

    /// OTP → folder → account → Ввести код / Backup Codes / Move / Remove;
    /// a folder also has Rename and Remove; then the accounts outside folders,
    /// and adding: Scan QR Code, Add Manually, Add Folder.
    func buildMenu() -> NSMenu {
        let menu = NSMenu()
        let layout = OTPKeychain.layout()
        let folders = layout.folders.map(\.name)
        if layout.folders.isEmpty && layout.loose.isEmpty {
            menu.addItem(NSMenuItem(title: "No accounts yet", action: nil, keyEquivalent: ""))
        }
        for folder in layout.folders {
            let parent = NSMenuItem(title: folder.name, action: nil, keyEquivalent: "")
            parent.image = NSImage(systemSymbolName: "folder", accessibilityDescription: "Folder")
            let sub = NSMenu()
            if folder.accounts.isEmpty {
                sub.addItem(NSMenuItem(title: "Empty — Move accounts here", action: nil, keyEquivalent: ""))
            }
            for name in folder.accounts { sub.addItem(accountItem(name, folder: folder.name, folders: folders)) }
            sub.addItem(.separator())
            sub.addItem(action("Rename…", #selector(renameFolderClicked(_:)), folder.name))
            sub.addItem(action("Remove", #selector(removeFolderClicked(_:)), folder.name))
            parent.submenu = sub
            menu.addItem(parent)
        }
        for name in layout.loose { menu.addItem(accountItem(name, folder: nil, folders: folders)) }
        menu.addItem(.separator())
        menu.addItem(action("Scan QR Code…", #selector(scanClicked)))
        menu.addItem(action("Add Manually…", #selector(addClicked)))
        menu.addItem(action("Add Folder…", #selector(addFolderClicked)))
        return menu
    }

    /// An account: its own submenu with what can be done to it.
    private func accountItem(_ name: String, folder: String?, folders: [String]) -> NSMenuItem {
        let item = NSMenuItem(title: displayName(name, inFolder: folder), action: nil, keyEquivalent: "")
        item.toolTip = name
        let sub = NSMenu()
        // The code is not shown here: reading the key to draw it would skip the
        // Touch ID gate. Touch ID → it is typed (and copied).
        let type = action("Ввести код", #selector(typeClicked(_:)), name)
        type.image = NSImage(systemSymbolName: "touchid", accessibilityDescription: nil)
        sub.addItem(type)
        sub.addItem(action("Backup Codes…", #selector(backupClicked(_:)), name))

        let move = NSMenuItem(title: "Move", action: nil, keyEquivalent: "")
        let moveMenu = NSMenu()
        for f in folders {
            let target = action(f, #selector(moveClicked(_:)), MoveTarget(account: name, folder: f))
            target.state = f == folder ? .on : .off
            moveMenu.addItem(target)
        }
        if !folders.isEmpty { moveMenu.addItem(.separator()) }
        let top = action("No Folder", #selector(moveClicked(_:)), MoveTarget(account: name, folder: nil))
        top.state = folder == nil ? .on : .off
        moveMenu.addItem(top)
        moveMenu.addItem(action("New Folder…", #selector(moveToNewFolderClicked(_:)), name))
        move.submenu = moveMenu
        sub.addItem(move)

        sub.addItem(.separator())
        sub.addItem(action("Remove…", #selector(removeClicked(_:)), name))
        item.submenu = sub
        return item
    }

    private final class MoveTarget: NSObject {
        let account: String
        let folder: String?
        init(account: String, folder: String?) { self.account = account; self.folder = folder }
    }

    private func action(_ title: String, _ selector: Selector, _ object: Any? = nil) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: "")
        item.target = self
        item.representedObject = object
        return item
    }

    @objc private func typeClicked(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        typeCode(name)
    }

    @objc private func scanClicked() {
        // Let the menu fade out first, so it does not cover the QR in the capture.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { self.scan() }
    }

    @objc private func addClicked() { addManually() }

    @objc private func addFolderClicked() {
        guard let name = askFolderName("Add a folder", "Accounts go into it with Move (in each account's menu).",
                                       value: "", button: "Add") else { return }
        OTPFolders.add(name)
        log("2FA: folder \"\(name)\" added.")
    }

    @objc private func moveClicked(_ sender: NSMenuItem) {
        guard let target = sender.representedObject as? MoveTarget else { return }
        if OTPKeychain.setFolder(target.account, target.folder) {
            log("2FA: \"\(target.account)\" moved to \(target.folder.map { "\"\($0)\"" } ?? "the top level").")
        }
    }

    @objc private func moveToNewFolderClicked(_ sender: NSMenuItem) {
        guard let account = sender.representedObject as? String,
              let name = askFolderName("Move \"\(account)\" to a new folder", "", value: "", button: "Move")
        else { return }
        if OTPKeychain.setFolder(account, name) { log("2FA: \"\(account)\" moved to new folder \"\(name)\".") }
    }

    @objc private func renameFolderClicked(_ sender: NSMenuItem) {
        guard let old = sender.representedObject as? String,
              let new = askFolderName("Rename \"\(old)\"",
                                      "Its accounts stay in it. An existing name merges the two folders.",
                                      value: old, button: "Rename"),
              new != old else { return }
        let accounts = OTPKeychain.entries().filter { $0.folder == old }.map(\.name)
        let moved = accounts.filter { OTPKeychain.setFolder($0, new) }.count
        OTPFolders.rename(old, to: new)
        if accounts.isEmpty { OTPFolders.add(new) }
        log("2FA: folder \"\(old)\" renamed to \"\(new)\" (\(moved) account(s)).")
    }

    /// Removes the folder, not its accounts: they move to the top level.
    @objc private func removeFolderClicked(_ sender: NSMenuItem) {
        guard let folder = sender.representedObject as? String else { return }
        let accounts = OTPKeychain.entries().filter { $0.folder == folder }.map(\.name)
        if !accounts.isEmpty {
            let alert = makeAlert("Remove the folder \"\(folder)\"?",
                "Its \(accounts.count) account(s) are kept and move to the top level of OTP.")
            alert.addButton(withTitle: "Remove Folder")
            alert.addButton(withTitle: "Cancel")
            guard runModal(alert) == .alertFirstButtonReturn else { return }
        }
        let moved = accounts.filter { OTPKeychain.setFolder($0, nil) }.count
        OTPFolders.remove(folder)
        log("2FA: folder \"\(folder)\" removed; \(moved) account(s) moved to the top level.")
    }

    /// A folder name dialog; nil when cancelled or blank.
    private func askFolderName(_ title: String, _ text: String, value: String, button: String) -> String? {
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
        field.stringValue = value
        field.placeholderString = "Folder name"
        let alert = makeAlert(title, text)
        alert.accessoryView = field
        alert.addButton(withTitle: button)
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard runModal(alert) == .alertFirstButtonReturn else { return nil }
        return OTPEntry(name: "", folder: field.stringValue).folder
    }

    @objc private func backupClicked(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        showBackupCodes(name)
    }

    @objc private func removeClicked(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        remove(name)
    }

    // MARK: Typing a code

    /// Touch ID → the current code is typed into the focused field + Enter, and
    /// copied — the same as "Ввести пароль" (the clipboard covers a field that was not focused).
    func typeCode(_ name: String) {
        Thread.detachNewThread { [weak self] in
            guard let self = self else { return }
            guard self.begin() else { log("2FA: already typing — skipped."); return }
            defer { self.end() }

            guard Biometrics.authenticate(reason: "type the 2FA code for \(name)") else {
                log("2FA: Touch ID failed or cancelled.")
                return
            }
            guard let account = OTPKeychain.read(name) else {
                self.alertOnMain("Cannot read \"\(name)\"", "The Keychain did not return this account — add it again.")
                return
            }
            Thread.sleep(forTimeInterval: focusReturnDelay)
            let code = self.freshCode(account)
            DispatchQueue.main.sync { CodeClipboard.copy(code) }
            guard Accessibility.isTrusted else {
                self.alertOnMain("Code copied", "\(formatCode(code)) is on the clipboard. TouchPass cannot type it: " +
                                 "it has no Accessibility permission (Setup…).")
                return
            }
            var front = "?"
            DispatchQueue.main.sync { front = NSWorkspace.shared.frontmostApplication?.localizedName ?? "?" }
            log("2FA: typing the code for \"\(name)\" into the active window (\(front)).")
            typeString(code)
        }
    }

    /// The code to type now; waits for the next period when this one is about to expire.
    private func freshCode(_ account: OTPAccount) -> String {
        var current = account.code()
        if current.secondsLeft < otpMinSecondsLeft {
            Thread.sleep(forTimeInterval: Double(current.secondsLeft) + 0.2)
            current = account.code()
        }
        return current.code
    }

    // MARK: Adding

    private func scan() {
        if ScreenRecording.isAllowed {
            Task { @MainActor in
                var links: [String] = []
                do {
                    for image in try await QRScanner.captureScreens() { links += QRScanner.otpauthLinks(in: image) }
                } catch {
                    log("⚠️ 2FA: screen capture failed: \(error.localizedDescription).")
                }
                // Not on screen (or capture failed): a screenshot on the clipboard still works.
                if links.isEmpty { links = QRScanner.clipboardLinks(); self.foundLinks(links, fromClipboard: true) }
                else { self.foundLinks(links, fromClipboard: false) }
            }
            return
        }
        let links = QRScanner.clipboardLinks()
        if !links.isEmpty { foundLinks(links, fromClipboard: true); return }

        let alert = makeAlert("Allow Screen Recording to scan the QR code",
            "TouchPass reads the 2FA setup QR code straight off the screen, which needs the Screen Recording " +
            "permission (the screenshot stays in memory).\n\nWithout it: take a screenshot of the QR code to " +
            "the clipboard (Cmd-Ctrl-Shift-4, select the code) and choose \"Scan QR Code…\" again.")
        alert.addButton(withTitle: "Allow…")
        alert.addButton(withTitle: "Open Settings")
        alert.addButton(withTitle: "Cancel")
        switch runModal(alert) {
        case .alertFirstButtonReturn: ScreenRecording.resetAndRequest()
        case .alertSecondButtonReturn: ScreenRecording.openSettings()
        default: break
        }
    }

    private func foundLinks(_ links: [String], fromClipboard: Bool) {
        guard let link = links.first else {
            let alert = makeAlert("No 2FA QR code found",
                "Open the site's 2FA setup page with the QR code fully visible and choose \"Scan QR Code…\" " +
                "again. Or copy a screenshot of the code to the clipboard (Cmd-Ctrl-Shift-4), or use " +
                "\"Add Manually…\" with the text key.")
            alert.addButton(withTitle: "OK")
            runModal(alert)
            return
        }
        // The clipboard held a secret; once it is in the Keychain it should not linger there.
        if fromClipboard { NSPasteboard.general.clearContents() }
        do {
            let uri = try OTPAuthURI(link)
            if links.count > 1 { log("2FA: \(links.count) QR codes found — using the first.") }
            confirmAndSave(uri.account, suggestedName: uri.suggestedName,
                           note: links.count > 1 ? "Several 2FA QR codes were visible; this is the first one." : nil)
        } catch {
            let alert = makeAlert("This QR code cannot be used", "\(error)")
            alert.addButton(withTitle: "OK")
            runModal(alert)
        }
    }

    func addManually() {
        let nameField = NSTextField(frame: NSRect(x: 0, y: 30, width: 300, height: 24))
        nameField.placeholderString = "Name, e.g. WordPress.org: alice"
        let secretField = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
        secretField.placeholderString = "Key (base32) or otpauth:// link"
        let box = NSView(frame: NSRect(x: 0, y: 0, width: 300, height: 54))
        box.addSubview(nameField)
        box.addSubview(secretField)
        nameField.nextKeyView = secretField
        secretField.nextKeyView = nameField

        let alert = makeAlert("Add a 2FA account",
            "Paste the text key the site shows under its QR code (\"can't scan?\"), or the otpauth:// link.")
        alert.accessoryView = box
        alert.addButton(withTitle: "Add")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = nameField
        guard runModal(alert) == .alertFirstButtonReturn else { return }

        do {
            let parsed = try parseSecretInput(secretField.stringValue)
            let typed = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            confirmAndSave(parsed.account, suggestedName: typed.isEmpty ? (parsed.suggestedName ?? "") : typed,
                           note: nil, askName: typed.isEmpty)
        } catch {
            let fail = makeAlert("Not added", "\(error)")
            fail.addButton(withTitle: "OK")
            runModal(fail)
        }
    }

    /// Asks for (or confirms) the menu name, guards against overwriting, saves,
    /// then shows the current code for the site's "enter the code" step.
    private func confirmAndSave(_ account: OTPAccount, suggestedName: String, note: String?, askName: Bool = true) {
        var name = suggestedName
        // Default folder: the site (issuer), so ten WordPress.org accounts land in one folder.
        var folder: String? = account.issuer
        if askName {
            let field = NSTextField(frame: NSRect(x: 0, y: 32, width: 300, height: 24))
            field.stringValue = suggestedName
            field.placeholderString = "Name"
            let folderBox = folderComboBox(NSRect(x: 0, y: 0, width: 300, height: 26), value: folder)
            let box = NSView(frame: NSRect(x: 0, y: 0, width: 300, height: 56))
            box.addSubview(field)
            box.addSubview(folderBox)
            var details = "The name appears in TouchPass → OTP, inside the folder (leave the folder " +
                "empty for the top level)."
            if account.algorithm != .sha1 || account.digits != 6 || account.period != 30 {
                details += " Codes: \(account.digits) digits, every \(account.period) s, \(account.algorithm.rawValue)."
            }
            if let note = note { details += "\n\n" + note }
            let alert = makeAlert("Save the 2FA account", details)
            alert.accessoryView = box
            alert.addButton(withTitle: "Save")
            alert.addButton(withTitle: "Cancel")
            alert.window.initialFirstResponder = field
            guard runModal(alert) == .alertFirstButtonReturn else { return }
            name = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            folder = folderBox.stringValue
        }
        guard !name.isEmpty else {
            let fail = makeAlert("Not saved", "The name is empty.")
            fail.addButton(withTitle: "OK")
            runModal(fail)
            return
        }
        if OTPKeychain.exists(name) {
            let replace = makeAlert("Replace \"\(name)\"?",
                "TouchPass already has a 2FA account with this name. Replacing it drops its old key and backup codes.")
            replace.alertStyle = .warning
            replace.addButton(withTitle: "Replace")
            replace.addButton(withTitle: "Cancel")
            guard runModal(replace) == .alertFirstButtonReturn else { return }
        }
        guard OTPKeychain.save(name, account) else {
            let fail = makeAlert("Not saved", "The Keychain refused the item (details in the log).")
            fail.addButton(withTitle: "OK")
            runModal(fail)
            return
        }
        OTPKeychain.setFolder(name, folder)
        log("2FA: saved account \"\(name)\".")
        showCodeAfterSave(name, account)
    }

    /// Right after saving: the site wants the current code to finish its setup.
    private func showCodeAfterSave(_ name: String, _ account: OTPAccount) {
        let (code, left) = account.code()
        CodeClipboard.copy(code)
        let canType = Accessibility.isTrusted
        let alert = makeAlert("Saved \"\(name)\"",
            "Current code: \(formatCode(code)) (\(left) s left) — it is on the clipboard." +
            (canType ? "\n\n\"Type It\" closes this and types the code (a fresh one, if this expires) into the " +
                       "field that was focused before." : ""))
        if canType { alert.addButton(withTitle: "Type It") }
        alert.addButton(withTitle: "Done")
        guard canType, runModal(alert) == .alertFirstButtonReturn else {
            if !canType { runModal(alert) }
            return
        }
        // Give focus back to the browser, then type — no Touch ID: the key was just entered.
        NSApp.hide(nil)
        Thread.detachNewThread { [weak self] in
            guard let self = self, self.begin() else { return }
            defer { self.end() }
            Thread.sleep(forTimeInterval: 0.5)
            let fresh = self.freshCode(account)
            DispatchQueue.main.sync { CodeClipboard.copy(fresh) }
            log("2FA: typing the first code for \"\(name)\".")
            typeString(fresh)
        }
    }

    // MARK: Folders

    /// A folder field that offers the existing folders and takes a new name too.
    private func folderComboBox(_ frame: NSRect, value: String?) -> NSComboBox {
        let box = NSComboBox(frame: frame)
        box.placeholderString = "Folder (optional): pick one or type a new name"
        box.addItems(withObjectValues: OTPKeychain.folders())
        box.completes = true
        box.stringValue = value ?? ""
        return box
    }

    // MARK: Backup codes and removal

    func showBackupCodes(_ name: String) {
        Thread.detachNewThread { [weak self] in
            guard let self = self else { return }
            guard Biometrics.authenticate(reason: "show the backup codes for \(name)") else { return }
            guard let account = OTPKeychain.read(name) else {
                self.alertOnMain("Cannot read \"\(name)\"", "The Keychain did not return this account.")
                return
            }
            DispatchQueue.main.async { self.editBackupCodes(name, account) }
        }
    }

    private func editBackupCodes(_ name: String, _ account: OTPAccount) {
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 320, height: 160))
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        let text = NSTextView(frame: scroll.bounds)
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        text.isRichText = false
        text.autoresizingMask = [.width]
        text.string = account.backupCodes ?? ""
        scroll.documentView = text

        let alert = makeAlert("Backup codes: \(name)",
            "One-time codes the site gave for when the authenticator is unavailable. Paste or edit them here; " +
            "they are kept in this account's Keychain item.")
        alert.accessoryView = scroll
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Copy")
        alert.addButton(withTitle: "Close")
        alert.window.initialFirstResponder = text
        switch runModal(alert) {
        case .alertFirstButtonReturn:
            var updated = account
            let codes = text.string.trimmingCharacters(in: .whitespacesAndNewlines)
            updated.backupCodes = codes.isEmpty ? nil : codes
            if OTPKeychain.save(name, updated) { log("2FA: backup codes for \"\(name)\" updated.") }
        case .alertSecondButtonReturn:
            CodeClipboard.copy(text.string)
        default:
            break
        }
    }

    func remove(_ name: String) {
        let alert = makeAlert("Remove \"\(name)\"?",
            "Its key and backup codes are deleted from the Keychain. Turn 2FA off on the site first, or keep " +
            "another way to sign in — without the key there are no more codes.")
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Remove")
        alert.addButton(withTitle: "Cancel")
        guard runModal(alert) == .alertFirstButtonReturn else { return }
        Thread.detachNewThread {
            guard Biometrics.authenticate(reason: "remove the 2FA account \(name)") else { return }
            if OTPKeychain.delete(name) { log("2FA: removed account \"\(name)\".") }
        }
    }

    // MARK: Alerts

    private func makeAlert(_ title: String, _ text: String) -> NSAlert {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        return alert
    }

    /// An accessory app's alert would open behind the browser and its text fields
    /// would get no keys: activate first.
    @discardableResult
    private func runModal(_ alert: NSAlert) -> NSApplication.ModalResponse {
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal()
    }

    private func alertOnMain(_ title: String, _ text: String) {
        log("2FA: \(title).")
        DispatchQueue.main.async {
            let alert = self.makeAlert(title, text)
            alert.addButton(withTitle: "OK")
            self.runModal(alert)
        }
    }
}

// MARK: - CLI self-test

/// `touchpass --otp-selftest`: a Keychain round trip with a throwaway account
/// and the RFC 6238 key — save, list, read, generate, delete. Touches no other item.
func runOTPSelfTest() -> Bool {
    let name = "__touchpass-selftest__"
    var ok = true
    func check(_ cond: Bool, _ what: String) {
        print("\(cond ? "ok  " : "FAIL") \(what)")
        ok = ok && cond
    }
    guard let account = try? OTPAccount(secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", backupCodes: "1111 2222") else {
        print("FAIL dummy account"); return false
    }
    check(!OTPKeychain.exists(name), "no leftover test item")
    check(OTPKeychain.save(name, account), "save")
    check(OTPKeychain.names().contains(name), "listed by name")
    check(OTPKeychain.setFolder(name, "__selftest folder__")
          && OTPKeychain.entries().first { $0.name == name }?.folder == "__selftest folder__", "moved to a folder")
    let back = OTPKeychain.read(name)
    check(back == account, "read back identical (incl. backup codes)")
    var edited = account
    edited.backupCodes = "3333"
    check(OTPKeychain.save(name, edited) && OTPKeychain.read(name) == edited
          && OTPKeychain.entries().first { $0.name == name }?.folder == "__selftest folder__",
          "re-save keeps the folder")
    check(back?.code(at: Date(timeIntervalSince1970: 59)).code == "287082", "RFC 6238 code from the stored key")
    check(OTPKeychain.delete(name) && !OTPKeychain.exists(name), "deleted")
    return ok
}
