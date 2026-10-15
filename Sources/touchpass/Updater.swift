// Auto-update from GitHub Releases of the public mirror (arolus/touchpass),
// the same scheme as Translit: the dotfiles workflow `publish-touchpass`
// mirrors tools/touchpass there, its CI builds TouchPass.app for every new
// VERSION, and the app checks releases/latest 30 s after start and every 6
// hours, downloads the zip and swaps ~/Applications/TouchPass.app — no
// toolchain needed on the machine with the Touch ID.
//
// Releases are signed with the ARSIDIAN Developer ID (built by release.sh on
// the maintainer's Mac — the certificate never goes to CI). A team-signed app
// installs only a team-signed release, so a hijacked GitHub release cannot
// replace it; its identity is stable, so permissions and Keychain access stay.
// An ad-hoc build (no certificate around) gets a new identity per binary:
// then the stale TCC entries are reset on purpose and macOS asks again.

import AppKit
import Foundation
import TouchPassCore

let autoUpdateDefaultsKey = "autoUpdate"

/// On by default, like Translit.
var autoUpdateEnabled: Bool {
    get {
        let d = UserDefaults.standard
        return d.object(forKey: autoUpdateDefaultsKey) == nil ? true : d.bool(forKey: autoUpdateDefaultsKey)
    }
    set { UserDefaults.standard.set(newValue, forKey: autoUpdateDefaultsKey) }
}

final class Updater {
    static let releasesRepo = "arolus/touchpass"
    static let zipName = "TouchPass.app.zip"

    /// Latest version seen on GitHub — lets the menu offer "Update to X".
    private(set) static var latestKnown: String?

    private var timer: Timer?
    private var busy = false

    /// Only the installed copy updates itself: a bundle in the repo or a bare
    /// `.build` binary is a developer's build.
    static var canUpdate: Bool { appVersion != "dev" && Installer.isInstalled }

    func start() {
        guard Updater.canUpdate else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in self?.checkAndApply() }
        let t = Timer.scheduledTimer(withTimeInterval: 6 * 3600, repeats: true) { [weak self] _ in
            self?.checkAndApply()
        }
        t.tolerance = 1800
        timer = t
    }

    struct Release {
        let version: String
        let zipURL: URL
    }

    /// Stops URLSession at the first redirect so the Location header is ours.
    private final class RedirectCatcher: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }

    /// Resolves the latest release without the GitHub API (60 calls/hr per IP
    /// unauthenticated): /releases/latest redirects to .../tag/vX.Y.Z, and the
    /// asset URL follows from the tag. Completion runs on a URLSession queue.
    static func fetchLatest(completion: @escaping (Release?, String?) -> Void) {
        let url = URL(string: "https://github.com/\(releasesRepo)/releases/latest")!
        let session = URLSession(configuration: .ephemeral, delegate: RedirectCatcher(), delegateQueue: nil)
        var request = URLRequest(url: url)
        request.timeoutInterval = 30
        session.dataTask(with: request) { _, response, error in
            defer { session.finishTasksAndInvalidate() }
            if let error = error {
                completion(nil, error.localizedDescription)
                return
            }
            guard let http = response as? HTTPURLResponse, (300..<400).contains(http.statusCode),
                  let location = http.value(forHTTPHeaderField: "Location"),
                  let version = versionFromReleaseLocation(location) else {
                let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                completion(nil, "no releases found (HTTP \(code))")
                return
            }
            let zip = URL(string: "https://github.com/\(releasesRepo)/releases/download/v\(version)/\(zipName)")!
            DispatchQueue.main.async { latestKnown = version }
            completion(Release(version: version, zipURL: zip), nil)
        }.resume()
    }

    /// force = the person chose the menu item: every outcome is shown, not just logged.
    func checkAndApply(force: Bool = false) {
        guard force || autoUpdateEnabled else { return }
        guard !busy else {
            if force { Updater.alert("An update is already in progress.") }
            return
        }
        busy = true
        Updater.fetchLatest { [weak self] release, problem in
            DispatchQueue.main.async {
                guard let self = self else { return }
                guard let release = release else {
                    self.busy = false
                    log("Update check failed: \(problem ?? "unknown").")
                    if force { Updater.alert("Could not check for updates: \(problem ?? "unknown error").") }
                    return
                }
                guard isNewerVersion(release.version, than: appVersion) else {
                    self.busy = false
                    log("Update check: \(appVersion) is current (latest \(release.version)).")
                    if force { Updater.alert("TouchPass \(appVersion) is up to date.") }
                    return
                }
                // A background update must not kill a dialog the person is filling
                // in (adding a 2FA account, the setup window): try again next time.
                if !force && Updater.uiIsOpen {
                    self.busy = false
                    log("Update \(release.version) postponed: a TouchPass window is open.")
                    return
                }
                log("Update \(appVersion) → \(release.version): downloading…")
                if force {
                    Updater.alert("Updating \(appVersion) → \(release.version). TouchPass restarts by itself." +
                                  (CodeSigning.isTeamSigned ? "" : " Then macOS asks for Accessibility again."))
                }
                DispatchQueue.global(qos: .utility).async {
                    self.performUpdate(release, verbose: force)
                    DispatchQueue.main.async { self.busy = false }
                }
            }
        }
    }

    private static var uiIsOpen: Bool {
        NSApp.modalWindow != nil || NSApp.windows.contains { $0.isVisible && $0.canBecomeKey }
    }

    static func alert(_ message: String) {
        let show = {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = "TouchPass"
            alert.informativeText = message
            alert.runModal()
        }
        if Thread.isMainThread { show() } else { DispatchQueue.main.async(execute: show) }
    }

    /// Background thread: download, unpack, check, swap the installed app, relaunch.
    private func performUpdate(_ release: Release, verbose: Bool) {
        func fail(_ message: String) {
            log("⚠️ \(message)")
            if verbose { Updater.alert(message) }
        }

        let sem = DispatchSemaphore(value: 0)
        var zipData: Data?
        var downloadProblem: String?
        URLSession.shared.dataTask(with: release.zipURL) { data, response, error in
            if (response as? HTTPURLResponse)?.statusCode == 200 { zipData = data }
            downloadProblem = error?.localizedDescription
                ?? ((response as? HTTPURLResponse).map { "HTTP \($0.statusCode)" })
            sem.signal()
        }.resume()
        sem.wait()
        guard let data = zipData else {
            fail("Could not download the update: \(downloadProblem ?? "no data").")
            return
        }

        let fm = FileManager.default
        let tmpDir = NSTemporaryDirectory() + "touchpass-update-\(release.version)"
        let zipPath = tmpDir + "/" + Updater.zipName
        try? fm.removeItem(atPath: tmpDir)
        do {
            try fm.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
            try data.write(to: URL(fileURLWithPath: zipPath))
        } catch {
            fail("Could not save the update: \(error.localizedDescription)")
            return
        }
        guard run("/usr/bin/ditto", ["-x", "-k", zipPath, tmpDir]) == 0 else {
            fail("Could not unpack the update.")
            return
        }
        let newApp = tmpDir + "/TouchPass.app"
        let newBinary = newApp + "/Contents/MacOS/touchpass"
        guard fm.isExecutableFile(atPath: newBinary) else {
            fail("The release archive has no TouchPass.app.")
            return
        }
        // Downloaded files carry the quarantine flag; Gatekeeper would refuse the
        // ad-hoc-signed bundle at the relaunch.
        run("/usr/bin/xattr", ["-dr", "com.apple.quarantine", newApp])
        // The bundle must be what the release says, not a half-built one.
        guard bundleVersion(newApp) == release.version else {
            fail("The release archive holds version \(bundleVersion(newApp) ?? "?"), not \(release.version).")
            return
        }
        // Once team-signed, never step down to a bundle someone else signed.
        if CodeSigning.isTeamSigned && !CodeSigning.bundleIsTeamSigned(newApp) {
            fail("The release \(release.version) is not signed by ARSIDIAN (\(CodeSigning.teamID)) — not installed.")
            return
        }

        let dst = Installer.installedPath
        do {
            if fm.fileExists(atPath: dst) { try fm.removeItem(atPath: dst) }
            try fm.moveItem(atPath: newApp, toPath: dst)
        } catch {
            fail("Could not install the update: \(error.localizedDescription)")
            return
        }
        try? fm.removeItem(atPath: tmpDir)

        let lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/" +
                         "LaunchServices.framework/Support/lsregister"
        if fm.isExecutableFile(atPath: lsregister) { run(lsregister, ["-f", dst]) }
        // An ad-hoc predecessor's TCC entries point at the old binary: reset them
        // so the new one can raise the prompts. A team-signed app keeps its grants
        // across updates — but the first team-signed update after an ad-hoc build
        // still needs the reset, hence the check on the NEW bundle.
        if !CodeSigning.bundleIsTeamSigned(dst) || !CodeSigning.isTeamSigned {
            for service in ["Accessibility", "ScreenCapture"] { run("/usr/bin/tccutil", ["reset", service, bundleID]) }
        }
        // The LaunchAgent already points at Installer.installedPath — nothing to rewrite.

        log("Updated to \(release.version), restarting…")
        // --just-installed: the fresh copy waits for LaunchServices/TCC to see
        // the bundle before asking for Accessibility. The detached shell outlives
        // us; the delay frees the singleton lock.
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sh")
        proc.arguments = ["-c", "sleep 1; /usr/bin/open -a '\(dst)' --args --just-installed"]
        try? proc.run()
        DispatchQueue.main.async { NSApp.terminate(nil) }
    }

    private func bundleVersion(_ app: String) -> String? {
        NSDictionary(contentsOfFile: app + "/Contents/Info.plist")?["CFBundleShortVersionString"] as? String
    }
}

// MARK: - Code signing

/// Who signed this app, and checks on a downloaded bundle.
enum CodeSigning {
    static let teamID = "K8ZZA5DA72"

    /// What a release must satisfy once the installed app is team-signed: Apple-issued
    /// certificate of our team and our bundle identifier.
    static let releaseRequirement =
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" " +
        "and identifier \"\(bundleID)\""

    /// Team ID of the running binary; nil for ad-hoc (or unsigned) builds.
    static let runningTeamID: String? = {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code = code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let s = staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(s, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }()

    /// A team signature is a stable identity: TCC grants and Keychain ACLs
    /// survive rebuilds and updates, so they must not be reset.
    static var isTeamSigned: Bool { runningTeamID == teamID }

    /// true when the bundle at `path` is validly signed by our team.
    static func bundleIsTeamSigned(_ path: String) -> Bool {
        var staticCode: SecStaticCode?
        var requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode,
              SecRequirementCreateWithString(releaseRequirement as CFString, [], &requirement) == errSecSuccess
        else { return false }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode)
        return SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess
    }

    /// Clears stale TCC entries — only for ad-hoc builds, whose identity changes with every binary.
    static func resetTCCIfAdHoc(_ services: [String]) {
        guard !isTeamSigned else { return }
        for service in services { run("/usr/bin/tccutil", ["reset", service, bundleID]) }
    }
}
