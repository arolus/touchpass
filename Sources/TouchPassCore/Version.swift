// Version handling for the auto-updater: comparing MAJOR.MINOR.PATCH strings
// and reading the version off a GitHub release tag URL.

import Foundation

/// Numeric component-wise comparison: "1.2.10" > "1.2.9"; missing parts count as 0.
public func isNewerVersion(_ a: String, than b: String) -> Bool {
    let av = a.split(separator: ".").map { Int($0) ?? 0 }
    let bv = b.split(separator: ".").map { Int($0) ?? 0 }
    for i in 0..<max(av.count, bv.count) {
        let x = i < av.count ? av[i] : 0
        let y = i < bv.count ? bv[i] : 0
        if x != y { return x > y }
    }
    return false
}

/// "https://github.com/o/r/releases/tag/v1.2.3" → "1.2.3"; nil when it is not a version tag.
public func versionFromReleaseLocation(_ location: String) -> String? {
    guard let tag = URL(string: location)?.lastPathComponent, tag.hasPrefix("v") else { return nil }
    let version = String(tag.dropFirst())
    let parts = version.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count >= 2, parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }) else { return nil }
    return version
}

/// Whether a permission's TCC entry must be reset before asking again.
///
/// Keep it only when it is a working grant of a stable (team-signed) identity.
/// Everything else is stale or denied: an ad-hoc build's entry points at an
/// older binary, and a team-signed app that is not granted may be looking at a
/// toggle left over from an earlier ad-hoc build — shown "on", applying to
/// nothing, and the system prompt never reappears until the entry is reset.
public func shouldResetTCCEntry(teamSigned: Bool, granted: Bool) -> Bool {
    !(teamSigned && granted)
}
