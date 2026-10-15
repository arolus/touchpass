// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TouchPass",
    // macOS 14: the QR scan captures the screen with ScreenCaptureKit's
    // SCScreenshotManager (CGWindowListCreateImage is obsolete in current SDKs).
    platforms: [.macOS(.v14)],
    targets: [
        // Pure TOTP / base32 / otpauth logic without AppKit — covered by tests.
        .target(name: "TouchPassCore"),
        .executableTarget(name: "touchpass", dependencies: ["TouchPassCore"]),
        .testTarget(name: "TouchPassCoreTests", dependencies: ["TouchPassCore"]),
    ]
)
