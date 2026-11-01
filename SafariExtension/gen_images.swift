// Regenerates Resources/images from assets/AppIcon.icns and the SF Symbol for the
// menu item. Run once from tools/touchpass: swift SafariExtension/gen_images.swift
// The glass is mid-gray because a menu icon is not a template image here: it has
// to stay visible on both the light and the dark menu.

import AppKit

func writePNG(size: Int, to path: String, draw: (NSRect) -> Void) {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    draw(NSRect(x: 0, y: 0, width: size, height: size))
    NSGraphicsContext.restoreGraphicsState()
    try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: path))
}

let out = "SafariExtension/Resources/images"
let appIcon = NSImage(contentsOfFile: "assets/AppIcon.icns")!
for size in [48, 96, 128, 256, 512] {
    writePNG(size: size, to: "\(out)/icon-\(size).png") { appIcon.draw(in: $0) }
}

for size in [16, 32] {
    let config = NSImage.SymbolConfiguration(pointSize: CGFloat(size) * 0.8, weight: .semibold)
        .applying(.init(paletteColors: [NSColor(white: 0.55, alpha: 1)]))
    let glass = NSImage(systemSymbolName: "magnifyingglass", accessibilityDescription: nil)!
        .withSymbolConfiguration(config)!
    writePNG(size: size, to: "\(out)/search-\(size).png") { rect in
        let s = glass.size
        glass.draw(in: NSRect(x: (rect.width - s.width) / 2, y: (rect.height - s.height) / 2,
                              width: s.width, height: s.height))
    }
}
