// Генератор AppIcon.icns для TouchPass.
// Тёмный сквиркл, зелёный открытый замок с отпечатком.
import AppKit

let size: CGFloat = 1024

func drawIcon() -> NSImage {
    let img = NSImage(size: NSSize(width: size, height: size))
    img.lockFocus()

    let inset: CGFloat = size * 0.098
    let rect = NSRect(x: inset, y: inset, width: size - inset * 2, height: size - inset * 2)
    let path = NSBezierPath(roundedRect: rect, xRadius: size * 0.185, yRadius: size * 0.185)
    let top = NSColor(calibratedRed: 0.20, green: 0.24, blue: 0.28, alpha: 1)
    let bottom = NSColor(calibratedRed: 0.07, green: 0.09, blue: 0.11, alpha: 1)
    NSGradient(starting: top, ending: bottom)!.draw(in: path, angle: -90)
    path.lineWidth = size * 0.006
    NSColor(white: 1, alpha: 0.10).setStroke()
    path.stroke()

    // touchid — узнаваемый символ отпечатка; зелёный = «можно войти».
    let cfg = NSImage.SymbolConfiguration(pointSize: size * 0.5, weight: .regular)
        .applying(.init(paletteColors: [NSColor(calibratedRed: 0.30, green: 0.85, blue: 0.45, alpha: 1)]))
    if let sym = NSImage(systemSymbolName: "touchid", accessibilityDescription: nil)?
        .withSymbolConfiguration(cfg) {
        let s = sym.size
        let scale = (size * 0.52) / max(s.width, s.height)
        let w = s.width * scale, h = s.height * scale
        sym.draw(in: NSRect(x: (size - w) / 2, y: (size - h) / 2, width: w, height: h))
    }

    img.unlockFocus()
    return img
}

let icon = drawIcon()
let dir = FileManager.default.currentDirectoryPath
guard let tiff = icon.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff) else {
    fatalError("нет rep")
}
rep.size = NSSize(width: size, height: size)
try! rep.representation(using: .png, properties: [:])!
    .write(to: URL(fileURLWithPath: dir + "/icon_1024.png"))
print("OK: icon_1024.png")
