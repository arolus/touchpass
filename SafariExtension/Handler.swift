// Safari requires a principal class in a web extension's bundle. The extension
// sends no native messages, so every request is simply completed.

import Foundation

@objc(SafariWebExtensionHandler)
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        context.completeRequest(returningItems: nil)
    }
}
