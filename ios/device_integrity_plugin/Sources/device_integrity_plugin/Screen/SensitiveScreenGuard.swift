import UIKit

/// Reports screen recording / mirroring status on iOS.
///
/// The host app can use this to overlay or hide sensitive content.
/// This cannot detect a physical camera pointed at the screen and
/// does not claim to reliably block screenshots.
class SensitiveScreenGuardiOS {

    /// Whether screen recording or mirroring is currently active.
    @available(iOS 11.0, *)
    var isCaptured: Bool {
        return UIScreen.main.isCaptured
    }

    /// Register for screen capture state change notifications.
    ///
    /// The host app should use this to dynamically obscure or reveal
    /// sensitive content.
    @available(iOS 11.0, *)
    func observeCaptureChanges(handler: @escaping (Bool) -> Void) -> NSObjectProtocol {
        return NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification,
            object: nil,
            queue: .main
        ) { _ in
            handler(UIScreen.main.isCaptured)
        }
    }
}
