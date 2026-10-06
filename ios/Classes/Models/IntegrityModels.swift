import Foundation

/// A single integrity observation — matches the Dart `IntegrityFinding`.
struct Finding {
    let signalId: String
    let status: String      // "detected" | "notDetected" | "unavailable" | "error"
    let source: String      // "local" | "platformAttestation"
    let reasonCode: String
    let detail: String?

    func toMap() -> [String: Any?] {
        var map: [String: Any?] = [
            "signalId": signalId,
            "status": status,
            "source": source,
            "reasonCode": reasonCode,
        ]
        if let d = detail { map["detail"] = d }
        return map
    }

    static func detected(_ signalId: String, _ reasonCode: String, _ detail: String? = nil) -> Finding {
        Finding(signalId: signalId, status: "detected", source: "local", reasonCode: reasonCode, detail: detail)
    }

    static func notDetected(_ signalId: String, _ reasonCode: String) -> Finding {
        Finding(signalId: signalId, status: "notDetected", source: "local", reasonCode: reasonCode, detail: nil)
    }

    static func unavailable(_ signalId: String, _ reasonCode: String) -> Finding {
        Finding(signalId: signalId, status: "unavailable", source: "local", reasonCode: reasonCode, detail: nil)
    }

    static func error(_ signalId: String, _ reasonCode: String, _ detail: String? = nil) -> Finding {
        Finding(signalId: signalId, status: "error", source: "local", reasonCode: reasonCode, detail: detail)
    }
}

/// Protocol for independent integrity check modules.
protocol IntegrityCheck {
    func execute() -> [Finding]
}
