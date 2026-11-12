import Foundation

/// Checks app configuration and tampering indicators on iOS.
///
/// Produces two distinct findings:
/// - `signing_anomaly`: Reports the app's code signing information
///   (embedded provisioning profile type) for backend evaluation.
/// - `installer_anomaly`: Reports unexpected bundle or provisioning state.
class AppTamperingCheckiOS: IntegrityCheck {

    func execute() -> [Finding] {
        var findings: [Finding] = []

        // ── Signing / provisioning profile ──────────────────────────────
        findings.append(checkSigningInfo())

        // ── Bundle integrity ────────────────────────────────────────────
        findings.append(checkBundleIntegrity())

        return findings
    }

    private func checkSigningInfo() -> Finding {
        // Check for embedded.mobileprovision — App Store builds don't have it
        let provisionPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision")

        if let path = provisionPath {
            // Read provisioning profile to determine type
            do {
                let data = try Data(contentsOf: URL(fileURLWithPath: path))
                let profileString = String(data: data, encoding: .ascii) ?? ""

                if profileString.contains("<key>ProvisionsAllDevices</key>") {
                    // Enterprise distribution
                    return Finding(
                        signalId: "signing_anomaly",
                        status: "detected",
                        source: "local",
                        reasonCode: "enterprise_profile",
                        detail: "Enterprise provisioning profile detected"
                    )
                } else if profileString.contains("<key>get-task-allow</key>") &&
                          profileString.contains("<true/>") {
                    // Development profile (get-task-allow = true)
                    return Finding(
                        signalId: "signing_anomaly",
                        status: "notDetected",
                        source: "local",
                        reasonCode: "development_profile",
                        detail: "Development provisioning profile"
                    )
                } else {
                    // Ad hoc distribution
                    return Finding(
                        signalId: "signing_anomaly",
                        status: "notDetected",
                        source: "local",
                        reasonCode: "adhoc_profile",
                        detail: "Ad hoc provisioning profile"
                    )
                }
            } catch {
                return .error("signing_anomaly", "profile_read_error", error.localizedDescription)
            }
        } else {
            // No provisioning profile — likely App Store or TestFlight
            return .notDetected("signing_anomaly", "appstore_distribution")
        }
    }

    private func checkBundleIntegrity() -> Finding {
        // Check that Info.plist exists and bundle identifier is present
        guard let bundleId = Bundle.main.bundleIdentifier else {
            return .detected(
                "installer_anomaly",
                "missing_bundle_identifier",
                "No bundle identifier found"
            )
        }

        // Check for _CodeSignature directory
        let codeSignPath = Bundle.main.bundlePath + "/_CodeSignature"
        if !FileManager.default.fileExists(atPath: codeSignPath) {
            return .detected(
                "installer_anomaly",
                "missing_code_signature",
                "No _CodeSignature directory found"
            )
        }

        // Check for SC_Info (App Store receipt)
        // SC_Info is present in App Store builds
        let scInfoPath = Bundle.main.bundlePath + "/SC_Info"
        let hasReceipt = Bundle.main.appStoreReceiptURL
            .flatMap { try? Data(contentsOf: $0) } != nil

        return .notDetected(
            "installer_anomaly",
            "bundle_integrity_ok"
        )
    }
}
