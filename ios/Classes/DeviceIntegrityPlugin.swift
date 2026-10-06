import Flutter
import UIKit

/// Flutter platform plugin for device_integrity (iOS).
///
/// Orchestrates independent check modules and the App Attest provider.
/// Each check reports its own status — errors in one check never
/// suppress findings from other checks.
public class DeviceIntegrityPlugin: NSObject, FlutterPlugin {

    private let screenGuard = SensitiveScreenGuardiOS()

    static let packageVersion = "0.1.0"

    // MARK: - Plugin registration

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "com.example.device_integrity/methods",
            binaryMessenger: registrar.messenger()
        )
        let instance = DeviceIntegrityPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    // MARK: - Method dispatch

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "checkLocalSignals":
            handleCheckLocalSignals(result: result)

        case "getCapabilities":
            handleGetCapabilities(result: result)

        case "createProof":
            handleCreateProof(call: call, result: result)

        case "generateAppAttestKey":
            handleGenerateAppAttestKey(result: result)

        case "attestAppAttestKey":
            handleAttestAppAttestKey(call: call, result: result)

        case "setSecureScreen":
            // FLAG_SECURE is Android-only. On iOS, use isScreenBeingCaptured.
            result(false)

        case "isScreenBeingCaptured":
            handleIsScreenBeingCaptured(result: result)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - checkLocalSignals

    private func handleCheckLocalSignals(result: @escaping FlutterResult) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var findings: [Finding] = []

            // Each check is independent — a failure in one does not
            // prevent others from running.
            let checks: [IntegrityCheck] = [
                JailbreakCheck(),
                SimulatorCheck(),
                DebuggerCheckiOS(),
                HookingCheckiOS(),
                AppTamperingCheckiOS(),
                NetworkContextCheckiOS(),
            ]

            for check in checks {
                do {
                    let checkFindings = check.execute()
                    findings.append(contentsOf: checkFindings)
                } catch {
                    findings.append(.error(
                        "check_\(type(of: check))",
                        "unexpected_exception",
                        error.localizedDescription
                    ))
                }
            }

            // Screen capture is a local signal too
            if #available(iOS 11.0, *) {
                let isCaptured = self?.screenGuard.isCaptured ?? false
                if isCaptured {
                    findings.append(.detected(
                        "screen_capture_active",
                        "screen_being_captured"
                    ))
                } else {
                    findings.append(.notDetected(
                        "screen_capture_active",
                        "screen_not_captured"
                    ))
                }
            } else {
                findings.append(.unavailable(
                    "screen_capture_active",
                    "ios_11_required"
                ))
            }

            let report = self?.buildReport(findings: findings) ?? [:]
            DispatchQueue.main.async {
                result(report)
            }
        }
    }

    // MARK: - getCapabilities

    private func handleGetCapabilities(result: @escaping FlutterResult) {
        var capabilities: [[String: Any?]] = []

        // Local checks — always available on iOS 12+
        let localChecks = [
            "root_jailbreak_artifacts",
            "rootless_jailbreak",
            "restricted_write_access",
            "emulator_simulator",
            "debugger_attached",
            "debuggable_build",
            "hooking_framework",
            "signing_anomaly",
            "installer_anomaly",
            "proxy_configured",
            "vpn_active",
        ]

        for id in localChecks {
            capabilities.append([
                "id": id,
                "available": true,
                "minimumOsVersion": "12.0",
            ])
        }

        // Screen capture detection (iOS 11+)
        capabilities.append([
            "id": "screen_capture_active",
            "available": true,
            "minimumOsVersion": "11.0",
        ])

        // App Attest (iOS 14+)
        if #available(iOS 14.0, *) {
            let provider = AppAttestProvider()
            capabilities.append([
                "id": "app_attest",
                "available": provider.isSupported,
                "unavailableReason": provider.isSupported ? nil : "unsupported_device",
                "minimumOsVersion": "14.0",
            ])
        } else {
            capabilities.append([
                "id": "app_attest",
                "available": false,
                "unavailableReason": "ios_14_required",
                "minimumOsVersion": "14.0",
            ])
        }

        result(capabilities)
    }

    // MARK: - createProof (App Attest assertion)

    private func handleCreateProof(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any],
              let challenge = args["challenge"] as? String,
              !challenge.isEmpty else {
            result(FlutterError(
                code: "INVALID_ARGUMENT",
                message: "challenge is required and must not be empty",
                details: nil
            ))
            return
        }

        let requestHash = args["requestHash"] as? String

        guard #available(iOS 14.0, *) else {
            result(FlutterError(
                code: "UNSUPPORTED",
                message: "App Attest requires iOS 14.0+",
                details: nil
            ))
            return
        }

        let provider = AppAttestProvider()
        guard provider.isSupported else {
            result(FlutterError(
                code: "UNSUPPORTED",
                message: "App Attest is not supported on this device",
                details: nil
            ))
            return
        }

        // For createProof we need an already-attested key ID.
        // The host app should have stored this from a previous attestKey call.
        guard let keyId = args["keyId"] as? String else {
            result(FlutterError(
                code: "INVALID_ARGUMENT",
                message: "keyId is required for assertion generation. Call generateAppAttestKey and attestAppAttestKey first.",
                details: nil
            ))
            return
        }

        provider.generateAssertion(
            keyId: keyId,
            challenge: challenge,
            requestHash: requestHash
        ) { assertionResult in
            switch assertionResult {
            case .success(let proof):
                result(proof)
            case .failure(let error):
                result(FlutterError(
                    code: "ATTESTATION_FAILED",
                    message: "App Attest assertion failed: \(error.localizedDescription)",
                    details: nil
                ))
            }
        }
    }

    // MARK: - generateAppAttestKey

    private func handleGenerateAppAttestKey(result: @escaping FlutterResult) {
        guard #available(iOS 14.0, *) else {
            result(FlutterError(
                code: "UNSUPPORTED",
                message: "App Attest requires iOS 14.0+",
                details: nil
            ))
            return
        }

        let provider = AppAttestProvider()
        guard provider.isSupported else {
            result(FlutterError(
                code: "UNSUPPORTED",
                message: "App Attest is not supported on this device",
                details: nil
            ))
            return
        }

        provider.generateKey { keyResult in
            switch keyResult {
            case .success(let keyId):
                result(keyId)
            case .failure(let error):
                result(FlutterError(
                    code: "KEY_GENERATION_FAILED",
                    message: error.localizedDescription,
                    details: nil
                ))
            }
        }
    }

    // MARK: - attestAppAttestKey

    private func handleAttestAppAttestKey(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any],
              let keyId = args["keyId"] as? String,
              let challenge = args["challenge"] as? String else {
            result(FlutterError(
                code: "INVALID_ARGUMENT",
                message: "keyId and challenge are required",
                details: nil
            ))
            return
        }

        guard #available(iOS 14.0, *) else {
            result(FlutterError(
                code: "UNSUPPORTED",
                message: "App Attest requires iOS 14.0+",
                details: nil
            ))
            return
        }

        let provider = AppAttestProvider()
        provider.attestKey(keyId: keyId, challenge: challenge) { attestResult in
            switch attestResult {
            case .success(let proof):
                result(proof)
            case .failure(let error):
                result(FlutterError(
                    code: "ATTESTATION_FAILED",
                    message: error.localizedDescription,
                    details: nil
                ))
            }
        }
    }

    // MARK: - isScreenBeingCaptured

    private func handleIsScreenBeingCaptured(result: @escaping FlutterResult) {
        if #available(iOS 11.0, *) {
            // Must check on main thread for UIScreen access
            DispatchQueue.main.async { [weak self] in
                result(self?.screenGuard.isCaptured ?? false)
            }
        } else {
            result(false)
        }
    }

    // MARK: - Helpers

    private func buildReport(findings: [Finding]) -> [String: Any?] {
        let osVersion = UIDevice.current.systemVersion
        let isoFormatter = ISO8601DateFormatter()

        return [
            "platform": "ios",
            "osVersion": osVersion,
            "packageVersion": DeviceIntegrityPlugin.packageVersion,
            "checkTimeIso": isoFormatter.string(from: Date()),
            "findings": findings.map { $0.toMap() },
        ]
    }
}
