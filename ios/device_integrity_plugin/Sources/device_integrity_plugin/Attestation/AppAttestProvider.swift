import Foundation
import DeviceCheck
import CryptoKit

/// App Attest client-side provider.
///
/// Supports:
/// - Key generation and attestation (initial trust establishment)
/// - Assertion generation (subsequent request verification)
/// - Runtime availability check
///
/// The plugin returns raw attestation/assertion data. The host app's
/// backend is responsible for all verification:
/// - Validating the challenge
/// - Verifying app identity
/// - Checking the public key / signature
/// - Enforcing the monotonically increasing assertion counter
///
/// Never place Apple server credentials in the app.
@available(iOS 14.0, *)
class AppAttestProvider {

    private let service = DCAppAttestService.shared

    /// Whether App Attest is supported on this device.
    ///
    /// Returns `false` on simulators and unsupported hardware.
    var isSupported: Bool {
        return service.isSupported
    }

    /// Generate a new App Attest key pair.
    ///
    /// - Returns: The key identifier string.
    func generateKey(completion: @escaping (Result<String, Error>) -> Void) {
        service.generateKey { keyId, error in
            if let error = error {
                completion(.failure(error))
            } else if let keyId = keyId {
                completion(.success(keyId))
            } else {
                completion(.failure(AppAttestError.unknownKeyGenerationFailure))
            }
        }
    }

    /// Attest a key with a server-provided challenge.
    ///
    /// The challenge must be a one-time, high-entropy value from the backend.
    /// The returned attestation object must be verified server-side.
    ///
    /// - Parameters:
    ///   - keyId: The key identifier from `generateKey()`.
    ///   - challenge: The server-provided challenge string.
    func attestKey(
        keyId: String,
        challenge: String,
        completion: @escaping (Result<[String: Any?], Error>) -> Void
    ) {
        // Hash the challenge for the attestation request
        guard let challengeData = challenge.data(using: .utf8) else {
            completion(.failure(AppAttestError.invalidChallenge))
            return
        }
        let challengeHash = Data(SHA256.hash(data: challengeData))

        service.attestKey(keyId, clientDataHash: challengeHash) { attestation, error in
            if let error = error {
                completion(.failure(error))
            } else if let attestation = attestation {
                completion(.success([
                    "provider": "app_attest",
                    "tokenBase64": attestation.base64EncodedString(),
                    "challenge": challenge,
                    "keyId": keyId,
                    "createdAtIso": ISO8601DateFormatter().string(from: Date()),
                ]))
            } else {
                completion(.failure(AppAttestError.unknownAttestationFailure))
            }
        }
    }

    /// Generate an assertion for a request bound to a challenge.
    ///
    /// - Parameters:
    ///   - keyId: The attested key identifier.
    ///   - challenge: The server-provided challenge.
    ///   - requestHash: Optional hash of the request being protected.
    func generateAssertion(
        keyId: String,
        challenge: String,
        requestHash: String?,
        completion: @escaping (Result<[String: Any?], Error>) -> Void
    ) {
        // Build client data that includes challenge + request hash
        var clientData: [String: Any] = ["challenge": challenge]
        if let hash = requestHash {
            clientData["requestHash"] = hash
        }

        guard let clientDataJson = try? JSONSerialization.data(withJSONObject: clientData),
              let clientDataHash = clientDataJson.sha256Hash else {
            completion(.failure(AppAttestError.invalidClientData))
            return
        }

        service.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
            if let error = error {
                completion(.failure(error))
            } else if let assertion = assertion {
                // Also encode the client data so the server can reconstruct it
                completion(.success([
                    "provider": "app_attest",
                    "tokenBase64": assertion.base64EncodedString(),
                    "challenge": challenge,
                    "requestHash": requestHash as Any,
                    "clientDataBase64": clientDataJson.base64EncodedString(),
                    "createdAtIso": ISO8601DateFormatter().string(from: Date()),
                ]))
            } else {
                completion(.failure(AppAttestError.unknownAssertionFailure))
            }
        }
    }

    enum AppAttestError: Error, LocalizedError {
        case unknownKeyGenerationFailure
        case invalidChallenge
        case unknownAttestationFailure
        case invalidClientData
        case unknownAssertionFailure

        var errorDescription: String? {
            switch self {
            case .unknownKeyGenerationFailure: return "Key generation failed with no error"
            case .invalidChallenge: return "Challenge could not be encoded to UTF-8"
            case .unknownAttestationFailure: return "Attestation returned no data and no error"
            case .invalidClientData: return "Client data could not be serialised"
            case .unknownAssertionFailure: return "Assertion returned no data and no error"
            }
        }
    }
}

// MARK: - Data extension for SHA-256

private extension Data {
    @available(iOS 13.0, *)
    var sha256Hash: Data? {
        return Data(SHA256.hash(data: self))
    }
}
