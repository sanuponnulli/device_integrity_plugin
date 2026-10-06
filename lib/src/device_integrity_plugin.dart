import 'models/attestation_proof.dart';
import 'models/capability.dart';
import 'models/integrity_report.dart';
import 'platform/device_integrity_platform.dart';

/// Main entry point for the device_integrity_plugin package.
///
/// Provides three operations:
/// 1. [checkLocalSignals] — offline, on-device checks.
/// 2. [getCapabilities] — what checks and attestation providers are available.
/// 3. [createProof] — request a platform attestation token for backend
///    verification.
///
/// All findings are independent; an error in one check never suppresses
/// another. The plugin does not produce a single "safe/unsafe" verdict —
/// the host app's backend makes that decision.
class DeviceIntegrityPlugin {
  DeviceIntegrityPlugin._();

  static final DeviceIntegrityPlugin instance = DeviceIntegrityPlugin._();

  DeviceIntegrityPlatform get _platform => DeviceIntegrityPlatform.instance;

  // ── Local signals ─────────────────────────────────────────────────────

  /// Run all available local integrity checks.
  ///
  /// Returns an [IntegrityReport] containing one [IntegrityFinding] per
  /// check. Checks that are unavailable or that error still appear in the
  /// report with the appropriate status — they are never silently omitted.
  ///
  /// This method does not make any network calls.
  Future<IntegrityReport> checkLocalSignals() async {
    final raw = await _platform.checkLocalSignals();
    return IntegrityReport.fromMap(raw);
  }

  // ── Capabilities ──────────────────────────────────────────────────────

  /// Report which local checks and attestation providers are available on
  /// this device/app combination.
  ///
  /// Use this before calling [createProof] to avoid requesting an
  /// attestation from a provider that isn't available.
  Future<List<IntegrityCapability>> getCapabilities() async {
    final raw = await _platform.getCapabilities();
    return raw
        .map((m) => IntegrityCapability.fromMap(m))
        .toList(growable: false);
  }

  // ── Attestation ───────────────────────────────────────────────────────

  /// Request a platform-backed attestation proof.
  ///
  /// [challenge] must be a high-entropy, one-time value created by the
  /// host app's backend with a short expiry, bound to the transaction
  /// being protected.
  ///
  /// [requestHash] (optional) binds the proof to specific request data.
  /// On Android (Play Integrity) this is included in the integrity token.
  /// On iOS the host app is responsible for including it in the assertion
  /// client data.
  ///
  /// [keyId] is required for iOS App Attest assertions. Generate and attest
  /// the key first with [generateAppAttestKey] and [attestAppAttestKey]. It is
  /// ignored by Android.
  ///
  /// The returned [AttestationProof] is opaque — the plugin does not
  /// validate it. The host app must submit it to its backend for
  /// server-side verification. Never place Google or Apple server
  /// credentials in the app.
  Future<AttestationProof> createProof({
    required String challenge,
    String? requestHash,
    String? keyId,
  }) async {
    final raw = await _platform.createProof(
      challenge: challenge,
      requestHash: requestHash,
      keyId: keyId,
    );
    return AttestationProof.fromMap(raw);
  }

  // ── iOS App Attest key lifecycle ──────────────────────────────────────

  /// Generate a new App Attest key pair. Returns the key identifier.
  ///
  /// The key must subsequently be attested via [attestAppAttestKey] before
  /// it can be used for assertions.
  Future<String> generateAppAttestKey() async {
    return _platform.generateAppAttestKey();
  }

  /// Attest a previously generated App Attest key.
  ///
  /// The [challenge] must come from the backend. The returned proof
  /// contains the attestation object that the backend must verify to
  /// establish trust in the key.
  Future<AttestationProof> attestAppAttestKey({
    required String keyId,
    required String challenge,
  }) async {
    final raw = await _platform.attestAppAttestKey(
      keyId: keyId,
      challenge: challenge,
    );
    return AttestationProof.fromMap(raw);
  }

  // ── Sensitive-screen protection ───────────────────────────────────────

  /// Enable or disable `FLAG_SECURE` on the current Android activity.
  ///
  /// When enabled, the system prevents screenshots and screen recording of
  /// the activity. This has device-specific limitations — some OEM
  /// launchers or accessibility tools may bypass it.
  ///
  /// On iOS this is a no-op — use [isScreenBeingCaptured] instead and let
  /// the host app decide how to obscure sensitive views.
  ///
  /// Returns `true` if the flag was set successfully.
  Future<bool> setSecureScreen(bool enabled) {
    return _platform.setSecureScreen(enabled);
  }

  /// Check whether screen recording or mirroring is currently active
  /// (iOS only).
  ///
  /// The host app can use this to overlay or hide sensitive content.
  /// This cannot detect a physical camera pointing at the screen.
  Future<bool> isScreenBeingCaptured() {
    return _platform.isScreenBeingCaptured();
  }
}
