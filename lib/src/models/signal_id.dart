/// Stable, well-known signal identifiers.
///
/// Native code may return IDs not listed here. The Dart layer preserves
/// them as-is — it never collapses unrecognized IDs to a generic "unknown"
/// that would lose the original value.
abstract final class SignalId {
  // ── Root / jailbreak ──────────────────────────────────────────────────
  /// Common root or jailbreak artifacts detected (su binary, Cydia, etc.).
  static const rootJailbreakArtifacts = 'root_jailbreak_artifacts';

  /// Write access to normally restricted filesystem locations.
  static const restrictedWriteAccess = 'restricted_write_access';

  /// Root/jailbreak tooling detected via runtime indicators.
  static const rootJailbreakTooling = 'root_jailbreak_tooling';

  /// Rootless jailbreak indicators (e.g. Dopamine, Fugu15).
  static const rootlessJailbreak = 'rootless_jailbreak';

  // ── Emulator / simulator ──────────────────────────────────────────────
  /// The device appears to be an emulator or simulator.
  static const emulatorSimulator = 'emulator_simulator';

  // ── Debugger ──────────────────────────────────────────────────────────
  /// A debugger is currently attached.
  static const debuggerAttached = 'debugger_attached';

  /// The app binary is a debuggable (development) build.
  static const debuggableBuild = 'debuggable_build';

  // ── Hooking / instrumentation ─────────────────────────────────────────
  /// Indicators of common hooking frameworks (Frida, Xposed, Substrate, …).
  static const hookingFramework = 'hooking_framework';

  // ── App configuration & tampering ─────────────────────────────────────
  /// The app's signing identity does not match expectations.
  static const signingAnomaly = 'signing_anomaly';

  /// The app's installer or distribution channel is unexpected.
  static const installerAnomaly = 'installer_anomaly';

  // ── Network context ───────────────────────────────────────────────────
  /// A system-level HTTP proxy is configured.
  static const proxyConfigured = 'proxy_configured';

  /// A VPN interface is active.
  static const vpnActive = 'vpn_active';

  // ── Platform attestation (server-side verdicts) ───────────────────────
  /// Play Integrity device verdict (basic / device / strong).
  static const playIntegrityDevice = 'play_integrity_device';

  /// Play Integrity app verdict (recognized / unrecognized / …).
  static const playIntegrityApp = 'play_integrity_app';

  /// Play Integrity account verdict (licensed / unlicensed / …).
  static const playIntegrityAccount = 'play_integrity_account';

  /// Play Integrity app-access-risk verdict.
  static const playIntegrityAppAccessRisk = 'play_integrity_app_access_risk';

  /// App Attest key attestation result.
  static const appAttestKeyAttestation = 'app_attest_key_attestation';

  /// App Attest assertion verification result.
  static const appAttestAssertion = 'app_attest_assertion';

  /// Screen recording or mirroring is active (iOS).
  static const screenCaptureActive = 'screen_capture_active';
}
