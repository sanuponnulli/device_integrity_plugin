import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'method_channel_device_integrity.dart';

/// Platform-agnostic interface for the device_integrity_plugin package.
///
/// Implementations must provide local-signal checking, capability
/// reporting, and attestation proof creation.
abstract class DeviceIntegrityPlatform extends PlatformInterface {
  DeviceIntegrityPlatform() : super(token: _token);

  static final Object _token = Object();

  static DeviceIntegrityPlatform _instance = MethodChannelDeviceIntegrity();

  /// The current platform implementation.
  static DeviceIntegrityPlatform get instance => _instance;

  /// Override the default platform implementation (for testing).
  static set instance(DeviceIntegrityPlatform value) {
    PlatformInterface.verifyToken(value, _token);
    _instance = value;
  }

  /// Run all available local checks and return the raw map.
  Future<Map<String, dynamic>> checkLocalSignals();

  /// Return the list of available capabilities as raw maps.
  Future<List<Map<String, dynamic>>> getCapabilities();

  /// Request a platform attestation proof.
  Future<Map<String, dynamic>> createProof({
    required String challenge,
    String? requestHash,
    String? keyId,
  });

  /// Enable or disable secure-screen protection on Android.
  Future<bool> setSecureScreen(bool enabled);

  /// Check whether screen capture/mirroring is active (iOS).
  Future<bool> isScreenBeingCaptured();

  /// Generate an App Attest key (iOS only). Returns the key ID.
  Future<String> generateAppAttestKey();

  /// Attest a previously generated App Attest key (iOS only).
  Future<Map<String, dynamic>> attestAppAttestKey({
    required String keyId,
    required String challenge,
  });
}
