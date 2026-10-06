import 'package:flutter/services.dart';

import 'device_integrity_platform.dart';

/// Method-channel implementation of [DeviceIntegrityPlatform].
class MethodChannelDeviceIntegrity extends DeviceIntegrityPlatform {
  /// The channel must match the name registered on each platform side.
  final MethodChannel _channel =
      const MethodChannel('com.sanuponnulli.device_integrity_plugin/methods');

  @override
  Future<Map<String, dynamic>> checkLocalSignals() async {
    final result =
        await _channel.invokeMapMethod<String, dynamic>('checkLocalSignals');
    return result ?? <String, dynamic>{};
  }

  @override
  Future<List<Map<String, dynamic>>> getCapabilities() async {
    final result = await _channel.invokeListMethod<dynamic>('getCapabilities');
    if (result == null) return [];
    return result
        .whereType<Map>()
        .map((e) => Map<String, dynamic>.from(e))
        .toList();
  }

  @override
  Future<Map<String, dynamic>> createProof({
    required String challenge,
    String? requestHash,
    String? keyId,
  }) async {
    final result = await _channel.invokeMapMethod<String, dynamic>(
      'createProof',
      <String, dynamic>{
        'challenge': challenge,
        if (requestHash != null) 'requestHash': requestHash,
        if (keyId != null) 'keyId': keyId,
      },
    );
    return result ?? <String, dynamic>{};
  }

  @override
  Future<bool> setSecureScreen(bool enabled) async {
    final result = await _channel.invokeMethod<bool>(
      'setSecureScreen',
      <String, dynamic>{'enabled': enabled},
    );
    return result ?? false;
  }

  @override
  Future<bool> isScreenBeingCaptured() async {
    final result = await _channel.invokeMethod<bool>('isScreenBeingCaptured');
    return result ?? false;
  }

  @override
  Future<String> generateAppAttestKey() async {
    final result = await _channel.invokeMethod<String>('generateAppAttestKey');
    return result ?? '';
  }

  @override
  Future<Map<String, dynamic>> attestAppAttestKey({
    required String keyId,
    required String challenge,
  }) async {
    final result = await _channel.invokeMapMethod<String, dynamic>(
      'attestAppAttestKey',
      <String, dynamic>{
        'keyId': keyId,
        'challenge': challenge,
      },
    );
    return result ?? <String, dynamic>{};
  }
}
