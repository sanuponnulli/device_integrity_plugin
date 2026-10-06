import 'package:device_integrity_plugin/device_integrity_plugin.dart';
import 'package:device_integrity_plugin/src/platform/method_channel_device_integrity.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

class _FakeDeviceIntegrityPlatform extends DeviceIntegrityPlatform {
  Map<String, dynamic> report = <String, dynamic>{
    'platform': 'android',
    'osVersion': '35',
    'packageVersion': '0.1.0',
    'checkTimeIso': '2026-01-01T00:00:00.000Z',
    'findings': <Map<String, Object>>[
      <String, Object>{
        'signalId': 'future_signal',
        'status': 'detected',
        'source': 'local',
        'reasonCode': 'matched',
      },
    ],
  };
  List<Map<String, dynamic>> capabilities = <Map<String, dynamic>>[
    <String, dynamic>{'id': 'play_integrity', 'available': true},
  ];
  Map<String, dynamic> proof = <String, dynamic>{
    'provider': 'app_attest',
    'tokenBase64': 'proof-bytes',
    'challenge': 'nonce',
    'requestHash': 'request-hash',
    'createdAtIso': '2026-01-01T00:00:00.000Z',
  };
  Object? failure;
  String? receivedChallenge;
  String? receivedRequestHash;
  String? receivedKeyId;
  bool receivedSecureScreen = false;

  @override
  Future<Map<String, dynamic>> checkLocalSignals() async {
    if (failure case final error?) throw error;
    return report;
  }

  @override
  Future<List<Map<String, dynamic>>> getCapabilities() async {
    if (failure case final error?) throw error;
    return capabilities;
  }

  @override
  Future<Map<String, dynamic>> createProof({
    required String challenge,
    String? requestHash,
    String? keyId,
  }) async {
    if (failure case final error?) throw error;
    receivedChallenge = challenge;
    receivedRequestHash = requestHash;
    receivedKeyId = keyId;
    return proof;
  }

  @override
  Future<bool> setSecureScreen(bool enabled) async {
    if (failure case final error?) throw error;
    receivedSecureScreen = enabled;
    return true;
  }

  @override
  Future<bool> isScreenBeingCaptured() async {
    if (failure case final error?) throw error;
    return false;
  }

  @override
  Future<String> generateAppAttestKey() async {
    if (failure case final error?) throw error;
    return 'generated-key-id';
  }

  @override
  Future<Map<String, dynamic>> attestAppAttestKey({
    required String keyId,
    required String challenge,
  }) async {
    if (failure case final error?) throw error;
    receivedKeyId = keyId;
    receivedChallenge = challenge;
    return proof;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late _FakeDeviceIntegrityPlatform platform;
  final plugin = DeviceIntegrityPlugin.instance;

  setUp(() {
    platform = _FakeDeviceIntegrityPlatform();
    DeviceIntegrityPlatform.instance = platform;
  });

  tearDown(() {
    DeviceIntegrityPlatform.instance = MethodChannelDeviceIntegrity();
  });

  group('DeviceIntegrityPlugin API', () {
    test('parses local reports and preserves unknown signal identifiers',
        () async {
      final report = await plugin.checkLocalSignals();

      expect(report.platform, 'android');
      expect(report.findings.single.signalId, 'future_signal');
      expect(report.findings.single.status, FindingStatus.detected);
    });

    test('parses capabilities', () async {
      final capabilities = await plugin.getCapabilities();

      expect(capabilities.single.id, 'play_integrity');
      expect(capabilities.single.available, isTrue);
    });

    test('forwards challenge, request hash, and App Attest key ID', () async {
      final proof = await plugin.createProof(
        challenge: 'nonce',
        requestHash: 'request-hash',
        keyId: 'attested-key-id',
      );

      expect(platform.receivedChallenge, 'nonce');
      expect(platform.receivedRequestHash, 'request-hash');
      expect(platform.receivedKeyId, 'attested-key-id');
      expect(proof.provider, 'app_attest');
      expect(proof.tokenBase64, 'proof-bytes');
    });

    test('omits optional proof arguments when absent', () async {
      await plugin.createProof(challenge: 'nonce');

      expect(platform.receivedChallenge, 'nonce');
      expect(platform.receivedRequestHash, isNull);
      expect(platform.receivedKeyId, isNull);
    });

    test('supports the App Attest key lifecycle', () async {
      expect(await plugin.generateAppAttestKey(), 'generated-key-id');

      final attestation = await plugin.attestAppAttestKey(
        keyId: 'generated-key-id',
        challenge: 'registration-nonce',
      );

      expect(platform.receivedKeyId, 'generated-key-id');
      expect(platform.receivedChallenge, 'registration-nonce');
      expect(attestation.provider, 'app_attest');
    });

    test('forwards screen protection controls', () async {
      expect(await plugin.setSecureScreen(true), isTrue);
      expect(platform.receivedSecureScreen, isTrue);
      expect(await plugin.isScreenBeingCaptured(), isFalse);
    });

    test('propagates platform errors instead of manufacturing a result',
        () async {
      platform.failure = PlatformException(code: 'ATTESTATION_FAILED');

      await expectLater(
        plugin.createProof(challenge: 'nonce'),
        throwsA(isA<PlatformException>()),
      );
    });
  });
}
