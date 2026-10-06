import 'package:device_integrity_plugin/src/platform/method_channel_device_integrity.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

const _channelName = 'com.sanuponnulli.device_integrity_plugin/methods';
const _channel = MethodChannel(_channelName);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final platform = MethodChannelDeviceIntegrity();
  MethodCall? lastCall;

  setUp(() {
    lastCall = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, (call) async {
      lastCall = call;
      switch (call.method) {
        case 'checkLocalSignals':
          return <String, Object>{'findings': <Object>[]};
        case 'getCapabilities':
          return <Object>[
            <String, Object>{'id': 'proxy_configured', 'available': true},
            'malformed entry',
          ];
        case 'createProof':
          return <String, Object>{
            'provider': 'app_attest',
            'tokenBase64': 'token',
            'challenge': 'nonce',
            'createdAtIso': '2026-01-01T00:00:00.000Z',
          };
        case 'setSecureScreen':
        case 'isScreenBeingCaptured':
          return true;
        case 'generateAppAttestKey':
          return 'key-id';
        case 'attestAppAttestKey':
          return <String, Object>{
            'provider': 'app_attest',
            'tokenBase64': 'attestation',
            'challenge': 'registration-nonce',
            'createdAtIso': '2026-01-01T00:00:00.000Z',
          };
        default:
          fail('Unexpected method ${call.method}');
      }
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, null);
  });

  test('uses the native channel and method for local checks', () async {
    final result = await platform.checkLocalSignals();

    expect(lastCall?.method, 'checkLocalSignals');
    expect(result, containsPair('findings', isEmpty));
  });

  test('filters malformed capability entries', () async {
    final result = await platform.getCapabilities();

    expect(lastCall?.method, 'getCapabilities');
    expect(result, hasLength(1));
    expect(result.single['id'], 'proxy_configured');
  });

  test('sends iOS assertion key ID with proof arguments', () async {
    await platform.createProof(
      challenge: 'nonce',
      requestHash: 'body-hash',
      keyId: 'attested-key-id',
    );

    expect(lastCall?.method, 'createProof');
    expect(lastCall?.arguments, <String, String>{
      'challenge': 'nonce',
      'requestHash': 'body-hash',
      'keyId': 'attested-key-id',
    });
  });

  test('omits optional proof values', () async {
    await platform.createProof(challenge: 'nonce');

    expect(lastCall?.arguments, <String, String>{'challenge': 'nonce'});
  });

  test('forwards screen and App Attest methods', () async {
    expect(await platform.setSecureScreen(true), isTrue);
    expect(lastCall?.method, 'setSecureScreen');
    expect(lastCall?.arguments, <String, bool>{'enabled': true});

    expect(await platform.isScreenBeingCaptured(), isTrue);
    expect(lastCall?.method, 'isScreenBeingCaptured');
    expect(await platform.generateAppAttestKey(), 'key-id');
    expect(lastCall?.method, 'generateAppAttestKey');

    await platform.attestAppAttestKey(
      keyId: 'key-id',
      challenge: 'registration-nonce',
    );
    expect(lastCall?.method, 'attestAppAttestKey');
    expect(lastCall?.arguments, <String, String>{
      'keyId': 'key-id',
      'challenge': 'registration-nonce',
    });
  });

  test('propagates native platform exceptions', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, (_) async {
      throw PlatformException(code: 'UNSUPPORTED');
    });

    await expectLater(
      platform.generateAppAttestKey(),
      throwsA(isA<PlatformException>()),
    );
  });
}
