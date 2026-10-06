import 'package:device_integrity_example/main.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel =
      MethodChannel('com.sanuponnulli.device_integrity_plugin/methods');

  testWidgets('dashboard displays capabilities and starts local checks',
      (tester) async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      switch (call.method) {
        case 'getCapabilities':
          return <Object>[
            <String, Object>{
              'id': 'root_jailbreak_artifacts',
              'available': true
            },
          ];
        case 'checkLocalSignals':
          return <String, Object>{
            'platform': 'android',
            'osVersion': '35',
            'packageVersion': '0.1.0',
            'checkTimeIso': '2026-01-01T00:00:00.000Z',
            'findings': <Object>[
              <String, Object>{
                'signalId': 'emulator_simulator',
                'status': 'notDetected',
                'source': 'local',
                'reasonCode': 'no_emulator_indicators',
              },
            ],
          };
        default:
          fail('Unexpected method ${call.method}');
      }
    });
    addTearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    });

    await tester.pumpWidget(const DeviceIntegrityExampleApp());
    await tester.pumpAndSettle();

    expect(find.text('Capabilities'), findsOneWidget);
    expect(find.text('root_jailbreak_artifacts'), findsOneWidget);
    expect(find.text('Run Local Integrity Checks'), findsOneWidget);

    await tester.tap(find.text('Run Local Integrity Checks'));
    await tester.pumpAndSettle();

    expect(find.text('emulator_simulator'), findsOneWidget);
    expect(find.text('notDetected · local'), findsOneWidget);
  });
}
