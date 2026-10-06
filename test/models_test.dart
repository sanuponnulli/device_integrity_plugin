import 'package:flutter_test/flutter_test.dart';
import 'package:device_integrity_plugin/device_integrity_plugin.dart';

void main() {
  group('FindingStatus', () {
    test('fromString parses known values', () {
      expect(FindingStatus.fromString('detected'), FindingStatus.detected);
      expect(
          FindingStatus.fromString('notDetected'), FindingStatus.notDetected);
      expect(
          FindingStatus.fromString('unavailable'), FindingStatus.unavailable);
      expect(FindingStatus.fromString('error'), FindingStatus.error);
    });

    test('fromString maps unknown values to error', () {
      // Unknown statuses become error — but the original value is
      // preserved in the finding's reasonCode, not lost.
      expect(FindingStatus.fromString('futureStatus'), FindingStatus.error);
      expect(FindingStatus.fromString(''), FindingStatus.error);
    });
  });

  group('FindingSource', () {
    test('fromString parses known values', () {
      expect(FindingSource.fromString('local'), FindingSource.local);
      expect(
        FindingSource.fromString('platformAttestation'),
        FindingSource.platformAttestation,
      );
    });

    test('fromString defaults unknown to local', () {
      expect(FindingSource.fromString('future'), FindingSource.local);
    });
  });

  group('IntegrityFinding', () {
    test('fromMap preserves unknown signalId verbatim', () {
      final map = {
        'signalId': 'some_future_signal_v2',
        'status': 'detected',
        'source': 'local',
        'reasonCode': 'new_check',
        'detail': 'extra info',
      };
      final finding = IntegrityFinding.fromMap(map);

      // Critical: unknown IDs must survive parsing unchanged.
      expect(finding.signalId, 'some_future_signal_v2');
      expect(finding.status, FindingStatus.detected);
      expect(finding.source, FindingSource.local);
      expect(finding.reasonCode, 'new_check');
      expect(finding.detail, 'extra info');
    });

    test('fromMap handles missing optional fields', () {
      final map = {
        'signalId': 'root_jailbreak_artifacts',
        'status': 'notDetected',
        'source': 'local',
      };
      final finding = IntegrityFinding.fromMap(map);

      expect(finding.reasonCode, 'unknown');
      expect(finding.detail, isNull);
    });

    test('toMap roundtrips correctly', () {
      const finding = IntegrityFinding(
        signalId: 'emulator_simulator',
        status: FindingStatus.detected,
        source: FindingSource.local,
        reasonCode: 'fingerprint_match',
        detail: 'generic_x86',
      );

      final map = finding.toMap();
      final restored = IntegrityFinding.fromMap(map);

      expect(restored.signalId, finding.signalId);
      expect(restored.status, finding.status);
      expect(restored.source, finding.source);
      expect(restored.reasonCode, finding.reasonCode);
      expect(restored.detail, finding.detail);
    });

    test('toMap omits null detail', () {
      const finding = IntegrityFinding(
        signalId: 'debugger_attached',
        status: FindingStatus.notDetected,
        source: FindingSource.local,
        reasonCode: 'no_debugger',
      );

      final map = finding.toMap();
      expect(map.containsKey('detail'), isFalse);
    });
  });

  group('IntegrityReport', () {
    test('fromMap builds report with multiple findings', () {
      final map = {
        'platform': 'android',
        'osVersion': '34',
        'packageVersion': '0.1.0',
        'checkTimeIso': '2024-01-15T10:30:00.000Z',
        'findings': [
          {
            'signalId': 'root_jailbreak_artifacts',
            'status': 'notDetected',
            'source': 'local',
            'reasonCode': 'no_artifacts',
          },
          {
            'signalId': 'emulator_simulator',
            'status': 'detected',
            'source': 'local',
            'reasonCode': 'fingerprint_match',
          },
          {
            'signalId': 'debugger_attached',
            'status': 'error',
            'source': 'local',
            'reasonCode': 'check_exception',
            'detail': 'SecurityException',
          },
        ],
      };

      final report = IntegrityReport.fromMap(map);

      expect(report.platform, 'android');
      expect(report.osVersion, '34');
      expect(report.packageVersion, '0.1.0');
      expect(report.findings, hasLength(3));

      // Each finding is independent
      expect(
        report.findings[0].status,
        FindingStatus.notDetected,
      );
      expect(
        report.findings[1].status,
        FindingStatus.detected,
      );
      // Error in debugger check does NOT erase root or emulator findings
      expect(
        report.findings[2].status,
        FindingStatus.error,
      );
    });

    test('fromMap handles empty findings list', () {
      final map = {
        'platform': 'ios',
        'osVersion': '17.4',
        'packageVersion': '0.1.0',
        'checkTimeIso': '2024-01-15T10:30:00.000Z',
        'findings': <dynamic>[],
      };

      final report = IntegrityReport.fromMap(map);
      expect(report.findings, isEmpty);
    });

    test('fromMap handles missing findings key', () {
      final map = {
        'platform': 'ios',
        'osVersion': '17.4',
        'packageVersion': '0.1.0',
      };

      final report = IntegrityReport.fromMap(map);
      expect(report.findings, isEmpty);
    });

    test('findBySignal filters correctly', () {
      final report = IntegrityReport(
        platform: 'android',
        osVersion: '34',
        packageVersion: '0.1.0',
        checkTime: DateTime.now(),
        findings: const [
          IntegrityFinding(
            signalId: 'root_jailbreak_artifacts',
            status: FindingStatus.notDetected,
            source: FindingSource.local,
            reasonCode: 'no_artifacts',
          ),
          IntegrityFinding(
            signalId: 'emulator_simulator',
            status: FindingStatus.detected,
            source: FindingSource.local,
            reasonCode: 'qemu',
          ),
        ],
      );

      expect(report.findBySignal('emulator_simulator'), hasLength(1));
      expect(
        report.findBySignal('emulator_simulator').first.status,
        FindingStatus.detected,
      );
      expect(report.findBySignal('nonexistent'), isEmpty);
    });
  });

  group('IntegrityCapability', () {
    test('fromMap parses available capability', () {
      final map = {
        'id': 'root_jailbreak_artifacts',
        'available': true,
        'minimumOsVersion': '21',
      };

      final cap = IntegrityCapability.fromMap(map);
      expect(cap.id, 'root_jailbreak_artifacts');
      expect(cap.available, isTrue);
      expect(cap.unavailableReason, isNull);
      expect(cap.minimumOsVersion, '21');
    });

    test('fromMap parses unavailable capability', () {
      final map = {
        'id': 'vpn_active',
        'available': false,
        'unavailableReason': 'api_level_too_low',
        'minimumOsVersion': '23',
      };

      final cap = IntegrityCapability.fromMap(map);
      expect(cap.available, isFalse);
      expect(cap.unavailableReason, 'api_level_too_low');
    });
  });

  group('AttestationProof', () {
    test('fromMap parses Play Integrity proof', () {
      final map = {
        'provider': 'play_integrity',
        'tokenBase64': 'eyJhbGciOiJSUz...',
        'challenge': 'server-nonce-123',
        'requestHash': 'sha256-of-request',
        'createdAtIso': '2024-01-15T10:30:00.000Z',
      };

      final proof = AttestationProof.fromMap(map);
      expect(proof.provider, 'play_integrity');
      expect(proof.tokenBase64, 'eyJhbGciOiJSUz...');
      expect(proof.challenge, 'server-nonce-123');
      expect(proof.requestHash, 'sha256-of-request');
    });

    test('fromMap handles missing requestHash', () {
      final map = {
        'provider': 'app_attest',
        'tokenBase64': 'base64data...',
        'challenge': 'server-nonce-456',
        'createdAtIso': '2024-01-15T10:30:00.000Z',
      };

      final proof = AttestationProof.fromMap(map);
      expect(proof.requestHash, isNull);
    });

    test('toMap roundtrips correctly', () {
      final now = DateTime.now().toUtc();
      final proof = AttestationProof(
        provider: 'play_integrity',
        tokenBase64: 'abc123',
        challenge: 'nonce',
        requestHash: 'hash',
        createdAt: now,
      );

      final map = proof.toMap();
      final restored = AttestationProof.fromMap(map);

      expect(restored.provider, proof.provider);
      expect(restored.tokenBase64, proof.tokenBase64);
      expect(restored.challenge, proof.challenge);
      expect(restored.requestHash, proof.requestHash);
    });
  });

  group('SignalId constants', () {
    test('all IDs are unique', () {
      final ids = [
        SignalId.rootJailbreakArtifacts,
        SignalId.restrictedWriteAccess,
        SignalId.rootJailbreakTooling,
        SignalId.rootlessJailbreak,
        SignalId.emulatorSimulator,
        SignalId.debuggerAttached,
        SignalId.debuggableBuild,
        SignalId.hookingFramework,
        SignalId.signingAnomaly,
        SignalId.installerAnomaly,
        SignalId.proxyConfigured,
        SignalId.vpnActive,
        SignalId.playIntegrityDevice,
        SignalId.playIntegrityApp,
        SignalId.playIntegrityAccount,
        SignalId.playIntegrityAppAccessRisk,
        SignalId.appAttestKeyAttestation,
        SignalId.appAttestAssertion,
        SignalId.screenCaptureActive,
      ];

      expect(ids.toSet().length, ids.length,
          reason: 'All signal IDs must be unique');
    });

    test('IDs use snake_case format', () {
      final ids = [
        SignalId.rootJailbreakArtifacts,
        SignalId.emulatorSimulator,
        SignalId.debuggerAttached,
      ];

      for (final id in ids) {
        expect(id, matches(RegExp(r'^[a-z][a-z0-9_]*$')),
            reason: '$id should be snake_case');
      }
    });
  });

  group('Error isolation', () {
    test('error finding does not affect other findings in report', () {
      // Simulates the scenario where one check errors but others succeed.
      final report = IntegrityReport(
        platform: 'android',
        osVersion: '30',
        packageVersion: '0.1.0',
        checkTime: DateTime.now(),
        findings: const [
          // Root check succeeded
          IntegrityFinding(
            signalId: 'root_jailbreak_artifacts',
            status: FindingStatus.notDetected,
            source: FindingSource.local,
            reasonCode: 'no_artifacts',
          ),
          // Emulator check errored
          IntegrityFinding(
            signalId: 'emulator_simulator',
            status: FindingStatus.error,
            source: FindingSource.local,
            reasonCode: 'check_exception',
            detail: 'SecurityException: cannot read build props',
          ),
          // Debugger check succeeded
          IntegrityFinding(
            signalId: 'debugger_attached',
            status: FindingStatus.notDetected,
            source: FindingSource.local,
            reasonCode: 'no_debugger',
          ),
        ],
      );

      // The error in emulator check must not erase root or debugger results
      final root = report.findBySignal('root_jailbreak_artifacts');
      expect(root, hasLength(1));
      expect(root.first.status, FindingStatus.notDetected);

      final emulator = report.findBySignal('emulator_simulator');
      expect(emulator, hasLength(1));
      expect(emulator.first.status, FindingStatus.error);

      final debugger = report.findBySignal('debugger_attached');
      expect(debugger, hasLength(1));
      expect(debugger.first.status, FindingStatus.notDetected);
    });

    test('unavailable finding is distinct from notDetected', () {
      // A check returning unavailable must NOT be interpreted as notDetected
      const finding = IntegrityFinding(
        signalId: 'vpn_active',
        status: FindingStatus.unavailable,
        source: FindingSource.local,
        reasonCode: 'api_level_too_low',
      );

      expect(finding.status, isNot(FindingStatus.notDetected));
      expect(finding.status, FindingStatus.unavailable);
    });
  });

  group('Signal distinctness', () {
    test('emulator, debugger, proxy, root are different signal IDs', () {
      // These must never be conflated
      expect(
          SignalId.emulatorSimulator, isNot(SignalId.rootJailbreakArtifacts));
      expect(SignalId.debuggerAttached, isNot(SignalId.rootJailbreakArtifacts));
      expect(SignalId.proxyConfigured, isNot(SignalId.rootJailbreakArtifacts));
      expect(SignalId.vpnActive, isNot(SignalId.rootJailbreakArtifacts));
      expect(SignalId.emulatorSimulator, isNot(SignalId.debuggerAttached));
      expect(SignalId.proxyConfigured, isNot(SignalId.debuggerAttached));
    });
  });
}
