import 'integrity_finding.dart';

/// The complete report returned by [DeviceIntegrityPlugin.checkLocalSignals].
///
/// Includes platform metadata alongside every individual finding. Errors in
/// one check do not suppress other findings.
class IntegrityReport {
  /// Target platform (e.g. `"android"`, `"ios"`).
  final String platform;

  /// OS version string (e.g. `"14"`, `"17.4"`).
  final String osVersion;

  /// Plugin package version that produced this report.
  final String packageVersion;

  /// UTC timestamp when the report was generated.
  final DateTime checkTime;

  /// Individual findings, one per check that ran. An empty list is valid
  /// and means the plugin had nothing to report (e.g. unsupported platform).
  final List<IntegrityFinding> findings;

  const IntegrityReport({
    required this.platform,
    required this.osVersion,
    required this.packageVersion,
    required this.checkTime,
    required this.findings,
  });

  factory IntegrityReport.fromMap(Map<String, dynamic> map) {
    final rawFindings = (map['findings'] as List<dynamic>?) ?? [];
    return IntegrityReport(
      platform: map['platform'] as String? ?? 'unknown',
      osVersion: map['osVersion'] as String? ?? 'unknown',
      packageVersion: map['packageVersion'] as String? ?? '0.0.0',
      checkTime: map['checkTimeIso'] != null
          ? DateTime.parse(map['checkTimeIso'] as String)
          : DateTime.now().toUtc(),
      findings: rawFindings
          .whereType<Map>()
          .map((e) =>
              IntegrityFinding.fromMap(Map<String, dynamic>.from(e)))
          .toList(growable: false),
    );
  }

  Map<String, dynamic> toMap() => {
        'platform': platform,
        'osVersion': osVersion,
        'packageVersion': packageVersion,
        'checkTimeIso': checkTime.toUtc().toIso8601String(),
        'findings': findings.map((f) => f.toMap()).toList(),
      };

  /// Find all findings with the given [signalId].
  List<IntegrityFinding> findBySignal(String signalId) =>
      findings.where((f) => f.signalId == signalId).toList();

  @override
  String toString() =>
      'IntegrityReport(platform: $platform, os: $osVersion, '
      'findings: ${findings.length})';
}
