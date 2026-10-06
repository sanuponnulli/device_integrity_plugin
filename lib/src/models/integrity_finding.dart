import 'finding_source.dart';
import 'finding_status.dart';

/// A single integrity observation.
///
/// Each finding carries its own [status] so that errors in one check never
/// erase results from other checks. The [signalId] is a stable string —
/// unknown IDs from native code are preserved verbatim.
class IntegrityFinding {
  /// A stable identifier for the signal (see [SignalId] for well-known
  /// values). Unknown IDs are kept as-is; they are never collapsed.
  final String signalId;

  /// Whether the condition was detected, not detected, unavailable, or error.
  final FindingStatus status;

  /// Where this finding originated.
  final FindingSource source;

  /// A stable, machine-readable reason code giving more detail.
  /// Examples: `"su_binary_found"`, `"ptrace_denied"`, `"api_too_low"`.
  final String reasonCode;

  /// Optional human-readable detail (debug builds only; may be empty).
  final String? detail;

  const IntegrityFinding({
    required this.signalId,
    required this.status,
    required this.source,
    required this.reasonCode,
    this.detail,
  });

  /// Deserialise from the platform-channel map.
  ///
  /// Unknown [signalId] values are preserved verbatim — this is critical
  /// for forward-compatibility.
  factory IntegrityFinding.fromMap(Map<String, dynamic> map) {
    return IntegrityFinding(
      signalId: map['signalId'] as String,
      status: FindingStatus.fromString(map['status'] as String),
      source: FindingSource.fromString(map['source'] as String),
      reasonCode: (map['reasonCode'] as String?) ?? 'unknown',
      detail: map['detail'] as String?,
    );
  }

  Map<String, dynamic> toMap() => {
        'signalId': signalId,
        'status': status.toJson(),
        'source': source.toJson(),
        'reasonCode': reasonCode,
        if (detail != null) 'detail': detail,
      };

  @override
  String toString() =>
      'IntegrityFinding(signalId: $signalId, status: $status, '
      'source: $source, reasonCode: $reasonCode)';
}
