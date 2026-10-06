/// Stable status of an individual integrity finding.
///
/// Every check produces exactly one of these values.
/// [unavailable] means the check cannot run on this platform/device.
/// [error] means the check ran but failed internally — it must not be
/// interpreted as [notDetected].
enum FindingStatus {
  /// The condition was positively detected (e.g. root artifacts found).
  detected,

  /// The condition was explicitly not detected after a successful check.
  notDetected,

  /// The check is not available on this platform, OS version, or device
  /// configuration. The host app should treat this as "we don't know."
  unavailable,

  /// The check attempted to run but encountered an internal error.
  /// The [IntegrityFinding.reasonCode] carries context.
  error;

  static FindingStatus fromString(String value) {
    switch (value) {
      case 'detected':
        return FindingStatus.detected;
      case 'notDetected':
        return FindingStatus.notDetected;
      case 'unavailable':
        return FindingStatus.unavailable;
      case 'error':
        return FindingStatus.error;
      default:
        // Unknown statuses from future native code become errors with
        // the original value preserved in the finding's reasonCode.
        return FindingStatus.error;
    }
  }

  String toJson() => name;
}
