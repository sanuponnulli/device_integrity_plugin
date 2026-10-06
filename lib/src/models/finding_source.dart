/// Where a finding originated.
enum FindingSource {
  /// Result of a local on-device check (no network call).
  local,

  /// Result derived from a platform attestation service
  /// (Play Integrity, App Attest).
  platformAttestation;

  static FindingSource fromString(String value) {
    switch (value) {
      case 'local':
        return FindingSource.local;
      case 'platformAttestation':
        return FindingSource.platformAttestation;
      default:
        return FindingSource.local;
    }
  }

  String toJson() => name;
}
