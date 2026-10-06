/// Describes a single capability that the plugin can provide on this
/// device/app combination.
class IntegrityCapability {
  /// Capability identifier (matches a [SignalId] or attestation provider name).
  final String id;

  /// Whether this capability is available right now.
  final bool available;

  /// If [available] is `false`, the reason why (e.g. `"api_level_too_low"`,
  /// `"play_services_missing"`, `"unsupported_device"`).
  final String? unavailableReason;

  /// Minimum OS version required, if applicable.
  final String? minimumOsVersion;

  const IntegrityCapability({
    required this.id,
    required this.available,
    this.unavailableReason,
    this.minimumOsVersion,
  });

  factory IntegrityCapability.fromMap(Map<String, dynamic> map) {
    return IntegrityCapability(
      id: map['id'] as String,
      available: map['available'] as bool? ?? false,
      unavailableReason: map['unavailableReason'] as String?,
      minimumOsVersion: map['minimumOsVersion'] as String?,
    );
  }

  Map<String, dynamic> toMap() => {
        'id': id,
        'available': available,
        if (unavailableReason != null) 'unavailableReason': unavailableReason,
        if (minimumOsVersion != null) 'minimumOsVersion': minimumOsVersion,
      };

  @override
  String toString() => 'IntegrityCapability(id: $id, available: $available'
      '${unavailableReason != null ? ', reason: $unavailableReason' : ''})';
}
