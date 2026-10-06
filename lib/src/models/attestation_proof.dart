/// Opaque proof returned by platform-backed attestation.
///
/// The host app submits this to its backend for server-side verification.
/// The plugin never interprets or validates the token itself.
class AttestationProof {
  /// The attestation provider that produced this proof
  /// (e.g. `"play_integrity"`, `"app_attest"`).
  final String provider;

  /// The raw token / assertion bytes, base64-encoded.
  /// The backend is responsible for decoding and verifying this.
  final String tokenBase64;

  /// The challenge that was bound to this proof.
  final String challenge;

  /// The request hash that was bound to this proof (may be empty if not
  /// applicable to the provider).
  final String? requestHash;

  /// Timestamp when the proof was created (device clock).
  final DateTime createdAt;

  const AttestationProof({
    required this.provider,
    required this.tokenBase64,
    required this.challenge,
    this.requestHash,
    required this.createdAt,
  });

  factory AttestationProof.fromMap(Map<String, dynamic> map) {
    return AttestationProof(
      provider: map['provider'] as String,
      tokenBase64: map['tokenBase64'] as String,
      challenge: map['challenge'] as String,
      requestHash: map['requestHash'] as String?,
      createdAt: map['createdAtIso'] != null
          ? DateTime.parse(map['createdAtIso'] as String)
          : DateTime.now().toUtc(),
    );
  }

  Map<String, dynamic> toMap() => {
        'provider': provider,
        'tokenBase64': tokenBase64,
        'challenge': challenge,
        if (requestHash != null) 'requestHash': requestHash,
        'createdAtIso': createdAt.toUtc().toIso8601String(),
      };

  @override
  String toString() =>
      'AttestationProof(provider: $provider, challenge: $challenge)';
}
