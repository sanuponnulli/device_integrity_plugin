/// Device Integrity Plugin
///
/// Reports separate, explainable integrity signals and supports
/// platform-backed attestation for server verification.
///
/// ## Quick start
/// ```dart
/// import 'package:device_integrity/device_integrity.dart';
///
/// final plugin = DeviceIntegrityPlugin.instance;
///
/// // 1. Check what's available
/// final caps = await plugin.getCapabilities();
///
/// // 2. Run local checks (no network)
/// final report = await plugin.checkLocalSignals();
/// for (final f in report.findings) {
///   print('${f.signalId}: ${f.status} (${f.reasonCode})');
/// }
///
/// // 3. Request attestation for backend verification
/// final proof = await plugin.createProof(
///   challenge: serverChallenge,
///   requestHash: sha256OfRequest,
/// );
/// // Submit proof.tokenBase64 to your backend
/// ```
library device_integrity;

export 'src/device_integrity_plugin.dart';
export 'src/models/attestation_proof.dart';
export 'src/models/capability.dart';
export 'src/models/finding_source.dart';
export 'src/models/finding_status.dart';
export 'src/models/integrity_finding.dart';
export 'src/models/integrity_report.dart';
export 'src/models/signal_id.dart';
export 'src/platform/device_integrity_platform.dart';
