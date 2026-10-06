# device_integrity_plugin

A reusable Flutter plugin that reports **separate, explainable integrity signals** and supports **platform-backed attestation** for server-side verification.

## Design principles

| Principle | What this means |
|---|---|
| **Signals are distinct** | Root/jailbreak, emulator, debugger, proxy, hooking, and app-tampering are independent findings — never collapsed into one verdict. |
| **No single `isSafe` flag** | The plugin reports observations. Your backend makes policy decisions. |
| **Errors are honest** | A check that fails returns `error`, not `notDetected`. `unavailable` means the check can't run. |
| **Unknown IDs survive** | Future native signal IDs pass through Dart unchanged — no data loss. |
| **Attestation is request-bound** | Proofs are tied to a backend challenge and optional request hash. Server verifies. |
| **No automatic telemetry** | The plugin sends nothing off-device. The host app controls data flow. |

## Quick start

```dart
import 'package:device_integrity_plugin/device_integrity_plugin.dart';

final plugin = DeviceIntegrityPlugin.instance;

// 1. What checks are available?
final capabilities = await plugin.getCapabilities();

// 2. Run local checks (offline, no network)
final report = await plugin.checkLocalSignals();
for (final finding in report.findings) {
  print('${finding.signalId}: ${finding.status} (${finding.reasonCode})');
}

// 3. Request attestation for a banking transaction
final proof = await plugin.createProof(
  challenge: serverNonce,       // from your backend
  requestHash: sha256OfBody,    // optional
  // keyId: appAttestKeyId,     // required on iOS after key attestation
);
// Submit proof.tokenBase64 to your backend for verification
```

On Android, configure the Google Cloud project number used by Play Integrity
in the host app's `android/app/src/main/AndroidManifest.xml` inside the
`<application>` element. The project number is public configuration, not a
credential:

```xml
<meta-data
    android:name="com.sanuponnulli.device_integrity_plugin.CLOUD_PROJECT_NUMBER"
    android:value="123456789012" />
```

Android binds both the challenge and optional request hash into the Play
Integrity Standard API `requestHash`. The backend must recompute the documented
binding hash from its stored challenge and expected request hash, then compare
it with the decoded token's `requestHash` claim. The host app must not treat the
proof's echoed challenge or request hash as trusted by themselves.

The bound value is base64url without padding over SHA-256 of this UTF-8 string:
`device-integrity-v1\n<challenge-length>:<challenge>\n<request-hash-length>:<request-hash>`.
Lengths are Dart/Kotlin string lengths; when the optional request hash is
omitted, its length is `-1` and its value is empty. For example, the backend
can reproduce it with:

```dart
final bindingInput =
    'device-integrity-v1\n${challenge.length}:$challenge\n'
    '${requestHash?.length ?? -1}:${requestHash ?? ''}';
final expectedRequestHash = base64Url
    .encode(sha256.convert(utf8.encode(bindingInput)).bytes)
    .replaceAll('=', '');
```

This snippet needs `dart:convert` and `package:crypto/crypto.dart` in the
backend. Compare `expectedRequestHash` to the decoded Play Integrity token's
`requestDetails.requestHash` value.

## API

### `checkLocalSignals() → Future<IntegrityReport>`

Runs all available local checks. Returns one `IntegrityFinding` per check, each with:

| Field | Type | Description |
|---|---|---|
| `signalId` | `String` | Stable identifier (see [Signal IDs](#signal-ids)) |
| `status` | `FindingStatus` | `detected` · `notDetected` · `unavailable` · `error` |
| `source` | `FindingSource` | `local` · `platformAttestation` |
| `reasonCode` | `String` | Machine-readable reason (e.g. `su_binary_found`) |
| `detail` | `String?` | Optional human-readable context |

### `getCapabilities() → Future<List<IntegrityCapability>>`

Reports which checks and attestation providers are available, with minimum OS versions and unavailability reasons.

### `createProof({challenge, requestHash, keyId}) → Future<AttestationProof>`

Requests a platform attestation token:
- **Android**: Play Integrity token (backend decodes via Google API)
- **iOS**: App Attest assertion (backend verifies via Apple guidelines)

### iOS App Attest lifecycle

```dart
// One-time: generate and attest a key
final keyId = await plugin.generateAppAttestKey();
final attestation = await plugin.attestAppAttestKey(
  keyId: keyId,
  challenge: serverChallenge,
);
// Send attestation to backend → backend stores public key

// Per-request: generate assertions
final proof = await plugin.createProof(
  challenge: newChallenge,
  requestHash: sha256OfRequest,
  keyId: keyId,
);
```

### Sensitive screen protection

```dart
// Android: block screenshots/recording
await plugin.setSecureScreen(true);

// iOS: check if screen is being captured
final captured = await plugin.isScreenBeingCaptured();
if (captured) {
  // Overlay or hide sensitive content
}
```

## Signal IDs

| Signal ID | Category | Description |
|---|---|---|
| `root_jailbreak_artifacts` | Root/JB | Common root or jailbreak file artifacts |
| `restricted_write_access` | Root/JB | Write access to restricted locations |
| `root_jailbreak_tooling` | Root/JB | Root management tooling (su, Magisk, etc.) |
| `rootless_jailbreak` | Root/JB | Rootless jailbreak indicators (iOS) |
| `emulator_simulator` | Environment | Emulator or simulator detection |
| `debugger_attached` | Debug | Active debugger connection |
| `debuggable_build` | Debug | Debug build configuration |
| `hooking_framework` | Instrumentation | Frida, Xposed, Substrate indicators |
| `signing_anomaly` | App integrity | Unexpected signing configuration |
| `installer_anomaly` | App integrity | Unexpected installation source |
| `proxy_configured` | Network | HTTP proxy configuration detected |
| `vpn_active` | Network | VPN interface active |
| `screen_capture_active` | Screen | Screen recording/mirroring active (iOS) |

## Platform support

| Feature | Android | iOS |
|---|---|---|
| Local checks | API 21+ | iOS 12+ |
| VPN detection | API 23+ | iOS 12+ |
| Play Integrity | Requires Play Services | — |
| App Attest | — | iOS 14+ (physical device) |
| Secure screen | `FLAG_SECURE` | Report only (`isCaptured`) |

## Server-side verification

### Play Integrity (Android)

1. Backend creates a high-entropy, single-use challenge with short expiry
2. App calls `createProof(challenge: challenge, requestHash: sha256OfBody)`
3. App sends `proof.tokenBase64` to backend
4. Backend calls Google Play Integrity API to decode the token
5. Backend recomputes the bound request hash from the challenge and request hash, verifies it against the token, and checks device/app verdicts against policy

**References:**
- [Play Integrity overview](https://developer.android.com/google/play/integrity/overview)
- [Standard requests](https://developer.android.com/google/play/integrity/standard)
- [Verdict details](https://developer.android.com/google/play/integrity/verdicts)

### App Attest (iOS)

1. One-time: app generates key, attests it with backend challenge, backend stores public key
2. Per-request: app generates assertion with new challenge + request hash
3. Backend verifies assertion signature, challenge, and enforces monotonically increasing counter

**References:**
- [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- [DCAppAttestService.isSupported](https://developer.apple.com/documentation/devicecheck/dcappattestservice/issupported)

## Privacy

- No automatic telemetry or uploads
- No device fingerprint or device identifier retained
- No installed-app scanning or broad URL-scheme queries
- Host app controls what data leaves the device and when
- Document which provider data leaves the device (attestation tokens are sent to platform servers by the OS; local checks never leave the device)

## Limitations

- **No guarantee of safety**: Client-side checks can be bypassed by a sufficiently motivated attacker. Attestation adds a stronger signal but is not infallible.
- **Heuristic-based**: Hooking and root detection use heuristic indicators, not definitive proofs.
- **Device-specific**: `FLAG_SECURE` behavior varies by OEM. Screen capture detection on iOS cannot prevent physical photography.
- **Detection rates**: Do not advertise measured detection rates until tested on a documented device and OS matrix.

## Release validation

See [doc/RELEASE_CHECKLIST.md](doc/RELEASE_CHECKLIST.md) for the automated,
physical-device, attestation, and pub.dev checks used before a release.

## Project structure

```
device_integrity_plugin/
├── lib/
│   ├── device_integrity_plugin.dart   # Barrel export
│   └── src/
│       ├── device_integrity_plugin.dart   # Main API
│       ├── models/                    # Dart models
│       └── platform/                  # Platform interface
├── android/src/main/kotlin/.../
│   ├── DeviceIntegrityPlugin.kt       # Android plugin entry
│   ├── checks/                        # Independent check modules
│   ├── attestation/                   # Play Integrity provider
│   └── screen/                        # FLAG_SECURE guard
├── ios/Classes/
│   ├── DeviceIntegrityPlugin.swift    # iOS plugin entry
│   ├── Checks/                        # Independent check modules
│   ├── Attestation/                   # App Attest provider
│   └── Screen/                        # Capture detection
├── example/                           # Demo app
└── test/                              # Dart unit tests
```

## License

MIT
