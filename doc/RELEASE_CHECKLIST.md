# Release validation checklist

Complete this checklist for the exact source revision intended for release.
Record the revision, test date, device and OS versions, build type, and outcome
for each manual run. A local detector result is an observation, not a security
verdict.

## Automated checks

- [ ] `flutter pub get`
- [ ] `flutter analyze --fatal-infos`
- [ ] `flutter test`
- [ ] Run the package on the minimum supported Flutter release and current
  stable Flutter; verify CI passes on both.
- [ ] Build the example for Android and iOS. The CI Android build also checks
  16 KB native-library alignment and APK alignment.
- [ ] `flutter pub outdated`; review incompatible or stale dependencies.
- [ ] `dart doc --output /tmp/device-integrity-docs`; review generated API docs.
- [ ] `flutter pub publish --dry-run`; inspect the exact file list and resolve
  every warning before publishing.
- [ ] Run `pana` against a disposable copy of the package and review its report.

## Android physical-device checks

Use at least one Google Play certified device on the oldest Android version the
release supports and one current Android device. Also use an emulator for the
environment detection path. Record exact model and API level.

- [ ] Local checks return a complete report; an individual failure does not
  suppress other findings.
- [ ] Run with and without a configured HTTP proxy and with VPN disconnected
  and connected. Confirm findings track the configured state.
- [ ] Verify debugger-attached and debuggable-build results separately.
- [ ] Verify secure-screen enable/disable on the foreground Activity by trying
  a screenshot and screen recording; confirm behavior after Activity recreation.
- [ ] Request Play Integrity from an eligible Play-installed test build and
  from a device/configuration where Play services or the provider is
  unavailable. Confirm errors and unavailable capabilities are explicit.
- [ ] Configure `com.sanuponnulli.device_integrity_plugin.CLOUD_PROJECT_NUMBER` in the
  host app manifest and verify the backend can recompute the challenge and
  request-hash binding documented in the README.
- [ ] Test app installed from the intended distribution channel and a sideload
  where installer detection is expected to differ.

## iOS physical-device checks

Use a physical supported iPhone for App Attest; simulator runs do not establish
App Attest readiness. Include the oldest supported iOS version for local checks
and a supported iOS 14+ device for App Attest.

- [ ] Local checks return a complete report; simulator and device findings are
  distinguishable and individual failures do not suppress other findings.
- [ ] Run with and without proxy and VPN configurations and record observed
  results.
- [ ] Verify screen-capture state changes while recording/mirroring and confirm
  the app can react to the reported state. Physical photography is out of
  scope for this signal.
- [ ] Generate a key, attest it with a backend challenge, persist the key ID in
  the host app, then generate an assertion with that key ID.
- [ ] Verify unsupported devices and unavailable App Attest report a clear
  platform error/capability state.

## Backend attestation checks

Use a non-production backend and the same verifier logic intended for
production. Keep Google and Apple server credentials off-device.

- [ ] Verify valid Play Integrity tokens and App Attest key attestations and
  assertions on the server.
- [ ] Confirm the verifier binds the expected app identity, challenge, and
  request hash; enforce assertion counters for App Attest.
- [ ] Reject expired, unknown, reused, or altered challenges and altered
  request bodies.
- [ ] Confirm a valid client proof alone does not bypass the server's policy
  checks or create a client-side `safe` verdict.

## Package publication review

- [ ] Confirm package name, version, repository, homepage, issue tracker,
  license, README, and changelog are accurate and match the release.
- [ ] Confirm the package name is available to this publisher on pub.dev.
- [ ] Review the dry-run archive for generated files, local caches, secrets,
  and missing source or documentation.
- [ ] Confirm README examples compile against the shipped public API,
  especially the iOS App Attest key ID required by `createProof`.
- [ ] Publish only after all automated checks and required device/backend
  validations above are recorded as passing.
