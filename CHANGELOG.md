## 0.2.0

- **Breaking:** Updates the minimum supported SDK version to Flutter 3.44/Dart 3.12.
- Migrates the Android plugin to AGP Built-in Kotlin (no longer applies the Kotlin Gradle Plugin).
- Android now compiles with Java 17, `compileSdk` 36 and `minSdk` 24.
- Adds Swift Package Manager support on iOS (CocoaPods is still supported).
- Raises the iOS minimum deployment target to 13.0.
- Fixes a crash in `checkLocalSignals()` and `createProof()` on Android 7.0/7.1 (API 24-25) caused by `java.time.Instant`.
- Fixes Android VPN detection always reporting `error`: the plugin now declares `ACCESS_NETWORK_STATE` (a normal, install-time permission).

## 0.1.0

- Initial implementation
- **Dart API**: `checkLocalSignals()`, `getCapabilities()`, `createProof()`
- **Android local checks**: Root detection (artifacts, tooling, restricted write access), emulator, debugger (attached + debuggable build), hooking frameworks (Frida, Xposed, Substrate), app tampering (signing, installer), network context (proxy, VPN)
- **iOS local checks**: Jailbreak (classic + rootless), simulator, debugger (sysctl + DEBUG flag), hooking (dylib inspection, Frida), app tampering (provisioning profile, bundle integrity), network context (CFNetwork proxy, interface-based VPN)
- **Android attestation**: Play Integrity client-side token with challenge + request hash binding
- **iOS attestation**: App Attest key generation, attestation, and assertion with challenge binding
- **Sensitive screen**: Android `FLAG_SECURE`, iOS `UIScreen.isCaptured` reporting
- **Example app**: Signal-by-signal dashboard with capability display
