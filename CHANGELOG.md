## 0.1.0

- Initial implementation
- **Dart API**: `checkLocalSignals()`, `getCapabilities()`, `createProof()`
- **Android local checks**: Root detection (artifacts, tooling, restricted write access), emulator, debugger (attached + debuggable build), hooking frameworks (Frida, Xposed, Substrate), app tampering (signing, installer), network context (proxy, VPN)
- **iOS local checks**: Jailbreak (classic + rootless), simulator, debugger (sysctl + DEBUG flag), hooking (dylib inspection, Frida), app tampering (provisioning profile, bundle integrity), network context (CFNetwork proxy, interface-based VPN)
- **Android attestation**: Play Integrity client-side token with challenge + request hash binding
- **iOS attestation**: App Attest key generation, attestation, and assertion with challenge binding
- **Sensitive screen**: Android `FLAG_SECURE`, iOS `UIScreen.isCaptured` reporting
- **Example app**: Signal-by-signal dashboard with capability display
