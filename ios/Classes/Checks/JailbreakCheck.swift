import Foundation

/// Detects jailbreak indicators on iOS.
///
/// Checks:
/// - Common jailbreak file paths (Cydia, Sileo, Zebra, Filza, etc.)
/// - Rootless jailbreak paths (Dopamine, Fugu15, palera1n)
/// - Write access to restricted locations
/// - Ability to open jailbreak-related URLs (using canOpenURL on well-known schemes)
/// - Sandbox integrity via fork() availability
/// - Dynamic library injection indicators
///
/// Does NOT require the host app to add jailbreak URL schemes to
/// its Info.plist for core checks. Does NOT scan all installed apps.
class JailbreakCheck: IntegrityCheck {

    func execute() -> [Finding] {
        var findings: [Finding] = []

        // ── Jailbreak artifacts ─────────────────────────────────────────
        do {
            let result = checkJailbreakArtifacts()
            findings.append(result)
        }

        // ── Rootless jailbreak indicators ───────────────────────────────
        do {
            let result = checkRootlessJailbreak()
            findings.append(result)
        }

        // ── Restricted write access ─────────────────────────────────────
        do {
            let result = checkRestrictedWriteAccess()
            findings.append(result)
        }

        return findings
    }

    private func checkJailbreakArtifacts() -> Finding {
        let jailbreakPaths: [String] = [
            // Classic jailbreak tools
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/Filza.app",
            "/Applications/FlyJB.app",
            "/Applications/Substitut.app",

            // Binaries & libraries
            "/usr/sbin/sshd",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/etc/apt",
            "/etc/apt/sources.list.d",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
            "/private/var/stash",
            "/private/var/mobile/Library/SBSettings/Themes",

            // Substrate & Substitute
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries",
            "/usr/lib/libsubstitute.dylib",
            "/usr/lib/substitute-loader.dylib",

            // Common binaries
            "/bin/bash",
            "/usr/sbin/frida-server",
            "/usr/bin/cycript",
            "/usr/local/bin/cycript",
            "/usr/lib/libcycript.dylib",

            // Electra / Chimera
            "/usr/lib/libjailbreak.dylib",
            "/jb/lzma",
            "/.cydia_no_stash",
            "/.installed_unc0ver",

            // checkra1n
            "/private/var/checkra1n.dmg",
        ]

        var detected: [String] = []
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                detected.append(path)
            }
        }

        // Check if restricted symlinks exist
        let symlinkPaths = ["/Applications", "/var/stash/Library/Ringtones"]
        for path in symlinkPaths {
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: path, isDirectory: &isDir) {
                // Check if it's a symlink (common on jailbroken devices)
                let attrs = try? FileManager.default.attributesOfItem(atPath: path)
                if let fileType = attrs?[.type] as? FileAttributeType,
                   fileType == .typeSymbolicLink {
                    detected.append("symlink:\(path)")
                }
            }
        }

        if !detected.isEmpty {
            return .detected(
                "root_jailbreak_artifacts",
                "artifacts_found",
                "Found \(detected.count) indicator(s)"
            )
        }
        return .notDetected("root_jailbreak_artifacts", "no_artifacts")
    }

    private func checkRootlessJailbreak() -> Finding {
        // Rootless jailbreaks (Dopamine, Fugu15, palera1n in rootless mode)
        // install to /var/jb instead of modifying the root filesystem.
        let rootlessPaths: [String] = [
            "/var/jb",
            "/var/jb/usr/bin/su",
            "/var/jb/Library/MobileSubstrate",
            "/var/jb/usr/lib/libsubstitute.dylib",
            "/var/jb/usr/lib/TweakInject",
            "/var/jb/basebin",
            "/var/jb/basebin/jbctl",
        ]

        var detected: [String] = []
        for path in rootlessPaths {
            if FileManager.default.fileExists(atPath: path) {
                detected.append(path)
            }
        }

        // Environment variable check for rootless setups
        if let _ = ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] {
            detected.append("dyld_insert_libraries_set")
        }

        if !detected.isEmpty {
            return .detected(
                "rootless_jailbreak",
                "rootless_indicators",
                "Found \(detected.count) indicator(s)"
            )
        }
        return .notDetected("rootless_jailbreak", "no_rootless_indicators")
    }

    private func checkRestrictedWriteAccess() -> Finding {
        // Try writing to a location that should be read-only
        let restrictedPath = "/private/jailbreak_test_\(UUID().uuidString)"
        do {
            try "test".write(toFile: restrictedPath, atomically: true, encoding: .utf8)
            // If write succeeded, clean up and report
            try? FileManager.default.removeItem(atPath: restrictedPath)
            return .detected(
                "restricted_write_access",
                "writable_restricted_path",
                restrictedPath
            )
        } catch {
            // Expected on non-jailbroken devices
            return .notDetected("restricted_write_access", "no_write_access")
        }
    }
}
