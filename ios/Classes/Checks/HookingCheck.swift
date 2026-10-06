import Foundation
import MachO
import Darwin

/// Detects common hooking and instrumentation frameworks on iOS.
///
/// Checks:
/// - Frida (dylib presence, port, environment variables)
/// - Substrate / Substitute / TweakInject
/// - DYLD_INSERT_LIBRARIES
/// - Suspicious loaded dylibs via _dyld_image_count
///
/// Reported as a heuristic — not proof of malicious compromise.
class HookingCheckiOS: IntegrityCheck {

    func execute() -> [Finding] {
        var indicators: [String] = []

        // ── DYLD_INSERT_LIBRARIES ───────────────────────────────────────
        if let dyldInsert = ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] {
            indicators.append("dyld_insert_libraries:\(dyldInsert)")
        }

        // ── Loaded dylib inspection ─────────────────────────────────────
        let suspiciousNames = [
            "FridaGadget",
            "frida-agent",
            "libcycript",
            "MobileSubstrate",
            "libsubstitute",
            "SubstrateLoader",
            "SubstrateInserter",
            "TweakInject",
            "SSLKillSwitch",
            "ssl_kill_switch",
            "objection",
        ]

        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            guard let imageName = _dyld_get_image_name(i) else { continue }
            let name = String(cString: imageName)
            for suspicious in suspiciousNames {
                if name.localizedCaseInsensitiveContains(suspicious) {
                    indicators.append("loaded_dylib:\(suspicious)")
                }
            }
        }

        // ── Frida port check ────────────────────────────────────────────
        if isFridaPortOpen() {
            indicators.append("frida_default_port_open")
        }

        // ── Frida artifacts on disk ─────────────────────────────────────
        let fridaPaths = [
            "/usr/sbin/frida-server",
            "/usr/bin/frida-server",
            "/usr/local/bin/frida-server",
            "/var/jb/usr/sbin/frida-server",
        ]
        for path in fridaPaths {
            if FileManager.default.fileExists(atPath: path) {
                indicators.append("frida_artifact:\(path)")
            }
        }

        if !indicators.isEmpty {
            return [.detected(
                "hooking_framework",
                "hooking_indicators",
                "\(indicators.count) indicator(s): \(indicators.prefix(5).joined(separator: ", "))"
            )]
        }
        return [.notDetected("hooking_framework", "no_hooking_indicators")]
    }

    private func isFridaPortOpen() -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = CFSwapInt16HostToBig(27042) // Frida default port
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        // Set non-blocking
        let flags = fcntl(sock, F_GETFL, 0)
        fcntl(sock, F_SETFL, flags | O_NONBLOCK)

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                Darwin.connect(sock, ptr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if result == 0 {
            return true
        }

        // Check if connection is in progress
        if errno == EINPROGRESS {
            var descriptor = pollfd(
                fd: sock,
                events: Int16(POLLOUT),
                revents: 0
            )
            guard poll(&descriptor, 1, 200) > 0 else { return false }

            var socketError: Int32 = 0
            var errorLength = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(
                sock,
                SOL_SOCKET,
                SO_ERROR,
                &socketError,
                &errorLength
            ) == 0 else { return false }
            return socketError == 0
        }

        return false
    }
}
