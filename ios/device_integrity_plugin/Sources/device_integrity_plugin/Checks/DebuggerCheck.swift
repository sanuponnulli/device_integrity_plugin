import Foundation

/// Detects debugger attachment and debuggable build configuration on iOS.
///
/// Produces two distinct signals:
/// - `debugger_attached`: A debugger (e.g. LLDB) is currently connected.
/// - `debuggable_build`: The app is a DEBUG build (compile-time flag).
class DebuggerCheckiOS: IntegrityCheck {

    func execute() -> [Finding] {
        var findings: [Finding] = []

        // ── Active debugger ─────────────────────────────────────────────
        let isDebugged = isDebuggerAttached()
        if isDebugged {
            findings.append(.detected("debugger_attached", "sysctl_ptrace"))
        } else {
            findings.append(.notDetected("debugger_attached", "no_debugger"))
        }

        // ── Debug build ─────────────────────────────────────────────────
        #if DEBUG
        findings.append(.detected("debuggable_build", "debug_flag_set"))
        #else
        findings.append(.notDetected("debuggable_build", "release_build"))
        #endif

        return findings
    }

    /// Uses sysctl to check the P_TRACED flag, which indicates a debugger
    /// is attached to the current process.
    private func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride

        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result != 0 {
            // sysctl failed — cannot determine debugger status
            return false
        }

        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
}
