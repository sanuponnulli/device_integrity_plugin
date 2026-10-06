package com.example.device_integrity.checks

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import com.example.device_integrity.models.Finding
import com.example.device_integrity.models.IntegrityCheck

/**
 * Detects debugger attachment and debuggable build configuration.
 *
 * These are reported as two distinct signals:
 * - [SIGNAL_DEBUGGER_ATTACHED]: A debugger is currently connected.
 * - [SIGNAL_DEBUGGABLE_BUILD]: The APK was built with android:debuggable=true.
 *
 * This lets the host app distinguish a development build from an
 * active debugging session in production.
 */
class DebuggerCheck(private val context: Context) : IntegrityCheck {

    override fun execute(): List<Finding> {
        val findings = mutableListOf<Finding>()

        // ── Active debugger attachment ──────────────────────────────────
        try {
            val isDebuggerConnected = Debug.isDebuggerConnected()
            findings.add(
                if (isDebuggerConnected) {
                    Finding.detected(
                        SIGNAL_DEBUGGER_ATTACHED,
                        "debugger_connected"
                    )
                } else {
                    // Also check waitingForDebugger as a secondary signal
                    if (Debug.waitingForDebugger()) {
                        Finding.detected(
                            SIGNAL_DEBUGGER_ATTACHED,
                            "waiting_for_debugger"
                        )
                    } else {
                        Finding.notDetected(
                            SIGNAL_DEBUGGER_ATTACHED,
                            "no_debugger"
                        )
                    }
                }
            )
        } catch (e: Exception) {
            findings.add(
                Finding.error(
                    SIGNAL_DEBUGGER_ATTACHED,
                    "check_exception",
                    e.message
                )
            )
        }

        // ── Debuggable build flag ──────────────────────────────────────
        try {
            val appInfo = context.applicationInfo
            val isDebuggable =
                (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

            findings.add(
                if (isDebuggable) {
                    Finding.detected(SIGNAL_DEBUGGABLE_BUILD, "flag_debuggable_set")
                } else {
                    Finding.notDetected(
                        SIGNAL_DEBUGGABLE_BUILD,
                        "flag_debuggable_not_set"
                    )
                }
            )
        } catch (e: Exception) {
            findings.add(
                Finding.error(
                    SIGNAL_DEBUGGABLE_BUILD,
                    "check_exception",
                    e.message
                )
            )
        }

        return findings
    }

    companion object {
        const val SIGNAL_DEBUGGER_ATTACHED = "debugger_attached"
        const val SIGNAL_DEBUGGABLE_BUILD = "debuggable_build"
    }
}
