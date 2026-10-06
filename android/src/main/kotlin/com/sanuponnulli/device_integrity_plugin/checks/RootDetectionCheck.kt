package com.sanuponnulli.device_integrity_plugin.checks

import com.sanuponnulli.device_integrity_plugin.models.Finding
import com.sanuponnulli.device_integrity_plugin.models.IntegrityCheck
import java.io.File

/**
 * Detects root indicators on Android.
 *
 * Checks:
 * - Common su binary locations
 * - Known root management app paths
 * - Magisk and other root-hiding tool indicators
 * - Write access to restricted locations
 * - Build tags indicating test-keys
 *
 * Does NOT scan all installed applications or treat developer options
 * or external storage alone as proof of root.
 */
class RootDetectionCheck : IntegrityCheck {

    override fun execute(): List<Finding> {
        val findings = mutableListOf<Finding>()

        // ── Root artifacts ──────────────────────────────────────────────
        try {
            val artifactResult = checkRootArtifacts()
            findings.add(artifactResult)
        } catch (e: Exception) {
            findings.add(
                Finding.error(
                    SIGNAL_ROOT_ARTIFACTS,
                    "check_exception",
                    e.message
                )
            )
        }

        // ── Root tooling runtime indicators ─────────────────────────────
        try {
            val toolingResult = checkRootTooling()
            findings.add(toolingResult)
        } catch (e: Exception) {
            findings.add(
                Finding.error(
                    SIGNAL_ROOT_TOOLING,
                    "check_exception",
                    e.message
                )
            )
        }

        // ── Restricted write access ─────────────────────────────────────
        try {
            val writeResult = checkRestrictedWriteAccess()
            findings.add(writeResult)
        } catch (e: Exception) {
            findings.add(
                Finding.error(
                    SIGNAL_RESTRICTED_WRITE,
                    "check_exception",
                    e.message
                )
            )
        }

        return findings
    }

    private fun checkRootArtifacts(): Finding {
        val detectedPaths = mutableListOf<String>()

        // su binary in common locations
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/su",
            "/system/usr/we-need-root/su",
            "/system/app/Superuser.apk",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
        )
        for (path in suPaths) {
            if (File(path).exists()) {
                detectedPaths.add(path)
            }
        }

        // Known root management artifacts
        val rootManagementPaths = listOf(
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/app/SuperSU",
            "/system/etc/init.d/99telecom",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/data/adb/ksu",           // KernelSU
            "/data/adb/ap",            // APatch
        )
        for (path in rootManagementPaths) {
            if (File(path).exists()) {
                detectedPaths.add(path)
            }
        }

        // Test-keys in build tags
        val buildTags = android.os.Build.TAGS ?: ""
        if (buildTags.contains("test-keys")) {
            detectedPaths.add("build_tags:test-keys")
        }

        return if (detectedPaths.isNotEmpty()) {
            Finding.detected(
                SIGNAL_ROOT_ARTIFACTS,
                "artifacts_found",
                "Found ${detectedPaths.size} indicator(s)"
            )
        } else {
            Finding.notDetected(SIGNAL_ROOT_ARTIFACTS, "no_artifacts")
        }
    }

    private fun checkRootTooling(): Finding {
        val indicators = mutableListOf<String>()

        // Check for common root-related system properties
        val dangerousProps = mapOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0",
        )
        for ((prop, badValue) in dangerousProps) {
            try {
                val value = getSystemProperty(prop)
                if (value == badValue) {
                    indicators.add("$prop=$value")
                }
            } catch (_: Exception) {
                // Property not readable — not an indicator
            }
        }

        // Check if su is executable
        try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val exitCode = process.waitFor()
            if (exitCode == 0) {
                indicators.add("su_in_path")
            }
            process.destroy()
        } catch (_: Exception) {
            // Expected on non-rooted devices
        }

        // Magisk-specific: check for magisk binary
        try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "magisk"))
            val exitCode = process.waitFor()
            if (exitCode == 0) {
                indicators.add("magisk_binary")
            }
            process.destroy()
        } catch (_: Exception) {
            // Expected on non-rooted devices
        }

        return if (indicators.isNotEmpty()) {
            Finding.detected(
                SIGNAL_ROOT_TOOLING,
                "tooling_detected",
                indicators.joinToString(", ")
            )
        } else {
            Finding.notDetected(SIGNAL_ROOT_TOOLING, "no_tooling")
        }
    }

    private fun checkRestrictedWriteAccess(): Finding {
        val writablePaths = listOf(
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin",
            "/sbin",
            "/etc",
        )

        for (path in writablePaths) {
            val file = File(path)
            if (file.exists() && file.canWrite()) {
                return Finding.detected(
                    SIGNAL_RESTRICTED_WRITE,
                    "writable_restricted_path",
                    path
                )
            }
        }

        return Finding.notDetected(SIGNAL_RESTRICTED_WRITE, "no_write_access")
    }

    @Suppress("PrivateApi")
    private fun getSystemProperty(key: String): String? {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            method.invoke(null, key) as? String
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        const val SIGNAL_ROOT_ARTIFACTS = "root_jailbreak_artifacts"
        const val SIGNAL_ROOT_TOOLING = "root_jailbreak_tooling"
        const val SIGNAL_RESTRICTED_WRITE = "restricted_write_access"
    }
}
