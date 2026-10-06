package com.sanuponnulli.device_integrity_plugin.checks

import android.os.Build
import com.sanuponnulli.device_integrity_plugin.models.Finding
import com.sanuponnulli.device_integrity_plugin.models.IntegrityCheck
import java.io.BufferedReader
import java.io.File
import java.io.FileReader

/**
 * Detects common hooking and instrumentation frameworks.
 *
 * Checks for:
 * - Frida (server process, gadget library, named pipes)
 * - Xposed framework (class presence, JAR files)
 * - Substrate / Cydia Substrate for Android
 * - Common hooking libraries loaded in the process
 *
 * This is reported as a heuristic — presence of indicators suggests
 * instrumentation but is not proof of malicious compromise.
 */
class HookingCheck : IntegrityCheck {

    override fun execute(): List<Finding> {
        return try {
            val indicators = mutableListOf<String>()

            // ── Frida indicators ────────────────────────────────────────
            checkFridaIndicators(indicators)

            // ── Xposed indicators ───────────────────────────────────────
            checkXposedIndicators(indicators)

            // ── Substrate indicators ────────────────────────────────────
            checkSubstrateIndicators(indicators)

            // ── Loaded libraries (from /proc/self/maps) ─────────────────
            checkLoadedLibraries(indicators)

            if (indicators.isNotEmpty()) {
                listOf(
                    Finding.detected(
                        SIGNAL_HOOKING,
                        "hooking_indicators",
                        "${indicators.size} indicator(s): ${indicators.take(5).joinToString(", ")}"
                    )
                )
            } else {
                listOf(
                    Finding.notDetected(SIGNAL_HOOKING, "no_hooking_indicators")
                )
            }
        } catch (e: Exception) {
            listOf(
                Finding.error(SIGNAL_HOOKING, "check_exception", e.message)
            )
        }
    }

    private fun checkFridaIndicators(indicators: MutableList<String>) {
        // Frida default listening port
        try {
            val socket = java.net.Socket()
            socket.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 200)
            socket.close()
            indicators.add("frida_default_port_open")
        } catch (_: Exception) {
            // Port not open — expected
        }

        // Frida named pipes
        val fridaPipes = listOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
        )
        for (path in fridaPipes) {
            if (File(path).exists()) {
                indicators.add("frida_artifact:$path")
            }
        }

        // Frida gadget in loaded native libraries
        try {
            val mapsFile = File("/proc/self/maps")
            if (mapsFile.exists()) {
                BufferedReader(FileReader(mapsFile)).use { reader ->
                    reader.lineSequence().forEach { line ->
                        val lower = line.lowercase()
                        if (lower.contains("frida") ||
                            lower.contains("gadget")
                        ) {
                            indicators.add("frida_in_maps")
                            return@forEach
                        }
                    }
                }
            }
        } catch (_: Exception) {}
    }

    private fun checkXposedIndicators(indicators: MutableList<String>) {
        // Xposed installer paths
        val xposedPaths = listOf(
            "/system/framework/XposedBridge.jar",
            "/system/bin/app_process.orig",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/data/adb/lspd",          // LSPosed
            "/data/adb/modules/zygisk_lsposed",
        )
        for (path in xposedPaths) {
            if (File(path).exists()) {
                indicators.add("xposed_artifact:$path")
            }
        }

        // Try to load Xposed class
        try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            indicators.add("xposed_class_loaded")
        } catch (_: ClassNotFoundException) {
            // Expected on non-hooked devices
        }

        // Check stack trace for Xposed
        try {
            val stackTrace = Thread.currentThread().stackTrace
            for (element in stackTrace) {
                val className = element.className.lowercase()
                if (className.contains("xposed") ||
                    className.contains("lsposed")
                ) {
                    indicators.add("xposed_in_stacktrace")
                    break
                }
            }
        } catch (_: Exception) {}
    }

    private fun checkSubstrateIndicators(indicators: MutableList<String>) {
        val substratePaths = listOf(
            "/data/local/tmp/com.saurik.substrate",
            "/system/lib/libsubstrate.so",
            "/system/lib/libsubstrate-dvm.so",
        )
        for (path in substratePaths) {
            if (File(path).exists()) {
                indicators.add("substrate_artifact:$path")
            }
        }

        try {
            Class.forName("com.saurik.substrate.MS")
            indicators.add("substrate_class_loaded")
        } catch (_: ClassNotFoundException) {}
    }

    private fun checkLoadedLibraries(indicators: MutableList<String>) {
        val suspiciousLibs = listOf(
            "libsubstrate",
            "libxposed",
            "libfrida",
            "libgadget",
            "libredirect",      // Various hooking redirectors
        )

        try {
            val mapsFile = File("/proc/self/maps")
            if (mapsFile.exists()) {
                BufferedReader(FileReader(mapsFile)).use { reader ->
                    reader.lineSequence().forEach { line ->
                        val lower = line.lowercase()
                        for (lib in suspiciousLibs) {
                            if (lower.contains(lib)) {
                                indicators.add("suspicious_lib:$lib")
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {}
    }

    companion object {
        const val SIGNAL_HOOKING = "hooking_framework"
    }
}
