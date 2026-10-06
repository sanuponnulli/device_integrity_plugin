package com.sanuponnulli.device_integrity_plugin.checks

import android.os.Build
import com.sanuponnulli.device_integrity_plugin.models.Finding
import com.sanuponnulli.device_integrity_plugin.models.IntegrityCheck

/**
 * Detects whether the app is running on an Android emulator.
 *
 * Uses multiple heuristics: build properties, hardware characteristics,
 * and known emulator fingerprints. Reported separately from root/jailbreak.
 */
class EmulatorCheck : IntegrityCheck {

    override fun execute(): List<Finding> {
        return try {
            val indicators = mutableListOf<String>()

            // Build fingerprint checks
            val fingerprint = Build.FINGERPRINT.lowercase()
            if (fingerprint.contains("generic") ||
                fingerprint.contains("unknown") ||
                fingerprint.contains("sdk") ||
                fingerprint.contains("vbox") ||
                fingerprint.contains("genymotion")
            ) {
                indicators.add("fingerprint:$fingerprint")
            }

            // Build model checks
            val model = Build.MODEL.lowercase()
            if (model.contains("google_sdk") ||
                model.contains("emulator") ||
                model.contains("android sdk built for") ||
                model.contains("sdk_gphone")
            ) {
                indicators.add("model:${Build.MODEL}")
            }

            // Build hardware checks
            val hardware = Build.HARDWARE.lowercase()
            if (hardware.contains("goldfish") ||
                hardware.contains("ranchu") ||
                hardware.contains("vbox86")
            ) {
                indicators.add("hardware:${Build.HARDWARE}")
            }

            // Build product checks
            val product = Build.PRODUCT.lowercase()
            if (product.contains("sdk") ||
                product.contains("google_sdk") ||
                product.contains("sdk_x86") ||
                product.contains("vbox86p") ||
                product == "emulator"
            ) {
                indicators.add("product:${Build.PRODUCT}")
            }

            // Build manufacturer checks
            val manufacturer = Build.MANUFACTURER.lowercase()
            if (manufacturer.contains("genymotion") ||
                manufacturer.contains("unknown")
            ) {
                indicators.add("manufacturer:${Build.MANUFACTURER}")
            }

            // Build brand check
            if (Build.BRAND.lowercase().startsWith("generic")) {
                indicators.add("brand:${Build.BRAND}")
            }

            // Board check
            if (Build.BOARD.lowercase() == "unknown" ||
                Build.BOARD.lowercase().contains("goldfish")
            ) {
                indicators.add("board:${Build.BOARD}")
            }

            // Qemu properties
            try {
                val qemuProp = getSystemProperty("ro.kernel.qemu")
                if (qemuProp == "1") {
                    indicators.add("qemu_property")
                }
            } catch (_: Exception) {}

            if (indicators.isNotEmpty()) {
                listOf(
                    Finding.detected(
                        SIGNAL_EMULATOR,
                        "emulator_indicators",
                        indicators.joinToString(", ")
                    )
                )
            } else {
                listOf(
                    Finding.notDetected(SIGNAL_EMULATOR, "no_emulator_indicators")
                )
            }
        } catch (e: Exception) {
            listOf(
                Finding.error(SIGNAL_EMULATOR, "check_exception", e.message)
            )
        }
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
        const val SIGNAL_EMULATOR = "emulator_simulator"
    }
}
