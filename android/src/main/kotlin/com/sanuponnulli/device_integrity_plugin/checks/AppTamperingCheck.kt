package com.sanuponnulli.device_integrity_plugin.checks

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.sanuponnulli.device_integrity_plugin.models.Finding
import com.sanuponnulli.device_integrity_plugin.models.IntegrityCheck

/**
 * Checks app configuration and tampering indicators.
 *
 * Produces two distinct findings:
 * - Signing anomaly: whether the app's signing certificate(s) match
 *   an expected set (if configured).
 * - Installer anomaly: whether the installer source is unexpected.
 *
 * Does NOT require the host app to declare external URL schemes or
 * scan all installed packages.
 */
class AppTamperingCheck(private val context: Context) : IntegrityCheck {

    override fun execute(): List<Finding> {
        val findings = mutableListOf<Finding>()

        // ── Signing information ─────────────────────────────────────────
        findings.add(checkSigningInfo())

        // ── Installer source ────────────────────────────────────────────
        findings.add(checkInstaller())

        return findings
    }

    @Suppress("DEPRECATION")
    private fun checkSigningInfo(): Finding {
        return try {
            val packageName = context.packageName
            val signingInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val pi = context.packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signers = pi.signingInfo
                if (signers != null && signers.hasMultipleSigners()) {
                    // Multiple signers could be anomalous for most apps
                    return Finding.detected(
                        SIGNAL_SIGNING_ANOMALY,
                        "multiple_signers",
                        "App has multiple signing certificates"
                    )
                }
                val certs = signers?.apkContentsSigners
                certs?.map { sig ->
                    sig.toByteArray().let {
                        java.security.MessageDigest.getInstance("SHA-256")
                            .digest(it)
                            .joinToString("") { b -> "%02x".format(b) }
                    }
                } ?: emptyList()
            } else {
                @Suppress("DEPRECATION")
                val pi = context.packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES
                )
                pi.signatures?.map { sig ->
                    sig.toByteArray().let {
                        java.security.MessageDigest.getInstance("SHA-256")
                            .digest(it)
                            .joinToString("") { b -> "%02x".format(b) }
                    }
                } ?: emptyList()
            }

            // We report the signing hashes as detail so the backend can
            // compare against expected values. The plugin itself does not
            // hardcode expected hashes — the host app configures that.
            Finding(
                signalId = SIGNAL_SIGNING_ANOMALY,
                status = "notDetected",
                source = "local",
                reasonCode = "signing_info_available",
                detail = "sha256_hashes:${signingInfo.joinToString(",")}"
            )
        } catch (e: Exception) {
            Finding.error(SIGNAL_SIGNING_ANOMALY, "check_exception", e.message)
        }
    }

    private fun checkInstaller(): Finding {
        return try {
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager
                    .getInstallSourceInfo(context.packageName)
                    .installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager
                    .getInstallerPackageName(context.packageName)
            }

            val knownStores = setOf(
                "com.android.vending",           // Google Play Store
                "com.amazon.venezia",            // Amazon Appstore
                "com.huawei.appmarket",          // Huawei AppGallery
                "com.samsung.android.vending",   // Samsung Galaxy Store
                "com.sec.android.app.samsungapps",
            )

            if (installer == null) {
                // Sideloaded or installed via adb — not necessarily malicious
                Finding.detected(
                    SIGNAL_INSTALLER_ANOMALY,
                    "no_installer_recorded",
                    "App has no recorded installer package"
                )
            } else if (installer !in knownStores) {
                Finding.detected(
                    SIGNAL_INSTALLER_ANOMALY,
                    "unknown_installer",
                    "installer:$installer"
                )
            } else {
                Finding.notDetected(
                    SIGNAL_INSTALLER_ANOMALY,
                    "known_store_installer"
                )
            }
        } catch (e: Exception) {
            Finding.error(SIGNAL_INSTALLER_ANOMALY, "check_exception", e.message)
        }
    }

    companion object {
        const val SIGNAL_SIGNING_ANOMALY = "signing_anomaly"
        const val SIGNAL_INSTALLER_ANOMALY = "installer_anomaly"
    }
}
