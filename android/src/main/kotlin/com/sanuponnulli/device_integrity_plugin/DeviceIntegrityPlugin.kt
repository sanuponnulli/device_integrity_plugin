package com.sanuponnulli.device_integrity_plugin

import android.app.Activity
import android.content.Context
import android.os.Build
import com.sanuponnulli.device_integrity_plugin.attestation.PlayIntegrityProvider
import com.sanuponnulli.device_integrity_plugin.checks.*
import com.sanuponnulli.device_integrity_plugin.models.Finding
import com.sanuponnulli.device_integrity_plugin.models.IntegrityCheck
import com.sanuponnulli.device_integrity_plugin.screen.SensitiveScreenGuard
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import kotlinx.coroutines.*

/**
 * Flutter platform plugin for device_integrity (Android).
 *
 * Orchestrates independent check modules and attestation providers.
 * Each check reports its own status — errors in one check never
 * suppress findings from other checks.
 */
class DeviceIntegrityPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {

    private lateinit var channel: MethodChannel
    private lateinit var context: Context
    private var activity: Activity? = null

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val screenGuard = SensitiveScreenGuard()
    private lateinit var playIntegrityProvider: PlayIntegrityProvider

    companion object {
        const val CHANNEL_NAME = "com.sanuponnulli.device_integrity_plugin/methods"
        const val PACKAGE_VERSION = "0.1.0"
    }

    // ── FlutterPlugin lifecycle ─────────────────────────────────────────

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
        playIntegrityProvider = PlayIntegrityProvider(context)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        scope.cancel()
    }

    // ── ActivityAware lifecycle ─────────────────────────────────────────

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    // ── Method dispatch ─────────────────────────────────────────────────

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "checkLocalSignals" -> handleCheckLocalSignals(result)
            "getCapabilities" -> handleGetCapabilities(result)
            "createProof" -> handleCreateProof(call, result)
            "setSecureScreen" -> handleSetSecureScreen(call, result)
            "isScreenBeingCaptured" -> {
                // Not applicable on Android — this is an iOS-specific check.
                result.success(false)
            }
            "generateAppAttestKey" -> {
                result.error(
                    "UNSUPPORTED",
                    "App Attest is only available on iOS",
                    null
                )
            }
            "attestAppAttestKey" -> {
                result.error(
                    "UNSUPPORTED",
                    "App Attest is only available on iOS",
                    null
                )
            }
            else -> result.notImplemented()
        }
    }

    // ── checkLocalSignals ───────────────────────────────────────────────

    private fun handleCheckLocalSignals(result: MethodChannel.Result) {
        scope.launch {
            try {
                val findings = mutableListOf<Finding>()

                // Each check is independent — a failure in one does not
                // prevent others from running.
                val checks: List<IntegrityCheck> = listOf(
                    RootDetectionCheck(),
                    EmulatorCheck(),
                    DebuggerCheck(context),
                    HookingCheck(),
                    AppTamperingCheck(context),
                    NetworkContextCheck(context),
                )

                for (check in checks) {
                    try {
                        findings.addAll(check.execute())
                    } catch (e: Exception) {
                        // If a check itself throws unexpectedly, record
                        // an error finding rather than losing all results.
                        findings.add(
                            Finding.error(
                                "check_${check.javaClass.simpleName}",
                                "unexpected_exception",
                                e.message
                            )
                        )
                    }
                }

                val report = buildReport(findings)
                withContext(Dispatchers.Main) {
                    result.success(report)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    result.error(
                        "CHECK_FAILED",
                        "Local signal check failed: ${e.message}",
                        null
                    )
                }
            }
        }
    }

    // ── getCapabilities ─────────────────────────────────────────────────

    private fun handleGetCapabilities(result: MethodChannel.Result) {
        val capabilities = mutableListOf<Map<String, Any?>>()

        // Local checks — always available on API 21+
        val localChecks = listOf(
            "root_jailbreak_artifacts",
            "restricted_write_access",
            "root_jailbreak_tooling",
            "emulator_simulator",
            "debugger_attached",
            "debuggable_build",
            "hooking_framework",
            "signing_anomaly",
            "installer_anomaly",
            "proxy_configured",
        )

        for (id in localChecks) {
            capabilities.add(
                mapOf(
                    "id" to id,
                    "available" to true,
                    "minimumOsVersion" to "21",
                )
            )
        }

        // VPN detection requires API 23+
        capabilities.add(
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                mapOf(
                    "id" to "vpn_active",
                    "available" to true,
                    "minimumOsVersion" to "23",
                )
            } else {
                mapOf(
                    "id" to "vpn_active",
                    "available" to false,
                    "unavailableReason" to "api_level_too_low",
                    "minimumOsVersion" to "23",
                )
            }
        )

        // Play Integrity
        val playAvailable = playIntegrityProvider.isAvailable()
        capabilities.add(
            mapOf(
                "id" to "play_integrity",
                "available" to playAvailable,
                "unavailableReason" to playIntegrityProvider.unavailableReason,
            )
        )

        // Secure screen
        capabilities.add(
            mapOf(
                "id" to "secure_screen",
                "available" to true,
            )
        )

        result.success(capabilities)
    }

    // ── createProof ─────────────────────────────────────────────────────

    private fun handleCreateProof(call: MethodCall, result: MethodChannel.Result) {
        val challenge = call.argument<String>("challenge")
        if (challenge.isNullOrBlank()) {
            result.error(
                "INVALID_ARGUMENT",
                "challenge is required and must not be empty",
                null
            )
            return
        }

        val requestHash = call.argument<String>("requestHash")

        scope.launch {
            try {
                val proof = playIntegrityProvider.requestToken(
                    challenge = challenge,
                    requestHash = requestHash,
                )
                withContext(Dispatchers.Main) {
                    result.success(proof)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    result.error(
                        "ATTESTATION_FAILED",
                        "Play Integrity request failed: ${e.message}",
                        e.stackTraceToString()
                    )
                }
            }
        }
    }

    // ── setSecureScreen ─────────────────────────────────────────────────

    private fun handleSetSecureScreen(call: MethodCall, result: MethodChannel.Result) {
        val enabled = call.argument<Boolean>("enabled") ?: false

        // FLAG_SECURE must be set on the UI thread
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }

        currentActivity.runOnUiThread {
            val success = screenGuard.setSecure(currentActivity, enabled)
            result.success(success)
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private fun buildReport(findings: List<Finding>): Map<String, Any?> {
        return mapOf(
            "platform" to "android",
            "osVersion" to Build.VERSION.SDK_INT.toString(),
            "packageVersion" to PACKAGE_VERSION,
            "checkTimeIso" to java.time.Instant.now().toString(),
            "findings" to findings.map { it.toMap() },
        )
    }
}
