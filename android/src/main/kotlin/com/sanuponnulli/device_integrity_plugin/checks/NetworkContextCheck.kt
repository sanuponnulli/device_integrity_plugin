package com.sanuponnulli.device_integrity_plugin.checks

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import com.sanuponnulli.device_integrity_plugin.models.Finding
import com.sanuponnulli.device_integrity_plugin.models.IntegrityCheck

/**
 * Reports network context: proxy configuration and VPN status.
 *
 * These are reported as **separate signals** that never influence
 * the root/jailbreak verdict. A proxy or VPN alone is not evidence
 * of compromise.
 */
class NetworkContextCheck(private val context: Context) : IntegrityCheck {

    override fun execute(): List<Finding> {
        val findings = mutableListOf<Finding>()

        // ── Proxy configuration ─────────────────────────────────────────
        findings.add(checkProxy())

        // ── VPN status ──────────────────────────────────────────────────
        findings.add(checkVpn())

        return findings
    }

    @Suppress("DEPRECATION")
    private fun checkProxy(): Finding {
        return try {
            val proxyHost = System.getProperty("http.proxyHost")
            val proxyPort = System.getProperty("http.proxyPort")

            // Also check global proxy settings
            val globalProxyHost = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                android.provider.Settings.Global.getString(
                    context.contentResolver,
                    android.provider.Settings.Global.HTTP_PROXY
                )
            } else {
                null
            }

            if (!proxyHost.isNullOrBlank() || !globalProxyHost.isNullOrBlank()) {
                Finding.detected(
                    SIGNAL_PROXY,
                    "proxy_configured",
                    buildString {
                        if (!proxyHost.isNullOrBlank()) {
                            append("system_proxy:$proxyHost:$proxyPort")
                        }
                        if (!globalProxyHost.isNullOrBlank()) {
                            if (isNotEmpty()) append(", ")
                            append("global_proxy:$globalProxyHost")
                        }
                    }
                )
            } else {
                Finding.notDetected(SIGNAL_PROXY, "no_proxy")
            }
        } catch (e: Exception) {
            Finding.error(SIGNAL_PROXY, "check_exception", e.message)
        }
    }

    private fun checkVpn(): Finding {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as? ConnectivityManager

                if (cm != null) {
                    val activeNetwork = cm.activeNetwork
                    val caps = if (activeNetwork != null) {
                        cm.getNetworkCapabilities(activeNetwork)
                    } else {
                        null
                    }

                    if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        Finding.detected(SIGNAL_VPN, "vpn_transport_active")
                    } else {
                        Finding.notDetected(SIGNAL_VPN, "no_vpn_transport")
                    }
                } else {
                    Finding.error(SIGNAL_VPN, "no_connectivity_manager")
                }
            } else {
                // API < 23: VPN detection via NetworkCapabilities not available
                Finding.unavailable(SIGNAL_VPN, "api_level_too_low")
            }
        } catch (e: Exception) {
            Finding.error(SIGNAL_VPN, "check_exception", e.message)
        }
    }

    companion object {
        const val SIGNAL_PROXY = "proxy_configured"
        const val SIGNAL_VPN = "vpn_active"
    }
}
