package com.sanuponnulli.device_integrity_plugin.screen

import android.app.Activity
import android.view.WindowManager

/**
 * Manages FLAG_SECURE on the current activity for screenshot and
 * screen-recording prevention.
 *
 * Limitations:
 * - Some OEM launchers, accessibility services, or screen-capture
 *   frameworks may bypass FLAG_SECURE.
 * - This cannot prevent a physical camera from photographing the screen.
 * - The flag applies to the entire activity window.
 */
class SensitiveScreenGuard {

    /**
     * Enable or disable FLAG_SECURE on the given activity.
     *
     * @return `true` if the flag was set successfully.
     */
    fun setSecure(activity: Activity?, enabled: Boolean): Boolean {
        val window = activity?.window ?: return false
        return try {
            if (enabled) {
                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
            true
        } catch (_: Exception) {
            false
        }
    }
}
