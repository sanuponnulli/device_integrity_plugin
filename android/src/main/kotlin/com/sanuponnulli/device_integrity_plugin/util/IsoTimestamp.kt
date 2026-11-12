package com.sanuponnulli.device_integrity_plugin.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * UTC ISO-8601 timestamps (for example `2026-11-12T09:30:00.123Z`).
 *
 * `java.time.Instant` needs API 26 and the plugin supports API 24, so this
 * uses `SimpleDateFormat`. A new formatter is created per call because
 * `SimpleDateFormat` is not thread-safe.
 */
internal object IsoTimestamp {
    fun now(): String = format(Date())

    fun format(date: Date): String {
        val formatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        formatter.timeZone = TimeZone.getTimeZone("UTC")
        return formatter.format(date)
    }
}
