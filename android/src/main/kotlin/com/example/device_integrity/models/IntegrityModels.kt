package com.example.device_integrity.models

/**
 * A single integrity observation produced by one check.
 * Serialises to the map structure expected by the Dart side.
 */
data class Finding(
    val signalId: String,
    val status: String,    // "detected" | "notDetected" | "unavailable" | "error"
    val source: String,    // "local" | "platformAttestation"
    val reasonCode: String,
    val detail: String? = null
) {
    fun toMap(): Map<String, Any?> = buildMap {
        put("signalId", signalId)
        put("status", status)
        put("source", source)
        put("reasonCode", reasonCode)
        if (detail != null) put("detail", detail)
    }

    companion object {
        fun detected(signalId: String, reasonCode: String, detail: String? = null) =
            Finding(signalId, "detected", "local", reasonCode, detail)

        fun notDetected(signalId: String, reasonCode: String) =
            Finding(signalId, "notDetected", "local", reasonCode)

        fun unavailable(signalId: String, reasonCode: String) =
            Finding(signalId, "unavailable", "local", reasonCode)

        fun error(signalId: String, reasonCode: String, detail: String? = null) =
            Finding(signalId, "error", "local", reasonCode, detail)
    }
}

/**
 * Interface that every local check module implements.
 * Each check returns its own list of [Finding]s — errors in one
 * check never affect another.
 */
interface IntegrityCheck {
    fun execute(): List<Finding>
}
