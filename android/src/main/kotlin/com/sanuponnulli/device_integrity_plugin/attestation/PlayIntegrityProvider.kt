package com.sanuponnulli.device_integrity_plugin.attestation

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.MessageDigest
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Play Integrity Standard API client-side provider.
 *
 * The host app supplies its public Google Cloud project number through
 * application metadata. The challenge and optional request hash are combined
 * into the value bound by Play Integrity; the backend must recompute it.
 */
class PlayIntegrityProvider(private val context: Context) {

    companion object {
        const val CLOUD_PROJECT_NUMBER_METADATA =
            "com.sanuponnulli.device_integrity_plugin.CLOUD_PROJECT_NUMBER"
    }

    private val cloudProjectNumber: Long? by lazy {
        try {
            context.applicationInfo.metaData
                ?.getLong(CLOUD_PROJECT_NUMBER_METADATA)
                ?.takeIf { it > 0L }
        } catch (_: Exception) {
            null
        }
    }

    private val integrityManager by lazy {
        IntegrityManagerFactory.createStandard(context)
    }

    /** Reason the provider cannot be prepared, or null if configuration exists. */
    val unavailableReason: String?
        get() = when {
            cloudProjectNumber == null -> "cloud_project_number_missing"
            !isAvailable() -> "play_services_missing_or_outdated"
            else -> null
        }

    /** Check local configuration and whether the Play Integrity manager loads. */
    fun isAvailable(): Boolean {
        if (cloudProjectNumber == null) return false
        return try {
            IntegrityManagerFactory.createStandard(context)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Request a token bound to [challenge] and optional [requestHash].
     *
     * The decoded token's `requestHash` is the base64url SHA-256 digest of
     * `device-integrity-v1\n<challenge-length>:<challenge>\n<hash-length>:<request-hash>`.
     * A missing request hash uses length `-1` and an empty value. The backend
     * can recompute this exact value from the original challenge and hash.
     */
    suspend fun requestToken(
        challenge: String,
        requestHash: String?
    ): Map<String, Any?> {
        val projectNumber = cloudProjectNumber
            ?: throw IllegalStateException(
                "Set application metadata $CLOUD_PROJECT_NUMBER_METADATA to use Play Integrity"
            )

        return suspendCancellableCoroutine { continuation ->
            val prepareRequest =
                StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
                    .setCloudProjectNumber(projectNumber)
                    .build()

            integrityManager.prepareIntegrityToken(prepareRequest)
                .addOnSuccessListener { tokenProvider ->
                    val tokenRequest =
                        StandardIntegrityManager.StandardIntegrityTokenRequest
                            .builder()
                            .setRequestHash(bindingHash(challenge, requestHash))
                            .build()

                    tokenProvider.request(tokenRequest)
                        .addOnSuccessListener { response ->
                            if (continuation.isActive) {
                                continuation.resume(
                                    mapOf(
                                        "provider" to "play_integrity",
                                        "tokenBase64" to response.token(),
                                        "challenge" to challenge,
                                        "requestHash" to requestHash,
                                        "createdAtIso" to java.time.Instant.now().toString(),
                                    )
                                )
                            }
                        }
                        .addOnFailureListener { exception ->
                            if (continuation.isActive) {
                                continuation.resumeWithException(exception)
                            }
                        }
                }
                .addOnFailureListener { exception ->
                    if (continuation.isActive) {
                        continuation.resumeWithException(exception)
                    }
                }
        }
    }

    private fun bindingHash(challenge: String, requestHash: String?): String {
        val requestLength = requestHash?.length ?: -1
        val input = "device-integrity-v1\n${challenge.length}:$challenge\n" +
            "$requestLength:${requestHash.orEmpty()}"
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(
            digest,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
    }
}
