package com.example.device_integrity.attestation

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.Base64
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Play Integrity API client-side provider.
 *
 * Responsibilities:
 * - Check whether Play Integrity is available on this device.
 * - Request an integrity token bound to a challenge + request hash.
 * - Return the raw token for the host app to submit to its backend.
 *
 * The plugin NEVER places Google Cloud credentials in the app and
 * NEVER decodes the token client-side. Server-side verification is
 * the host app's responsibility.
 */
class PlayIntegrityProvider(private val context: Context) {

    private val integrityManager by lazy {
        IntegrityManagerFactory.create(context)
    }

    /**
     * Check whether Play Integrity can be used on this device.
     *
     * Requires Google Play Services with a sufficiently recent version.
     */
    fun isAvailable(): Boolean {
        return try {
            // Attempt to resolve the integrity manager — if Play Services
            // is missing or too old this will fail.
            IntegrityManagerFactory.create(context)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Request a Play Integrity token.
     *
     * @param challenge A high-entropy, one-time nonce from the backend.
     *   The backend must verify this value in the decoded token.
     * @param requestHash Optional SHA-256 hash of the protected request
     *   body. Play Integrity binds this into the token so the backend can
     *   verify the request was not tampered with.
     *
     * @return A map ready for Dart serialisation containing:
     *   - `provider`: `"play_integrity"`
     *   - `tokenBase64`: The raw integrity token (already base64 from the API)
     *   - `challenge`: The challenge used
     *   - `requestHash`: The request hash used (if provided)
     *   - `createdAtIso`: ISO 8601 creation timestamp
     */
    suspend fun requestToken(
        challenge: String,
        requestHash: String?
    ): Map<String, Any?> {
        return suspendCancellableCoroutine { continuation ->
            val requestBuilder = IntegrityTokenRequest.builder()
                .setNonce(challenge)

            if (requestHash != null) {
                requestBuilder.setRequestHash(requestHash)
            }

            val task = integrityManager.requestIntegrityToken(
                requestBuilder.build()
            )

            task.addOnSuccessListener { response ->
                val token = response.token()
                continuation.resume(
                    mapOf(
                        "provider" to "play_integrity",
                        "tokenBase64" to token,
                        "challenge" to challenge,
                        "requestHash" to requestHash,
                        "createdAtIso" to java.time.Instant.now().toString(),
                    )
                )
            }

            task.addOnFailureListener { exception ->
                continuation.resumeWithException(exception)
            }
        }
    }
}
