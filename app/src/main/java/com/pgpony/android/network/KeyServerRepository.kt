// KeyServerRepository.kt
// PGPony Android — Phase A8 + Fix2
//
// Matches iOS KeyServerService.swift.
// Queries keys.openpgp.org VKS API for key discovery and upload.
//
// Phase A8 — unified email lookup:
//   • searchByEmail(email) — backward-compatible signature, returns
//     just the armored key string. Internally now tries WKD advanced →
//     WKD direct → Hagrid before giving up. Existing callers (Exchange,
//     Contacts) get WKD discovery for free without code changes.
//   • findByEmail(email) — new signature returning KeyLookupResult
//     with both the armored key and the source it came from. Use this
//     in new code where the UI wants to label key provenance ("found
//     via WKD" vs "found via keys.openpgp.org") — the import preview
//     in A10 will switch to this.
//
// Phase A8 Fix2 — Hagrid upload now triggers email verification:
//   • upload() previously POSTed the key, discarded the response
//     token, and reported "ok" — leaving the key on Hagrid as
//     "unpublished" (searchable only by fingerprint). Now parses
//     the upload response, extracts the token + per-email status,
//     and automatically POSTs /vks/v1/request-verify so Hagrid
//     emails the user to confirm ownership. The user clicks the
//     link → key becomes searchable by email.
//   • requestVerificationBatch() added for the multi-email case.
//   • Diagnostic Log.d added at WKD/Hagrid decision points so
//     `adb logcat | grep "KeyServer\|WKD"` reveals which source
//     produced (or failed to produce) a key.

package com.pgpony.android.network

import android.util.Log
import io.ktor.client.*
import io.ktor.client.engine.android.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

sealed class KeyServerError(message: String) : Exception(message) {
    class NotFound : KeyServerError("Key not found on key server")
    class NetworkError(msg: String) : KeyServerError("Key server network error: $msg")
    class UploadFailed(msg: String) : KeyServerError("Key upload failed: $msg")
}

/**
 * Result of a Hagrid VKS upload, including any auto-triggered
 * verification step.
 *
 * Field map:
 *   • token: server-issued token for follow-up verification calls.
 *     Null only if the upload response was malformed.
 *   • status: legacy single-word summary ("ok" on success). Kept for
 *     existing callers; new code should prefer emailStatuses.
 *   • keyFingerprint: uppercase hex fingerprint as Hagrid parsed it.
 *     Useful for sanity-checking that the right key was accepted.
 *   • emailStatuses: per-email state from Hagrid:
 *       "unpublished" — uploaded but not searchable by email yet
 *       "pending"     — verification email sent, awaiting user click
 *       "published"   — verified, searchable by email
 *       "revoked"     — Hagrid knows this address is revoked
 *   • verificationRequested: true if PGPony successfully POSTed
 *     /vks/v1/request-verify after the upload. False if there was
 *     no token, no emails to verify, or the request-verify call
 *     itself failed (in which case the key is uploaded but only
 *     searchable by fingerprint until the user manually re-verifies).
 */
data class KeyServerUploadResult(
    val token: String?,
    val status: String,
    val keyFingerprint: String = "",
    val emailStatuses: Map<String, String> = emptyMap(),
    val verificationRequested: Boolean = false
)

class KeyServerRepository {

    companion object {
        private const val BASE_URL = "https://keys.openpgp.org"
        // Fix2: diagnostic logging tag — visible via `adb logcat | grep KeyServer`.
        // Used to surface WKD/Hagrid source decisions and upload+verify flow.
        private const val LOG_TAG = "KeyServer"
        val shared = KeyServerRepository()
    }

    private val client = HttpClient(Android) {
        engine {
            connectTimeout = 15_000
            socketTimeout = 15_000
        }
    }

    /**
     * Search for a public key by email address. Tries Web Key
     * Directory first (advanced subdomain, then direct), falls back
     * to the keys.openpgp.org Hagrid API.
     *
     * Returns the armored ASCII key string if found through ANY of
     * the sources, or null if none matched. Existing callers
     * (ExchangeViewModel, ContactsViewModel, ContactsService) get
     * WKD discovery transparently — no signature change.
     *
     * If callers want to know WHICH source returned the key (for
     * "Found via WKD (direct)" labeling), use [findByEmail] instead.
     */
    suspend fun searchByEmail(email: String): String? {
        return findByEmail(email)?.armoredKey
    }

    /**
     * Unified email lookup with source attribution. Tries:
     *   1. WKD advanced (https://openpgpkey.<domain>/.well-known/...)
     *   2. WKD direct (https://<domain>/.well-known/...)
     *   3. keys.openpgp.org (Hagrid VKS by-email)
     *
     * Returns the first match, including which source produced it.
     * Null if all three fail.
     *
     * Performance note: WKD timeouts are tight (8s connect, 15s
     * socket per WkdService); failures cascade quickly so the
     * worst-case latency for a complete miss is roughly
     * 2 × WKD-timeout + Hagrid-timeout. Typical hits return in
     * <1s from whichever source is configured.
     */
    suspend fun findByEmail(email: String): KeyLookupResult? {
        // WKD attempt — returns null if both advanced and direct fail.
        WkdService.shared.lookup(email)?.let {
            Log.d(LOG_TAG, "findByEmail($email) → hit via ${it.source.displayName}")
            return it
        }

        // Hagrid fallback. The pre-A8 implementation lived here under
        // searchByEmail; same logic, just renamed and wrapped.
        val hagrid = hagridSearchByEmail(email)
        return if (hagrid != null) {
            Log.d(LOG_TAG, "findByEmail($email) → hit via keys.openpgp.org (Hagrid, after WKD miss)")
            KeyLookupResult(armoredKey = hagrid, source = KeyLookupSource.HAGRID)
        } else {
            Log.d(LOG_TAG, "findByEmail($email) → miss on all sources (WKD advanced+direct, Hagrid)")
            null
        }
    }

    /**
     * Hagrid (keys.openpgp.org) by-email lookup.
     * GET /vks/v1/by-email/{email}
     *
     * Used internally by [findByEmail] as the final fallback after
     * WKD attempts. Hagrid serves the armored ASCII directly, so we
     * can read it as text without going through the armor-wrapping
     * step that WKD requires.
     */
    private suspend fun hagridSearchByEmail(email: String): String? = withContext(Dispatchers.IO) {
        try {
            val response = client.get("$BASE_URL/vks/v1/by-email/${email.trim()}") {
                accept(ContentType.Application.OctetStream)
            }
            if (response.status == HttpStatusCode.OK) {
                response.bodyAsText()
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Search for a public key by fingerprint.
     * GET /vks/v1/by-fingerprint/{fingerprint}
     */
    suspend fun searchByFingerprint(fingerprint: String): String? = withContext(Dispatchers.IO) {
        try {
            val fp = fingerprint.uppercase().replace(" ", "")
            val response = client.get("$BASE_URL/vks/v1/by-fingerprint/$fp") {
                accept(ContentType.Application.OctetStream)
            }
            if (response.status == HttpStatusCode.OK) {
                response.bodyAsText()
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Upload a public key to keys.openpgp.org and auto-trigger
     * email-verification requests for all addresses Hagrid extracted
     * from the key.
     *
     * Pre-Fix2 behavior was broken: the code POSTed the key, ignored
     * the response body (including the token Hagrid issued), and
     * reported "ok". Without the token-based /vks/v1/request-verify
     * follow-up, the key would sit in Hagrid as "unpublished" —
     * searchable only by fingerprint, never by email. Users who
     * uploaded via PGPony and then searched by their own email would
     * see "No key found" because Hagrid suppresses email-based
     * lookups until each address has been verified by the owner
     * clicking a link in a confirmation email.
     *
     * Fix2 flow:
     *   1. POST /vks/v1/upload with the armored key. JSON body built
     *      with JSONObject so embedded newlines / control characters
     *      in the armor are escaped correctly (the old string-concat
     *      approach worked for typical keys but was technically
     *      brittle).
     *   2. Parse the upload response. Extract token, key_fpr, and
     *      the per-email status map (Hagrid lists every email it
     *      pulled out of the key with state "unpublished").
     *   3. For every email marked "unpublished", POST
     *      /vks/v1/request-verify with the token + email list. Hagrid
     *      sends a confirmation email to each address. The user clicks
     *      the link in each → that address becomes "published" and
     *      the key becomes searchable by that email.
     *   4. Return KeyServerUploadResult with all the metadata so the
     *      UI can tell the user exactly which addresses got
     *      verification emails.
     *
     * On request-verify failure (rate limit, network blip), the upload
     * itself is still successful — the user just needs to manually
     * re-request verification later. Result will have
     * verificationRequested=false so the UI can adapt its message.
     */
    suspend fun upload(armoredPublicKey: String): KeyServerUploadResult = withContext(Dispatchers.IO) {
        try {
            // Build the request body with JSONObject — handles the
            // newline/escape concerns the old string-concat couldn't.
            val requestBody = JSONObject().apply {
                put("keytext", armoredPublicKey)
            }.toString()

            val response = client.post("$BASE_URL/vks/v1/upload") {
                contentType(ContentType.Application.Json)
                setBody(requestBody)
            }
            if (response.status != HttpStatusCode.OK) {
                Log.d(LOG_TAG, "upload → HTTP ${response.status.value}; throwing UploadFailed")
                throw KeyServerError.UploadFailed("HTTP ${response.status.value}")
            }

            // Parse the upload response.
            //   { "token": "...", "key_fpr": "...",
            //     "status": { "email@example.com": "unpublished", ... } }
            val responseText = response.bodyAsText()
            val json = JSONObject(responseText)
            val token = json.optString("token", "")
            val fpr = json.optString("key_fpr", "")
            val statusObj = json.optJSONObject("status")
            val emailStatuses = mutableMapOf<String, String>()
            if (statusObj != null) {
                val keys = statusObj.keys()
                while (keys.hasNext()) {
                    val email = keys.next()
                    emailStatuses[email] = statusObj.optString(email, "")
                }
            }
            Log.d(LOG_TAG, "upload → fpr=$fpr emails=${emailStatuses.keys}")

            // Collect addresses needing verification. Hagrid won't
            // re-send for already-pending or already-published, so we
            // filter to just "unpublished".
            val emailsToVerify = emailStatuses
                .filter { (_, s) -> s == "unpublished" }
                .keys
                .toList()

            // Auto-trigger verification. The user has to click the
            // link in each email Hagrid sends; until then the key is
            // searchable only by fingerprint.
            val verificationOk = if (token.isNotEmpty() && emailsToVerify.isNotEmpty()) {
                val ok = requestVerificationBatch(token, emailsToVerify)
                Log.d(LOG_TAG, "upload → verify requested for $emailsToVerify ok=$ok")
                ok
            } else {
                Log.d(LOG_TAG, "upload → no verify needed (token=${token.isNotEmpty()}, " +
                        "unpublished=${emailsToVerify.size})")
                false
            }

            KeyServerUploadResult(
                token = token.ifEmpty { null },
                status = "ok",
                keyFingerprint = fpr,
                emailStatuses = emailStatuses,
                verificationRequested = verificationOk
            )
        } catch (e: KeyServerError) {
            throw e
        } catch (e: Exception) {
            Log.d(LOG_TAG, "upload → exception: ${e.message}")
            throw KeyServerError.UploadFailed(e.message ?: "Unknown error")
        }
    }

    /**
     * Request email verification for a single address. Kept for
     * external API compatibility; new code should use
     * [requestVerificationBatch] which is one round-trip for many
     * addresses.
     */
    suspend fun requestVerification(email: String, token: String): Boolean {
        return requestVerificationBatch(token, listOf(email))
    }

    /**
     * Batch request verification for multiple addresses in one
     * /vks/v1/request-verify call. Hagrid sends a confirmation email
     * to each address in [emails]; the user must click the link in
     * each before that address becomes searchable on Hagrid.
     *
     * Returns true if Hagrid acknowledged the batch (HTTP 200); false
     * on any failure (no emails, no token, HTTP error, network).
     * Caller can re-try later if needed — there's no destructive
     * effect of duplicate verification requests, just additional
     * emails to the user (Hagrid rate-limits internally).
     */
    suspend fun requestVerificationBatch(token: String, emails: List<String>): Boolean =
        withContext(Dispatchers.IO) {
            if (emails.isEmpty() || token.isEmpty()) return@withContext false
            try {
                val body = JSONObject().apply {
                    put("token", token)
                    put("addresses", JSONArray(emails))
                }.toString()
                val response = client.post("$BASE_URL/vks/v1/request-verify") {
                    contentType(ContentType.Application.Json)
                    setBody(body)
                }
                response.status == HttpStatusCode.OK
            } catch (e: Exception) {
                false
            }
        }
}
