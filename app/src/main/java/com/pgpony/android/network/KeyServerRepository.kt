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
import com.pgpony.android.PGPonyApp
import com.pgpony.android.keyserver.KeyServerDirectory
import com.pgpony.android.keyserver.MultiKeyServerService
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

    // 4.0.0 Phase 6 — route through the shared proxy-aware client
    // (Tor/Orbot when enabled; direct otherwise). Replaces the private
    // per-service HttpClient so proxy config applies uniformly.
    private val client get() = com.pgpony.android.network.HttpClientFactory.client()

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
    /**
     * 4.6.0 (item 17.8): a by-email answer is trusted only as far as it holds
     * the address asked for. Only the certificates that carry a User ID,
     * certified by their own primary (and not revoked), whose address is
     * exactly [email] are kept; the rest of the answer is discarded, and an
     * answer with none left is a miss. Returns the kept certificates armored.
     */
    private fun keepHolding(armored: String, email: String): String? = runCatching {
        val binary = com.pgpony.android.crypto.pqc.CompositeSigPacket.dearmor(armored)
        val want = com.pgpony.android.crypto.CertificateBindings.mailboxOf(email)
        val kept = com.pgpony.android.crypto.CertificateBindings.splitCertificates(binary).filter { cert ->
            com.pgpony.android.crypto.CertificateBindings.analyze(cert)?.certifiedUserIds
                ?.any { com.pgpony.android.crypto.CertificateBindings.mailboxOf(it) == want } == true
        }
        if (kept.isEmpty()) return@runCatching null
        val out = java.io.ByteArrayOutputStream()
        org.bouncycastle.bcpg.ArmoredOutputStream(out).use { a -> kept.forEach { a.write(it) } }
        out.toString(Charsets.UTF_8.name())
    }.getOrNull()

    suspend fun findByEmail(email: String): KeyLookupResult? {
        // WKD attempt — returns null if both advanced and direct fail.
        // item 21 (#request): honor the Settings WKD lookup toggle. Off drops
        // WKD from the chain; the configured servers + Hagrid still run.
        if (WkdLookup.isEnabled()) {
            WkdService.shared.lookup(email)?.let {
                Log.d(LOG_TAG, "findByEmail($email) → hit via ${it.source.displayName}")
                return it
            }
        }

        // Phase 6: consult the configured keyserver directory before the
        // openpgp.org fallback — first-party (keys.pgpony.app) FIRST, then
        // any other lookup-enabled servers in directory order. This finds
        // v6/PQC keys that keys.openpgp.org won't serve, and rides the
        // onion when Tor is on. keys.openpgp.org is handled by the Hagrid
        // step below, so it's skipped here to avoid a double round-trip.
        val emailServers = directoryLookupServers()
        logDirectory("findByEmail($email)", emailServers.map { it.label })
        for (server in emailServers) {
            val outcome = runCatching {
                MultiKeyServerService.shared.searchByEmail(server, email)
            }
            val hit = outcome.getOrNull()?.let { keepHolding(it, email) } // 4.6.0 (item 17.8)
            if (!hit.isNullOrBlank()) {
                Log.d(LOG_TAG, "findByEmail($email) → hit via ${server.label}")
                return KeyLookupResult(armoredKey = hit, source = KeyLookupSource.KEYSERVER)
            }
            logMiss("findByEmail($email)", server.label, outcome.exceptionOrNull())
        }

        // Hagrid fallback (keys.openpgp.org) — always the final source so
        // "keep openpgp" holds even if it's disabled in the directory.
        val hagrid = hagridSearchByEmail(email)?.let { keepHolding(it, email) } // 4.6.0 (item 17.8)
        return if (hagrid != null) {
            Log.d(LOG_TAG, "findByEmail($email) → hit via keys.openpgp.org (Hagrid)")
            KeyLookupResult(armoredKey = hagrid, source = KeyLookupSource.HAGRID)
        } else {
            Log.d(LOG_TAG, "findByEmail($email) → miss on all sources (WKD, directory, Hagrid)")
            null
        }
    }

    /**
     * Unified fingerprint lookup mirroring [findByEmail]'s source order:
     * configured directory servers (keys.pgpony.app first) → keys.openpgp.org.
     * WKD is email-only so it isn't part of this path.
     */
    suspend fun findByFingerprint(fingerprint: String): KeyLookupResult? {
        val fpServers = directoryLookupServers()
        logDirectory("findByFingerprint", fpServers.map { it.label })
        for (server in fpServers) {
            val outcome = runCatching {
                MultiKeyServerService.shared.fetchByFingerprint(server, fingerprint)
            }
            val hit = outcome.getOrNull()
            if (!hit.isNullOrBlank()) {
                Log.d(LOG_TAG, "findByFingerprint → hit via ${server.label}")
                return KeyLookupResult(armoredKey = hit, source = KeyLookupSource.KEYSERVER)
            }
            logMiss("findByFingerprint", server.label, outcome.exceptionOrNull())
        }
        val hagrid = searchByFingerprint(fingerprint)
        return if (hagrid != null) {
            Log.d(LOG_TAG, "findByFingerprint → hit via keys.openpgp.org (Hagrid)")
            KeyLookupResult(armoredKey = hagrid, source = KeyLookupSource.HAGRID)
        } else {
            Log.d(LOG_TAG, "findByFingerprint → miss on all sources")
            null
        }
    }

    /**
     * 4.1.0 Phase 14e. Unified 64-bit key ID lookup, same source order
     * as [findByFingerprint]: configured directory servers with the
     * first-party one (keys.pgpony.app) first, then keys.openpgp.org.
     *
     * Used by the signer lookup on the decrypt path, which has no
     * fingerprint to offer. Less precise than by-fingerprint, which is
     * the trade VerificationResult.UnknownSigner already documents; the
     * user confirms the result before anything reaches the keyring.
     */
    suspend fun findByKeyId(keyId: String): KeyLookupResult? {
        val keyIdServers = directoryLookupServers()
        logDirectory("findByKeyId($keyId)", keyIdServers.map { it.label })
        for (server in keyIdServers) {
            val outcome = runCatching {
                MultiKeyServerService.shared.fetchByKeyId(server, keyId)
            }
            val hit = outcome.getOrNull()
            if (!hit.isNullOrBlank()) {
                Log.d(LOG_TAG, "findByKeyId → hit via ${server.label}")
                return KeyLookupResult(armoredKey = hit, source = KeyLookupSource.KEYSERVER)
            }
            logMiss("findByKeyId($keyId)", server.label, outcome.exceptionOrNull())
        }
        val hagrid = searchByKeyId(keyId)
        return if (hagrid != null) {
            Log.d(LOG_TAG, "findByKeyId → hit via keys.openpgp.org (Hagrid)")
            KeyLookupResult(armoredKey = hagrid, source = KeyLookupSource.HAGRID)
        } else {
            Log.d(LOG_TAG, "findByKeyId → miss on all sources")
            null
        }
    }

    /**
     * 4.1.0 Phase 19. Name the directory a lookup is about to walk, or
     * say plainly that there is none.
     *
     * Without this, an empty directory and a directory that simply had
     * no answer looked the same in logcat, because the loop only spoke
     * on success. That is exactly the wrong conclusion to make easy in a
     * feature whose whole point is "we asked your server first".
     */
    private fun logDirectory(op: String, labels: List<String>) {
        if (labels.isEmpty()) {
            Log.d(LOG_TAG, "$op → no lookup-enabled directory servers, Hagrid only")
        } else {
            Log.d(LOG_TAG, "$op → directory order: ${labels.joinToString()}")
        }
    }

    /**
     * 4.1.0 Phase 19. One line per server that did not answer,
     * distinguishing "asked, no key there" from "could not reach it".
     * The callers swallow both into a null, which is right for control
     * flow and useless for diagnosis.
     */
    private fun logMiss(op: String, label: String, error: Throwable?) {
        val why = error?.let { " (${it.javaClass.simpleName}: ${it.message})" } ?: ""
        Log.d(LOG_TAG, "$op → no result from $label$why")
    }

    /**
     * Lookup-enabled directory servers with keys.openpgp.org removed
     * (handled separately as the final fallback) and the first-party
     * server sorted to the front. Empty if the directory can't be read.
     */
    private suspend fun directoryLookupServers() =
        runCatching {
            KeyServerDirectory.get(PGPonyApp.instance).readOnce()
        }.getOrDefault(emptyList())
            .filter { it.lookupEnabled && it.id != KeyServerDirectory.ID_OPENPGP }
            .sortedByDescending { it.isFirstParty }

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
                response.textCapped()
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
                response.textCapped()
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 4.1.0 Phase 14d. Search for a public key by 64-bit long key ID.
     * GET /vks/v1/by-keyid/{keyid}
     *
     * The signer lookup wants a fingerprint, and gets one on the
     * clear-signed path because VerifyService reads the issuer
     * fingerprint subpacket. The decrypt path has no fingerprint to
     * offer: DecryptResult and DecryptStreamResult carry only the raw
     * key ID from the signature packets. Rather than leave the yellow
     * banner tappable and inert, fall back to this.
     *
     * Less precise than by-fingerprint, which is the trade
     * VerificationResult.UnknownSigner already documents for signatures
     * without the subpacket. Hagrid still returns at most one key, and
     * the user confirms before anything is added to the keyring, so the
     * imprecision does not reach the keyring unreviewed.
     *
     * Same swallow-everything contract as [searchByFingerprint]: null
     * for "no result" and for transport failure alike.
     */
    suspend fun searchByKeyId(keyId: String): String? = withContext(Dispatchers.IO) {
        try {
            val id = keyId.uppercase().replace(" ", "").removePrefix("0X")
            if (id.isEmpty()) return@withContext null
            val response = client.get("$BASE_URL/vks/v1/by-keyid/$id") {
                accept(ContentType.Application.OctetStream)
            }
            if (response.status == HttpStatusCode.OK) {
                response.textCapped()
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 4.0.0 Phase 2 (iOS v7.1.1 F5) — fetch a key's armored material by
     * fingerprint, distinguishing "not published" from "couldn't reach
     * the server". Returns the armored key on 200, null on any other
     * HTTP status (Hagrid 404s unpublished fingerprints), and THROWS on
     * transport failure (no network, DNS, TLS, timeout) so the refresh
     * flow reports an actual error instead of a false "not found".
     * [searchByFingerprint] above keeps its swallow-everything contract
     * — KS1's check row and the import search treat null as "no result"
     * and stay unchanged.
     */
    suspend fun fetchByFingerprint(fingerprint: String): String? = withContext(Dispatchers.IO) {
        val fp = fingerprint.uppercase().replace(" ", "")
        val response = client.get("$BASE_URL/vks/v1/by-fingerprint/$fp") {
            accept(ContentType.Application.OctetStream)
        }
        if (response.status == HttpStatusCode.OK) response.textCapped() else null
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
            val responseText = response.textCapped()
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
