// MultiKeyServerService.kt
// PGPony Android — 4.0.0 Phase 5a
//
// Per-server VKS operations for the multi-keyserver model: fetch,
// upload, and verification-status polling against an arbitrary
// KeyServer.baseUrl. The shipped KeyServerRepository stays the
// single-server (keys.openpgp.org) path for the existing refresh /
// exchange / contacts callers — this class is the additive multi-server
// layer PublishSheet and the (future) Phase 5 batch refresh use, so the
// blast radius on shipped code is zero. (Plan said "modify
// KeyServerRepository"; a focused new service is the lower-risk shape
// and keeps the existing single-server contract intact.)
//
// All three seed/servers speak the keys.openpgp.org VKS dialect
// (keys.pgpony.app implements the same API by design), so one client
// path covers them. HKP POST /pks/add is the fallback upload verb if a
// server lacks /vks/v1/upload (Open Question 5); VKS is preferred and
// tried first.

package com.pgpony.android.keyserver

import com.pgpony.android.network.textCapped
import com.pgpony.android.PGPonyApp
import com.pgpony.android.network.HttpClientFactory
import com.pgpony.android.network.ProxyPrefs
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.client.request.forms.FormDataContent
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.contentType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** Outcome of publishing one key to one server. */
sealed class PublishOutcome {
    /** Uploaded; verification emails requested for [pendingEmails] (may be empty). */
    data class Ok(val pendingEmails: List<String>) : PublishOutcome()
    /** The server refused the key — very likely a key-type it doesn't accept (R5). */
    data class RejectedKeyType(val httpStatus: Int) : PublishOutcome()
    /** Any other failure (network, 5xx, malformed). [message] is user-safe. */
    data class Failed(val message: String) : PublishOutcome()
}

class MultiKeyServerService {

    companion object {
        val shared = MultiKeyServerService()
    }

    // Phase 6: the shared proxy-aware client (Tor/Orbot when enabled).
    private val client get() = HttpClientFactory.client()

    // Phase 6: rewrite keys.pgpony.app → its onion when a proxy + the
    // onion mirror are active; clearnet otherwise.
    private fun base(server: KeyServer): String =
        ProxyPrefs.effectiveBaseUrl(PGPonyApp.instance, server.baseUrl)

    /**
     * Fetch a key's armored material by fingerprint from one server.
     * Returns the armor on 200, null on 404 (not published), THROWS on
     * transport failure so the caller can tell "not there" from
     * "couldn't reach it" (matches KeyServerRepository.fetchByFingerprint).
     */
    suspend fun fetchByFingerprint(server: KeyServer, fingerprint: String): String? =
        withContext(Dispatchers.IO) {
            val fp = fingerprint.uppercase().replace(" ", "")
            val response = client.get("${base(server)}/vks/v1/by-fingerprint/$fp") {
                accept(ContentType.Application.OctetStream)
            }
            if (response.status == HttpStatusCode.OK) response.textCapped() else null
        }

    /**
     * 4.1.0 Phase 14e. The by-keyid twin of [fetchByFingerprint], same
     * contract: armor on 200, null on any other status, throws on
     * transport failure so the caller can tell "not there" from
     * "couldn't reach it".
     *
     * Exists for the signer lookup on the decrypt path, which has only
     * the 64-bit key ID from the signature packets to go on: the
     * issuer-fingerprint subpacket is read by VerifyService but is not
     * carried through DecryptResult or DecryptStreamResult.
     */
    suspend fun fetchByKeyId(server: KeyServer, keyId: String): String? =
        withContext(Dispatchers.IO) {
            val id = keyId.uppercase().replace(" ", "").removePrefix("0X")
            if (id.isEmpty()) return@withContext null
            val response = client.get("${base(server)}/vks/v1/by-keyid/$id") {
                accept(ContentType.Application.OctetStream)
            }
            if (response.status == HttpStatusCode.OK) response.textCapped() else null
        }

    /**
     * Fetch a key's armored material by EMAIL from one server's VKS
     * by-email endpoint. Returns the armor on 200, null on any other
     * status (Hagrid/VKS 404s addresses it hasn't verified), THROWS on
     * transport failure so the caller can distinguish "not there" from
     * "couldn't reach it". Mirrors [fetchByFingerprint].
     *
     * Phase 6: used by KeyServerRepository.findByEmail to search the
     * configured directory (keys.pgpony.app first) before falling back
     * to keys.openpgp.org — so v6 keys that live only on the first-party
     * server are found, and the lookup rides the onion when Tor is on.
     */
    suspend fun searchByEmail(server: KeyServer, email: String): String? =
        withContext(Dispatchers.IO) {
            val response = client.get("${base(server)}/vks/v1/by-email/${email.trim()}") {
                accept(ContentType.Application.OctetStream)
            }
            if (response.status == HttpStatusCode.OK) response.textCapped() else null
        }

    /**
     * Query [servers] (already filtered to lookupEnabled, in order) and
     * return the FIRST armored hit. Merge across servers is the caller's
     * job (the import layer merges by fingerprint), so this just returns
     * the first non-null; callers wanting every server's copy can map
     * over [fetchByFingerprint] instead.
     */
    suspend fun lookupInOrderByFingerprint(
        servers: List<KeyServer>,
        fingerprint: String
    ): String? {
        for (server in servers) {
            val hit = runCatching { fetchByFingerprint(server, fingerprint) }.getOrNull()
            if (!hit.isNullOrBlank()) return hit
        }
        return null
    }

    /**
     * Publish [armoredPublicKey] to one server. Tries VKS
     * /vks/v1/upload (+ auto request-verify for unpublished emails);
     * falls back to HKP POST /pks/add if VKS isn't available. A 4xx that
     * looks like a key-type rejection returns [PublishOutcome.RejectedKeyType]
     * so the sheet can show the R5 "not accepted — key type" copy
     * instead of a raw HTTP error.
     */
    suspend fun publish(server: KeyServer, armoredPublicKey: String): PublishOutcome =
        withContext(Dispatchers.IO) {
            // VKS first. A clean 404 means "no VKS here"; a thrown connection
            // error (some HKP-only servers reset rather than drain a large key
            // body posted to a missing endpoint) is treated the same way, so the
            // HKP fallback still runs instead of the whole publish aborting.
            val vks = runCatching { tryVksUpload(server, armoredPublicKey) }.getOrNull()
            if (vks != null) return@withContext vks
            // HKP add, with one retry: keyservers like keyserver.ubuntu.com
            // routinely drop a pooled connection with "unexpected end of stream".
            var last: Exception? = null
            repeat(2) {
                try {
                    return@withContext tryHkpAdd(server, armoredPublicKey)
                } catch (e: Exception) {
                    last = e
                }
            }
            PublishOutcome.Failed(friendlyPublishError(server, last))
        }

    /**
     * A user-safe failure message for a thrown transport error. Never surfaces
     * the raw okhttp/ktor exception text, which can include internal object
     * hashcodes like "com.android.okhttp.Address@96702914".
     */
    private fun friendlyPublishError(server: KeyServer, e: Exception?): String {
        val host = runCatching { java.net.URI(server.baseUrl).host }.getOrNull()
            ?: server.baseUrl
        return "Couldn't reach $host. Check your connection and try again."
    }

    /** @return null if the server has no /vks/v1/upload (caller falls back to HKP). */
    private suspend fun tryVksUpload(server: KeyServer, armored: String): PublishOutcome? {
        val response = client.post("${base(server)}/vks/v1/upload") {
            contentType(ContentType.Application.Json)
            setBody(JSONObject().put("keytext", armored).toString())
        }
        return when (response.status) {
            HttpStatusCode.OK -> {
                val json = JSONObject(response.textCapped())
                val token = json.optString("token", "")
                val statusObj = json.optJSONObject("status")
                val unpublished = mutableListOf<String>()
                if (statusObj != null) {
                    val it = statusObj.keys()
                    while (it.hasNext()) {
                        val email = it.next()
                        if (statusObj.optString(email, "") == "unpublished") unpublished += email
                    }
                }
                if (token.isNotEmpty() && unpublished.isNotEmpty()) {
                    runCatching { requestVerify(server, token, unpublished) }
                }
                PublishOutcome.Ok(pendingEmails = unpublished)
            }
            HttpStatusCode.NotFound -> null // no VKS upload endpoint here
            HttpStatusCode.BadRequest,
            HttpStatusCode.UnsupportedMediaType,
            HttpStatusCode.UnprocessableEntity ->
                PublishOutcome.RejectedKeyType(response.status.value)
            else -> PublishOutcome.Failed("HTTP ${response.status.value}")
        }
    }

    private suspend fun tryHkpAdd(server: KeyServer, armored: String): PublishOutcome {
        val response = client.post("${base(server)}/pks/add") {
            setBody(FormDataContent(Parameters.build { append("keytext", armored) }))
        }
        return when {
            response.status == HttpStatusCode.OK -> PublishOutcome.Ok(pendingEmails = emptyList())
            response.status.value in 400..499 ->
                PublishOutcome.RejectedKeyType(response.status.value)
            else -> PublishOutcome.Failed("HTTP ${response.status.value}")
        }
    }

    private suspend fun requestVerify(server: KeyServer, token: String, emails: List<String>) {
        client.post("${base(server)}/vks/v1/request-verify") {
            contentType(ContentType.Application.Json)
            setBody(
                JSONObject().apply {
                    put("token", token)
                    put("addresses", JSONArray(emails))
                }.toString()
            )
        }
    }

    /**
     * Verification status for (key, server): fetch the server's copy by
     * fingerprint and check whether it carries [expectedEmail] as a
     * user id. Hagrid/VKS suppress email UIDs until the owner confirms,
     * so a served key WITH the UID means "✓ verified identity"; served
     * WITHOUT it means "published, awaiting email verification"; not
     * served at all → NotPublished.
     */
    suspend fun verificationStatus(
        server: KeyServer,
        fingerprint: String,
        expectedEmail: String?
    ): VerificationStatus = withContext(Dispatchers.IO) {
        val armored = runCatching { fetchByFingerprint(server, fingerprint) }.getOrElse {
            return@withContext VerificationStatus.Unknown
        } ?: return@withContext VerificationStatus.NotPublished
        if (expectedEmail.isNullOrBlank()) return@withContext VerificationStatus.Published
        if (armored.contains(expectedEmail, ignoreCase = true)) {
            VerificationStatus.VerifiedIdentity
        } else {
            VerificationStatus.AwaitingEmailVerification
        }
    }
}

enum class VerificationStatus {
    Unknown,
    NotPublished,
    Published,                 // served, no email UID expected/checked
    AwaitingEmailVerification, // served by fingerprint, UID not yet confirmed
    VerifiedIdentity           // served WITH the confirmed email UID
}
