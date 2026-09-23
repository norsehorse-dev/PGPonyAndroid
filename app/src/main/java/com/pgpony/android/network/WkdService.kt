// WkdService.kt
// PGPony Android — Phase A8
//
// Web Key Directory (WKD) lookup per draft-koch-openpgp-webkey-service-15.
// Given an email address, computes the canonical WKD URL and fetches the
// public key directly from the user's mail domain. This is preferred over
// keys.openpgp.org because the key is served by the same organization
// that runs the recipient's mail — no third-party keyserver in the trust
// path. iOS reference: Services/WKDService.swift (224 lines).
//
// URL structure:
//   advanced: https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<localpart>
//   direct:   https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<localpart>
//
// <hash> = ZBase32.encode(SHA1(lowercased(localpart)))
//
// The advanced method is tried first; if it fails (DNS, 404, network),
// the direct method is tried as a fallback. The response body is BINARY
// OpenPGP key data, not ASCII armor, so this service wraps it in ASCII
// armor with BouncyCastle's ArmoredOutputStream (the same path exports
// use) before handing the result to the existing armored-key import
// flow. Earlier versions hand-rolled the armor here; that mis-framed
// some keys and broke import (issue #41), so the hand-rolled base64 and
// CRC24 wrap was removed.

package com.pgpony.android.network

import com.pgpony.android.crypto.util.ZBase32
import io.ktor.client.call.body
import io.ktor.client.plugins.timeout
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.bcpg.ArmoredOutputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

// ── Result types ───────────────────────────────────────────────────────

/**
 * Where a key-lookup result came from. Useful for UI to label the
 * source ("Found via WKD (direct)" vs "Found via keys.openpgp.org")
 * so the user can judge trust appropriately.
 *
 * Display name is the user-facing string; the enum value itself is
 * stable for logging / persistence.
 */
enum class KeyLookupSource(val displayName: String) {
    WKD_ADVANCED("WKD (advanced)"),
    WKD_DIRECT("WKD (direct)"),
    // A configured directory server other than keys.openpgp.org
    // (e.g. keys.pgpony.app). Phase 6: the import/exchange search now
    // consults the user's keyserver directory before the openpgp.org
    // fallback.
    KEYSERVER("key server"),
    HAGRID("keys.openpgp.org")
}

/**
 * Result of a unified key lookup. Returned by
 * [KeyServerRepository.findByEmail] once any of the configured
 * sources resolves; the source field tells the caller which one
 * succeeded.
 */
data class KeyLookupResult(
    val armoredKey: String,
    val source: KeyLookupSource
)

// ── Service ────────────────────────────────────────────────────────────

/**
 * Looks up OpenPGP public keys via Web Key Directory.
 *
 * Singleton via [shared] — the underlying Ktor client maintains a
 * connection pool, so we want one instance for the app lifetime.
 * The pool is fine to share across coroutines.
 *
 * Timeouts are deliberately tighter than [KeyServerRepository]'s
 * 15-second Hagrid lookup: WKD should be served by a small static
 * file on the mail provider's web server, so 8s is plenty. Fast fail
 * lets [KeyServerRepository.findByEmail] try the next source quickly
 * without making the user wait through a long DNS / TCP hang.
 */
class WkdService {

    companion object {
        val shared = WkdService()

        // Short request timeout: WKD endpoints serve a tiny static
        // file; if they're not responding in 8s they likely aren't
        // configured, and we should fall through to the next source.
        private const val REQUEST_TIMEOUT_MS = 8_000L
        private const val SOCKET_TIMEOUT_MS = 15_000L
    }

    // 4.0.0 Phase 6 — route through the shared proxy-aware client
    // (Tor/Orbot when enabled; direct otherwise). Replaces the private
    // per-service HttpClient so proxy config applies uniformly.
    private val client get() = com.pgpony.android.network.HttpClientFactory.client()

    /**
     * Look up the public key for [email] via WKD. Tries the "advanced"
     * URL (openpgpkey subdomain) first, then "direct" (apex domain) as
     * a fallback. Returns null if both fail — the unified
     * [KeyServerRepository.findByEmail] will then try Hagrid.
     *
     * Not throwing on failure because all the failure modes (no DNS
     * for openpgpkey.<domain>, 404 because the user hasn't published,
     * mail provider doesn't run WKD) are normal expected paths in the
     * lookup pipeline. Throwing would force callers into a try-catch
     * for every routine case.
     *
     * On success, the returned armored key is RFC-4880 compliant:
     * proper BEGIN/END markers, base64 wrapped at 64 chars, CRC24
     * footer, trailing newline. Drop straight into the existing
     * armored-key import path.
     */
    suspend fun lookup(email: String): KeyLookupResult? = withContext(Dispatchers.IO) {
        val parsed = parseEmail(email) ?: return@withContext null
        val (localpart, domain) = parsed

        // WKD spec §3.1: hash the LOWERCASED localpart. This is the
        // canonical form so lookups are case-insensitive on the
        // localpart side. The `?l=` query param preserves the user's
        // original capitalization for the server to disambiguate
        // sub-addressing if it wants — most don't care.
        // 4.6.0 (item 17.8): lowercase ASCII only, as GnuPG does; Unicode
        // lowercasing produced a different hash for non-ASCII local parts.
        val sha1 = MessageDigest.getInstance("SHA-1")
            .digest(com.pgpony.android.crypto.CertificateBindings.asciiLower(localpart).toByteArray(Charsets.UTF_8))
        val hash = ZBase32.encode(sha1)

        // URL-encode the original localpart for the `l=` query
        // parameter. java.net.URLEncoder handles + → %2B etc.; the
        // localpart can contain ".", "+", etc. that need encoding.
        val encodedLocalpart = java.net.URLEncoder.encode(localpart, Charsets.UTF_8.name())
            // URLEncoder uses "+" for spaces (form-encoding); WKD is a
            // URL query and "+" is fine, but be safe with literal
            // percent encoding for whitespace.
            .replace("+", "%20")

        // Try advanced first. The advanced URL exists when the mail
        // domain has set up a dedicated openpgpkey subdomain.
        val advancedUrl =
            "https://openpgpkey.$domain/.well-known/openpgpkey/$domain/hu/$hash?l=$encodedLocalpart"
        // 4.6.0 (item 17.8): the direct method is tried only when the advanced
        // host does not exist (the draft's rule), not after any failure, and a
        // response counts only when it holds a key for exactly this address.
        val advanced = tryFetch(advancedUrl)
        advanced.bytes?.let { binary ->
            filterToAddress(binary, trimmedAddress(email))?.let {
                return@withContext KeyLookupResult(armoredKey = it, source = KeyLookupSource.WKD_ADVANCED)
            }
            return@withContext null
        }
        if (!advanced.hostMissing) return@withContext null

        val directUrl =
            "https://$domain/.well-known/openpgpkey/hu/$hash?l=$encodedLocalpart"
        tryFetch(directUrl).bytes?.let { binary ->
            filterToAddress(binary, trimmedAddress(email))?.let {
                return@withContext KeyLookupResult(armoredKey = it, source = KeyLookupSource.WKD_DIRECT)
            }
        }

        null
    }

    // ── Internals ───────────────────────────────────────────────────

    /**
     * Parse "user@example.com" into ("user", "example.com"). Returns
     * null if the input doesn't look like an email. Conservative
     * parser: localpart and domain non-empty, domain contains at
     * least one dot. Doesn't try to be RFC 5321-complete — bad
     * inputs just fall back through to Hagrid which has its own
     * validation.
     */
    private fun parseEmail(email: String): Pair<String, String>? {
        val trimmed = email.trim()
        val at = trimmed.indexOf('@')
        if (at <= 0 || at == trimmed.length - 1) return null
        val localpart = trimmed.substring(0, at)
        val domain = trimmed.substring(at + 1).lowercase()
        if (localpart.isEmpty() || domain.isEmpty()) return null
        if (!domain.contains('.')) return null
        return localpart to domain
    }

    /**
     * Fetch a URL and return the response body bytes, or null on any
     * failure (DNS, timeout, non-200). Suppresses all exceptions so
     * the caller can rapidly fall through.
     */
    /** 4.6.0 (item 17.8): a fetch outcome that tells "no such host" apart. */
    private class Fetch(val bytes: ByteArray?, val hostMissing: Boolean)

    private suspend fun tryFetch(urlString: String): Fetch {
        return try {
            val response = client.get(urlString) {
                accept(ContentType.Application.OctetStream)
                timeout {
                    requestTimeoutMillis =
                        if (com.pgpony.android.network.ProxyPrefs
                                .config(com.pgpony.android.PGPonyApp.instance).enabled
                        ) 20_000L else REQUEST_TIMEOUT_MS
                }
            }
            if (response.status == HttpStatusCode.OK) {
                // 4.6.0 (item 17.8): bounded read (see ResponseLimits).
                val bytes = response.bytesCapped()
                Fetch(if (bytes.isNotEmpty()) bytes else null, hostMissing = false)
            } else {
                Fetch(null, hostMissing = false)
            }
        } catch (e: Exception) {
            Fetch(null, hostMissing = isHostMissing(e))
        }
    }

    /**
     * True when [e] means the host name does not resolve: a local DNS miss,
     * or, through a SOCKS proxy (which resolves names itself), the proxy's
     * "host unreachable" reply. Anything else (TLS, timeout, refused) is not
     * a missing host, so it does not trigger the direct-method fallback.
     */
    private fun isHostMissing(e: Throwable): Boolean {
        var cur: Throwable? = e
        while (cur != null) {
            if (cur is java.net.UnknownHostException) return true
            val m = cur.message?.lowercase() ?: ""
            if (m.contains("host unreachable") || m.contains("unable to resolve host") ||
                m.contains("no address associated")
            ) return true
            cur = cur.cause
        }
        return false
    }

    private fun trimmedAddress(email: String): String = email.trim()

    /**
     * 4.6.0 (item 17.8): what a WKD host returns is only trusted as far as it
     * matches the query. Each certificate in [bytes] keeps only the User IDs
     * (certified by its primary) whose address is exactly [address]; a
     * certificate with none is dropped, and a response with none left is
     * refused. Returns the surviving certificates armored, or null.
     */
    internal fun filterToAddress(bytes: ByteArray, address: String): String? {
        val binary = runCatching {
            val head = String(bytes, 0, minOf(15, bytes.size), Charsets.US_ASCII)
            if (head.trimStart().startsWith("-----BEGIN PGP")) {
                org.bouncycastle.bcpg.ArmoredInputStream(bytes.inputStream()).readBytes()
            } else bytes
        }.getOrNull() ?: return null
        val want = com.pgpony.android.crypto.CertificateBindings.mailboxOf(address)
        val kept = com.pgpony.android.crypto.CertificateBindings.splitCertificates(binary).mapNotNull { cert ->
            com.pgpony.android.crypto.CertificateBindings.keepUserIds(cert) {
                com.pgpony.android.crypto.CertificateBindings.mailboxOf(it) == want
            }
        }
        if (kept.isEmpty()) return null
        val joined = java.io.ByteArrayOutputStream().apply { kept.forEach { write(it) } }.toByteArray()
        return armorFetchedKey(joined)
    }

    private fun armorFetchedKey(bytes: ByteArray): String {
        val head = String(bytes, 0, minOf(15, bytes.size), Charsets.US_ASCII)
        if (head.trimStart().startsWith("-----BEGIN PGP")) {
            return bytes.toString(Charsets.UTF_8)
        }
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { it.write(bytes) }
        return out.toString(Charsets.UTF_8.name())
    }
}
