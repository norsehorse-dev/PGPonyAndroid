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
// OpenPGP key data — NOT ASCII armor. This service wraps the binary in
// standard ASCII armor (matching RFC 4880 §6.2 + CRC24) so the caller
// can hand the result to the existing armored-key import flow without
// branching on format.
//
// Why we don't use BC's ArmoredOutputStream here:
//   • Keeps the network layer free of cross-package coupling to BC.
//   • This is a small write-once-then-throw-away string; we don't need
//     BC's full armor machinery (chunk-counted CRC, header table, etc).
//   • The manual CRC24 + base64 wrap is ~30 lines and easier to verify
//     against RFC 4880 than threading binary key bytes through BC.

package com.pgpony.android.network

import com.pgpony.android.crypto.util.ZBase32
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.android.Android
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.Base64

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

    private val client = HttpClient(Android) {
        engine {
            connectTimeout = REQUEST_TIMEOUT_MS.toInt()
            socketTimeout = SOCKET_TIMEOUT_MS.toInt()
        }
    }

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
        val sha1 = MessageDigest.getInstance("SHA-1")
            .digest(localpart.lowercase().toByteArray(Charsets.UTF_8))
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
        tryFetch(advancedUrl)?.let { binary ->
            return@withContext KeyLookupResult(
                armoredKey = armorBinaryPublicKey(binary),
                source = KeyLookupSource.WKD_ADVANCED
            )
        }

        // Direct fallback: same path under the apex domain. Slightly
        // more common for self-hosted mail; Gmail uses this since
        // 2024 (no openpgpkey.gmail.com subdomain).
        val directUrl =
            "https://$domain/.well-known/openpgpkey/hu/$hash?l=$encodedLocalpart"
        tryFetch(directUrl)?.let { binary ->
            return@withContext KeyLookupResult(
                armoredKey = armorBinaryPublicKey(binary),
                source = KeyLookupSource.WKD_DIRECT
            )
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
    private suspend fun tryFetch(urlString: String): ByteArray? {
        return try {
            val response = client.get(urlString) {
                // WKD spec recommends accepting application/octet-stream;
                // most servers serve a fixed binary blob regardless.
                accept(ContentType.Application.OctetStream)
            }
            if (response.status == HttpStatusCode.OK) {
                // Ktor 2.x: response.body<ByteArray>() is the canonical
                // way to read a binary response. bodyAsBytes() doesn't
                // exist in Ktor 2.3.12 (it's a JVM-only API in some
                // forks but not in the published artifact PGPony uses).
                val bytes = response.body<ByteArray>()
                if (bytes.isNotEmpty()) bytes else null
            } else {
                null
            }
        } catch (e: Exception) {
            // DNS-not-found / connection-refused / SSL handshake fail /
            // request timeout / read timeout / etc. All normal in the
            // "this domain doesn't run WKD" path; absorb and let the
            // caller try the next source.
            null
        }
    }

    /**
     * Wrap binary OpenPGP key bytes in RFC 4880 §6.2 ASCII armor.
     *
     * Output format:
     *   -----BEGIN PGP PUBLIC KEY BLOCK-----
     *   <blank line>
     *   <base64 of bytes, 64 chars per line>
     *   =<base64 of 24-bit CRC>
     *   -----END PGP PUBLIC KEY BLOCK-----
     *
     * Notes:
     *   • Blank line after BEGIN is REQUIRED by RFC 4880 — gpg warns
     *     "invalid armor header" without it (same regression A7 Fix2
     *     fixed in PGPCryptoService).
     *   • No Version or Comment headers — matches the post-Fix2
     *     behavior elsewhere in PGPony. We do NOT add a "Comment:
     *     PGPony Android" here because this is a key we DOWNLOADED,
     *     not one we produced; attributing it to PGPony would be
     *     misleading.
     *   • CRC24 polynomial per RFC 4880 §6.1: initial 0xB704CE, poly
     *     0x1864CFB.
     *   • base64 uses java.util.Base64.getEncoder() — RFC 4648
     *     standard alphabet, no URL-safe nonsense, no newlines (we
     *     wrap manually to 64 char lines).
     */
    private fun armorBinaryPublicKey(bytes: ByteArray): String {
        val base64 = Base64.getEncoder().encodeToString(bytes)
        val wrapped = base64.chunked(64).joinToString("\n")
        val crc = crc24(bytes)
        val crcBytes = byteArrayOf(
            ((crc shr 16) and 0xFF).toByte(),
            ((crc shr 8) and 0xFF).toByte(),
            (crc and 0xFF).toByte()
        )
        val crcBase64 = Base64.getEncoder().encodeToString(crcBytes)
        return buildString {
            append("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
            append("\n")
            append(wrapped)
            append("\n=")
            append(crcBase64)
            append("\n-----END PGP PUBLIC KEY BLOCK-----\n")
        }
    }

    /**
     * CRC-24 from RFC 4880 §6.1.
     *   crc_init      = 0xB704CE
     *   crc_polynom   = 0x1864CFB
     *   output mask   = 0xFFFFFF (24 bits)
     *
     * Verified against the spec example. Used only for armoring
     * downloaded WKD keys; PGPony's own exports go through BC's
     * ArmoredOutputStream which does its own CRC.
     */
    private fun crc24(data: ByteArray): Int {
        var crc = 0xB704CE
        for (byte in data) {
            crc = crc xor ((byte.toInt() and 0xFF) shl 16)
            repeat(8) {
                crc = crc shl 1
                if ((crc and 0x1000000) != 0) {
                    crc = crc xor 0x1864CFB
                }
            }
        }
        return crc and 0xFFFFFF
    }
}
