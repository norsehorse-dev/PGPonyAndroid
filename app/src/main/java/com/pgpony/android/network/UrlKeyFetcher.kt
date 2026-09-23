// UrlKeyFetcher.kt
// PGPony Android, 4.6.0 (item 2): import a public key from a link.
//
// The fetch goes through the shared proxy-aware client, so offline mode and
// the Off / Orbot / Custom proxy setting apply to it like any key-server
// lookup. Only https is fetched (plain http only for a .onion address, where
// Tor already encrypts the path); redirects are followed by hand, at most
// MAX_REDIRECTS of them, and each hop must meet the same rule, so a link can
// never be bounced to plain http. The body is read with the key-response cap.
//
// What comes back is only public key material: a raw binary key, or the
// PUBLIC KEY BLOCKs found anywhere in a text or HTML page (a key shown on a
// personal site, a gist, a raw .asc). Every block is validated the way a
// key-server answer is (KeyResponse), so a page with no key, a message or a
// private key block is "no public key at this link". Nothing is stored here:
// the caller shows the key for a fingerprint check and imports only on
// confirm.

package com.pgpony.android.network

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpStatusCode
import io.ktor.http.isSuccess
import java.net.URI

object UrlKeyFetcher {

    const val MAX_REDIRECTS = 5

    sealed class Result {
        /** Validated public key armor, and the address it finally came from. */
        data class Keys(val armored: String, val finalUrl: String) : Result()
        object NotHttps : Result()
        object Offline : Result()
        object NoKey : Result()
        object TooManyRedirects : Result()
        data class HttpError(val status: Int) : Result()
        data class Failed(val message: String) : Result()
    }

    /** Parse [input] as a link this fetcher may follow, or null. */
    fun allowedUri(input: String): URI? {
        val uri = runCatching { URI(input.trim()) }.getOrNull() ?: return null
        val host = uri.host?.lowercase() ?: return null
        return when (uri.scheme?.lowercase()) {
            "https" -> uri
            "http" -> if (host.endsWith(".onion")) uri else null
            else -> null
        }
    }

    suspend fun fetch(input: String): Result {
        if (OfflineMode.isEnabled()) return Result.Offline
        var uri = allowedUri(input) ?: return Result.NotHttps
        val client = HttpClientFactory.client().config { followRedirects = false }
        try {
            repeat(MAX_REDIRECTS + 1) {
                val response: HttpResponse = client.get(uri.toString()) {
                    header("Accept", "application/pgp-keys, text/plain;q=0.9, */*;q=0.5")
                }
                val status = response.status
                if (status.value in 300..399 && status != HttpStatusCode.NotModified) {
                    val location = response.headers["Location"] ?: return Result.HttpError(status.value)
                    val next = runCatching { uri.resolve(location) }.getOrNull()
                        ?: return Result.HttpError(status.value)
                    uri = allowedUri(next.toString()) ?: return Result.NotHttps
                    return@repeat
                }
                if (!status.isSuccess()) return Result.HttpError(status.value)
                val body = response.bytesCapped()
                val armored = keysFrom(body) ?: return Result.NoKey
                return Result.Keys(armored, uri.toString())
            }
            return Result.TooManyRedirects
        } catch (e: OfflineModeException) {
            return Result.Offline
        } catch (e: Exception) {
            return Result.Failed(e.message ?: e.javaClass.simpleName)
        } finally {
            client.close()
        }
    }

    /**
     * The validated public key armor in a fetched [body], or null. Binary
     * OpenPGP is checked as is; text (including an HTML page) is searched for
     * PUBLIC KEY BLOCKs, with any markup inside a block removed first.
     */
    fun keysFrom(body: ByteArray): String? {
        if (body.isEmpty()) return null
        if (body[0].toInt() and 0x80 != 0) return KeyResponse.validate(body)
        val text = String(body, Charsets.UTF_8)
        val blocks = PUBLIC_BLOCK.findAll(text).map { cleanBlock(it.value) }.toList()
        if (blocks.isEmpty()) return null
        return KeyResponse.validate(blocks.joinToString("\n"))
    }

    private val PUBLIC_BLOCK = Regex(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----[\\s\\S]*?-----END PGP PUBLIC KEY BLOCK-----"
    )

    /** One armor block as found on a page: markup dropped, entities decoded,
     *  each line trimmed, so the base64 lines come back intact. */
    private fun cleanBlock(block: String): String =
        block.replace(Regex("<[^>]*>"), "\n")
            .replace("&#43;", "+").replace("&#47;", "/").replace("&#61;", "=")
            .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&amp;", "&")
            .lines().map { it.trim() }.filter { it.isNotEmpty() }
            .let { lines ->
                // Armor needs a blank line after the header lines; restore it
                // after the BEGIN line and any "Key: value" headers.
                val out = ArrayList<String>()
                var i = 0
                out.add(lines[i++])
                while (i < lines.size && lines[i].contains(": ")) out.add(lines[i++])
                out.add("")
                while (i < lines.size) out.add(lines[i++])
                out.joinToString("\n")
            }
}
