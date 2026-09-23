// ResponseLimits.kt
// PGPony Android, 4.6.0 (item 17.8): read a key server, WKD or update-check
// response with a ceiling. Bodies used to be read whole into memory with no
// limit, so a hostile host could exhaust the app's heap with one response.

package com.pgpony.android.network

import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsChannel
import io.ktor.utils.io.readAvailable
import java.io.ByteArrayOutputStream
import java.io.IOException

object ResponseLimits {
    /** Largest key response accepted. Far above any real certificate keys.openpgp.org
     *  or a WKD host serves; matches CertificateBindings' own ceiling. */
    const val MAX_KEY_RESPONSE_BYTES = 8L * 1024 * 1024
    /** Largest update-check (release metadata) response accepted. */
    const val MAX_METADATA_RESPONSE_BYTES = 2L * 1024 * 1024
}

/** The response body as bytes, failing once it passes [max]. */
suspend fun HttpResponse.bytesCapped(max: Long = ResponseLimits.MAX_KEY_RESPONSE_BYTES): ByteArray {
    val declared = headers["Content-Length"]?.toLongOrNull()
    if (declared != null && declared > max) throw IOException("response larger than $max bytes")
    val ch = bodyAsChannel()
    val out = ByteArrayOutputStream()
    val buf = ByteArray(1 shl 16)
    var total = 0L
    while (true) {
        val n = ch.readAvailable(buf, 0, buf.size)
        if (n < 0) break
        if (n == 0) { if (ch.isClosedForRead) break else continue }
        total += n
        if (total > max) throw IOException("response larger than $max bytes")
        out.write(buf, 0, n)
    }
    return out.toByteArray()
}

/** The response body as UTF-8 text, failing once it passes [max]. */
suspend fun HttpResponse.textCapped(max: Long = ResponseLimits.MAX_KEY_RESPONSE_BYTES): String =
    String(bytesCapped(max), Charsets.UTF_8)
