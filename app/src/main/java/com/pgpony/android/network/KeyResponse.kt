// KeyResponse.kt
// PGPony Android, 4.6.0 (item 18): a key server or WKD answer is shown as
// "Key Found" only when it really holds public key material for the query.
//
// A lookup used to accept any 200 body. A host (or a captive portal, or a
// proxy error page) that answered with an HTML page had that page wrapped in
// ASCII armor and offered for import as "BEGIN PGP MESSAGE". Every lookup
// path (WKD, keys.pgpony.app and the other directory servers, keys.openpgp.org)
// now runs its body through [certificates] before anything reaches the UI:
//
//   * a text/html (or XHTML) content type is refused outright;
//   * armored input must be PUBLIC KEY BLOCK only: any other armor type in the
//     body (MESSAGE, SIGNATURE, PRIVATE KEY BLOCK) refuses the whole answer;
//   * binary input must start with a public-key packet and hold only the
//     packets a transferable public key may carry (no secret keys, no message
//     packets); anything else refuses the whole answer;
//   * a certificate whose primary this app cannot read is left out;
//   * a by-fingerprint or by-key-ID answer keeps only the certificates whose
//     primary or a subkey is the one asked for.
//
// What survives is re-armored from the parsed packets, so the result is
// always a PUBLIC KEY BLOCK and an arbitrary HTTP body is never re-armored.

package com.pgpony.android.network

import com.pgpony.android.crypto.CertificateBindings
import io.ktor.client.statement.HttpResponse
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import java.io.ByteArrayOutputStream

object KeyResponse {

    /** What a lookup asked for, so the answer can be checked against it. */
    sealed class Query {
        /** By-email lookups: the address filter runs separately. */
        object Any : Query()
        /** Primary or subkey fingerprint, hex; spaces, colons and 0x ignored.
         *  A 16-digit value is a long key ID typed into the fingerprint box
         *  and matches as one. */
        class Fingerprint(fp: String) : Query() {
            val hex: String = normalize(fp)
        }
        /** 64-bit (16 digits) or 32-bit (8 digits) key ID, hex. */
        class KeyId(id: String) : Query() {
            val hex: String = normalize(id)
        }
    }

    internal fun normalize(s: String): String =
        s.trim().removePrefix("0x").removePrefix("0X").filter { !it.isWhitespace() && it != ':' }.uppercase()

    private fun keyIdMatches(hex: String, keyId: Long): Boolean {
        val full = String.format("%016X", keyId)
        return when (hex.length) {
            16 -> full == hex
            8 -> full.endsWith(hex)
            else -> false
        }
    }

    private const val PUBLIC_HEADER = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    private const val PUBLIC_FOOTER = "-----END PGP PUBLIC KEY BLOCK-----"

    private const val TAG_SIGNATURE = 2
    private const val TAG_PUBLIC_KEY = 6
    private const val TAG_TRUST = 12
    private const val TAG_USER_ID = 13
    private const val TAG_PUBLIC_SUBKEY = 14
    private const val TAG_USER_ATTRIBUTE = 17
    private val ALLOWED_TAGS = setOf(TAG_SIGNATURE, TAG_PUBLIC_KEY, TAG_TRUST, TAG_USER_ID,
        TAG_PUBLIC_SUBKEY, TAG_USER_ATTRIBUTE)

    /** True for a content type that marks the body as a web page. */
    fun isHtml(contentType: String?): Boolean {
        val t = contentType?.substringBefore(';')?.trim()?.lowercase() ?: return false
        return t == "text/html" || t == "application/xhtml+xml"
    }

    /**
     * The public certificates in [body], one binary certificate per entry, or
     * null when the answer is not public key material (see the header).
     * Trust packets are dropped.
     */
    fun certificates(body: ByteArray, contentType: String? = null): List<ByteArray>? {
        if (body.isEmpty() || isHtml(contentType)) return null
        val binary = decode(body) ?: return null
        val pkts = CertificateBindings.packets(binary)
        if (pkts.isEmpty() || pkts.first().tag != TAG_PUBLIC_KEY) return null
        if (pkts.any { it.tag !in ALLOWED_TAGS }) return null
        val certs = ArrayList<ByteArray>()
        var cur: ByteArrayOutputStream? = null
        for (p in pkts) {
            if (p.tag == TAG_PUBLIC_KEY) {
                cur?.let { certs.add(it.toByteArray()) }
                cur = ByteArrayOutputStream()
            }
            if (p.tag == TAG_TRUST) continue
            cur?.write(CertificateBindings.frame(p.tag, p.body))
        }
        cur?.let { certs.add(it.toByteArray()) }
        // A certificate whose primary this app cannot read (a v3 key, say) is
        // left out; the others in the answer still count.
        return certs.filter { CertificateBindings.parse(it) != null }.takeIf { it.isNotEmpty() }
    }

    /** True when [cert]'s primary or one of its subkeys is what [query] names. */
    fun matches(cert: ByteArray, query: Query): Boolean {
        if (query is Query.Any) return true
        val parsed = CertificateBindings.parse(cert) ?: return false
        val keys = sequenceOf(parsed.primary) + parsed.components.asSequence()
            .filter { CertificateBindings.isSubkeyTag(it.tag) }
            .mapNotNull { c ->
                CertificateBindings.publicPart(c.tag, c.body)
                    ?.let { runCatching { CertificateBindings.KeyBody(it) }.getOrNull() }
            }
        return when (query) {
            is Query.Fingerprint -> query.hex.isNotEmpty() && keys.any {
                it.fingerprintHex == query.hex || (query.hex.length == 16 && keyIdMatches(query.hex, it.keyId))
            }
            is Query.KeyId -> keys.any { keyIdMatches(query.hex, it.keyId) }
            Query.Any -> true
        }
    }

    /**
     * [body] as validated, query-matched public key armor, or null when there
     * is nothing to show ("no key found").
     */
    fun validate(body: ByteArray, contentType: String? = null, query: Query = Query.Any): String? {
        val kept = certificates(body, contentType)?.filter { matches(it, query) } ?: return null
        return if (kept.isEmpty()) null else armor(kept)
    }

    fun validate(body: String, contentType: String? = null, query: Query = Query.Any): String? =
        validate(body.toByteArray(Charsets.UTF_8), contentType, query)

    /** [certs] (binary public certificates) as one PUBLIC KEY BLOCK, no Version header. */
    fun armor(certs: List<ByteArray>): String {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { a ->
            a.setHeader(ArmoredOutputStream.VERSION_HDR, null)
            certs.forEach { a.write(it) }
        }
        val text = out.toString(Charsets.UTF_8.name())
        // ArmoredOutputStream picks the armor type from the first packet; the
        // first packet is always a public key here, but never trust that blindly.
        return if (text.startsWith(PUBLIC_HEADER)) text else throw IllegalStateException("armor type")
    }

    /** Binary OpenPGP data from [body], or null when it is neither binary
     *  OpenPGP nor armor made only of PUBLIC KEY BLOCKs. */
    private fun decode(body: ByteArray): ByteArray? {
        if (body[0].toInt() and 0x80 != 0) return body
        val text = String(body, Charsets.UTF_8)
        val begins = Regex("-----BEGIN PGP ([A-Z ,/0-9]+)-----").findAll(text).toList()
        if (begins.isEmpty()) return null
        if (begins.any { it.value != PUBLIC_HEADER }) return null
        val out = ByteArrayOutputStream()
        var from = 0
        while (true) {
            val start = text.indexOf(PUBLIC_HEADER, from)
            if (start < 0) break
            val end = text.indexOf(PUBLIC_FOOTER, start)
            if (end < 0) return null
            val block = text.substring(start, end + PUBLIC_FOOTER.length)
            val bytes = runCatching {
                ArmoredInputStream(block.byteInputStream(Charsets.UTF_8)).use { it.readBytes() }
            }.getOrNull() ?: return null
            out.write(bytes)
            from = end + PUBLIC_FOOTER.length
        }
        return out.toByteArray().takeIf { it.isNotEmpty() }
    }
}

/**
 * 4.6.0 (item 18): the response body as validated public key armor matching
 * [query], or null when it is not one (see KeyResponse). Bounded like
 * [bytesCapped].
 */
suspend fun HttpResponse.publicKeyOrNull(query: KeyResponse.Query = KeyResponse.Query.Any): String? {
    val type = headers["Content-Type"]
    if (KeyResponse.isHtml(type)) return null
    return KeyResponse.validate(bytesCapped(), type, query)
}
