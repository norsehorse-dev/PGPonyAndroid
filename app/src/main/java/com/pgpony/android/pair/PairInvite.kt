// PairInvite.kt
// The invite a pairing host shows as a QR code (docs/PAIRING_PROTOCOL.md, section 8):
//
//     pgpony-pair:1?a=<address>[,<address>...]&h=<base64url(SHA-256(pk_H)[0..16])>
//
// A phone scans it instead of typing an address, and the joiner checks the host key in ACCEPT
// against `h`. Addresses are IP literals only (an IPv6 one in brackets), so a QR code can never
// make the joiner look up a name: they are parsed to their bytes here, strictly, and the socket
// address is built from those bytes.

package com.pgpony.android.pair

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64

class PairInvite(addresses: List<Address>, hostKeyHash: ByteArray) {

    /** One `host:port` from `a`. [host] is an IPv4 or IPv6 literal, without brackets. */
    data class Address(val host: String, val port: Int) {
        override fun toString(): String = if (':' in host) "[$host]:$port" else "$host:$port"

        /** The 4 or 16 bytes of [host]. */
        fun bytes(): ByteArray = hostBytes(host) ?: throw IllegalStateException("not an IP literal")

        /** No lookup: built from the literal's bytes, never from a name. */
        fun socketAddress(): InetSocketAddress = InetSocketAddress(InetAddress.getByAddress(bytes()), port)
    }

    val addresses: List<Address> = addresses.toList()
    private val hash: ByteArray = hostKeyHash.copyOf()

    /** The first 16 bytes of SHA-256(pk_H), for PairProtocol.join's expectedHostKeyHash. */
    val hostKeyHash: ByteArray get() = hash.copyOf()

    init {
        require(this.addresses.size in 1..MAX_ADDRESSES) { "an invite lists 1 to $MAX_ADDRESSES addresses" }
        require(hash.size == HASH_BYTES) { "the host key hash is $HASH_BYTES bytes" }
        require(this.addresses.all { parseAddress(it.toString()) == it }) { "addresses are IP literals with a port" }
    }

    fun toUri(): String = PREFIX + "a=" + addresses.joinToString(",") + "&h=" + B64.encodeToString(hash)

    override fun toString(): String = toUri()

    override fun equals(other: Any?): Boolean =
        other is PairInvite && other.addresses == addresses && other.hash.contentEquals(hash)

    override fun hashCode(): Int = addresses.hashCode() * 31 + hash.contentHashCode()

    /**
     * Connects to the first address that answers, in the order listed. Blocks; throws the last
     * failure when none answers.
     */
    fun connect(timeoutMs: Int = CONNECT_TIMEOUT_MS): Socket {
        var last: Exception? = null
        for (a in addresses) {
            val s = Socket()
            try {
                s.connect(a.socketAddress(), timeoutMs)
                return s
            } catch (e: Exception) {
                runCatching { s.close() }
                last = e
            }
        }
        throw PairException(PairFailure.CLOSED, last?.message ?: "no address answered")
    }

    companion object {
        const val PREFIX = "pgpony-pair:1?"
        const val HASH_BYTES = 16
        const val MAX_ADDRESSES = 8
        const val CONNECT_TIMEOUT_MS = 3_000

        private val B64 = Base64.getUrlEncoder().withoutPadding()
        private val HASH_TEXT = Regex("^[A-Za-z0-9_-]{22}$")
        private val IPV4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")
        private val PORT = Regex("^[1-9]\\d{0,4}$")

        /** The invite for a host whose window key is [hostPublicKey], reachable at [addresses]. */
        fun forHostKey(hostPublicKey: ByteArray, addresses: List<Address>): PairInvite =
            PairInvite(addresses, PairCrypto.sha256(hostPublicKey).copyOf(HASH_BYTES))

        /**
         * Reads an invite, or null when [text] is not a well-formed one. Members other than `a`
         * and `h` are ignored so a later version can add some; a repeated `a` or `h` is refused.
         */
        fun parse(text: String): PairInvite? = try {
            parseOrNull(text)
        } catch (e: RuntimeException) {
            null
        }

        private fun parseOrNull(text: String): PairInvite? {
            val t = text.trim()
            // The scheme matches without regard to ASCII case only (not Unicode case folding,
            // under which a dotless i would pass), as in the Swift twin.
            if (t.length < PREFIX.length || t.substring(0, PREFIX.length).map { if (it in 'A'..'Z') it + 32 else it }.joinToString("") != PREFIX) return null
            var a: String? = null
            var h: String? = null
            for (part in t.substring(PREFIX.length).split('&')) {
                val eq = part.indexOf('=')
                if (eq <= 0) return null
                val value = part.substring(eq + 1)
                when (part.substring(0, eq)) {
                    "a" -> if (a == null) a = value else return null
                    "h" -> if (h == null) h = value else return null
                }
            }
            val hashText = h ?: return null
            if (!HASH_TEXT.matches(hashText)) return null
            val hash = try {
                Base64.getUrlDecoder().decode(hashText)
            } catch (e: IllegalArgumentException) {
                return null
            }
            // One spelling per hash: the unused low bits of the last character must be zero.
            if (hash.size != HASH_BYTES || B64.encodeToString(hash) != hashText) return null
            val list = (a ?: return null).split(',')
            if (list.size > MAX_ADDRESSES) return null
            val addresses = list.map { parseAddress(it) ?: return null }
            return PairInvite(addresses, hash)
        }

        /** `192.168.1.20:49152` or `[fd00::1]:49152`; null for anything else, names included. */
        fun parseAddress(text: String): Address? {
            val colon = text.lastIndexOf(':')
            if (colon <= 0) return null
            val hostPart = text.substring(0, colon)
            val portPart = text.substring(colon + 1)
            if (!PORT.matches(portPart)) return null
            val port = portPart.toInt()
            if (port !in 1..65535) return null
            val host = if (hostPart.startsWith("[") && hostPart.endsWith("]") && hostPart.length >= 2) {
                val inner = hostPart.substring(1, hostPart.length - 1)
                if (':' !in inner || ipv6Bytes(inner) == null) return null
                inner.lowercase()
            } else {
                if (ipv4Bytes(hostPart) == null) return null
                hostPart
            }
            return Address(host, port)
        }

        /**
         * The bytes of an IP literal without brackets: 4 for a dotted quad, 16 for IPv6. Null for
         * anything else, names and zone ids included.
         */
        fun hostBytes(host: String): ByteArray? = if (':' in host) ipv6Bytes(host) else ipv4Bytes(host)

        /** A dotted quad with no leading zeros. */
        internal fun ipv4Bytes(text: String): ByteArray? {
            val m = IPV4.matchEntire(text) ?: return null
            val parts = m.groupValues.drop(1)
            if (parts.any { it.toInt() > 255 || (it.length > 1 && it.startsWith("0")) }) return null
            return ByteArray(4) { parts[it].toInt().toByte() }
        }

        /**
         * An IPv6 literal in the text forms of RFC 4291 section 2.2: eight groups of 1 to 4 hex
         * digits, or fewer with exactly one `::` standing for at least one zero group, and
         * optionally a dotted quad as the last 32 bits. No zone, no brackets, no white space.
         */
        internal fun ipv6Bytes(text: String): ByteArray? {
            if (text.length !in 2..45) return null
            if (text.any { !(it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.') }) return null
            val gap = text.indexOf("::")
            val words: List<Int> = if (gap < 0) {
                val all = ipv6Words(text, quadAllowed = true) ?: return null
                if (all.size != 8) return null
                all
            } else {
                if (text.indexOf("::", gap + 1) >= 0) return null
                val head = ipv6Words(text.substring(0, gap), quadAllowed = false) ?: return null
                val tail = ipv6Words(text.substring(gap + 2), quadAllowed = true) ?: return null
                if (head.size + tail.size > 7) return null
                head + List(8 - head.size - tail.size) { 0 } + tail
            }
            return ByteArray(16) { i -> (if (i % 2 == 0) words[i / 2] shr 8 else words[i / 2]).toByte() }
        }

        /** The 16-bit words of one side of `::` (or of a whole address without one). */
        private fun ipv6Words(part: String, quadAllowed: Boolean): List<Int>? {
            if (part.isEmpty()) return emptyList()
            val groups = part.split(':')
            val out = ArrayList<Int>(8)
            for ((i, g) in groups.withIndex()) {
                if ('.' in g) {
                    if (!quadAllowed || i != groups.lastIndex) return null
                    val q = ipv4Bytes(g) ?: return null
                    out += ((q[0].toInt() and 0xFF) shl 8) or (q[1].toInt() and 0xFF)
                    out += ((q[2].toInt() and 0xFF) shl 8) or (q[3].toInt() and 0xFF)
                } else {
                    if (g.length !in 1..4) return null
                    out += g.toInt(16)
                }
                if (out.size > 8) return null
            }
            return out
        }
    }
}
