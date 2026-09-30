// PairInvite.kt
// The invite a pairing host shows as a QR code (docs/PAIRING_PROTOCOL.md, section 8):
//
//     pgpony-pair:1?a=<address>[,<address>...]&h=<base64url(SHA-256(pk_H)[0..16])>
//
// A phone scans it instead of typing an address, and the joiner checks the host key in ACCEPT
// against `h`. Addresses are IP literals only (an IPv6 one in brackets), so a QR code can never
// make the joiner look up a name.

package com.pgpony.android.pair

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64

class PairInvite(addresses: List<Address>, hostKeyHash: ByteArray) {

    /** One `host:port` from `a`. [host] is an IPv4 or IPv6 literal, without brackets. */
    data class Address(val host: String, val port: Int) {
        override fun toString(): String = if (':' in host) "[$host]:$port" else "$host:$port"

        /** No lookup: [host] is a literal, which InetAddress parses without DNS. */
        fun socketAddress(): InetSocketAddress = InetSocketAddress(InetAddress.getByName(host), port)
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
        private val IPV6 = Regex("^[0-9A-Fa-f:.]{2,45}$")
        private val PORT = Regex("^[1-9]\\d{0,4}$")

        /** The invite for a host whose window key is [hostPublicKey], reachable at [addresses]. */
        fun forHostKey(hostPublicKey: ByteArray, addresses: List<Address>): PairInvite =
            PairInvite(addresses, PairCrypto.sha256(hostPublicKey).copyOf(HASH_BYTES))

        /**
         * Reads an invite, or null when [text] is not a well-formed one. Members other than `a`
         * and `h` are ignored so a later version can add some; a repeated `a` or `h` is refused.
         */
        fun parse(text: String): PairInvite? {
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
            val host = if (hostPart.startsWith("[") && hostPart.endsWith("]")) {
                val inner = hostPart.substring(1, hostPart.length - 1)
                if (!IPV6.matches(inner) || ':' !in inner) return null
                inner.lowercase()
            } else {
                val m = IPV4.matchEntire(hostPart) ?: return null
                if (m.groupValues.drop(1).any { it.toInt() > 255 || (it.length > 1 && it.startsWith("0")) }) return null
                hostPart
            }
            return Address(host, port)
        }
    }
}
