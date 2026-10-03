// PairPeer.kt
// Which connections a pairing host lets through to phase 1 (docs/PAIRING_PROTOCOL.md, section 1).
// The listener answers on every interface, so the host checks where each connection comes from
// and closes one from outside the local network before reading a byte; such a connection does
// not use up the window.

package com.pgpony.android.pair

import java.net.InetAddress

object PairPeer {

    /** A local network: an interface address and its prefix length. */
    class Subnet(address: ByteArray, val prefixLength: Int) {
        val address: ByteArray = address.copyOf()

        init {
            require(address.size == 4 || address.size == 16) { "an IPv4 or IPv6 address" }
            require(prefixLength in 0..address.size * 8) { "a prefix length that fits the address" }
        }

        /** Whether [peer] (4 or 16 bytes) is in this subnet. */
        fun contains(peer: ByteArray): Boolean {
            if (peer.size != address.size) return false
            return prefixEquals(peer, address, prefixLength)
        }
    }

    /**
     * True when a connection from [peer] (the 4 or 16 bytes of its address) may run phase 1:
     * loopback, link-local, RFC 1918, unique-local IPv6, or inside one of [subnets] (the host's
     * listed addresses with their prefix lengths). An IPv4-mapped IPv6 address is judged as the
     * IPv4 address it carries.
     */
    fun isAllowed(peer: ByteArray, subnets: List<Subnet> = emptyList()): Boolean {
        val addr = unmapped(peer) ?: return false
        if (isLocalRange(addr)) return true
        return subnets.any { it.contains(addr) }
    }

    fun isAllowed(peer: InetAddress, subnets: List<Subnet> = emptyList()): Boolean = isAllowed(peer.address, subnets)

    /** The ranges that are local whatever the host's own addresses are. */
    fun isLocalRange(peer: ByteArray): Boolean {
        val a = unmapped(peer) ?: return false
        val b0 = a[0].toInt() and 0xFF
        val b1 = a[1].toInt() and 0xFF
        return if (a.size == 4) {
            b0 == 127 ||                                  // 127.0.0.0/8 loopback
                b0 == 10 ||                               // 10.0.0.0/8
                (b0 == 172 && b1 in 16..31) ||            // 172.16.0.0/12
                (b0 == 192 && b1 == 168) ||               // 192.168.0.0/16
                (b0 == 169 && b1 == 254)                  // 169.254.0.0/16 link-local
        } else {
            a.contentEquals(LOOPBACK6) ||                 // ::1
                (b0 == 0xFE && (b1 and 0xC0) == 0x80) ||  // fe80::/10 link-local
                (b0 and 0xFE) == 0xFC                     // fc00::/7 unique local
        }
    }

    /** 4 bytes for IPv4 and for an IPv4-mapped IPv6 address, 16 for other IPv6, null otherwise. */
    private fun unmapped(peer: ByteArray): ByteArray? = when (peer.size) {
        4 -> peer
        16 -> if (prefixEquals(peer, MAPPED_PREFIX, 96)) peer.copyOfRange(12, 16) else peer
        else -> null
    }

    private fun prefixEquals(a: ByteArray, b: ByteArray, bits: Int): Boolean {
        val whole = bits / 8
        for (i in 0 until whole) if (a[i] != b[i]) return false
        val rest = bits % 8
        if (rest == 0) return true
        val mask = (0xFF shl (8 - rest)) and 0xFF
        return (a[whole].toInt() and mask) == (b[whole].toInt() and mask)
    }

    private val LOOPBACK6 = ByteArray(16).also { it[15] = 1 }
    private val MAPPED_PREFIX = ByteArray(16).also { it[10] = 0xFF.toByte(); it[11] = 0xFF.toByte() }
}
