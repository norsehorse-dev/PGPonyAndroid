// PairControllerTest.kt
// PGPony Android 4.6.3 (4.7.0 item 21): the phone-side pairing helpers that
// need no network or device: what a scan or a typed address resolves to,
// which interfaces a phone pairs on, IPv4-mapped addresses, and the "every
// secret is under a passphrase" check a key pair must pass both ways.

package com.pgpony.android.ui.pair

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.pair.PairCrypto
import com.pgpony.android.pair.PairInvite
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class PairControllerTest {

    @Test
    fun typedAddresses_parse() {
        val v4 = PairController.parse(" 192.168.1.20:49152 ")!!
        assertEquals("192.168.1.20", v4.address.hostAddress)
        assertEquals(49152, v4.port)
        assertNotNull(PairController.parse("[fd00::1]:1234"))
        assertNull(PairController.parse("192.168.1.20"))
        assertNull(PairController.parse("192.168.1.20:0"))
        assertNull(PairController.parse("192.168.1.20:70000"))
        assertNull(PairController.parse(":49152"))
    }

    @Test
    fun anInvite_resolvesWithItsHostKeyHash() {
        val key = PairCrypto.keyPair()
        val invite = PairInvite.forHostKey(key.public, listOf(PairInvite.parseAddress("192.168.1.20:49152")!!))
        val target = PairController.target(invite.toUri())!!
        assertEquals(1, target.addresses.size)
        assertEquals(49152, target.addresses.single().port)
        assertArrayEquals(invite.hostKeyHash, target.hostKeyHash)
    }

    @Test
    fun aBrokenInvite_isNotReadAsAnAddress() {
        assertTrue(PairController.looksLikeInvite("pgpony-pair:1?garbage"))
        assertNull(PairController.target("pgpony-pair:1?garbage"))
        assertNull(PairController.target("hello"))
        assertNull(PairController.target("192.168.1.20:49152")!!.hostKeyHash)
    }

    @Test
    fun onlyLocalInterfacesPair() {
        for (n in listOf("wlan0", "swlan0", "ap0", "p2p-wlan0-0", "eth0", "rndis0", "usb0", "bt-pan")) {
            assertTrue(n, PairController.isLocalInterface(n))
        }
        for (n in listOf("rmnet_data0", "ccmni0", "tun0", "dummy0", "lo", "v4-rmnet_data0")) {
            assertFalse(n, PairController.isLocalInterface(n))
        }
    }

    @Test
    fun anIpv4MappedAddress_comparesAsIpv4() {
        // Inet6Address directly: InetAddress.getByAddress would already turn
        // a mapped address into an Inet4Address.
        val mapped = java.net.Inet6Address.getByAddress(
            null, byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, -64, -88, 1, 20), -1
        )
        val v4 = InetAddress.getByName("192.168.1.20")
        assertArrayEquals(PairController.plain(v4), PairController.plain(mapped))
    }

    @Test
    fun aKeyPairTravelsOnlyUnderAPassphrase() {
        val svc = PGPCryptoService.shared
        val open = svc.generateKeyPair("Open", "open@pgpony.test", KeyAlgorithm.ED25519_CV25519, null)
        val locked = svc.generateKeyPair("Locked", "locked@pgpony.test", KeyAlgorithm.ED25519_CV25519, "pair-pass")
        assertFalse(PairKeyProtection.isFullyPassphraseProtected(open.privateKeyData))
        assertTrue(PairKeyProtection.isFullyPassphraseProtected(locked.privateKeyData))
        // A public key holds no secret to prove protected.
        assertFalse(PairKeyProtection.isFullyPassphraseProtected(open.publicKeyData))
    }
}
