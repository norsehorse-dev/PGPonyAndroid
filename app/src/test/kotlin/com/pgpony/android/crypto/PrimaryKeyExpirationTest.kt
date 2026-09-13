// PrimaryKeyExpirationTest.kt
// PGPony Android — 4.5.0 (item 24 / #55, lukascomer): primary key expiry read.
//
// A tester saw the primary key show "Never" while the subkey showed Sep 13 2050,
// and suspected PGPony missed the primary's expiry. Investigation (this fixture)
// shows the opposite: BouncyCastle reads this key's primary expiry correctly.
// This RSA 3072 key (created 2023-09-20) carries a 27-year Key Expiration Time on
// its primary User-ID self-certification and its subkey binding; gpg and BC both
// read both as expiring 2050-09-13. So there was no parsing bug; the tester's
// stale "Never" came from an older import. 4.5.0 reconciles it live at Key Details
// open (KeyRepository.reconcilePrimaryExpiry) using the creationTime + validSeconds
// formula this test locks. This is the regression guard that BC keeps reading the
// primary expiry that reconcile depends on.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream

class PrimaryKeyExpirationTest {

    private fun fixtureMaster() = PGPPublicKeyRing(
        ArmoredInputStream(
            ByteArrayInputStream(
                javaClass.getResourceAsStream("/keys/uid-selfsig-expiry-rsa.asc")!!.readBytes()
            )
        ),
        JcaKeyFingerprintCalculator()
    ).publicKey

    @Test
    fun `current code reads the primary expiry from the UID self-certification`() {
        val master = fixtureMaster()

        // 27-year Key Expiration Time on the primary UID self-cert.
        assertEquals("primary validity in seconds", 851472000L, master.validSeconds)

        val expiryEpoch = master.creationTime.time / 1000L + master.validSeconds
        assertEquals("primary expires 2050-09-13, same as gpg", 2546656205L, expiryEpoch)
    }

    @Test
    fun `the app load path preserves the primary expiry the reconcile reads`() {
        // The reconcile reads loadPublicKeyRing(fp).publicKey.validSeconds, and
        // loadPublicKeyRing re-parses the STORED bytes through importKeyData. The
        // stored form is the ring's binary encoding, so round-trip the fixture the
        // same way and confirm importKeyData keeps the primary's UID-cert expiry.
        // If this reads 0, the reconcile shows "Never" and the RC2 fix does not
        // actually resolve the reporter's key.
        val fixtureBytes =
            javaClass.getResourceAsStream("/keys/uid-selfsig-expiry-rsa.asc")!!.readBytes()
        val original = PGPPublicKeyRing(
            ArmoredInputStream(ByteArrayInputStream(fixtureBytes)),
            JcaKeyFingerprintCalculator()
        )
        val reloaded = PGPCryptoService.shared.importKeyData(original.encoded).publicKeyRing!!
        assertEquals(
            "importKeyData keeps the primary expiry, so the reconcile shows 2050 not Never",
            851472000L,
            reloaded.publicKey.validSeconds
        )
    }
}
