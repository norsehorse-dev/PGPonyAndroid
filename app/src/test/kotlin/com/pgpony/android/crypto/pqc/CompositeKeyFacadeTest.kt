// CompositeKeyFacadeTest.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Pins CompositeKeyFacade against CompositePrimaryKeyGen's output: the facade
// must recover the metadata and, crucially, key material that actually signs
// and verifies through the composite document path.

package com.pgpony.android.crypto.pqc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

class CompositeKeyFacadeTest {

    private val suite = CompositeSignSuite.MLDSA65_ED25519

    @Test
    fun `parses a composite primary into usable metadata and material`() {
        val uid = "PQ Primary <pq@pgpony.app>"
        val raw = CompositePrimaryKeyGen.assemble(uid, suite)

        assertTrue("recognized as a composite primary", CompositeKeyFacade.isCompositePrimary(raw))
        val info = CompositeKeyFacade.parse(raw)

        assertEquals("primary algorithm", suite.algId, info.primaryAlgId)
        assertEquals("suite", suite, info.suite)
        assertEquals("user id", listOf(uid), info.userIds)
        assertEquals("composite public length", suite.compositePubLen, info.compositePublic.size)
        assertEquals("composite secret length", suite.compositeSecretLen, info.compositeSecret?.size)
        assertEquals("fingerprint hex length", 64, info.fingerprintHex.length)

        assertNotNull("ML-KEM encryption subkey present", info.encryptionSubkey)
        val subkey = info.encryptionSubkey!!
        assertEquals("subkey is ML-KEM-768 + X25519 (algo 35)", 35, subkey.algId)
        assertEquals("subkey public material length", 1216, subkey.publicMaterial.size)
        assertEquals("subkey secret material length", 96, subkey.secretMaterial?.size)
    }

    @Test
    fun `the recovered secret material signs and verifies`() {
        val raw = CompositePrimaryKeyGen.assemble("Signer <s@pgpony.app>", suite)
        val info = CompositeKeyFacade.parse(raw)

        val data = "signed by a facade-recovered composite key".toByteArray()
        val sig = CompositeDocumentSigner.signDetached(
            suite, info.compositeSecret!!, info.fingerprint, data
        )
        assertTrue(
            "a signature from facade-recovered material must verify against facade-recovered public",
            CompositeDocumentVerifier.verifyDetached(info.compositePublic, sig, data).valid
        )
    }

    @Test
    fun `derives a public ring with no secret material`() {
        val raw = CompositePrimaryKeyGen.assemble("Pub <p@pgpony.app>", suite)
        val publicRing = CompositeKeyFacade.publicRingOf(raw)

        assertTrue("public ring is still a composite primary", CompositeKeyFacade.isCompositePrimary(publicRing))
        val info = CompositeKeyFacade.parse(publicRing)
        assertEquals("same composite public material", suite.compositePubLen, info.compositePublic.size)
        assertNull("public ring carries no primary secret", info.compositeSecret)
        assertNotNull("encryption subkey still present", info.encryptionSubkey)
        assertNull("public ring carries no subkey secret", info.encryptionSubkey!!.secretMaterial)

        // Fingerprint must be identical to the secret ring's.
        assertEquals(CompositeKeyFacade.parse(raw).fingerprintHex, info.fingerprintHex)
    }

    @Test
    fun `reads the primary expiration from the direct-key signature`() {
        val oneYear = 365L * 24 * 60 * 60
        val raw = CompositePrimaryKeyGen.assemble(
            "Expiring <e@pgpony.app>", suite,
            creationTime = Date(1_700_000_000_000L),
            expirationSeconds = oneYear
        )
        val info = CompositeKeyFacade.parse(raw)
        assertEquals("expiration seconds", oneYear, info.expirationSeconds)
        assertEquals("creation time", 1_700_000_000_000L / 1000L * 1000L, info.creationTimeMillis)
    }

    @Test
    fun `hasV4Algo35Subkey detects the v4 interop shape only`() {
        val svc = com.pgpony.android.crypto.PGPCryptoService.shared
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "V4 Interop", email = "v4@example.test",
                algorithm = com.pgpony.android.crypto.KeyAlgorithm.ED25519_CV25519,
                passphrase = null
            ).privateKeyData
        ).secretKeyRing!!
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base)

        assertTrue("secret ring carries the v4 algo-35 subkey",
            CompositeKeyFacade.hasV4Algo35Subkey(rings.secretRaw))
        assertTrue("public ring carries the v4 algo-35 subkey",
            CompositeKeyFacade.hasV4Algo35Subkey(rings.publicRaw))
        assertFalse("a plain v4 Ed25519+Cv25519 base has no algo-35 subkey",
            CompositeKeyFacade.hasV4Algo35Subkey(base.encoded))
        // The v4 interop primary is an ordinary Ed25519, not a composite
        // primary, so the two detectors never both fire on one key.
        assertFalse("v4 interop is not a composite primary",
            CompositeKeyFacade.isCompositePrimary(rings.secretRaw))
        // A composite ML-DSA key is a composite primary but its ML-KEM subkey
        // is v6, so it is not a v4 algo-35 key.
        val mldsa = CompositePrimaryKeyGen.assemble("PQ <pq@pgpony.app>", suite)
        assertTrue(CompositeKeyFacade.isCompositePrimary(mldsa))
        assertFalse("composite ML-DSA key has no v4 algo-35 subkey",
            CompositeKeyFacade.hasV4Algo35Subkey(mldsa))
    }

    @Test
    fun `v4 algo-35 material extraction yields 1216 public and 96 secret bytes`() {
        val svc = com.pgpony.android.crypto.PGPCryptoService.shared
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "V4 Interop", email = "v4@example.test",
                algorithm = com.pgpony.android.crypto.KeyAlgorithm.ED25519_CV25519,
                passphrase = null
            ).privateKeyData
        ).secretKeyRing!!
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base)

        val secBody = CompositeKeyFacade.v4Algo35SubkeyBody(rings.secretRaw)!!
        val pubBody = CompositeKeyFacade.v4Algo35SubkeyBody(rings.publicRaw)!!

        val pubMatFromSecret = CompositeKeyFacade.v4Algo35PublicMaterial(secBody)
        val pubMatFromPublic = CompositeKeyFacade.v4Algo35PublicMaterial(pubBody)
        assertEquals("public material is X25519(32) + ML-KEM-768(1184)", 1216, pubMatFromSecret.size)
        assertTrue("public material identical across secret and public rings",
            pubMatFromSecret.contentEquals(pubMatFromPublic))

        val secMat = CompositeKeyFacade.v4Algo35SecretMaterial(secBody)!!
        assertEquals("secret material is X25519 secret(32) + ML-KEM seed(64)", 96, secMat.size)
        // A public-only body carries no secret material.
        assertNull("public ring subkey has no secret material",
            CompositeKeyFacade.v4Algo35SecretMaterial(pubBody))

        // The v4 subkey fingerprint is SHA-1 (20 octets) and is the same whether
        // taken from the public or secret body (both share the 1222-octet head).
        val fp = CompositeKeyFacade.v4Algo35SubkeyFingerprint(pubBody)
        assertEquals("v4 subkey fingerprint is SHA-1", 20, fp.size)
        assertTrue("fingerprint identical from public and secret bodies",
            fp.contentEquals(CompositeKeyFacade.v4Algo35SubkeyFingerprint(secBody)))
    }
}
