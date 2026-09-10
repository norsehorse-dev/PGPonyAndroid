// V4Algo35EncryptionMethodGenerator.kt
// PGPony Android — 4.5.0 (item 14 / #56): encrypt to a v4 algo-35 subkey.
//
// A BouncyCastle PGPKeyEncryptionMethodGenerator that wraps the message
// session key for a v4 Ed25519 + algo-35 (ML-KEM-768 + X25519) interop
// recipient and emits the PKESK. BC cannot parse a v4 algo-35 subkey (no
// material-length field), so this generator is constructed from the raw
// subkey public material and the subkey's v4 SHA-1 fingerprint rather than a
// PGPPublicKey.
//
// The composite KEM is version-agnostic (identical to the v6 path); only the
// PKESK target framing differs. RFC 9580 5.1 lets a v6 PKESK address a v4 key
// by setting the target key-version octet to 4 and carrying the 20-octet
// fingerprint, and BC's createV6PKESKPacket writes the key-version octet we
// pass verbatim, so keyVersion=4 + the 20-octet fingerprint is exactly right.
// The PKESK itself stays version 6 (SEIPDv2/AEAD pairing); the session key is
// wrapped bare, no symmetric-algorithm octet.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ContainedPacket
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator
import java.security.SecureRandom

/**
 * item 14 (#56): a v4 algo-35 encryption recipient, carried alongside the BC
 * PGPPublicKeyRing recipients because a v4 algo-35 subkey is not BC-parseable.
 * [publicMaterial] is the 1216-octet X25519||ML-KEM public; [subkeyFingerprint]
 * is the subkey's 20-octet v4 SHA-1 fingerprint the PKESK addresses.
 */
data class V4Algo35Recipient(
    val publicMaterial: ByteArray,
    val subkeyFingerprint: ByteArray
)

class V4Algo35EncryptionMethodGenerator(
    /** X25519(32) || ML-KEM-768(1184) = 1216 octets. */
    private val subkeyPublicMaterial: ByteArray,
    /** The subkey's v4 (SHA-1) fingerprint, 20 octets. */
    private val subkeyFingerprintV4: ByteArray,
    private val random: SecureRandom = SecureRandom()
) : PGPKeyEncryptionMethodGenerator {

    override fun generate(
        dataEncryptorBuilder: PGPDataEncryptorBuilder,
        sessionKey: ByteArray
    ): ContainedPacket {
        val suite = CompositeSuite.IETF_768
        val (xPub, mPub) = CompositeKem.splitPublic(subkeyPublicMaterial, suite)

        val enc = CompositeKem.encapsulate(xPub, mPub, random, suite)
        val wrapped = CompositeKem.wrapSessionKey(enc.kek, sessionKey)

        // X25519 ephemeral (32) || ML-KEM ct (1088) || len (1) || wrapped.
        val algoFields = CompositePkesk.encodeAlgoFields(
            enc.ephemeralX25519, enc.mlkemCiphertext, wrapped, suite
        )

        // v6 PKESK addressing a v4 key: target key-version octet = 4, 20-octet
        // fingerprint. BC writes the key-version octet we pass through, and the
        // count octet as fingerprint.length + 1.
        return PublicKeyEncSessionPacket.createV6PKESKPacket(
            4,
            subkeyFingerprintV4,
            suite.ietfAlgId,
            arrayOf(algoFields)
        )
    }
}
