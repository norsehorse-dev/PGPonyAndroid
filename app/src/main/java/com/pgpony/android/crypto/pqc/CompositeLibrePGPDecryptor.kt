// CompositeLibrePGPDecryptor.kt
// PGPony Android — 4.0.0 Phase 2b (LibrePGP composite, algorithm 8)
//
// Decrypt a GnuPG/LibrePGP message whose session key is wrapped for a
// Kyber/ML-KEM-768 + X25519 composite (algorithm 8) recipient. As with the
// IETF algo-35 path, BouncyCastle's PKESK parser throws on the unknown
// algorithm, so we:
//   1. Split the top-level packets; find the v3 algo-8 PKESK, keep the
//      encrypted-data packet (SEIPDv1 tag 18, or LibrePGP AEAD tag 20) after it.
//   2. Recover the session key with the LibrePGP KMAC256 combiner:
//      X25519-ECDH + Kyber-decapsulate -> KEK -> RFC-3394 unwrap.
//   3. Hand the encrypted-data packet + session key to BC's session-key
//      decryptor (it handles both tag-18 v1 CFB/MDC and tag-20 AEAD).
//
// v3 algo-8 PKESK algorithm-specific fields (verified vs GnuPG 2.5.21):
//   ecc ephemeral MPI (X25519 point, 32) | kyberLen(4) | kyber ct (1088) |
//   symAlgo(1) | wrapLen(1) | AES-256-keywrapped session key
//
// Validated offline against GnuPG 2.5.21 composite messages.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import java.io.ByteArrayInputStream
import java.io.InputStream

object CompositeLibrePGPDecryptor {

    class Result(val stream: InputStream, val integrity: PGPEncryptedData)

    class NoMatchingKey(message: String) : Exception(message)

    private const val TAG_PKESK = 1
    private const val TAG_SKESK = 3
    private const val VERSION_3 = 3

    fun tryDecrypt(
        encryptedData: ByteArray,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String? = null
    ): Result? {
        val binary = toBinary(encryptedData)
        val split = split(binary) ?: return null // no LibrePGP algo-8 PKESK

        // Scott Lu (4.4.1): a multi-recipient message carries one composite
        // PKESK per recipient. Try each held key against every slot, not just
        // the first, so a message addressed to us plus others opens even when
        // we are not the first recipient.
        val recovered = recoverAmong(split.pkesks, secretKeyRings, passphrase)

        val bcpgIn = BCPGInputStream(ByteArrayInputStream(split.remainder))
        val encList = PGPEncryptedDataList(bcpgIn)
        val sessionEnc = encList.extractSessionKeyEncryptedData()
        val factory = BcSessionKeyDataDecryptorFactory(PGPSessionKey(recovered.symAlgo, recovered.sessionKey))
        return Result(sessionEnc.getDataStream(factory), sessionEnc)
    }

    /** 4.1.2 (issue #33): head-sniff for the streaming decrypt path.
     *  True when the leading ESK packets include a v3 algo-8 composite
     *  PKESK. Truncated or unparseable heads read as false; the caller
     *  falls through to BouncyCastle, same failure as before the sniff
     *  existed, so a miss cannot regress anything. */
    fun sniffHead(head: ByteArray): Boolean {
        var i = 0
        while (i < head.size) {
            val h = try { header(head, i) } catch (e: Exception) { null } ?: return false
            if (h.tag != TAG_PKESK && h.tag != TAG_SKESK) return false
            val end = h.bodyStart + h.bodyLen
            if (h.tag == TAG_PKESK) {
                if (h.bodyLen < 0 || end > head.size) return false
                val ok = try {
                    parsePkesk(head.copyOfRange(h.bodyStart, end)) != null
                } catch (e: Exception) { false }
                if (ok) return true
            }
            if (end <= i) return false
            i = end
        }
        return false
    }

    /** 4.2.0 workstream A: recover the session key from the leading ESK
     *  region alone. Returns null when no v3 algo-8 composite PKESK is
     *  present; throws like [tryDecrypt] when one is present but cannot be
     *  opened. The symmetric algorithm comes from the PKESK itself. */
    fun recoverSessionKey(
        eskRegion: ByteArray,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String? = null
    ): PGPSessionKey? {
        val pkesks = allPkesks(eskRegion)
        if (pkesks.isEmpty()) return null
        val recovered = recoverAmong(pkesks, secretKeyRings, passphrase)
        return PGPSessionKey(recovered.symAlgo, recovered.sessionKey)
    }

    private class Recovered(val sessionKey: ByteArray, val symAlgo: Int)

    /**
     * Scott Lu (4.4.1): try each composite PKESK in a multi-recipient message
     * against the held keys and return the first that opens, mirroring
     * CompositeDecryptor.recoverAmong on the IETF path. A slot addressed to a
     * key we do not hold misses with NoMatchingKey and we move on; a matched
     * but locked key surfaces its error as-is. Throw only when no slot matches.
     */
    private fun recoverAmong(
        pkesks: List<Pkesk>,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String?
    ): Recovered {
        for (pkesk in pkesks) {
            try {
                return Recovered(recover(pkesk, secretKeyRings, passphrase), pkesk.symAlgo)
            } catch (e: NoMatchingKey) {
                // this recipient slot is not ours; try the next PKESK
            }
        }
        throw NoMatchingKey(
            "no held LibrePGP composite secret key for any of the " +
                "${pkesks.size} composite recipient(s) in this message"
        )
    }

    /** Shared decapsulation core behind [recoverAmong].
     *  An all-zero key ID (GnuPG's wildcard, `gpg -R`) has nothing to look
     *  up, so it trials every held v5 algo-8 secret key instead. */
    private fun recover(
        pkesk: Pkesk,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String?
    ): ByteArray {
        if (pkesk.keyId.all { it == 0.toByte() }) {
            return recoverAnonymous(pkesk, secretKeyRings, passphrase)
        }
        val secKey = findSecretKey(pkesk.keyId, secretKeyRings)
            ?: throw NoMatchingKey("no held LibrePGP composite secret key for ${pkesk.keyId.toHex()}")
        return open(secKey, pkesk, passphrase)
    }

    /** Decapsulate + unwrap [pkesk] with [secKey]. Errors propagate to the
     *  caller (a locked key with no passphrase surfaces as-is on the
     *  addressed path); [recoverAnonymous] is the one that catches
     *  everything from this function. */
    private fun open(secKey: PGPSecretKey, pkesk: Pkesk, passphrase: String?): ByteArray {
        val packet = secKey.encoded

        val material = CompositeLibrePGPKeyMaterial.extractFromPacket(packet, passphrase?.toCharArray())
        val v5fp = CompositeLibrePGPKeyMaterial.v5Fingerprint(packet)
        val (recipientXPub, _) = CompositeLibrePGPKeyMaterial.publicMaterial(packet)

        // algo 8 is shared; the key's curve OID says which parameter set.
        val suite = CompositeLibrePGPKeyMaterial.suiteOf(packet)
        val mlkemSec = MLKEMPrivateKeyParameters(suite.mlkem.params, material.kyberSeed)
        val fixedInfo = CompositeKemLibrePGP.fixedInfo(pkesk.symAlgo, v5fp)
        val kek = CompositeKemLibrePGP.decapsulate(
            pkesk.eccEphemeral, pkesk.kyberCiphertext, material.x25519Secret, recipientXPub, mlkemSec, fixedInfo, suite
        )
        return CompositeKemLibrePGP.unwrapSessionKey(kek, pkesk.wrappedSessionKey)
    }

    /**
     * 4.2.0 RC2 workstream B (§3.4): same anonymous-PKESK trial as
     * `CompositeDecryptor.recoverAnonymous`, for the v3/algo-8 LibrePGP
     * PKESK. GnuPG's wildcard is an all-zero key ID rather than an absent
     * field, but the trial is identical in shape: every held v5 algo-8
     * secret key gets one attempt, locked-or-wrong candidates are silently
     * skipped, and RFC-3394 unwrap's integrity check is what makes
     * skipping safe.
     */
    private fun recoverAnonymous(
        pkesk: Pkesk,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String?
    ): ByteArray {
        for (ring in secretKeyRings) {
            for (candidate in ring.secretKeys) {
                if (candidate.publicKey.algorithm != CompositeLibrePGPKeyMaterial.ALGORITHM_ID ||
                    candidate.publicKey.version != 5
                ) continue
                val result = try {
                    open(candidate, pkesk, passphrase)
                } catch (e: Exception) {
                    null
                }
                if (result != null) return result
            }
        }
        throw NoMatchingKey("no held LibrePGP composite secret key opens this anonymous PKESK")
    }

    /** All parseable v3 algo-8 PKESKs in a region of ESK packets, in order. */
    private fun allPkesks(region: ByteArray): List<Pkesk> {
        val out = mutableListOf<Pkesk>()
        var i = 0
        while (i < region.size) {
            val h = try { header(region, i) } catch (e: Exception) { null } ?: break
            val end = h.bodyStart + h.bodyLen
            if (h.bodyLen < 0 || end > region.size || end <= i) break
            if (h.tag == TAG_PKESK) {
                parsePkesk(region.copyOfRange(h.bodyStart, end))?.let { out.add(it) }
            }
            i = end
        }
        return out
    }

    // ── PKESK parsing ────────────────────────────────────────────────

    private class Pkesk(
        val keyId: ByteArray,
        val symAlgo: Int,
        val eccEphemeral: ByteArray,
        val kyberCiphertext: ByteArray,
        val wrappedSessionKey: ByteArray
    )

    /** Parse a v3 algo-8 PKESK body, or null if it isn't one. */
    private fun parsePkesk(body: ByteArray): Pkesk? {
        try {
            var i = 0
            if ((body[i++].toInt() and 0xFF) != VERSION_3) return null
            val keyId = body.copyOfRange(i, i + 8); i += 8
            if ((body[i++].toInt() and 0xFF) != CompositeKemLibrePGP.ALGORITHM_ID) return null

            // ecc ephemeral: MPI (X25519 point)
            val bits = ((body[i].toInt() and 0xFF) shl 8) or (body[i + 1].toInt() and 0xFF); i += 2
            val eccLen = (bits + 7) / 8
            val ecc = body.copyOfRange(i, i + eccLen); i += eccLen
            // kyber ciphertext: 4-octet length prefix
            val kyberLen = readUInt32(body, i); i += 4
            val kyber = body.copyOfRange(i, i + kyberLen); i += kyberLen
            // wrapped session key: symAlgo(1), wrapLen(1), wrapped
            val symAlgo = body[i++].toInt() and 0xFF
            val wrapLen = body[i++].toInt() and 0xFF
            val wrapped = body.copyOfRange(i, i + wrapLen)
            return Pkesk(keyId, symAlgo, ecc, kyber, wrapped)
        } catch (e: Exception) {
            return null
        }
    }

    // ── packet splitting ─────────────────────────────────────────────

    private class Split(val pkesks: List<Pkesk>, val remainder: ByteArray)

    private fun split(data: ByteArray): Split? {
        var i = 0
        val pkesks = mutableListOf<Pkesk>()
        val n = data.size
        while (i < n) {
            // 4.1.2 (issue #33): same fix as CompositeDecryptor.split, and
            // for the same reason. Tag first, lengths only for ESKs; the
            // body packet keeps its framing (partial lengths included) and
            // BC reads it natively.
            val first = data[i].toInt() and 0xFF
            if (first and 0x80 == 0) break
            val tag = if (first and 0x40 != 0) first and 0x3F else (first shr 2) and 0x0F
            if (tag != TAG_PKESK && tag != TAG_SKESK) {
                // Scott Lu (4.4.1): collect EVERY composite PKESK, not just the
                // first, so multi-recipient messages try all recipient slots.
                if (pkesks.isEmpty()) return null
                return Split(pkesks, data.copyOfRange(i, n))
            }
            val h = header(data, i) ?: break
            if (h.tag == TAG_PKESK) {
                parsePkesk(data.copyOfRange(h.bodyStart, h.bodyStart + h.bodyLen))?.let { pkesks.add(it) }
            }
            i = h.bodyStart + h.bodyLen
        }
        return null
    }

    private class Header(val tag: Int, val bodyStart: Int, val bodyLen: Int)

    private fun header(data: ByteArray, start: Int): Header? {
        var i = start
        val c = data[i++].toInt() and 0xFF
        if (c and 0x80 == 0) return null
        val tag: Int
        val length: Int
        if (c and 0x40 != 0) {
            tag = c and 0x3F
            val l0 = data[i++].toInt() and 0xFF
            length = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (data[i++].toInt() and 0xFF) + 192
                l0 == 255 -> readUInt32(data, i).also { i += 4 }
                else -> return null
            }
        } else {
            tag = (c shr 2) and 0x0F
            length = when (c and 0x03) {
                0 -> data[i++].toInt() and 0xFF
                1 -> (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> readUInt32(data, i).also { i += 4 }
                else -> data.size - i
            }
        }
        return Header(tag, i, length)
    }

    // ── helpers ──────────────────────────────────────────────────────

    private fun findSecretKey(keyId: ByteArray, rings: List<PGPSecretKeyRing>): PGPSecretKey? =
        rings.asSequence()
            .flatMap { it.secretKeys.asSequence() }
            .firstOrNull { sk ->
                sk.publicKey.algorithm == CompositeLibrePGPKeyMaterial.ALGORITHM_ID &&
                    sk.publicKey.version == 5 &&
                    CompositeLibrePGPKeyMaterial.v5KeyId(sk.encoded).contentEquals(keyId)
            }

    private fun readUInt32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    private fun toBinary(data: ByteArray): ByteArray {
        val looksArmored = data.isNotEmpty() && data[0].toInt() == '-'.code
        if (!looksArmored) return data
        ArmoredInputStream(ByteArrayInputStream(data)).use { return it.readBytes() }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }
}
