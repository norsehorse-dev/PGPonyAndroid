// CompositeDecryptor.kt
// PGPony Android — 4.0.0 Phase 2b (slice 4b, decrypt side)
//
// Decrypt an OpenPGP message whose session key is wrapped for an IETF
// composite (algo 35, ML-KEM-768 + X25519) recipient. BouncyCastle's PKESK
// parser throws on algo 35 (PGPEncryptedDataList only skips *version*
// mismatches, not unknown algorithms), so we can't hand BC the raw message.
// Instead:
//
//   1. Split the top-level packets ourselves. Find the composite PKESK
//      (tag 1, v6, algo 35) and keep everything from the SEIPD onward.
//   2. Recover the session key with our own KEM: ML-KEM-decapsulate +
//      X25519-ECDH → combiner KEK → RFC-3394 unwrap.
//   3. Feed the SEIPD (with no ESK packet in front) to BC via
//      PGPEncryptedDataList.extractSessionKeyEncryptedData(), applying the
//      recovered session key. BC does the SEIPDv2 (AEAD) / SEIPDv1 body.
//
// Verified against sequoia-sq 1.4.0-pqc.1 composite messages.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import java.io.ByteArrayInputStream
import java.io.InputStream

object CompositeDecryptor {

    /** Composite decrypt succeeded: [stream] is the plaintext, [integrity]
     *  is BC's encrypted-data object for the SEIPD integrity gate. */
    class Result(val stream: InputStream, val integrity: PGPEncryptedData)

    class NoMatchingKey(message: String) : Exception(message)

    /**
     * Attempt composite decryption. Returns null when the message carries
     * no composite PKESK (caller should fall back to the normal path).
     * Throws [NoMatchingKey] / [CompositeSecretKeyMaterial.ProtectedKeyException]
     * when a composite PKESK IS present but can't be decrypted.
     */
    fun tryDecrypt(
        encryptedData: ByteArray,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String? = null,
        // #26 (RC4): raw composite-PRIMARY rings (algo 30/31 signing keys). Their
        // ML-KEM subkey is not a BouncyCastle ring, so it is tried packet-level.
        rawCompositeRings: List<ByteArray> = emptyList()
    ): Result? {
        val binary = toBinary(encryptedData)
        val split = split(binary) ?: return null // no composite PKESK

        val sessionKey = recover(split.parsed, secretKeyRings, rawCompositeRings, passphrase)

        // Hand the recovered session key to BC's SEIPD decryptor. The SEIPD
        // sits alone (no ESK packet), so use the session-key entry point.
        val bcpgIn = BCPGInputStream(ByteArrayInputStream(split.remainder))
        val encList = PGPEncryptedDataList(bcpgIn)
        val sessionEnc = encList.extractSessionKeyEncryptedData()
        val factory = BcSessionKeyDataDecryptorFactory(
            PGPSessionKey(SymmetricKeyAlgorithmTags.AES_256, sessionKey)
        )
        val stream = sessionEnc.getDataStream(factory)
        return Result(stream, sessionEnc)
    }

    /** 4.1.2 (issue #33): head-sniff for the streaming decrypt path.
     *  True when the leading ESK packets include an algo-35 composite
     *  PKESK. [head] is typically truncated somewhere past the ESKs; a
     *  truncated or unparseable head reads as false, and the caller then
     *  falls through to BouncyCastle, which fails the same way it did
     *  before the sniff existed, so a miss cannot regress anything. */
    fun sniffHead(head: ByteArray): Boolean {
        var i = 0
        while (i < head.size) {
            val h = try { header(head, i) } catch (e: Exception) { null } ?: return false
            if (h.tag != TAG_PKESK && h.tag != TAG_SKESK) return false
            val end = h.bodyStart + h.bodyLen
            if (h.tag == TAG_PKESK) {
                if (h.bodyLen < 0 || end > head.size) return false
                val ok = try {
                    CompositePkesk.parseBody(head.copyOfRange(h.bodyStart, end)) != null
                } catch (e: Exception) { false }
                if (ok) return true
            }
            if (end <= i) return false
            i = end
        }
        return false
    }

    /** 4.2.0 workstream A: recover the message session key from the
     *  leading ESK region ALONE, without the body. [eskRegion] holds the
     *  complete leading ESK packets (headers included) as consumed by the
     *  streaming caller. Returns null when no composite (algo 35/36) PKESK
     *  is present; throws like [tryDecrypt] when one is present but cannot
     *  be opened. AES-256 is the v6 pairing (the session key is wrapped
     *  bare; the algorithm lives in the SEIPDv2 packet). */
    fun recoverSessionKey(
        eskRegion: ByteArray,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String? = null
    ): PGPSessionKey? {
        val parsed = firstCompositePkesk(eskRegion) ?: return null
        return PGPSessionKey(
            SymmetricKeyAlgorithmTags.AES_256,
            recover(parsed, secretKeyRings, emptyList(), passphrase)
        )
    }

    /** The shared decapsulation core behind [tryDecrypt] and
     *  [recoverSessionKey]: match the recipient key (or trial every held
     *  composite key for an anonymous PKESK), extract its material,
     *  decapsulate with the PKESK's suite, unwrap the session key. */
    private fun recover(
        parsed: CompositePkesk.Parsed,
        secretKeyRings: List<PGPSecretKeyRing>,
        rawCompositeRings: List<ByteArray>,
        passphrase: String?
    ): ByteArray {
        if (parsed.recipientFingerprint.isEmpty()) {
            return recoverAnonymous(parsed, secretKeyRings, rawCompositeRings, passphrase)
        }
        findSecretKey(parsed.recipientFingerprint, secretKeyRings)?.let {
            return open(it, parsed, passphrase)
        }
        findRawComposite(parsed.recipientFingerprint, rawCompositeRings)?.let {
            return openRaw(it, parsed, passphrase)
        }
        throw NoMatchingKey(
            "no held composite secret key for recipient " +
                parsed.recipientFingerprint.toHex()
        )
    }

    /** Decapsulate + unwrap [parsed] with a raw composite-PRIMARY ring's ML-KEM
     *  subkey (extracted packet-level, since the ring is not BC-parseable). */
    private fun openRaw(
        rawRing: ByteArray,
        parsed: CompositePkesk.Parsed,
        passphrase: String?
    ): ByteArray {
        val info = CompositeKeyFacade.parse(rawRing, passphrase?.toCharArray())
        val sub = info.encryptionSubkey
            ?: throw NoMatchingKey("composite key has no ML-KEM subkey")
        val secret = sub.secretMaterial
            ?: throw CompositeSecretKeyMaterial.ProtectedKeyException(
                "composite ML-KEM subkey secret is unavailable"
            )
        val suite = parsed.suite
        if (sub.algId != suite.ietfAlgId) {
            throw NoMatchingKey("composite subkey suite does not match the message")
        }
        val xSec = secret.copyOfRange(0, suite.curve.keyLen)
        val mlkemSeed = secret.copyOfRange(suite.curve.keyLen, secret.size)
        val mlkemSec = MLKEMPrivateKeyParameters(suite.mlkem.params, mlkemSeed)
        val (recipientXPub, _) = CompositeKem.splitPublic(sub.publicMaterial, suite)
        val kek = CompositeKem.decapsulate(
            ephemeralX25519 = parsed.ephemeralX25519,
            mlkemCiphertext = parsed.mlkemCiphertext,
            recipientX25519Sec = xSec,
            recipientMlkemSec = mlkemSec,
            recipientX25519Pub = recipientXPub,
            suite = suite
        )
        return CompositeKem.unwrapSessionKey(kek, parsed.wrappedSessionKey)
    }

    /** The raw composite-PRIMARY ring whose ML-KEM subkey fingerprint is [fp]. */
    private fun findRawComposite(fp: ByteArray, rawRings: List<ByteArray>): ByteArray? =
        rawRings.firstOrNull { ring ->
            runCatching {
                CompositeKeyFacade.parse(ring).encryptionSubkey?.fingerprint?.contentEquals(fp) == true
            }.getOrDefault(false)
        }

    /** Decapsulate + unwrap [parsed] with [secKey]. Errors propagate to the
     *  caller: [CompositeSecretKeyMaterial.extract] throws
     *  [CompositeSecretKeyMaterial.ProtectedKeyException] for a locked key
     *  with no passphrase, and that must surface as-is on the addressed
     *  path below, not read as "no match". [recoverAnonymous] is the one
     *  that catches everything from this function. */
    private fun open(
        secKey: org.bouncycastle.openpgp.PGPSecretKey,
        parsed: CompositePkesk.Parsed,
        passphrase: String?
    ): ByteArray {
        val material = CompositeSecretKeyMaterial.extract(secKey, passphrase?.toCharArray())
            ?: throw NoMatchingKey("matched key is not a composite secret key")
        val suite = parsed.suite
        val mlkemSec = MLKEMPrivateKeyParameters(suite.mlkem.params, material.mlkemSeed)
        val (recipientXPub, _) = CompositeKeyMaterial.publicMaterial(secKey.publicKey)
            ?: throw NoMatchingKey("composite public material malformed")
        val kek = CompositeKem.decapsulate(
            ephemeralX25519 = parsed.ephemeralX25519,
            mlkemCiphertext = parsed.mlkemCiphertext,
            recipientX25519Sec = material.x25519Secret,
            recipientMlkemSec = mlkemSec,
            recipientX25519Pub = recipientXPub,
            suite = suite
        )
        return CompositeKem.unwrapSessionKey(kek, parsed.wrappedSessionKey)
    }

    /**
     * 4.2.0 RC2 workstream B (§3.4): an anonymous PKESK carries no
     * recipient fingerprint (RFC 9580 §5.1's wildcard, `gpg -R`), so there
     * is nothing to look up. Trial every held composite secret key instead,
     * the same shape as the classical wildcard path
     * (`PGPCryptoService.resolvePkesk`) for RSA/ECDH: a key that is locked
     * with no passphrase, or simply the wrong key, is silently skipped
     * rather than aborting the scan, since during a trial that is the
     * expected outcome for every candidate but one. RFC-3394 unwrap's
     * built-in integrity check is what makes skipping safe here, a wrong
     * KEK fails the unwrap rather than yielding wrong plaintext bytes.
     */
    private fun recoverAnonymous(
        parsed: CompositePkesk.Parsed,
        secretKeyRings: List<PGPSecretKeyRing>,
        rawCompositeRings: List<ByteArray>,
        passphrase: String?
    ): ByteArray {
        for (ring in secretKeyRings) {
            for (candidate in ring.secretKeys) {
                if (CompositeSuite.ietfFor(candidate.publicKey.algorithm) == null) continue
                val result = try {
                    open(candidate, parsed, passphrase)
                } catch (e: Exception) {
                    null
                }
                if (result != null) return result
            }
        }
        for (rawRing in rawCompositeRings) {
            val result = try {
                openRaw(rawRing, parsed, passphrase)
            } catch (e: Exception) {
                null
            }
            if (result != null) return result
        }
        throw NoMatchingKey("no held composite secret key opens this anonymous PKESK")
    }

    /** First parseable composite PKESK in a region of ESK packets, walking
     *  definite-length packets only; null on none. */
    private fun firstCompositePkesk(region: ByteArray): CompositePkesk.Parsed? {
        var i = 0
        while (i < region.size) {
            val h = try { header(region, i) } catch (e: Exception) { null } ?: return null
            val end = h.bodyStart + h.bodyLen
            if (h.bodyLen < 0 || end > region.size || end <= i) return null
            if (h.tag == TAG_PKESK) {
                CompositePkesk.parseBody(region.copyOfRange(h.bodyStart, end))?.let { return it }
            }
            i = end
        }
        return null
    }

    // ── packet splitting ─────────────────────────────────────────────

    private class Split(val parsed: CompositePkesk.Parsed, val remainder: ByteArray)

    /**
     * Walk the top-level packets, dropping every leading ESK packet
     * (PKESK tag 1 / SKESK tag 3) and returning the composite PKESK's
     * parsed fields plus the byte stream from the first non-ESK packet
     * (the SEIPD) onward. Returns null if no composite PKESK is present.
     */
    private fun split(data: ByteArray): Split? {
        var i = 0
        var parsed: CompositePkesk.Parsed? = null
        val n = data.size
        while (i < n) {
            // 4.1.2 (issue #33): decide ESK-vs-body from the tag octet
            // alone, BEFORE parsing any length. The SEIPD that follows the
            // ESKs may use partial-length framing (BC's generator emits it
            // for anything over its buffer), which header() rejects, and
            // the old order made that reject read as "no composite PKESK",
            // so any composite message over roughly one buffer fell
            // through to BC and failed. ESK packets themselves always
            // carry definite lengths, so header() stays correct for them.
            val first = data[i].toInt() and 0xFF
            if (first and 0x80 == 0) break
            val tag = if (first and 0x40 != 0) first and 0x3F else (first shr 2) and 0x0F
            if (tag != TAG_PKESK && tag != TAG_SKESK) {
                // First non-ESK packet: the encrypted-data (SEIPD) packet,
                // handed onward with its framing intact; BC reads partial
                // lengths natively.
                val p = parsed ?: return null
                return Split(p, data.copyOfRange(i, n))
            }
            val h = header(data, i) ?: break
            if (h.tag == TAG_PKESK && parsed == null) {
                val body = data.copyOfRange(h.bodyStart, h.bodyStart + h.bodyLen)
                CompositePkesk.parseBody(body)?.let { parsed = it }
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
        if (c and 0x40 != 0) { // new format
            tag = c and 0x3F
            val l0 = data[i++].toInt() and 0xFF
            length = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (data[i++].toInt() and 0xFF) + 192
                l0 == 255 -> uint32(data, i).also { i += 4 }
                else -> return null // partial length: not expected before/at SEIPD start
            }
        } else { // old format
            tag = (c shr 2) and 0x0F
            length = when (c and 0x03) {
                0 -> data[i++].toInt() and 0xFF
                1 -> (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> uint32(data, i).also { i += 4 }
                else -> data.size - i
            }
        }
        return Header(tag, i, length)
    }

    private fun uint32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or
            ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or
            (b[off + 3].toInt() and 0xFF)

    private const val TAG_PKESK = 1
    private const val TAG_SKESK = 3

    // ── helpers ──────────────────────────────────────────────────────

    private fun findSecretKey(fp: ByteArray, rings: List<PGPSecretKeyRing>) =
        rings.asSequence()
            .flatMap { it.secretKeys.asSequence() }
            .firstOrNull {
                CompositeSuite.ietfFor(it.publicKey.algorithm) != null &&
                    it.publicKey.fingerprint.contentEquals(fp)
            }

    private fun toBinary(data: ByteArray): ByteArray {
        val looksArmored = data.isNotEmpty() && data[0].toInt() == '-'.code
        if (!looksArmored) return data
        ArmoredInputStream(ByteArrayInputStream(data)).use { armored ->
            return armored.readBytes()
        }
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02X".format(it) }
}
