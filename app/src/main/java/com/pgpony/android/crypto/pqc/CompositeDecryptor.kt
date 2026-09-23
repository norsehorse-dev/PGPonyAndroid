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

    /** item 14 (#56): a recovered session key plus the symmetric-algorithm ID
     *  the PKESK declared — nonzero only for a v3 PKESK (SEIPDv1), where the
     *  algorithm is not carried in the SEIPD packet; 0 for a v6 PKESK. */
    private class Recovered(val sessionKey: ByteArray, val symAlgId: Int)

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

        val recovered = recoverAmong(split.parsed, secretKeyRings, rawCompositeRings, passphrase)

        // Hand the recovered session key to BC's SEIPD decryptor. The SEIPD
        // sits alone (no ESK packet), so use the session-key entry point. A v3
        // PKESK (SEIPDv1) carries its own symmetric-algorithm octet; a v6 PKESK
        // (SEIPDv2) leaves it 0 and the algorithm lives in the SEIPD packet
        // (AES-256 is the pairing).
        val bcpgIn = BCPGInputStream(ByteArrayInputStream(split.remainder))
        val encList = PGPEncryptedDataList(bcpgIn)
        val sessionEnc = encList.extractSessionKeyEncryptedData()
        val factory = BcSessionKeyDataDecryptorFactory(
            PGPSessionKey(symAlgOrDefault(recovered.symAlgId), recovered.sessionKey)
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
        // Scott Lu / Umotas (RC8): the streaming (file) path must thread the
        // raw composite-PRIMARY rings too, or a file encrypted to an imported
        // composite key (ML-DSA primary + ML-KEM subkey) never reaches
        // findRawComposite and fails with "no held composite secret key".
        rawCompositeRings: List<ByteArray> = emptyList(),
        passphrase: String? = null
    ): PGPSessionKey? {
        val parsedList = allCompositePkesks(eskRegion)
        if (parsedList.isEmpty()) return null
        val recovered = recoverAmong(parsedList, secretKeyRings, rawCompositeRings, passphrase)
        return PGPSessionKey(symAlgOrDefault(recovered.symAlgId), recovered.sessionKey)
    }

    /**
     * item 18 (#57): a multi-recipient message carries one composite PKESK
     * per recipient. Try each against the held keys and return the first
     * session key that opens. A PKESK addressed to a key we do not hold
     * misses with [NoMatchingKey] and we move to the next, while a matched
     * but locked key surfaces its ProtectedKeyException as-is. Throw only
     * when no PKESK in the message matches any held key.
     */
    private fun recoverAmong(
        parsedList: List<CompositePkesk.Parsed>,
        secretKeyRings: List<PGPSecretKeyRing>,
        rawCompositeRings: List<ByteArray>,
        passphrase: String?
    ): Recovered {
        for (parsed in parsedList) {
            try {
                return recover(parsed, secretKeyRings, rawCompositeRings, passphrase)
            } catch (e: NoMatchingKey) {
                // this recipient slot is not ours; try the next PKESK
            }
        }
        throw NoMatchingKey(
            "no held composite secret key for any of the " +
                "${parsedList.size} composite recipient(s) in this message"
        )
    }

    /** The shared decapsulation core behind [recoverAmong]: match the
     *  recipient key (or trial every held composite key for an anonymous
     *  PKESK), extract its material, decapsulate with the PKESK's suite,
     *  unwrap the session key. */
    private fun recover(
        parsed: CompositePkesk.Parsed,
        secretKeyRings: List<PGPSecretKeyRing>,
        rawCompositeRings: List<ByteArray>,
        passphrase: String?
    ): Recovered {
        // item 14 (#56): a v3 PKESK (RFC 9980 A.2.3, SEIPDv1) identifies the
        // recipient by 8-octet key ID and carries the symmetric-algorithm octet
        // itself. The KEM core is identical to the v6 path; only the lookup key
        // and the trailing symAlgId differ.
        if (parsed.recipientKeyId.isNotEmpty()) {
            findSecretKeyByKeyId(parsed.recipientKeyId, secretKeyRings)?.let {
                return Recovered(open(it, parsed, passphrase), parsed.symAlgId)
            }
            findRawCompositeByKeyId(parsed.recipientKeyId, rawCompositeRings)?.let {
                return Recovered(openRaw(it, parsed, passphrase), parsed.symAlgId)
            }
            throw NoMatchingKey(
                "no held composite secret key for v3 recipient key ID " +
                    parsed.recipientKeyId.toHex()
            )
        }
        if (parsed.recipientFingerprint.isEmpty()) {
            return Recovered(
                recoverAnonymous(parsed, secretKeyRings, rawCompositeRings, passphrase),
                parsed.symAlgId
            )
        }
        findSecretKey(parsed.recipientFingerprint, secretKeyRings)?.let {
            return Recovered(open(it, parsed, passphrase), parsed.symAlgId)
        }
        findRawComposite(parsed.recipientFingerprint, rawCompositeRings)?.let {
            return Recovered(openRaw(it, parsed, passphrase), parsed.symAlgId)
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
        // item 14 (#56): a v4 interop ring carries an ordinary Ed25519 primary
        // and a v4 algo-35 subkey that CompositeKeyFacade.parse cannot model
        // (parse expects a composite primary), so it takes its own path.
        if (CompositeKeyFacade.hasV4Algo35Subkey(rawRing)) {
            return openV4Algo35(rawRing, parsed, passphrase)
        }
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

    /** item 14 (#56): decapsulate + unwrap [parsed] with a v4 interop ring's
     *  algo-35 subkey. The subkey has no material-length field, so its public
     *  and secret material are extracted by the v4-specific facade helpers; the
     *  KEM itself is the same version-agnostic core. */
    private fun openV4Algo35(
        rawRing: ByteArray,
        parsed: CompositePkesk.Parsed,
        passphrase: String?
    ): ByteArray {
        val suite = parsed.suite
        if (suite.ietfAlgId != 35) {
            throw NoMatchingKey("v4 interop subkey is ML-KEM-768 (algo 35) only")
        }
        // 4.6.0 (item 19): a key can hold more than one v4 algo-35 subkey. Use
        // the one the PKESK names; an anonymous PKESK tries each in turn.
        val bodies = CompositeKeyFacade.v4Algo35SubkeyBodies(rawRing)
        if (bodies.isEmpty()) throw NoMatchingKey("v4 algo-35 subkey not found")
        val named = bodies.filter { body ->
            val fp = CompositeKeyFacade.v4Algo35SubkeyFingerprint(body)
            when {
                parsed.recipientFingerprint.isNotEmpty() -> fp.contentEquals(parsed.recipientFingerprint)
                parsed.recipientKeyId.size == 8 ->
                    fp.copyOfRange(fp.size - 8, fp.size).contentEquals(parsed.recipientKeyId)
                else -> true
            }
        }
        if (named.isEmpty()) throw NoMatchingKey("v4 algo-35 subkey not found")
        var last: Exception? = null
        for (body in named) {
            try {
                return openV4Algo35Body(body, parsed, passphrase)
            } catch (e: CompositeSecretKeyMaterial.ProtectedKeyException) {
                throw e
            } catch (e: V4Algo35Protection.ProtectedKeyException) {
                throw e
            } catch (e: Exception) {
                last = e
            }
        }
        throw last ?: NoMatchingKey("v4 algo-35 subkey not found")
    }

    private fun openV4Algo35Body(
        subBody: ByteArray,
        parsed: CompositePkesk.Parsed,
        passphrase: String?
    ): ByteArray {
        val suite = parsed.suite
        val pubMat = CompositeKeyFacade.v4Algo35PublicMaterial(subBody)
        val secret = CompositeKeyFacade.v4Algo35SecretMaterial(subBody, passphrase?.toCharArray())
            ?: throw CompositeSecretKeyMaterial.ProtectedKeyException(
                "v4 algo-35 subkey secret is unavailable"
            )
        val xSec = secret.copyOfRange(0, suite.curve.keyLen)
        val mlkemSeed = secret.copyOfRange(suite.curve.keyLen, secret.size)
        val mlkemSec = MLKEMPrivateKeyParameters(suite.mlkem.params, mlkemSeed)
        val (recipientXPub, _) = CompositeKem.splitPublic(pubMat, suite)
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

    /** The raw ring whose ML-KEM subkey fingerprint is [fp]: a composite-PRIMARY
     *  ring's v6 subkey, or a v4 interop ring's v4 algo-35 subkey. */
    private fun findRawComposite(fp: ByteArray, rawRings: List<ByteArray>): ByteArray? =
        rawRings.firstOrNull { ring ->
            runCatching {
                if (CompositeKeyFacade.hasV4Algo35Subkey(ring)) {
                    // 4.6.0 (item 19): any of the ring's v4 algo-35 subkeys.
                    CompositeKeyFacade.v4Algo35SubkeyBodies(ring).any {
                        CompositeKeyFacade.v4Algo35SubkeyFingerprint(it).contentEquals(fp)
                    }
                } else {
                    CompositeKeyFacade.parse(ring).encryptionSubkey?.fingerprint?.contentEquals(fp) == true
                }
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

    /** Every parseable composite PKESK in a region of ESK packets, walking
     *  definite-length packets only; empty on none. item 18 (#57): the
     *  streaming path must see all recipients, not just the first. */
    private fun allCompositePkesks(region: ByteArray): List<CompositePkesk.Parsed> {
        val out = mutableListOf<CompositePkesk.Parsed>()
        var i = 0
        while (i < region.size) {
            val h = try { header(region, i) } catch (e: Exception) { null } ?: break
            val end = h.bodyStart + h.bodyLen
            if (h.bodyLen < 0 || end > region.size || end <= i) break
            if (h.tag == TAG_PKESK) {
                CompositePkesk.parseBody(region.copyOfRange(h.bodyStart, end))?.let { out.add(it) }
            }
            i = end
        }
        return out
    }

    // ── packet splitting ─────────────────────────────────────────────

    private class Split(val parsed: List<CompositePkesk.Parsed>, val remainder: ByteArray)

    /**
     * Walk the top-level packets, dropping every leading ESK packet
     * (PKESK tag 1 / SKESK tag 3) and returning the composite PKESK's
     * parsed fields plus the byte stream from the first non-ESK packet
     * (the SEIPD) onward. Returns null if no composite PKESK is present.
     */
    private fun split(data: ByteArray): Split? {
        var i = 0
        val parsed = mutableListOf<CompositePkesk.Parsed>()
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
                // lengths natively. item 18 (#57): hand back EVERY composite
                // PKESK collected so far (one per recipient), not just the
                // first, so a held key that is not the first recipient can
                // still be matched downstream.
                if (parsed.isEmpty()) return null
                return Split(parsed, data.copyOfRange(i, n))
            }
            val h = header(data, i) ?: break
            if (h.tag == TAG_PKESK) {
                val body = data.copyOfRange(h.bodyStart, h.bodyStart + h.bodyLen)
                CompositePkesk.parseBody(body)?.let { parsed.add(it) }
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

    /** item 14 (#56): a v3 PKESK addresses its recipient by 8-octet key ID.
     *  Match a held composite BC secret key whose key ID equals it. */
    private fun findSecretKeyByKeyId(keyId: ByteArray, rings: List<PGPSecretKeyRing>): org.bouncycastle.openpgp.PGPSecretKey? {
        val id = keyIdToLong(keyId)
        return rings.asSequence()
            .flatMap { it.secretKeys.asSequence() }
            .firstOrNull {
                CompositeSuite.ietfFor(it.publicKey.algorithm) != null && it.keyID == id
            }
    }

    /** item 14 (#56): the raw ring whose ML-KEM subkey key ID (low 8 octets of
     *  the subkey fingerprint) is [keyId] — a v4 interop ring's v4 algo-35
     *  subkey, or a composite-PRIMARY ring's v6 subkey. */
    private fun findRawCompositeByKeyId(keyId: ByteArray, rawRings: List<ByteArray>): ByteArray? =
        rawRings.firstOrNull { ring ->
            runCatching {
                // 4.6.0 (item 19): any of the ring's v4 algo-35 subkeys.
                val fps = if (CompositeKeyFacade.hasV4Algo35Subkey(ring)) {
                    CompositeKeyFacade.v4Algo35SubkeyBodies(ring)
                        .map { CompositeKeyFacade.v4Algo35SubkeyFingerprint(it) }
                } else {
                    listOfNotNull(CompositeKeyFacade.parse(ring).encryptionSubkey?.fingerprint)
                }
                fps.any { fp ->
                    fp.size >= 8 && fp.copyOfRange(fp.size - 8, fp.size).contentEquals(keyId)
                }
            }.getOrDefault(false)
        }

    /** Big-endian 8-octet key ID to the Long BC exposes as PGPSecretKey.keyID. */
    private fun keyIdToLong(keyId: ByteArray): Long {
        var v = 0L
        for (b in keyId) v = (v shl 8) or (b.toLong() and 0xFF)
        return v
    }

    /** The PKESK's symmetric-algorithm octet, or AES-256 when it carried none
     *  (a v6 PKESK: the algorithm lives in the paired SEIPDv2 packet). */
    private fun symAlgOrDefault(symAlgId: Int): Int =
        if (symAlgId != 0) symAlgId else SymmetricKeyAlgorithmTags.AES_256

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
