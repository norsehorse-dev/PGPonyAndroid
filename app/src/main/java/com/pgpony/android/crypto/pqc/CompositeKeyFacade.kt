// CompositeKeyFacade.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// A read model for composite ML-DSA + EdDSA signing keys, which cannot be held
// as a BouncyCastle PGPSecretKeyRing (BC rejects their algo-30/31 signatures).
// The app stores such a key as its raw OpenPGP octets; this facade hand-parses
// those octets into the metadata and key material the rest of the app needs:
//
//   * the primary's v6 fingerprint, algorithm, suite, and composite public /
//     secret material (for verifying and signing),
//   * the User IDs and creation / expiration,
//   * the ML-KEM encryption subkey, if present.
//
// Parsing assumes the unprotected on-disk form PGPony writes (the raw material
// is protected at rest by SecureKeyStore, not by an OpenPGP passphrase).

package com.pgpony.android.crypto.pqc

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

object CompositeKeyFacade {

    data class SubkeyInfo(
        val algId: Int,
        val fingerprint: ByteArray,
        val publicMaterial: ByteArray,
        val secretMaterial: ByteArray?,
        /** item 16 (#54): true if a 0x28 subkey-revocation follows this subkey. */
        val isRevoked: Boolean = false
    )

    /**
     * A composite ML-DSA + EdDSA key component that can make signatures: the
     * primary, or any composite (algo 30/31) subkey. Used to verify a signature
     * against whichever component made it (sequoia signs with a dedicated
     * signing subkey, PGPony's own keys sign with the primary).
     */
    data class CompositeComponent(
        val fingerprintHex: String,
        val algId: Int,
        val suite: CompositeSignSuite,
        val publicMaterial: ByteArray
    )

    data class Info(
        val fingerprint: ByteArray,
        val fingerprintHex: String,
        val primaryAlgId: Int,
        val suite: CompositeSignSuite,
        val userIds: List<String>,
        val creationTimeMillis: Long,
        val expirationSeconds: Long?,
        val compositePublic: ByteArray,
        val compositeSecret: ByteArray?,
        val encryptionSubkey: SubkeyInfo?,
        /** Every composite-signing component (primary + composite subkeys). */
        val compositeSigners: List<CompositeComponent>
    )

    /** True if the first key packet in [ring] is a composite signing key (algo 30/31). */
    fun isCompositePrimary(ring: ByteArray): Boolean {
        val packets = walk(ring)
        val primary = packets.firstOrNull { it.tag == 5 || it.tag == 6 } ?: return false
        val algId = primary.body[1 + 4].toInt() and 0xFF
        return CompositeSignSuite.forAlgId(algId) != null
    }

    /**
     * item 14 (#56): true if [ring] carries a v4 (version-4) ML-KEM-768+X25519
     * (algo 35) encryption subkey. Such a ring has an ordinary BC-parseable
     * Ed25519 primary but an algo-35 subkey BouncyCastle cannot parse (v4 key
     * packets carry no material-length field), so load and export paths detect
     * it here and carry the raw bytes rather than a re-serialized ring that
     * would silently drop the subkey. The algo byte sits at offset 1+4 (after
     * the version byte and 4-octet creation time) in both v4 and v6 framing.
     */
    fun hasV4Algo35Subkey(ring: ByteArray): Boolean =
        walk(ring).any { pkt ->
            (pkt.tag == 7 || pkt.tag == 14) &&
                pkt.body.size > 5 &&
                (pkt.body[0].toInt() and 0xFF) == 4 &&
                (pkt.body[1 + 4].toInt() and 0xFF) == 35
        }

    /** item 14 (#56): the v4 algo-35 subkey packet body from [ring] (the last
     *  such subkey), or null. Public (tag 14) or secret (tag 7). */
    fun v4Algo35SubkeyBody(ring: ByteArray): ByteArray? =
        walk(ring).lastOrNull { pkt ->
            (pkt.tag == 7 || pkt.tag == 14) &&
                pkt.body.size > 5 &&
                (pkt.body[0].toInt() and 0xFF) == 4 &&
                (pkt.body[1 + 4].toInt() and 0xFF) == 35
        }?.body

    /**
     * item 14 (#56): the 1216-byte public material (X25519 32 || ML-KEM-768
     * 1184) of a v4 algo-35 subkey body. A v4 key packet carries NO 4-octet
     * material-length field, so the material follows version(1)+ctime(4)+algo(1)
     * directly. This is the v4 counterpart of [publicMaterial], which reads the
     * v6 length field. The bytes feed CompositeKem unchanged (the KEM is
     * version-agnostic).
     */
    fun v4Algo35PublicMaterial(subkeyBody: ByteArray): ByteArray {
        require((subkeyBody[0].toInt() and 0xFF) == 4) { "not a v4 key packet" }
        require((subkeyBody[1 + 4].toInt() and 0xFF) == 35) { "not an algo-35 subkey" }
        val start = 1 + 4 + 1
        return subkeyBody.copyOfRange(start, start + 1216)
    }

    /**
     * item 14 (#56): the 96-byte secret material (X25519 secret 32 || ML-KEM
     * seed 64) of a v4 algo-35 secret subkey body, or null when the packet is
     * public-only. An unprotected (s2k-usage 0) body returns its material with
     * the trailing 2-octet checksum dropped; a passphrase-protected body (usage
     * 254 CFB, gpg's v4 form) is decrypted with [passphrase] via
     * [V4Algo35Protection.unlock], which throws when the key is protected and no
     * passphrase is supplied or the integrity check fails.
     */
    fun v4Algo35SecretMaterial(subkeyBody: ByteArray, passphrase: CharArray? = null): ByteArray? =
        V4Algo35Protection.unlock(subkeyBody, passphrase)

    /** item 14 (#56): true if a v4 algo-35 subkey body is passphrase-protected. */
    fun v4Algo35IsProtected(subkeyBody: ByteArray): Boolean =
        V4Algo35Protection.isProtected(subkeyBody)

    /**
     * item 14 (#56): reprotect an UNPROTECTED v4 interop ring under [newPass] for
     * export. The v4 Ed25519 primary and any classical subkey are re-encrypted by
     * BouncyCastle (usage 254, CFB); the algo-35 subkey — which BC cannot parse —
     * by [V4Algo35Protection] (usage 254, CFB, gpg's v4 form). The stored raw
     * octets are armored directly on export (BC would drop the unparseable
     * subkey), so this is the only way to add an export passphrase to a
     * passphrase-less interop key. Assumes the source is unprotected (the caller
     * gates on the subkey's own protection flag); the algo-35 subkey packet and
     * its binding signature keep their positions.
     */
    fun protectV4Algo35ForExport(ring: ByteArray, newPass: CharArray): ByteArray {
        val pkts = walk(ring)
        val subIdx = pkts.indexOfFirst { it.tag == 7 && isV4Algo35SecretBody(it.body) }
        require(subIdx >= 0) { "no v4 algo-35 secret subkey to protect" }

        // Base = every packet before the algo-35 subkey: a BC-parseable v4 ring.
        val baseBytes = ByteArrayOutputStream().apply {
            for (k in 0 until subIdx) write(packet(pkts[k].tag, pkts[k].body))
        }.toByteArray()
        val baseRing = org.bouncycastle.openpgp.PGPSecretKeyRing(
            java.io.ByteArrayInputStream(baseBytes),
            org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator()
        )
        val sha1 = org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
            .get(org.bouncycastle.bcpg.HashAlgorithmTags.SHA1)
        var rebuilt = baseRing
        for (sk in baseRing.secretKeys) {
            // Fresh encryptor per key: distinct salt + IV, never reused.
            val enc = org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder(
                org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256
            ).build(newPass)
            val protectedKey = org.bouncycastle.openpgp.PGPSecretKey.copyWithNewPassword(sk, null, enc, sha1)
            rebuilt = org.bouncycastle.openpgp.PGPSecretKeyRing.insertSecretKey(rebuilt, protectedKey)
        }

        val out = ByteArrayOutputStream()
        out.write(rebuilt.encoded)
        val subPkt = pkts[subIdx]
        val pubBody = subPkt.body.copyOfRange(0, 1 + 4 + 1 + 1216)
        val material = V4Algo35Protection.unlock(subPkt.body, null)
            ?: error("v4 algo-35 subkey carries no secret material")
        out.write(packet(7, pubBody + V4Algo35Protection.protect(material, newPass)))
        for (k in subIdx + 1 until pkts.size) out.write(packet(pkts[k].tag, pkts[k].body))
        return out.toByteArray()
    }

    private fun isV4Algo35SecretBody(body: ByteArray): Boolean =
        body.size > 5 && (body[0].toInt() and 0xFF) == 4 && (body[1 + 4].toInt() and 0xFF) == 35

    /**
     * item 14 (#56): the BC-parseable base ring bytes of a v4 interop key — every
     * packet before the v4 algo-35 subkey (the Ed25519 primary, its user IDs and
     * self-signatures, and any classical subkey). BouncyCastle can parse this even
     * though it cannot parse the algo-35 subkey that follows, so it is where the
     * key's fingerprint, user IDs, and dates are read on import. Null when the ring
     * carries no v4 algo-35 subkey.
     */
    fun v4Algo35BaseBytes(raw: ByteArray): ByteArray? {
        val pkts = walk(raw)
        val subIdx = pkts.indexOfFirst {
            (it.tag == 7 || it.tag == 14) && isV4Algo35SecretBody(it.body)
        }
        if (subIdx < 0) return null
        return ByteArrayOutputStream().apply {
            for (k in 0 until subIdx) write(packet(pkts[k].tag, pkts[k].body))
        }.toByteArray()
    }

    /**
     * item 14 (#56): the public transferable ring for a v4 interop key. A
     * public-only import is already public and returned unchanged; a secret ring
     * has its BC-parseable base converted to public keys and its algo-35 secret
     * subkey reduced to its public body (tag 14). Mirrors the publicRaw that
     * CompositeKeyGen.addV4Algo35SubkeyRings emits at generation.
     */
    fun v4Algo35PublicRingOf(raw: ByteArray): ByteArray {
        if (!hasSecret(raw)) return raw
        val pkts = walk(raw)
        val subIdx = pkts.indexOfFirst { it.tag == 7 && isV4Algo35SecretBody(it.body) }
        require(subIdx >= 0) { "no v4 algo-35 secret subkey to publish" }
        val baseBytes = ByteArrayOutputStream().apply {
            for (k in 0 until subIdx) write(packet(pkts[k].tag, pkts[k].body))
        }.toByteArray()
        val baseRing = org.bouncycastle.openpgp.PGPSecretKeyRing(
            java.io.ByteArrayInputStream(baseBytes),
            org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator()
        )
        val basePub = org.bouncycastle.openpgp.PGPPublicKeyRing(baseRing.publicKeys.asSequence().toList())
        val out = ByteArrayOutputStream()
        out.write(basePub.encoded)
        out.write(packet(14, pkts[subIdx].body.copyOfRange(0, 1 + 4 + 1 + 1216)))
        for (k in subIdx + 1 until pkts.size) out.write(packet(pkts[k].tag, pkts[k].body))
        return out.toByteArray()
    }

    /**
     * item 14 (#56): the v4 (SHA-1, 20-octet) fingerprint of a v4 algo-35 subkey
     * from its packet body. A v4 fingerprint is SHA-1 over 0x99 || 2-octet
     * length || public-key body, where the public body is version(1) + ctime(4)
     * + algo(1) + material(1216) = 1222 octets. This is the fingerprint a v6
     * PKESK carries (key-version octet 4, 20-octet fingerprint) to address the
     * subkey, per RFC 9580 5.1 / RFC 9980.
     */
    fun v4Algo35SubkeyFingerprint(subkeyBody: ByteArray): ByteArray {
        val pubBody = subkeyBody.copyOfRange(0, 1 + 4 + 1 + 1216)
        val framed = ByteArray(3 + pubBody.size)
        framed[0] = 0x99.toByte()
        framed[1] = ((pubBody.size ushr 8) and 0xFF).toByte()
        framed[2] = (pubBody.size and 0xFF).toByte()
        System.arraycopy(pubBody, 0, framed, 3, pubBody.size)
        return MessageDigest.getInstance("SHA-1").digest(framed)
    }

    /** #26 (RC4): unlock a secret region with [oldPassphrase] and re-emit it
     *  under [newPassphrase] (null/empty = unprotected). */
    private fun reprotectRegion(
        keyPacketBody: ByteArray,
        pubBody: ByteArray,
        secretLen: Int,
        oldPassphrase: CharArray?,
        newPassphrase: CharArray?
    ): ByteArray {
        val material = CompositeSecretProtection.unlock(keyPacketBody, oldPassphrase, secretLen)
        return if (newPassphrase == null || newPassphrase.isEmpty()) {
            byteArrayOf(0) + material
        } else {
            CompositeSecretProtection.protect(pubBody, material, newPassphrase)
        }
    }

    /** True if [ring] carries secret material (a tag-5 secret primary packet). */
    fun hasSecret(ring: ByteArray): Boolean =
        walk(ring).any { it.tag == 5 }

    /** #26 (RC4): true if the composite primary's secret is passphrase-protected. */
    fun isProtected(ring: ByteArray): Boolean {
        val primary = walk(ring).firstOrNull { it.tag == 5 } ?: return false
        return CompositeSecretProtection.isProtected(primary.body)
    }

    /**
     * #26 (RC4): return [ring] with the composite primary's secret re-protected
     * under [newPassphrase] (null/empty strips protection). [oldPassphrase]
     * unlocks the current material first (null/empty when unprotected). Only the
     * composite primary (tag 5) is touched; the ML-KEM subkey, which the app
     * never loads for these keys, is passed through unchanged. A wrong
     * [oldPassphrase] throws (BC AEAD tag mismatch).
     */
    fun reprotect(ring: ByteArray, oldPassphrase: CharArray?, newPassphrase: CharArray?): ByteArray {
        val out = ByteArrayOutputStream()
        for (pkt in walk(ring)) {
            if (pkt.tag == 5) {
                val pubBody = publicKeyBody(pkt.body)
                val algId = pubBody[1 + 4].toInt() and 0xFF
                val suite = CompositeSignSuite.forAlgId(algId)
                if (suite != null) {
                    out.write(packet(5, pubBody + reprotectRegion(
                        pkt.body, pubBody, suite.compositeSecretLen, oldPassphrase, newPassphrase
                    )))
                    continue
                }
            }
            if (pkt.tag == 7) {
                val pubBody = publicKeyBody(pkt.body)
                val algId = pubBody[1 + 4].toInt() and 0xFF
                val kem = com.pgpony.android.crypto.pqc.CompositeSuite.ietfFor(algId)
                if (kem != null) {
                    // #26 (RC4): protect the ML-KEM subkey too, so the passphrase
                    // gates decryption as well as signing.
                    val len = kem.curve.keyLen + kem.mlkem.seedLen
                    out.write(packet(7, pubBody + reprotectRegion(
                        pkt.body, pubBody, len, oldPassphrase, newPassphrase
                    )))
                    continue
                }
            }
            out.write(packet(pkt.tag, pkt.body))
        }
        return out.toByteArray()
    }

    fun parse(ring: ByteArray, passphrase: CharArray? = null): Info {
        val packets = walk(ring)
        val primary = packets.first { it.tag == 5 || it.tag == 6 }
        val primaryPublicBody = publicKeyBody(primary.body)
        val primaryAlgId = primaryPublicBody[1 + 4].toInt() and 0xFF
        val suite = requireNotNull(CompositeSignSuite.forAlgId(primaryAlgId)) {
            "not a composite signing key: algorithm $primaryAlgId"
        }
        val compositePublic = publicMaterial(primaryPublicBody)
        val ctimeSeconds = beInt(primaryPublicBody, 1).toLong() and 0xFFFFFFFFL
        val fingerprint = v6Fingerprint(primaryPublicBody)

        val compositeSecret = if (primary.tag == 5) {
            secretMaterial(primary.body, suite.compositeSecretLen, passphrase)
        } else null

        val userIds = packets.filter { it.tag == 13 }.map { String(it.body, Charsets.UTF_8) }
        val expirationSeconds = directKeyExpiration(packets)

        // Every key packet (primary + subkeys), classified by algorithm.
        val keyPackets = packets.filter { it.tag == 5 || it.tag == 6 || it.tag == 7 || it.tag == 14 }
        val compositeSigners = keyPackets.mapNotNull { pkt ->
            val pb = publicKeyBody(pkt.body)
            val algId = pb[1 + 4].toInt() and 0xFF
            val compSuite = CompositeSignSuite.forAlgId(algId) ?: return@mapNotNull null
            CompositeComponent(
                fingerprintHex = v6Fingerprint(pb).joinToString("") { "%02x".format(it) },
                algId = algId,
                suite = compSuite,
                publicMaterial = publicMaterial(pb)
            )
        }

        // The ML-KEM encryption subkey (algo 35/36), if any.
        val subIdx = packets.indexOfFirst { pkt ->
            if (pkt.tag != 7 && pkt.tag != 14) return@indexOfFirst false
            val a = publicKeyBody(pkt.body)[1 + 4].toInt() and 0xFF
            a == 35 || a == 36
        }
        val subkey = if (subIdx < 0) null else {
            val pkt = packets[subIdx]
            val subPublicBody = publicKeyBody(pkt.body)
            val subAlgId = subPublicBody[1 + 4].toInt() and 0xFF
            val subSecret = if (pkt.tag == 7) subkeySecret(pkt.body, subAlgId, passphrase) else null
            // A 0x28 revocation sits among the signatures immediately after the subkey.
            val revoked = (subIdx + 1 until packets.size).asSequence()
                .takeWhile { packets[it].tag == 2 }
                .any { (packets[it].body[1].toInt() and 0xFF) == 0x28 }
            SubkeyInfo(subAlgId, v6Fingerprint(subPublicBody), publicMaterial(subPublicBody), subSecret, revoked)
        }

        return Info(
            fingerprint = fingerprint,
            fingerprintHex = fingerprint.joinToString("") { "%02x".format(it) },
            primaryAlgId = primaryAlgId,
            suite = suite,
            userIds = userIds,
            creationTimeMillis = ctimeSeconds * 1000L,
            expirationSeconds = expirationSeconds,
            compositePublic = compositePublic,
            compositeSecret = compositeSecret,
            encryptionSubkey = subkey,
            compositeSigners = compositeSigners
        )
    }

    /**
     * 4.4.1 (#36, Umotas): build a BouncyCastle public key ring for THIS
     * composite key's ML-KEM encryption subkey, so it can be used as an
     * encryption recipient. BC rejects the algo-30/31 composite primary, so
     * the whole key fails to load through the normal import path; here we lift
     * just the algo-35/36 encryption subkey out of the raw public ring and
     * re-frame it as a bare primary public-key packet, which BC parses into an
     * UnknownBCPGKey exactly as it does a standalone ML-KEM key (same material,
     * same v6 fingerprint). Returns null if there is no composite encryption
     * subkey to receive a message.
     */
    fun encryptionSubkeyRing(publicRing: ByteArray): org.bouncycastle.openpgp.PGPPublicKeyRing? {
        val sub = walk(publicRing).firstOrNull { pkt ->
            if (pkt.tag != 6 && pkt.tag != 14 && pkt.tag != 5 && pkt.tag != 7) return@firstOrNull false
            val pb = publicKeyBody(pkt.body)
            val alg = pb[1 + 4].toInt() and 0xFF
            alg == 35 || alg == 36
        } ?: return null
        val bare = packet(6, publicKeyBody(sub.body))
        return try {
            org.bouncycastle.openpgp.PGPPublicKeyRing(
                bare,
                org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator()
            )
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Derive the public transferable key from a composite SECRET ring: convert
     * the secret key packet (tag 5) and secret subkey packets (tag 7) to their
     * public forms (tags 6 and 14) by keeping only the public key body, and pass
     * User ID and signature packets through unchanged. Used for storePublicKey /
     * export, since BouncyCastle cannot produce it.
     */
    fun publicRingOf(secretRing: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        for (pkt in walk(secretRing)) {
            when (pkt.tag) {
                5 -> out.write(packet(6, publicKeyBody(pkt.body)))
                7 -> out.write(packet(14, publicKeyBody(pkt.body)))
                else -> out.write(packet(pkt.tag, pkt.body))
            }
        }
        return out.toByteArray()
    }

    // -- parsing helpers ---------------------------------------------

    private fun publicKeyBody(keyPacketBody: ByteArray): ByteArray {
        var q = 1 + 4 + 1
        val matLen = beInt(keyPacketBody, q); q += 4
        return keyPacketBody.copyOfRange(0, q + matLen)
    }

    private fun publicMaterial(publicBody: ByteArray): ByteArray {
        var q = 1 + 4 + 1
        val matLen = beInt(publicBody, q); q += 4
        return publicBody.copyOfRange(q, q + matLen)
    }

    /** Fixed-length composite secret material after the s2k-usage octet (unprotected). */
    /**
     * #26 (RC4): the ML-KEM subkey secret, unlocked with [passphrase] when the
     * subkey is protected. Returns null for a locked subkey with no passphrase.
     */
    private fun subkeySecret(keyPacketBody: ByteArray, subAlgId: Int, passphrase: CharArray?): ByteArray? {
        val kem = com.pgpony.android.crypto.pqc.CompositeSuite.ietfFor(subAlgId) ?: return null
        val len = kem.curve.keyLen + kem.mlkem.seedLen
        return try {
            CompositeSecretProtection.unlock(keyPacketBody, passphrase, len)
        } catch (e: CompositeSecretProtection.ProtectedKeyException) {
            null
        }
    }

    private fun secretMaterial(
        keyPacketBody: ByteArray,
        secretLen: Int,
        passphrase: CharArray?
    ): ByteArray? =
        // #26 (RC4): unlock a passphrase-protected composite primary via
        // CompositeSecretProtection; a locked key with no passphrase surfaces
        // as null (the caller prompts), while a wrong passphrase throws.
        try {
            CompositeSecretProtection.unlock(keyPacketBody, passphrase, secretLen)
        } catch (e: CompositeSecretProtection.ProtectedKeyException) {
            null
        }

    /** The remaining secret octets after the usage octet (for the ML-KEM subkey). */
    private fun trailingSecret(keyPacketBody: ByteArray): ByteArray? {
        var q = 1 + 4 + 1
        val matLen = beInt(keyPacketBody, q); q += 4
        q += matLen
        val usage = keyPacketBody[q++].toInt() and 0xFF
        if (usage != 0) return null
        return keyPacketBody.copyOfRange(q, keyPacketBody.size)
    }

    private fun directKeyExpiration(packets: List<Pkt>): Long? {
        val direct = packets.firstOrNull { it.tag == 2 && (it.body[1].toInt() and 0xFF) == 0x1F }
            ?: return null
        // v6 sig body: ver,type,pubalgo,hash, 4-octet hashed len, hashed subpackets...
        val hLen = beInt(direct.body, 4)
        val hashed = direct.body.copyOfRange(8, 8 + hLen)
        var i = 0
        while (i < hashed.size) {
            val l0 = hashed[i++].toInt() and 0xFF
            val len = when {
                l0 < 192 -> l0
                l0 < 255 -> ((l0 - 192) shl 8) + (hashed[i++].toInt() and 0xFF) + 192
                else -> beInt(hashed, i).also { i += 4 }
            }
            val type = hashed[i].toInt() and 0x7F
            if (type == 9) { // Key Expiration Time
                return beInt(hashed, i + 1).toLong() and 0xFFFFFFFFL
            }
            i += len
        }
        return null
    }

    private fun v6Fingerprint(publicBody: ByteArray): ByteArray {
        val pre = byteArrayOf(0x9B.toByte()) +
            byteArrayOf(
                (publicBody.size ushr 24).toByte(), (publicBody.size ushr 16).toByte(),
                (publicBody.size ushr 8).toByte(), publicBody.size.toByte()
            ) + publicBody
        return MessageDigest.getInstance("SHA-256").digest(pre)
    }

    private fun beInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    private fun uint32(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun packet(tag: Int, body: ByteArray): ByteArray {
        val hdr = when {
            body.size < 192 -> byteArrayOf((0xC0 or tag).toByte(), body.size.toByte())
            body.size < 8384 -> {
                val l = body.size - 192
                byteArrayOf((0xC0 or tag).toByte(), (0xC0 or (l shr 8)).toByte(), (l and 0xFF).toByte())
            }
            else -> byteArrayOf((0xC0 or tag).toByte(), 0xFF.toByte()) + uint32(body.size)
        }
        return hdr + body
    }

    private data class Pkt(val tag: Int, val body: ByteArray)

    private fun walk(raw: ByteArray): List<Pkt> {
        val out = ArrayList<Pkt>()
        var i = 0
        while (i < raw.size) {
            val c = raw[i++].toInt() and 0xFF
            if (c and 0x80 == 0) break
            val tag: Int
            val len: Int
            if (c and 0x40 != 0) {
                tag = c and 0x3F
                val l0 = raw[i++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0
                    l0 < 224 -> ((l0 - 192) shl 8) + (raw[i++].toInt() and 0xFF) + 192
                    l0 == 255 -> beInt(raw, i).also { i += 4 }
                    else -> break
                }
            } else {
                tag = (c shr 2) and 0x0F
                len = when (c and 0x03) {
                    0 -> raw[i++].toInt() and 0xFF
                    1 -> (((raw[i].toInt() and 0xFF) shl 8) or (raw[i + 1].toInt() and 0xFF)).also { i += 2 }
                    2 -> beInt(raw, i).also { i += 4 }
                    else -> break
                }
            }
            if (i + len > raw.size) break
            out.add(Pkt(tag, raw.copyOfRange(i, i + len)))
            i += len
        }
        return out
    }
}
