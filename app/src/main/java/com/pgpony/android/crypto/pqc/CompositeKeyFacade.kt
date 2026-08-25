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
        val secretMaterial: ByteArray?
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
        val subkey = packets.asSequence()
            .filter { it.tag == 7 || it.tag == 14 }
            .mapNotNull { pkt ->
                val subPublicBody = publicKeyBody(pkt.body)
                val subAlgId = subPublicBody[1 + 4].toInt() and 0xFF
                if (subAlgId != 35 && subAlgId != 36) return@mapNotNull null
                val subSecret = if (pkt.tag == 7) subkeySecret(pkt.body, subAlgId, passphrase) else null
                SubkeyInfo(subAlgId, v6Fingerprint(subPublicBody), publicMaterial(subPublicBody), subSecret)
            }.firstOrNull()

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
