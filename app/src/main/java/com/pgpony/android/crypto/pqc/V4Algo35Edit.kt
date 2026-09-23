// V4Algo35Edit.kt
// PGPony Android, 4.6.0 (item 19 follow-ups): expiry, revocation and removal
// for the v4 ML-KEM (algo 35) subkeys Bouncy Castle cannot load.
//
// Key Detail now lists these subkeys, but the edit paths still went through a
// Bouncy Castle ring that does not hold them: an expiry change re-signed every
// other binding and left the ML-KEM one on its old expiry, and revoke or
// remove on the ML-KEM row reported "not found". The signatures here are made
// with the primary through Bouncy Castle's own signature generator, fed the
// v4 framing of both keys by hand (0x99, 2-octet length, key body), so any
// primary algorithm Bouncy Castle signs with works, and the packet edits run
// on the stored octets directly.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.RevocationService
import com.pgpony.android.data.RevocationReason
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import java.io.ByteArrayOutputStream
import java.util.Date

object V4Algo35Edit {

    private const val TAG_SECRET_SUBKEY = 7
    private const val TAG_PUBLIC_SUBKEY = 14
    private const val TAG_SIGNATURE = 2
    private const val TAG_TRUST = 12
    private const val V4_ALGO35_PUBLIC_LEN = 1 + 4 + 1 + 1216
    private const val SIG_SUBKEY_BINDING = 0x18
    /** Encrypt communications | encrypt storage. */
    private const val FLAGS_ENCRYPT = 0x0C

    private fun isV4Algo35(tag: Int, body: ByteArray): Boolean =
        (tag == TAG_SECRET_SUBKEY || tag == TAG_PUBLIC_SUBKEY) &&
            body.size >= V4_ALGO35_PUBLIC_LEN &&
            (body[0].toInt() and 0xFF) == 4 && (body[5].toInt() and 0xFF) == 35

    /** The public bodies of every v4 algo-35 subkey in [raw], in ring order. */
    fun publicBodies(raw: ByteArray): List<ByteArray> =
        CertificateBindings.packets(raw).filter { isV4Algo35(it.tag, it.body) }
            .map { it.body.copyOfRange(0, V4_ALGO35_PUBLIC_LEN) }

    /** Uppercase hex v4 fingerprint of a v4 algo-35 public body. */
    fun fingerprintHex(publicBody: ByteArray): String =
        CompositeKeyFacade.v4Algo35SubkeyFingerprint(publicBody).joinToString("") { "%02X".format(it) }

    /** The public body in [raw] whose fingerprint is [fpHex], or null. */
    fun find(raw: ByteArray, fpHex: String): ByteArray? =
        publicBodies(raw).firstOrNull { fingerprintHex(it).equals(fpHex, ignoreCase = true) }

    private fun framed(body: ByteArray): ByteArray = ByteArrayOutputStream().apply {
        write(0x99); write((body.size ushr 8) and 0xFF); write(body.size and 0xFF); write(body)
    }.toByteArray()

    /** A signature of [type] by the primary of [secretRing] over the primary and
     *  [subPublicBody], with [hashed] as its hashed area. Returns the packet body. */
    private fun signOverSubkey(
        secretRing: PGPSecretKeyRing,
        primaryPrivate: PGPPrivateKey,
        subPublicBody: ByteArray,
        type: Int,
        hashed: PGPSignatureSubpacketGenerator
    ): ByteArray {
        val primary = secretRing.publicKey
        val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(primary.algorithm, HashAlgorithmTags.SHA256), primary)
        gen.init(type, primaryPrivate)
        hashed.setSignatureCreationTime(false, Date())
        hashed.setIssuerFingerprint(false, primary)
        gen.setHashedSubpackets(hashed.generate())
        gen.update(framed(primary.publicKeyPacket.encodedContents))
        gen.update(framed(subPublicBody))
        val sig: PGPSignature = gen.generate()
        return CertificateBindings.packets(sig.encoded).first().body
    }

    /**
     * A fresh 0x18 binding for [subPublicBody] carrying the absolute expiry
     * [expiresAtEpochSeconds] (null = never). Throws when the expiry is not
     * after the subkey's creation, like the Bouncy Castle expiry path.
     */
    fun binding(
        secretRing: PGPSecretKeyRing,
        primaryPrivate: PGPPrivateKey,
        subPublicBody: ByteArray,
        expiresAtEpochSeconds: Long?
    ): ByteArray {
        val hashed = PGPSignatureSubpacketGenerator()
        hashed.setKeyFlags(false, FLAGS_ENCRYPT)
        if (expiresAtEpochSeconds != null) {
            val created = ((subPublicBody[1].toLong() and 0xFF) shl 24) or ((subPublicBody[2].toLong() and 0xFF) shl 16) or
                ((subPublicBody[3].toLong() and 0xFF) shl 8) or (subPublicBody[4].toLong() and 0xFF)
            val rel = expiresAtEpochSeconds - created
            require(rel > 0) { "Expiration date is before the subkey's creation date." }
            hashed.setKeyExpirationTime(false, rel)
        }
        return signOverSubkey(secretRing, primaryPrivate, subPublicBody, SIG_SUBKEY_BINDING, hashed)
    }

    /** A 0x28 subkey revocation for [subPublicBody]. */
    fun revocation(
        secretRing: PGPSecretKeyRing,
        primaryPrivate: PGPPrivateKey,
        subPublicBody: ByteArray,
        reason: RevocationReason,
        comment: String?
    ): ByteArray {
        val hashed = PGPSignatureSubpacketGenerator()
        hashed.setRevocationReason(false, RevocationService.reasonToTag(reason), comment.orEmpty())
        return signOverSubkey(secretRing, primaryPrivate, subPublicBody, PGPSignature.SUBKEY_REVOCATION, hashed)
    }

    /**
     * [raw] (public or secret octets) with the v4 algo-35 subkey whose public
     * body is [subPublicBody] edited: [remove] drops it with its signatures;
     * otherwise [replaceBinding] replaces its 0x18 bindings and [addSignature]
     * is appended after its signatures. Other packets are kept as they are.
     */
    fun edit(
        raw: ByteArray,
        subPublicBody: ByteArray,
        remove: Boolean = false,
        replaceBinding: ByteArray? = null,
        addSignature: ByteArray? = null
    ): ByteArray {
        val pkts = CertificateBindings.packets(raw)
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < pkts.size) {
            val p = pkts[i]
            val target = isV4Algo35(p.tag, p.body) &&
                p.body.copyOfRange(0, V4_ALGO35_PUBLIC_LEN).contentEquals(subPublicBody)
            if (!target) {
                out.write(CertificateBindings.frame(p.tag, p.body)); i++; continue
            }
            var j = i + 1
            val sigs = ArrayList<ByteArray>()
            while (j < pkts.size && (pkts[j].tag == TAG_SIGNATURE || pkts[j].tag == TAG_TRUST)) {
                if (pkts[j].tag == TAG_SIGNATURE) sigs.add(pkts[j].body)
                j++
            }
            i = j
            if (remove) continue
            out.write(CertificateBindings.frame(p.tag, p.body))
            val kept = if (replaceBinding != null) {
                sigs.filterNot { CertificateBindings.sigOrNull(it)?.type == SIG_SUBKEY_BINDING } + listOf(replaceBinding)
            } else sigs
            (kept + listOfNotNull(addSignature)).forEach { out.write(CertificateBindings.frame(TAG_SIGNATURE, it)) }
        }
        return out.toByteArray()
    }
}
