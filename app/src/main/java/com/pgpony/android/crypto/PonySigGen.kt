// PonySigGen.kt
// PGPony Android, 4.7.3
//
// PGPony's signature generator. For a v4 or v6 signing key it is Bouncy
// Castle's PGPSignatureGenerator, unchanged. For a LibrePGP v5 key (the kind
// GnuPG and Kleopatra make for Ed448) it writes the v5 signature itself,
// because Bouncy Castle 1.85 gets two things wrong there:
//   - the trailer: v5 hashes 0x05 0xFF and an 8-octet length; BC writes a
//     4-octet one, so neither GnuPG nor BC itself accepts the signature;
//   - signatures over documents (types 0x00 and 0x01): v5 also hashes the
//     literal data packet's format, file name and date, six zero octets for a
//     detached signature, or 't' and five zeros for a cleartext one (gnupg
//     g10/sign.c, hash_sigversion_to_magic and clearsign_file). BC hashes none
//     of it.
// BC also refuses to make a v4 signature with a v5 key, so there is no
// fallback. Key signatures hash a v5 key as 0x9A with a 4-octet length and a
// v4 key as 0x99 with a 2-octet length, by the key's own version, as GnuPG
// does. A v5 one-pass signature packet is version 3, as GnuPG writes it.
//
// Callers that write a literal data packet pass its fields with
// [setLiteralData] before [generate]; cleartext signers call [setCleartext].

package com.pgpony.android.crypto

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.MPInteger
import org.bouncycastle.bcpg.OnePassSignaturePacket
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SignaturePacket
import org.bouncycastle.bcpg.SignatureSubpacket
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.sig.IssuerFingerprint
import org.bouncycastle.bcpg.sig.SignatureCreationTime
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.PGPContentSigner
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.util.Date

class PonySigGen(private val builder: PGPContentSignerBuilder, private val signingKey: PGPPublicKey) {

    private val v5 = signingKey.version == 5
    private val bc: PGPSignatureGenerator? = if (v5) null else PGPSignatureGenerator(builder, signingKey)

    private var signer: PGPContentSigner? = null
    private var type = 0
    private var hashed: Array<SignatureSubpacket> = emptyArray()
    private var unhashed: Array<SignatureSubpacket> = emptyArray()
    private var documentExtra: ByteArray? = null
    private var last = 0

    fun init(signatureType: Int, privateKey: PGPPrivateKey) {
        if (bc != null) {
            bc.init(signatureType, privateKey)
            return
        }
        type = signatureType
        signer = builder.build(signatureType, privateKey)
        last = 0
    }

    fun setHashedSubpackets(v: PGPSignatureSubpacketVector?) {
        if (bc != null) bc.setHashedSubpackets(v) else hashed = v?.toArray() ?: emptyArray()
    }

    fun setUnhashedSubpackets(v: PGPSignatureSubpacketVector?) {
        if (bc != null) bc.setUnhashedSubpackets(v) else unhashed = v?.toArray() ?: emptyArray()
    }

    /** The literal data packet this signature covers: its format, file name and date. */
    fun setLiteralData(format: Char, fileName: String, modificationTime: Date) {
        documentExtra = LibrePgpV5Sig.literalExtra(format.code, fileName.toByteArray(Charsets.UTF_8), modificationTime)
    }

    /** This signature is a cleartext signature. */
    fun setCleartext() {
        documentExtra = LibrePgpV5Sig.CLEARTEXT_EXTRA
    }

    fun update(b: Byte) {
        if (bc != null) bc.update(b) else hashData(b.toInt() and 0xFF)
    }

    fun update(bytes: ByteArray) = update(bytes, 0, bytes.size)

    fun update(bytes: ByteArray, off: Int, len: Int) {
        if (bc != null) {
            bc.update(bytes, off, len)
            return
        }
        if (type != PGPSignature.CANONICAL_TEXT_DOCUMENT) {
            out().write(bytes, off, len)
            return
        }
        for (i in off until off + len) hashData(bytes[i].toInt() and 0xFF)
    }

    private fun out() = (signer ?: throw PGPException("signature generator not initialised")).outputStream

    // Text signatures hash CR LF line ends, exactly as Bouncy Castle does.
    private fun hashData(b: Int) {
        if (type != PGPSignature.CANONICAL_TEXT_DOCUMENT) {
            out().write(b)
            return
        }
        when (b) {
            0x0D -> { out().write(0x0D); out().write(0x0A) }
            0x0A -> if (last != 0x0D) { out().write(0x0D); out().write(0x0A) }
            else -> out().write(b)
        }
        last = b
    }

    fun generateOnePassVersion(isNested: Boolean): PGPOnePassSignature {
        if (bc != null) return bc.generateOnePassVersion(isNested)
        val s = signer ?: throw PGPException("signature generator not initialised")
        val packet = OnePassSignaturePacket(type, s.hashAlgorithm, s.keyAlgorithm, s.keyID, isNested)
        val bytes = ByteArrayOutputStream().also { o -> BCPGOutputStream(o).use { packet.encode(it) } }.toByteArray()
        return (BcPGPObjectFactory(bytes).nextObject() as PGPOnePassSignatureList)[0]
    }

    fun generate(): PGPSignature {
        if (bc != null) return bc.generate()
        val s = signer ?: throw PGPException("signature generator not initialised")

        if (hashed.none { it.type == SignatureSubpacketTags.CREATION_TIME }) {
            hashed = arrayOf<SignatureSubpacket>(SignatureCreationTime(false, Date())) + hashed
        }
        if (hashed.none { it.type == SignatureSubpacketTags.ISSUER_FINGERPRINT }) {
            hashed = hashed + IssuerFingerprint(false, signingKey.version, signingKey.fingerprint)
        }

        val subpackets = ByteArrayOutputStream().also { o -> hashed.forEach { it.encode(o) } }.toByteArray()
        val header = ByteArrayOutputStream().apply {
            write(5)
            write(type)
            write(s.keyAlgorithm)
            write(s.hashAlgorithm)
            write(subpackets.size ushr 8)
            write(subpackets.size and 0xFF)
            write(subpackets)
        }.toByteArray()
        val o = s.outputStream
        o.write(header)
        if (type == PGPSignature.BINARY_DOCUMENT || type == PGPSignature.CANONICAL_TEXT_DOCUMENT) {
            o.write(documentExtra ?: LibrePgpV5Sig.DETACHED_EXTRA)
        }
        val n = header.size
        o.write(byteArrayOf(5, 0xFF.toByte(), 0, 0, 0, 0, (n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()))

        val raw = s.signature
        val digest = s.digest
        val values = when (s.keyAlgorithm) {
            PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_SIGN ->
                arrayOf(MPInteger(BigInteger(1, raw)))
            PublicKeyAlgorithmTags.EDDSA_LEGACY -> arrayOf(
                MPInteger(BigInteger(1, raw.copyOfRange(0, raw.size / 2))),
                MPInteger(BigInteger(1, raw.copyOfRange(raw.size / 2, raw.size)))
            )
            PublicKeyAlgorithmTags.ECDSA, PublicKeyAlgorithmTags.DSA -> {
                val seq = ASN1Sequence.getInstance(raw)
                arrayOf(
                    MPInteger(ASN1Integer.getInstance(seq.getObjectAt(0)).value),
                    MPInteger(ASN1Integer.getInstance(seq.getObjectAt(1)).value)
                )
            }
            else -> throw PGPException("v5 signatures with algorithm ${s.keyAlgorithm} are not supported")
        }
        val packet = SignaturePacket(
            5, type, s.keyID, s.keyAlgorithm, s.hashAlgorithm,
            hashed, unhashed, digest.copyOf(2), values
        )
        val bytes = ByteArrayOutputStream().also { b -> BCPGOutputStream(b).use { packet.encode(it) } }.toByteArray()
        return (BcPGPObjectFactory(bytes).nextObject() as PGPSignatureList)[0]
    }

    /** A user ID certification (or its revocation) over [key]. */
    fun generateCertification(id: String, key: PGPPublicKey): PGPSignature {
        if (bc != null) return bc.generateCertification(id, key)
        hashKey(key)
        val idBytes = id.toByteArray(Charsets.UTF_8)
        out().write(byteArrayOf(0xB4.toByte(), (idBytes.size ushr 24).toByte(), (idBytes.size ushr 16).toByte(),
            (idBytes.size ushr 8).toByte(), idBytes.size.toByte()))
        out().write(idBytes)
        return generate()
    }

    /** A direct-key signature or key revocation over [key]. */
    fun generateCertification(key: PGPPublicKey): PGPSignature {
        if (bc != null) return bc.generateCertification(key)
        hashKey(key)
        return generate()
    }

    /** A subkey binding, primary key binding or subkey revocation. */
    fun generateCertification(primary: PGPPublicKey, subkey: PGPPublicKey): PGPSignature {
        if (bc != null) return bc.generateCertification(primary, subkey)
        hashKey(primary)
        hashKey(subkey)
        return generate()
    }

    private fun hashKey(key: PGPPublicKey) {
        val body = key.publicKeyPacket.encodedContents
        val o = out()
        when (key.version) {
            4, 3 -> o.write(byteArrayOf(0x99.toByte(), (body.size ushr 8).toByte(), body.size.toByte()))
            5 -> o.write(byteArrayOf(0x9A.toByte(), (body.size ushr 24).toByte(), (body.size ushr 16).toByte(),
                (body.size ushr 8).toByte(), body.size.toByte()))
            else -> o.write(byteArrayOf(0x9B.toByte(), (body.size ushr 24).toByte(), (body.size ushr 16).toByte(),
                (body.size ushr 8).toByte(), body.size.toByte()))
        }
        o.write(body)
    }
}
