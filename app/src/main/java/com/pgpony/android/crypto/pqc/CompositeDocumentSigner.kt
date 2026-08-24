// CompositeDocumentSigner.kt
// PGPony Android, 4.4.0 RC3 (RFC 9980 composite ML-DSA + EdDSA signatures)
//
// Produce composite ML-DSA + EdDSA document signatures in the three OpenPGP
// forms PGPony supports, none of which can go through BouncyCastle (it rejects
// algo-30 signatures):
//
//   * detached      - a bare signature packet over the data (RFC 9580 5.2.3),
//   * cleartext      - the Cleartext Signature Framework (RFC 9580 Section 7),
//   * inline one-pass - One-Pass Signature + Literal Data + Signature
//     (RFC 9580 Sections 5.4, 5.9).
//
// Every form signs through CompositeSigner over a standard v6 document hash;
// CompositeSigPacket owns the packet framing, canonicalization, and armor.

package com.pgpony.android.crypto.pqc

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

object CompositeDocumentSigner {

    private const val TAG_ONE_PASS = 4
    private const val TAG_LITERAL = 11

    private const val SIG_ARMOR_HEADER = "-----BEGIN PGP SIGNATURE-----"
    private const val SIG_ARMOR_TAIL = "-----END PGP SIGNATURE-----"

    /** A detached binary signature packet over [data]. */
    fun signDetached(
        suite: CompositeSignSuite,
        compositeSecret: ByteArray,
        signerFingerprint: ByteArray,
        data: ByteArray,
        creationTime: Date = Date(),
        random: SecureRandom = SecureRandom()
    ): ByteArray = CompositeSigPacket.buildDocumentSignature(
        suite, compositeSecret, CompositeSigPacket.TYPE_BINARY, data,
        signerFingerprint, (creationTime.time / 1000L).toInt(), random
    )

    /** A detached signature, ASCII-armored. */
    fun signDetachedArmored(
        suite: CompositeSignSuite,
        compositeSecret: ByteArray,
        signerFingerprint: ByteArray,
        data: ByteArray,
        creationTime: Date = Date(),
        random: SecureRandom = SecureRandom()
    ): String = CompositeSigPacket.armor(
        SIG_ARMOR_HEADER, SIG_ARMOR_TAIL,
        signDetached(suite, compositeSecret, signerFingerprint, data, creationTime, random)
    )

    /**
     * A cleartext signed message (RFC 9580 Section 7). The signature is a text
     * signature over the canonicalized cleartext; the visible body is dash-
     * escaped and trailing-whitespace trimmed to match what is signed.
     */
    fun signCleartext(
        suite: CompositeSignSuite,
        compositeSecret: ByteArray,
        signerFingerprint: ByteArray,
        text: String,
        creationTime: Date = Date(),
        random: SecureRandom = SecureRandom()
    ): String {
        val documentData = CompositeSigPacket.canonicalizeCleartext(text)
        val sigPacket = CompositeSigPacket.buildDocumentSignature(
            suite, compositeSecret, CompositeSigPacket.TYPE_TEXT, documentData,
            signerFingerprint, (creationTime.time / 1000L).toInt(), random
        )
        val armoredSig = CompositeSigPacket.armor(SIG_ARMOR_HEADER, SIG_ARMOR_TAIL, sigPacket)

        val display = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            .let { if (it.isNotEmpty() && it.last().isEmpty()) it.dropLast(1) else it }
            .joinToString("\n") { line ->
                val trimmed = line.trimEnd(' ', '\t')
                if (trimmed.startsWith("-")) "- $trimmed" else trimmed
            }

        return buildString {
            append("-----BEGIN PGP SIGNED MESSAGE-----\n")
            append("Hash: SHA256\n\n")
            append(display).append('\n')
            append(armoredSig)
        }
    }

    /**
     * An inline one-pass signed message: One-Pass Signature packet, Literal Data
     * packet holding [data] as binary, then the composite signature packet. The
     * one-pass packet carries the same salt as the signature (RFC 9580 5.4).
     */
    fun signInline(
        suite: CompositeSignSuite,
        compositeSecret: ByteArray,
        signerFingerprint: ByteArray,
        data: ByteArray,
        fileName: String = "",
        creationTime: Date = Date(),
        random: SecureRandom = SecureRandom()
    ): ByteArray {
        val ctime = (creationTime.time / 1000L).toInt()
        val sigPacket = CompositeSigPacket.buildDocumentSignature(
            suite, compositeSecret, CompositeSigPacket.TYPE_BINARY, data,
            signerFingerprint, ctime, random
        )
        val (_, sigBody) = CompositeSigPacket.firstPacket(sigPacket)
        val salt = CompositeSigPacket.parse(sigBody).salt

        val opsBody = ByteArrayOutputStream().apply {
            write(6)
            write(CompositeSigPacket.TYPE_BINARY)
            write(CompositeSigPacket.HASH_SHA256)
            write(suite.algId)
            write(salt.size)
            write(salt)
            write(signerFingerprint) // 32 octets, v6
            write(1) // nested flag: this is the only/last one-pass signature
        }.toByteArray()
        val ops = CompositeSigPacket.packet(TAG_ONE_PASS, opsBody)

        val nameBytes = fileName.toByteArray(Charsets.UTF_8)
        val literalBody = ByteArrayOutputStream().apply {
            write('b'.code) // binary literal
            write(nameBytes.size and 0xFF)
            write(nameBytes)
            write(CompositeSigPacket.uint32(ctime))
            write(data)
        }.toByteArray()
        val literal = CompositeSigPacket.packet(TAG_LITERAL, literalBody)

        return ops + literal + sigPacket
    }
}
