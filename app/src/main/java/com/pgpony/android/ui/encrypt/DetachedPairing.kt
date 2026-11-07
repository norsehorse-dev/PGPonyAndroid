// DetachedPairing.kt
// PGPony Android 4.8.0 (#106, and the 4.7.0 item 38 left-out): verify
// detached signatures with one trip to the picker.
//
// The system picker grants access to the picked documents only, never their
// folder, so the file a signature was made over cannot be opened as its
// sibling. Instead the Verify picker takes several files at once; each one is
// sorted into signature or data by its content, and each signature is matched
// to its file by display name ("report.pdf.sig" with "report.pdf"). A
// signature whose file was not picked keeps its row, with the usual "choose
// the file" action for that one signature.
//
// The classification and the matching are pure, so they are unit tested
// (DetachedPairingTest).

package com.pgpony.android.ui.encrypt

import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.intent.ClearSignedInput
import com.pgpony.android.intent.PacketSniff

/** 4.8.0 (#106): why a row of the multi-file verify has nothing to verify yet. */
enum class VerifyPairProblem {
    /** A signature whose signed file was not among the picked files. */
    FILE_NOT_PICKED,
    /** A signature that more than one picked file could belong to. */
    SEVERAL_FILES_MATCH,
    /** A picked file that no picked signature belongs to. */
    NO_SIGNATURE,
}

/**
 * 4.8.0 (#106): one row of the multi-file verify. A signature row has
 * [signatureName] and [signatureBytes]; [dataName] and [dataUri] are set once
 * its file is known. A row for a file with no signature has only the data side.
 */
data class VerifyPairRow(
    val signatureName: String?,
    val signatureBytes: ByteArray?,
    val dataName: String?,
    val dataUri: android.net.Uri?,
    val problem: VerifyPairProblem? = null,
    val result: VerificationResult? = null,
    val running: Boolean = false,
) {
    /** Both sides are known, so the row can be verified. */
    val ready: Boolean get() = signatureBytes != null && dataUri != null
}

/** 4.8.0 (#106): one file from the Verify picker, before it is classified. */
data class PickedVerifyFile(val name: String, val uri: android.net.Uri, val size: Long?)

internal object DetachedPairing {

    private const val BEGIN_SIGNATURE = "-----BEGIN PGP SIGNATURE-----"

    /**
     * Extensions a detached signature is usually named with. They only help
     * the name matching: whether a file is a signature is decided by its
     * content ([isDetachedSignature]), so "notes.asc" holding an encrypted
     * message is data, and a signature named "detached" is still a signature.
     */
    private val SIGNATURE_EXTENSIONS = listOf(".sig", ".asc", ".sign", ".gpg")

    /**
     * True when [bytes] is a detached signature by content: an armored block
     * whose first armor line is the PGP SIGNATURE one (as gpg, leading prose
     * is allowed; a clear-signed message, a key or an encrypted message opens
     * with another armor line), or one or more binary signature packets and
     * nothing else. Images, PDFs and zips are never signatures, even when
     * their first byte reads as a signature packet header (#67).
     */
    fun isDetachedSignature(bytes: ByteArray): Boolean {
        if (bytes.isEmpty() || bytes.size > PacketSniff.MAX_SIGNATURE_FILE) return false
        if (PacketSniff.isKnownNonOpenPgp(bytes)) return false
        if (PacketSniff.isDetachedSignature(bytes)) return true
        // Malformed UTF-8 decodes to replacement characters, so binary data
        // simply has no armor line here.
        val text = String(bytes, Charsets.UTF_8).removePrefix("﻿")
        return ClearSignedInput.firstArmorLine(text) == BEGIN_SIGNATURE
    }

    /** How one signature was matched by [pair]. */
    sealed class SigMatch {
        data class Paired(val dataIndex: Int) : SigMatch()
        data object NotPicked : SigMatch()
        data object Ambiguous : SigMatch()
    }

    /**
     * [signatures] has one entry per signature name, in the order given;
     * [unpairedData] the indices of data files no signature was paired with.
     */
    data class Result(val signatures: List<SigMatch>, val unpairedData: List<Int>)

    /** [name] without a trailing signature extension (any case), or null. */
    fun signatureStem(name: String): String? {
        val lower = name.lowercase()
        for (ext in SIGNATURE_EXTENSIONS) {
            if (lower.endsWith(ext)) return name.dropLast(ext.length).takeIf { it.isNotBlank() }
        }
        return null
    }

    /** [name] without its last extension, or null when it has none. */
    private fun withoutExtension(name: String): String? {
        if (!FileBatchNaming.hasExtension(name)) return null
        return name.substring(0, name.lastIndexOf('.')).takeIf { it.isNotBlank() }
    }

    /**
     * Match each signature to the data file it was made over, by display
     * name:
     *  1. "name.ext.sig" (or .asc, .sign, .gpg) goes with "name.ext". The
     *     same name matches first; failing that, the name in another case.
     *  2. GnuPG's other habit, "name.sig" for "name.ext", when exactly one
     *     picked file is "name" plus an extension and no signature has
     *     already claimed it by rule 1.
     *  3. With exactly one signature and one data file picked, the two go
     *     together whatever their names, as the two-button flow always did.
     * Two files that both fit a rule leave the signature [SigMatch.Ambiguous];
     * no fit leaves it [SigMatch.NotPicked]. Several signatures can go with the
     * same file (an .asc and a .sig, or two signers).
     */
    fun pair(signatureNames: List<String>, dataNames: List<String>): Result {
        val matches = arrayOfNulls<SigMatch>(signatureNames.size)
        val stems = signatureNames.map { signatureStem(it) }

        // Rule 1: the signature's name minus its extension is the file's name.
        stems.forEachIndexed { i, stem ->
            if (stem == null) return@forEachIndexed
            val exact = dataNames.indices.filter { dataNames[it] == stem }
            val candidates = exact.ifEmpty {
                dataNames.indices.filter { dataNames[it].equals(stem, ignoreCase = true) }
            }
            when (candidates.size) {
                0 -> Unit
                1 -> matches[i] = SigMatch.Paired(candidates[0])
                else -> matches[i] = SigMatch.Ambiguous
            }
        }

        // Rule 2: "name.sig" for "name.ext", among files rule 1 left free.
        val claimed = matches.mapNotNull { (it as? SigMatch.Paired)?.dataIndex }.toSet()
        stems.forEachIndexed { i, stem ->
            if (stem == null || matches[i] != null) return@forEachIndexed
            val candidates = dataNames.indices.filter { d ->
                d !in claimed && withoutExtension(dataNames[d])?.equals(stem, ignoreCase = true) == true
            }
            when (candidates.size) {
                0 -> Unit
                1 -> matches[i] = SigMatch.Paired(candidates[0])
                else -> matches[i] = SigMatch.Ambiguous
            }
        }

        // Rule 3: one of each.
        if (signatureNames.size == 1 && dataNames.size == 1 && matches[0] == null) {
            matches[0] = SigMatch.Paired(0)
        }

        val result = matches.map { it ?: SigMatch.NotPicked }
        val paired = result.mapNotNull { (it as? SigMatch.Paired)?.dataIndex }.toSet()
        return Result(result, dataNames.indices.filter { it !in paired })
    }
}
