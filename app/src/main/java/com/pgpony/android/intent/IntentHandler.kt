// IntentHandler.kt
// PGPony Android
//
// Processes incoming Android intents:
// - ACTION_SEND text/plain → pre-fill Encrypt tab
// - ACTION_VIEW .asc/.pgp/.gpg → detect key vs encrypted message → route to Import or Decrypt
// - ACTION_SEND with file URI → same detection logic
//
// Returns a sealed class indicating what action to take.
//
// ── Phase A15 — Rich share-target activity ─────────────────────────────
//
// IntentHandler now serves two callers:
//
//   1. MainActivity (legacy path): calls process() and uses the returned
//      IntentAction to navigate the main NavController. This stays
//      identical to the pre-A15 behaviour so dropping the new activity
//      out of the manifest still produces a working app.
//
//   2. ShareTargetActivity (A15 path): calls classifyShareIntent() to
//      get a richer ShareIntentContent that also carries the original
//      file bytes / filename / source-app uri so the standalone activity
//      doesn't have to re-read the stream. The classification logic is
//      shared with the legacy path; only the wrapper type differs.
//
// ── 3.1.0 Phase 1 (iOS 7.1.x parity: C1 / C3) ──────────────────────────
//
// C1 — open the app with ANY file, route by type (iOS onOpenURL parity):
//   • encrypted files (.asc/.gpg/.pgp, or binary OpenPGP) → Decrypt
//   • public/private key blocks → keyring Import (unchanged)
//   • a standalone detached signature block → the Verify-a-file sheet
//     (new IntentAction.VerifyDetachedSignature)
//   • anything else → Encrypt with the file preloaded
//     (new IntentAction.EncryptFile) instead of the old IntentAction.None
//
// C3 — large-file open without freezing, route by size:
//   • classification sniffs only the head of the file (HEAD_SNIFF_BYTES)
//     instead of decoding the whole payload into a String
//   • armored content larger than TEXT_PREFILL_LIMIT routes to file-mode
//     decrypt (a file card) rather than prefilling the text editor —
//     same ~32KB threshold iOS uses. Small messages still prefill.
//   • key blocks are exempt from the size routing: import consumes the
//     armored text directly, and keyserver keys with many third-party
//     certifications legitimately exceed 32KB.
//
// ── 3.1.0 Phase 1 Fix1 (origin: NorseHorse device testing) ─────────────
//
// Three real-world intent-delivery gaps found while testing Phase 1:
//
//   1. text/plain + EXTRA_STREAM: the Files app (and many others) share
//      text-like files (.asc, .sig, .txt) as ACTION_SEND type text/plain
//      with the file in EXTRA_STREAM and NO EXTRA_TEXT. Both handleSend
//      and classifySend only read EXTRA_TEXT for text/plain, so these
//      shares produced IntentAction.None / ShareIntentContent.Empty
//      ("No content was shared") for perfectly good armored files. Both
//      now fall through to the EXTRA_STREAM file path.
//
//   2. Binary detached signatures: gpg -b without --armor produces a
//      BINARY signature. Only armored detached sigs were recognized, so
//      binary .sig files fell through to "generic file → Encrypt". A
//      packet-tag sniff (tag 2 = Signature, old or new format) now
//      routes them to the Verify-a-file sheet, which already accepts
//      binary signatures.
//
//   3. Filenames: uri.lastPathSegment on content:// document URIs often
//      yields an opaque document ID, not the display name. Filenames are
//      now resolved via OpenableColumns.DISPLAY_NAME with lastPathSegment
//      as the fallback.

package com.pgpony.android.intent

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import com.pgpony.android.ui.encrypt.INLINE_FILE_LIMIT
import java.io.BufferedReader
import java.io.InputStreamReader

sealed class IntentAction {
    data class EncryptText(val text: String) : IntentAction()
    data class DecryptText(val armoredMessage: String) : IntentAction()
    /** 4.6.0 (item 6): a signed (not encrypted) message from the Quick
     *  Action: open it on the Decrypt screen and verify it straight away. */
    data class VerifyText(val signedMessage: String) : IntentAction()
    data class ImportKey(val armoredKey: String) : IntentAction()
    /**
     * 4.0.4 — [data] carries the file for anything small enough to hold
     * in memory, exactly as before. For a large file [data] is null and
     * [uri] points at it instead, so the Decrypt tab can stream it
     * rather than materialise it (issue #6). Exactly one is ever set.
     */
    data class DecryptFile(
        val data: ByteArray?,
        val uri: Uri?,
        val filename: String?
    ) : IntentAction()
    /** 4.0.0 Phase 3 — a PGPony (.pgpony) keyring backup → open Restore. */
    data class RestoreBackup(val data: ByteArray) : IntentAction()

    // 3.1.0 Phase 1 (C1) — a non-PGP file opened/shared into the app
    // routes to the Encrypt tab with the file preloaded, mirroring iOS
    // "everything else opens to Encrypt with recipients ready".
    data class EncryptFile(
        val data: ByteArray?,
        val uri: Uri?,
        val filename: String?
    ) : IntentAction()

    // 3.1.0 Phase 1 (C1) — a standalone detached signature (a
    // "-----BEGIN PGP SIGNATURE-----" block with no SIGNED MESSAGE
    // wrapper) routes to the Verify-a-file sheet with the signature
    // side preloaded; the user then picks the original file.
    data class VerifyDetachedSignature(val data: ByteArray, val filename: String?) : IntentAction()

    // 3.1.0 Phase 6 (J5) — two or more files shared into PGPony compose
    // a Bundle: the attachments land pre-loaded in the Encrypt tab's
    // Bundle mode (body optional, recipients picked there, outputs per
    // J4). Mirrors iOS ExtensionEncryptView's multi-file route.
    data class ComposeBundle(val files: List<ShareFileRef>) : IntentAction()

    /** 4.2.0 RC6 (#32): one shared file as uri + metadata, unread. The
     *  bundle streams it at encrypt time; size is -1 when the provider
     *  declares none. */
    data class ShareFileRef(
        val filename: String,
        val contentType: String,
        val size: Long,
        val uri: Uri
    )

    data object None : IntentAction()
}

// ── Phase A15 — Richer classification for ShareTargetActivity ──────────
//
// ShareIntentContent is what ShareTargetActivity reads. It distinguishes
// "user-shared plain text we could encrypt" from "user-shared armored
// PGP block we should decrypt or import" without forcing the activity
// to recompute classification on every recomposition. The wrapper keeps
// the original filename around (for UI display in the input preview)
// and the raw bytes for binary PGP files (no re-open of the content URI
// needed during the encrypt/decrypt action).
sealed class ShareIntentContent {
    // Plain text shared from another app — user can choose Encrypt or
    // (if it looks like a PGP message) Decrypt. The `looksLikePgp` flag
    // pre-classifies for the UI router so the action picker shows the
    // right primary action highlighted.
    data class Text(
        val text: String,
        val looksLikePgpMessage: Boolean,
        val looksLikePgpKey: Boolean,
    ) : ShareIntentContent()

    // PGP file (binary or armored) — typically .pgp/.gpg/.asc. The
    // armoredText is non-null when bytes parsed as UTF-8 contained a
    // PGP marker block; otherwise the binary path is taken.
    data class PgpFile(
        // 4.0.4 — [data] holds the file for anything small enough to keep
        // in memory, as before. For a large file it is null and [uri]
        // points at it instead, so the Quick Action can stream rather
        // than buffer (issue #6). Exactly one of the two is ever set.
        val data: ByteArray?,
        val uri: Uri? = null,
        val filename: String?,
        val armoredText: String?,
        val looksLikePgpMessage: Boolean,
        val looksLikePgpKey: Boolean,
        // 3.1.0 Phase 1 Fix3 — true when the file is a standalone
        // detached signature (armored SIGNATURE block or a binary
        // tag-2 packet). ShareTargetActivity forwards these to the
        // main app's Verify-a-file sheet, since the Quick Action has
        // no verify flow. Default false so existing constructions
        // are unaffected.
        val looksLikeDetachedSignature: Boolean = false,
    ) : ShareIntentContent()

    // Nothing usable in the intent. Activity should show an empty-state
    // message and a dismiss button.
    data object Empty : ShareIntentContent()
}

object IntentHandler {

    // ── 3.1.0 Phase 1 Fix3 — Quick Action → main app verify forward ────
    //
    // ShareTargetActivity has no verify flow; when it receives a
    // detached signature it forwards to MainActivity using this internal
    // action, carrying the signature bytes directly (detached sigs are
    // tiny — a few hundred bytes binary, a few KB armored — so a byte
    // extra is safe; FORWARD_SIZE_LIMIT guards the degenerate case,
    // which stays in the Quick Action rather than risking a
    // TransactionTooLargeException).
    const val ACTION_VERIFY_DETACHED = "com.pgpony.android.action.VERIFY_DETACHED"
    const val EXTRA_SIGNATURE_BYTES = "com.pgpony.android.extra.SIGNATURE_BYTES"
    const val EXTRA_SIGNATURE_NAME = "com.pgpony.android.extra.SIGNATURE_NAME"
    const val FORWARD_SIZE_LIMIT = 256 * 1024

    // 4.5.1 (#58): the "Encrypt in PGPony" share alias forwards its text here so
    // it goes straight to the Encrypt screen as plaintext, skipping the Quick
    // Action's classify (import key / decrypt / encrypt) step.
    const val ACTION_ENCRYPT_TEXT = "com.pgpony.android.action.ENCRYPT_TEXT"
    const val EXTRA_ENCRYPT_TEXT = "com.pgpony.android.extra.ENCRYPT_TEXT"

    // 4.6.0 (item 6): the Quick Action hands a signed-only message to the main
    // app's verify surface (signer lookup, trust, composite signatures).
    const val ACTION_VERIFY_TEXT = "com.pgpony.android.action.VERIFY_TEXT"
    const val EXTRA_VERIFY_TEXT = "com.pgpony.android.extra.VERIFY_TEXT"

    // ── 3.1.0 Phase 1 (C3) — size-aware routing constants ──────────────
    //
    // TEXT_PREFILL_LIMIT: armored content at or under this size prefills
    // the text editor (the pre-3.1.0 behaviour); anything larger routes
    // to file-mode decrypt so the UI never renders a giant string. Same
    // ~32KB threshold the iOS open path uses.
    //
    // HEAD_SNIFF_BYTES: how much of the payload is decoded as UTF-8 to
    // classify it. Armor markers appear at the very top of the content
    // (optionally after email headers), so 1KB is plenty.
    private const val TEXT_PREFILL_LIMIT = 32 * 1024
    private const val HEAD_SNIFF_BYTES = 1024

    // 4.0.4 — how much of a too-large-to-buffer file is pulled in to
    // classify it. Bigger than HEAD_SNIFF_BYTES because this head also
    // has to satisfy BouncyCastle's session-key parse, not just a
    // string search: a message with several recipients, or a PQC
    // composite KEM packet, pushes the first SEIPD byte well past 1 KB.
    private const val LARGE_HEAD_SNIFF_BYTES = 64 * 1024

    /**
     * 3.1.0 Phase 1 (C3) — decode just the head of [bytes] as UTF-8 for
     * marker sniffing. Lossy decoding is fine here: we only look for
     * ASCII armor markers, which survive any replacement-char damage in
     * surrounding binary content.
     */
    private fun headText(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val n = minOf(bytes.size, HEAD_SNIFF_BYTES)
        return try {
            String(bytes, 0, n, Charsets.UTF_8)
        } catch (_: Exception) {
            ""
        }
    }

    /**
     * 3.1.0 Phase 1 (C1) — true when [text] contains a standalone
     * detached signature block: a PGP SIGNATURE armor with no SIGNED
     * MESSAGE wrapper (a clear-signed message also contains a SIGNATURE
     * block, so the wrapper check is what disambiguates).
     */
    private fun isDetachedSignature(text: String): Boolean =
        text.contains("-----BEGIN PGP SIGNATURE-----") &&
            !text.contains("-----BEGIN PGP SIGNED MESSAGE-----")

    /**
     * 3.1.0 Phase 1 Fix1 — true when [bytes] starts with an OpenPGP
     * Signature packet (tag 2), i.e. a BINARY detached signature
     * (`gpg -b` without --armor). Header-only sniff, both packet
     * formats per RFC 4880 §4.2:
     *   • old format: bit7=1, bit6=0, tag in bits 5..2
     *   • new format: bit7=1, bit6=1, tag in bits 5..0
     * The Verify-a-file sheet does the real parse; this only routes.
     */
    private fun isBinaryDetachedSignature(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return false
        val b = bytes[0].toInt() and 0xFF
        if (b and 0x80 == 0) return false
        val tag = if (b and 0x40 == 0) (b shr 2) and 0x0F else b and 0x3F
        return tag == 2
    }

    /**
     * 3.1.0 Phase 1 Fix1 — resolve the user-visible filename for [uri].
     * content:// document URIs frequently return an opaque document ID
     * from lastPathSegment (e.g. "msf:1042"), so query
     * OpenableColumns.DISPLAY_NAME first and fall back to the old
     * lastPathSegment derivation.
     */
    private fun displayName(uri: Uri, resolver: ContentResolver): String? {
        try {
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0 && c.moveToFirst()) {
                    val name = c.getString(idx)
                    if (!name.isNullOrBlank()) return name
                }
            }
        } catch (_: Exception) {
            // Fall through to the URI-derived fallback.
        }
        return uri.lastPathSegment
            ?.substringAfterLast('/')
            ?.takeIf { it.isNotBlank() }
    }

    /**
     * Process an incoming intent and determine the action.
     * Called from MainActivity.onCreate and onNewIntent.
     */
    fun process(intent: Intent?, resolver: ContentResolver): IntentAction {
        if (intent == null) return IntentAction.None

        return when (intent.action) {
            Intent.ACTION_SEND -> handleSend(intent, resolver)
            // 3.1.0 Phase 6 (J5): multi-file share → Bundle compose.
            Intent.ACTION_SEND_MULTIPLE -> handleSendMultiple(intent, resolver)
            Intent.ACTION_VIEW -> handleView(intent, resolver)
            // 3.1.0 Phase 1 Fix3 — internal forward from the Quick
            // Action: a detached signature it can't handle itself.
            ACTION_VERIFY_DETACHED -> {
                val bytes = intent.getByteArrayExtra(EXTRA_SIGNATURE_BYTES)
                if (bytes != null && bytes.isNotEmpty()) {
                    IntentAction.VerifyDetachedSignature(
                        bytes,
                        intent.getStringExtra(EXTRA_SIGNATURE_NAME)
                    )
                } else {
                    IntentAction.None
                }
            }
            ACTION_ENCRYPT_TEXT -> {
                val text = intent.getStringExtra(EXTRA_ENCRYPT_TEXT)
                if (!text.isNullOrBlank()) IntentAction.EncryptText(text) else IntentAction.None
            }
            ACTION_VERIFY_TEXT -> {
                val text = intent.getStringExtra(EXTRA_VERIFY_TEXT)
                if (!text.isNullOrBlank()) IntentAction.VerifyText(text) else IntentAction.None
            }
            else -> IntentAction.None
        }
    }

    /**
     * Phase A15 — classify a share intent into a structure suitable for
     * ShareTargetActivity. Unlike process() this never decides on a
     * navigation route; it just describes the payload so the activity
     * can render its own picker.
     *
     * Returns ShareIntentContent.Empty if the intent is null or carries
     * no usable text/file payload.
     */
    fun classifyShareIntent(intent: Intent?, resolver: ContentResolver): ShareIntentContent {
        if (intent == null) return ShareIntentContent.Empty

        return when (intent.action) {
            Intent.ACTION_SEND -> classifySend(intent, resolver)
            Intent.ACTION_VIEW -> classifyView(intent, resolver)
            else -> ShareIntentContent.Empty
        }
    }

    // ── ACTION_SEND ────────────────────────────────────────────────────

    private fun handleSend(intent: Intent, resolver: ContentResolver): IntentAction {
        val type = intent.type ?: return IntentAction.None

        if (type == "text/plain") {
            val text = intent.getStringExtra(Intent.EXTRA_TEXT)
            // 3.1.0 Phase 1 Fix1 — a text/plain SEND with no EXTRA_TEXT is
            // a FILE share (Files and friends share .asc/.sig/.txt as
            // text/plain with only EXTRA_STREAM). Previously this returned
            // None; fall through to the file path instead.
            if (text != null) {
                return classifyText(text)
            }
        }

        // File share (e.g. from file manager)
        @Suppress("DEPRECATION")
        val uri = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
        if (uri != null) {
            return handleFileUri(uri, resolver)
        }

        return IntentAction.None
    }

    /**
     * 3.1.0 Phase 6 (J5) — ACTION_SEND_MULTIPLE: collect every shared
     * URI (clipData plus the EXTRA_STREAM list — senders vary in which
     * they populate), capture each as a ShareFileRef, and route:
     * 2+ readable files → ComposeBundle; exactly one → the normal
     * single-file classification (handleFileUri); none readable → None.
     */
    private fun handleSendMultiple(intent: Intent, resolver: ContentResolver): IntentAction {
        val uris = LinkedHashSet<Uri>()
        intent.clipData?.let { clip ->
            for (i in 0 until clip.itemCount) {
                clip.getItemAt(i)?.uri?.let { uris.add(it) }
            }
        }
        @Suppress("DEPRECATION")
        intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.let { list ->
            uris.addAll(list.filterNotNull())
        }
        if (uris.isEmpty()) return IntentAction.None
        if (uris.size == 1) return handleFileUri(uris.first(), resolver)

        // 4.2.0 RC6 (#32): metadata only — this path used to
        // DocumentBytes.read() every shared file into memory, so sharing
        // a few large files OOMed before the compose screen even
        // appeared. The refs stream at encrypt time; a file that turns
        // out unreadable then (revoked grant, cloud stub) surfaces as an
        // encrypt error instead of being silently dropped here.
        val files = uris.map { uri ->
            IntentAction.ShareFileRef(
                filename = displayName(uri, resolver) ?: "attachment",
                contentType = resolver.getType(uri) ?: "application/octet-stream",
                size = DocumentBytes.declaredSize(resolver, uri) ?: -1L,
                uri = uri
            )
        }
        return IntentAction.ComposeBundle(files)
    }

    private fun classifySend(intent: Intent, resolver: ContentResolver): ShareIntentContent {
        val type = intent.type
        if (type == "text/plain") {
            val text = intent.getStringExtra(Intent.EXTRA_TEXT)
            // 3.1.0 Phase 1 Fix1 — same fallthrough as handleSend: a
            // text/plain SEND carrying only EXTRA_STREAM is a file share.
            // Previously returned Empty → "No content was shared" for
            // perfectly good .asc files.
            if (text != null) {
                return classifyTextForShare(text)
            }
        }
        // File payload: ACTION_SEND can also carry EXTRA_STREAM.
        @Suppress("DEPRECATION")
        val uri = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
            ?: return ShareIntentContent.Empty
        return classifyFileForShare(uri, resolver)
    }

    // ── ACTION_VIEW ────────────────────────────────────────────────────

    private fun handleView(intent: Intent, resolver: ContentResolver): IntentAction {
        val uri = intent.data ?: return IntentAction.None
        return handleFileUri(uri, resolver)
    }

    private fun classifyView(intent: Intent, resolver: ContentResolver): ShareIntentContent {
        val uri = intent.data ?: return ShareIntentContent.Empty
        return classifyFileForShare(uri, resolver)
    }

    // ── File URI Handling ──────────────────────────────────────────────

    // ── 3.1.0 Phase 1 — pre-3.1.0 handleFileUri, superseded ────────────
    //
    // Kept for reference per the additive-edit convention. The old
    // implementation had three problems this phase fixes:
    //   • it decoded the WHOLE payload into a String before classifying,
    //     which froze the open path on large files (C3, origin Diego);
    //   • armored classification always went through classifyText(),
    //     which prefilled the text editor even for multi-megabyte
    //     armored files (C3);
    //   • a non-PGP file returned IntentAction.None — the file simply
    //     did nothing — instead of routing to Encrypt (C1).
    //
    // private fun handleFileUri(uri: Uri, resolver: ContentResolver): IntentAction {
    //     try {
    //         val inputStream = resolver.openInputStream(uri) ?: return IntentAction.None
    //         val bytes = inputStream.readBytes()
    //         inputStream.close()
    //
    //         // Extract filename from URI
    //         val filename = uri.lastPathSegment
    //             ?.substringAfterLast('/')
    //             ?.takeIf { it.isNotBlank() }
    //
    //         // Try to read as text first
    //         val text = try {
    //             String(bytes, Charsets.UTF_8)
    //         } catch (_: Exception) {
    //             null
    //         }
    //
    //         // If it looks like armored PGP text, classify it
    //         if (text != null && text.contains("-----BEGIN PGP")) {
    //             return classifyText(text)
    //         }
    //
    //         // Binary PGP data — assume encrypted file
    //         if (bytes.size > 2) {
    //             val firstByte = bytes[0].toInt() and 0xFF
    //             // OpenPGP packet tag byte: bit 7 is always set
    //             if (firstByte and 0x80 != 0) {
    //                 return IntentAction.DecryptFile(bytes, filename)
    //             }
    //         }
    //
    //         // Unknown format
    //         return IntentAction.None
    //     } catch (_: Exception) {
    //         return IntentAction.None
    //     }
    // }

    /**
     * 3.1.0 Phase 1 (C1 + C3) — read the file once, classify from a
     * 1KB head sniff, and route by type and size:
     *
     *   armored, ≤32KB  → classifyText() (text-editor prefill, as before,
     *                     now with the detached-signature route first)
     *   armored key     → ImportKey regardless of size (import needs the
     *                     armored text; big keyserver keys are legitimate)
     *   armored, >32KB  → detached sig → VerifyDetachedSignature;
     *                     otherwise DecryptFile (file card — never a
     *                     giant string in the editor)
     *   binary OpenPGP  → DecryptFile (parse-verified, not first-byte
     *                     sniffed — PNG/JPEG/zip all have bit 0x80 set)
     *   anything else   → EncryptFile (the C1 "everything else opens to
     *                     Encrypt" route)
     */
    /**
     * 4.0.4 — route a file too large to buffer, using only its head.
     *
     * Returns null when the head points at an outcome that needs the
     * whole file (ImportKey, VerifyDetachedSignature, RestoreBackup,
     * classifyText); the caller then falls back to the buffered path.
     * All of those are small-file outcomes in practice — a multi-megabyte
     * key block or detached signature does not occur in normal use.
     */
    private fun classifyLargeFileUri(uri: Uri, resolver: ContentResolver): IntentAction? {
        val head = DocumentBytes.readHead(resolver, uri, LARGE_HEAD_SNIFF_BYTES)
            ?: return null
        if (head.isEmpty()) return null
        val filename = displayName(uri, resolver)
        val headStr = headText(head)

        // Backups, key blocks, detached signatures and text all need the
        // full bytes downstream — hand them back to the buffered path.
        if (filename?.endsWith(".pgpony", ignoreCase = true) == true ||
            headStr.contains("PGPony Backup", ignoreCase = true) ||
            headStr.contains("Passphrase-Format", ignoreCase = true) ||
            headStr.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
            headStr.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") ||
            isDetachedSignature(headStr) ||
            isBinaryDetachedSignature(head)
        ) {
            return null
        }

        // An RFC 3156 envelope or an armored message: decrypt from the URI.
        if (headStr.contains("multipart/encrypted", ignoreCase = true) ||
            headStr.contains("-----BEGIN PGP")
        ) {
            return IntentAction.DecryptFile(null, uri, filename)
        }

        // Binary: the session-key packets are at the front, so the same
        // parse-don't-sniff test the buffered path uses works on the head.
        val looksEncrypted = try {
            val info = com.pgpony.android.crypto.PGPCryptoService.shared
                .inspectEncryptedMessage(head)
            info.publicKeyIDs.isNotEmpty() || info.isPasswordEncrypted
        } catch (_: Exception) {
            false
        }
        return if (looksEncrypted) {
            IntentAction.DecryptFile(null, uri, filename)
        } else {
            IntentAction.EncryptFile(null, uri, filename)
        }
    }

    private fun handleFileUri(uri: Uri, resolver: ContentResolver): IntentAction {
        try {
            // 4.0.4 — classify a large file from its head instead of
            // reading it. Before this, sharing a 13 MB file into PGPony
            // pulled the whole thing into memory here, before any of the
            // app's own code ran, and that read was the first of the
            // allocations behind issue #6.
            val declared = DocumentBytes.declaredSize(resolver, uri)
            if (declared != null && declared > INLINE_FILE_LIMIT) {
                val large = classifyLargeFileUri(uri, resolver)
                if (large != null) return large
                // Fall through: the head said this is one of the routes
                // that genuinely needs the whole file (a key block, a
                // detached signature, a backup). Those are small by
                // nature, so a file this size taking that branch is
                // pathological — read it and let the normal path decide.
            }

            // 3.1.0 Phase 8 Fix1: robust read (virtual/cloud docs).
            val bytes = DocumentBytes.read(resolver, uri) ?: return IntentAction.None

            if (bytes.isEmpty()) return IntentAction.None

            // 3.1.0 Phase 1 Fix1 — resolve the real display name (content
            // URIs often give an opaque document ID from lastPathSegment).
            val filename = displayName(uri, resolver)

            val head = headText(bytes)

            // 4.0.0 Phase 3 — a PGPony keyring backup opens to Restore, not
            // Decrypt. Detect by the armor comment (in the head sniff) or
            // the .pgpony extension, before the generic message routing.
            if (filename?.endsWith(".pgpony", ignoreCase = true) == true ||
                head.contains("PGPony Backup", ignoreCase = true) ||
                // OpenKeychain encrypted backup — the armor carries a
                // "Passphrase-Format: numeric9x4" header. Routing it to
                // Restore multi-imports every key inside (vs. the generic
                // decrypt path, which wouldn't).
                head.contains("Passphrase-Format", ignoreCase = true)
            ) {
                return IntentAction.RestoreBackup(bytes)
            }

            // 3.1.0 Phase 4 (J2): an encrypted .eml declares its RFC 3156
            // envelope in the headers (within the head sniff) but the
            // armored block may sit beyond it. Route to file-mode decrypt;
            // the decrypt path unwraps the envelope.
            if (head.contains("multipart/encrypted", ignoreCase = true)) {
                return IntentAction.DecryptFile(bytes, null, filename)
            }

            if (head.contains("-----BEGIN PGP")) {
                // Key blocks: import consumes armored text, size-exempt.
                if (head.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
                    head.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----")
                ) {
                    return IntentAction.ImportKey(String(bytes, Charsets.UTF_8).trim())
                }
                // Small armored content: full text classification, with
                // the detached-signature route checked first (C1).
                if (bytes.size <= TEXT_PREFILL_LIMIT) {
                    val text = String(bytes, Charsets.UTF_8).trim()
                    if (isDetachedSignature(text)) {
                        return IntentAction.VerifyDetachedSignature(bytes, filename)
                    }
                    return classifyText(text)
                }
                // Large armored content: never build the full String for
                // the editor — route by the head markers alone (C3).
                if (isDetachedSignature(head)) {
                    return IntentAction.VerifyDetachedSignature(bytes, filename)
                }
                return IntentAction.DecryptFile(bytes, null, filename)
            }

            // 3.1.0 Phase 1 Fix1 — a BINARY detached signature (gpg -b
            // without --armor, packet tag 2) routes to the Verify-a-file
            // sheet, same as its armored twin. Checked before the
            // encrypted-message parse: a signature packet carries no
            // PKESK/SKESK so the old logic classified it as a generic
            // file and sent it to Encrypt.
            if (isBinaryDetachedSignature(bytes)) {
                return IntentAction.VerifyDetachedSignature(bytes, filename)
            }

            // Binary: distinguish a real encrypted OpenPGP message from an
            // arbitrary binary file by PARSING, not first-byte sniffing —
            // same rationale as classifyFileForShare (A15). If BouncyCastle
            // finds recipients or a password packet it's encrypted →
            // Decrypt; otherwise it's a generic file → Encrypt (C1).
            val looksEncrypted = try {
                val info = com.pgpony.android.crypto.PGPCryptoService.shared
                    .inspectEncryptedMessage(bytes)
                info.publicKeyIDs.isNotEmpty() || info.isPasswordEncrypted
            } catch (_: Exception) {
                false
            }
            return if (looksEncrypted) {
                IntentAction.DecryptFile(bytes, null, filename)
            } else {
                IntentAction.EncryptFile(bytes, null, filename)
            }
        } catch (_: Exception) {
            return IntentAction.None
        }
    }

    /**
     * Phase A15 — read a file URI and wrap into ShareIntentContent.
     * Mirrors handleFileUri but returns the richer struct.
     */
    /**
     * 4.0.4 — Quick Action counterpart to [classifyLargeFileUri].
     *
     * Returns null when the head points at a route that needs the whole
     * file downstream (key import, detached-signature verify), letting
     * the caller fall back to the buffered read. armoredText is always
     * null here: it feeds a text editor, and a file this size must never
     * become a String — the same reasoning as the existing
     * TEXT_PREFILL_LIMIT guard, just applied earlier.
     */
    private fun classifyLargeFileForShare(uri: Uri, resolver: ContentResolver): ShareIntentContent? {
        val head = DocumentBytes.readHead(resolver, uri, LARGE_HEAD_SNIFF_BYTES) ?: return null
        if (head.isEmpty()) return null
        val filename = displayName(uri, resolver)
        val headStr = headText(head)

        if (headStr.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
            headStr.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") ||
            isDetachedSignature(headStr) ||
            isBinaryDetachedSignature(head)
        ) {
            return null
        }

        val armoredMessage = headStr.contains("-----BEGIN PGP MESSAGE-----") ||
            headStr.contains("-----BEGIN PGP SIGNED MESSAGE-----")
        val looksEncrypted = armoredMessage ||
            headStr.contains("multipart/encrypted", ignoreCase = true) ||
            try {
                val info = com.pgpony.android.crypto.PGPCryptoService.shared
                    .inspectEncryptedMessage(head)
                info.publicKeyIDs.isNotEmpty() || info.isPasswordEncrypted
            } catch (_: Exception) {
                false
            }

        return ShareIntentContent.PgpFile(
            data = null,
            uri = uri,
            filename = filename,
            armoredText = null,
            looksLikePgpMessage = looksEncrypted,
            looksLikePgpKey = false,
            looksLikeDetachedSignature = false,
        )
    }

    private fun classifyFileForShare(uri: Uri, resolver: ContentResolver): ShareIntentContent {
        return try {
            // 4.0.4 — a file too large to hold in memory is classified
            // from its head and carried as a URI, same as handleFileUri.
            val declared = DocumentBytes.declaredSize(resolver, uri)
            if (declared != null && declared > INLINE_FILE_LIMIT) {
                val large = classifyLargeFileForShare(uri, resolver)
                if (large != null) return large
                // Head pointed at a route needing the whole file (a key
                // block, a detached signature). Pathological at this size;
                // fall through and read it.
            }

            // 3.1.0 Phase 8 Fix1: robust read (virtual/cloud docs).
            val bytes = DocumentBytes.read(resolver, uri) ?: return ShareIntentContent.Empty

            // 3.1.0 Phase 1 Fix1 — resolve the real display name (content
            // URIs often give an opaque document ID from lastPathSegment).
            val filename = displayName(uri, resolver)

            val asText = try {
                String(bytes, Charsets.UTF_8)
            } catch (_: Exception) {
                null
            }

            if (asText != null && asText.contains("-----BEGIN PGP")) {
                // Armored block inside the file — keep both bytes (so we
                // can fall back to file-mode decrypt if needed) and the
                // armored string (preferred path).
                val trimmed = asText.trim()
                val isKey = trimmed.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")
                    || trimmed.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----")
                // 3.1.0 Phase 1 (C3) — a large armored MESSAGE must not
                // ride into the UI as a giant String (the share screen
                // renders armoredText into an editor). Null it out so the
                // binary/file-mode decrypt fallback is taken instead. Key
                // blocks are exempt: import consumes the armored text and
                // big keyserver keys are legitimate.
                val carryArmored = isKey || bytes.size <= TEXT_PREFILL_LIMIT
                ShareIntentContent.PgpFile(
                    data = bytes,
                    uri = uri,
                    filename = filename,
                    armoredText = if (carryArmored) trimmed else null,
                    looksLikePgpMessage = trimmed.contains("-----BEGIN PGP MESSAGE-----")
                        || trimmed.contains("-----BEGIN PGP SIGNED MESSAGE-----"),
                    looksLikePgpKey = isKey,
                    // 3.1.0 Phase 1 Fix3 — armored standalone SIGNATURE block.
                    looksLikeDetachedSignature = isDetachedSignature(trimmed),
                )
            } else if (bytes.isNotEmpty()) {
                // Distinguish a real encrypted OpenPGP message from an arbitrary
                // binary file by PARSING, not by sniffing the first byte: many
                // formats (PNG 0x89, JPEG 0xFF, zip, etc.) have bit 0x80 set, so
                // a first-byte check misfires and wrongly hides Encrypt. If
                // BouncyCastle finds public-key recipients or a password packet,
                // it's an encrypted message → offer Decrypt; otherwise it's a
                // generic file the user wants to Encrypt.
                val looksEncrypted = try {
                    val info = com.pgpony.android.crypto.PGPCryptoService.shared
                        .inspectEncryptedMessage(bytes)
                    info.publicKeyIDs.isNotEmpty() || info.isPasswordEncrypted
                } catch (_: Exception) {
                    false
                }
                ShareIntentContent.PgpFile(
                    data = bytes,
                    uri = uri,
                    filename = filename,
                    armoredText = null,
                    looksLikePgpMessage = looksEncrypted,
                    looksLikePgpKey = false,
                    // 3.1.0 Phase 1 Fix3 — binary tag-2 signature packet.
                    looksLikeDetachedSignature = isBinaryDetachedSignature(bytes),
                )
            } else {
                ShareIntentContent.Empty
            }
        } catch (_: Exception) {
            ShareIntentContent.Empty
        }
    }

    // ── Text Classification ────────────────────────────────────────────

    /**
     * Determine if text is a PGP key, encrypted message, or plain text to encrypt.
     */
    private fun classifyText(text: String): IntentAction {
        val trimmed = text.trim()

        return when {
            trimmed.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
            trimmed.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") ->
                IntentAction.ImportKey(trimmed)

            trimmed.contains("-----BEGIN PGP MESSAGE-----") ->
                IntentAction.DecryptText(trimmed)

            trimmed.contains("-----BEGIN PGP SIGNED MESSAGE-----") ->
                IntentAction.DecryptText(trimmed)

            // 3.1.0 Phase 1 (C1) — a standalone detached signature block
            // (shared as text or read from a small .sig/.asc) routes to
            // the Verify-a-file sheet, not the Encrypt tab. Must come
            // after the SIGNED MESSAGE case: clear-signed content also
            // contains a SIGNATURE block, and that should keep decrypting.
            isDetachedSignature(trimmed) ->
                IntentAction.VerifyDetachedSignature(
                    trimmed.toByteArray(Charsets.UTF_8),
                    null
                )

            // Plain text — user wants to encrypt it
            else -> IntentAction.EncryptText(trimmed)
        }
    }

    /**
     * Phase A15 — same classifier as classifyText() but yields the
     * ShareIntentContent wrapper. We can't reuse classifyText() directly
     * because that helper returns IntentAction.ImportKey / DecryptText /
     * EncryptText, which conflates routing with classification.
     */
    private fun classifyTextForShare(text: String): ShareIntentContent {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return ShareIntentContent.Empty
        return ShareIntentContent.Text(
            text = trimmed,
            looksLikePgpMessage = trimmed.contains("-----BEGIN PGP MESSAGE-----")
                || trimmed.contains("-----BEGIN PGP SIGNED MESSAGE-----"),
            looksLikePgpKey = trimmed.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")
                || trimmed.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        )
    }
}
