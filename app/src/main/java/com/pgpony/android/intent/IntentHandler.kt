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

package com.pgpony.android.intent

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import java.io.BufferedReader
import java.io.InputStreamReader

sealed class IntentAction {
    data class EncryptText(val text: String) : IntentAction()
    data class DecryptText(val armoredMessage: String) : IntentAction()
    data class ImportKey(val armoredKey: String) : IntentAction()
    data class DecryptFile(val data: ByteArray, val filename: String?) : IntentAction()
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
        val data: ByteArray,
        val filename: String?,
        val armoredText: String?,
        val looksLikePgpMessage: Boolean,
        val looksLikePgpKey: Boolean,
    ) : ShareIntentContent()

    // Nothing usable in the intent. Activity should show an empty-state
    // message and a dismiss button.
    data object Empty : ShareIntentContent()
}

object IntentHandler {

    /**
     * Process an incoming intent and determine the action.
     * Called from MainActivity.onCreate and onNewIntent.
     */
    fun process(intent: Intent?, resolver: ContentResolver): IntentAction {
        if (intent == null) return IntentAction.None

        return when (intent.action) {
            Intent.ACTION_SEND -> handleSend(intent, resolver)
            Intent.ACTION_VIEW -> handleView(intent, resolver)
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
                ?: return IntentAction.None

            return classifyText(text)
        }

        // File share (e.g. from file manager)
        val uri = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
        if (uri != null) {
            return handleFileUri(uri, resolver)
        }

        return IntentAction.None
    }

    private fun classifySend(intent: Intent, resolver: ContentResolver): ShareIntentContent {
        val type = intent.type
        if (type == "text/plain") {
            val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                ?: return ShareIntentContent.Empty
            return classifyTextForShare(text)
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

    private fun handleFileUri(uri: Uri, resolver: ContentResolver): IntentAction {
        try {
            val inputStream = resolver.openInputStream(uri) ?: return IntentAction.None
            val bytes = inputStream.readBytes()
            inputStream.close()

            // Extract filename from URI
            val filename = uri.lastPathSegment
                ?.substringAfterLast('/')
                ?.takeIf { it.isNotBlank() }

            // Try to read as text first
            val text = try {
                String(bytes, Charsets.UTF_8)
            } catch (_: Exception) {
                null
            }

            // If it looks like armored PGP text, classify it
            if (text != null && text.contains("-----BEGIN PGP")) {
                return classifyText(text)
            }

            // Binary PGP data — assume encrypted file
            if (bytes.size > 2) {
                val firstByte = bytes[0].toInt() and 0xFF
                // OpenPGP packet tag byte: bit 7 is always set
                if (firstByte and 0x80 != 0) {
                    return IntentAction.DecryptFile(bytes, filename)
                }
            }

            // Unknown format
            return IntentAction.None
        } catch (_: Exception) {
            return IntentAction.None
        }
    }

    /**
     * Phase A15 — read a file URI and wrap into ShareIntentContent.
     * Mirrors handleFileUri but returns the richer struct.
     */
    private fun classifyFileForShare(uri: Uri, resolver: ContentResolver): ShareIntentContent {
        return try {
            val inputStream = resolver.openInputStream(uri) ?: return ShareIntentContent.Empty
            val bytes = inputStream.readBytes()
            inputStream.close()

            val filename = uri.lastPathSegment
                ?.substringAfterLast('/')
                ?.takeIf { it.isNotBlank() }

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
                ShareIntentContent.PgpFile(
                    data = bytes,
                    filename = filename,
                    armoredText = trimmed,
                    looksLikePgpMessage = trimmed.contains("-----BEGIN PGP MESSAGE-----")
                        || trimmed.contains("-----BEGIN PGP SIGNED MESSAGE-----"),
                    looksLikePgpKey = trimmed.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")
                        || trimmed.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
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
                    filename = filename,
                    armoredText = null,
                    looksLikePgpMessage = looksEncrypted,
                    looksLikePgpKey = false,
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
