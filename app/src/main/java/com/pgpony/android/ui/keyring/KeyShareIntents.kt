// KeyShareIntents.kt
// PGPony Android — Phase A4b + A6 + A7 + A7 Fix3 + A8.6
//
// System-share Intent helpers for keyring artifacts. As of A8.6 ALL
// three share helpers use FileProvider-backed .asc file Intents
// instead of text-only Intent.EXTRA_TEXT:
//   • sharePublicKey            — file via FileProvider (A8.6)
//   • shareRevocationCertificate — file via FileProvider (A8.6)
//   • shareArmoredPrivateKey    — file via FileProvider (A7 Fix3)
//
// Clipboard helpers (separate from share, used by the result sheets
// to provide a Copy alternative alongside Save-as-file):
//   • copyPublicKeyToClipboard           — no sensitive flag (A8.6)
//   • copyRevocationCertToClipboard      — no sensitive flag (A8.6)
//   • copyPrivateKeyToClipboard          — EXTRA_IS_SENSITIVE on API 33+ (A7 Fix4)
//
// Why the public + cert helpers don't set EXTRA_IS_SENSITIVE: public
// keys and revocation certs are public material — they're meant to
// be distributed widely. The clipboard-preview suppression that
// EXTRA_IS_SENSITIVE produces would actively hurt UX here, since
// users often want to verify what they're about to paste.

package com.pgpony.android.ui.keyring

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.PersistableBundle
import androidx.core.content.FileProvider
import java.io.File
import com.pgpony.android.R

object KeyShareIntents {

    /**
     * Phase A8.6 — share an armored public key as a downloadable
     * `.asc` file via FileProvider. Previously this was a text/plain
     * Intent that only surfaced text-handling targets (Messages,
     * Drive-as-Google-Doc, Chrome); switching to a file Intent
     * unlocks Drive-as-file, Files app, and mail-with-attachment as
     * destinations. The .asc extension is the universal hint that
     * makes recipients recognize the artifact as an OpenPGP key file.
     *
     * Mechanics:
     *   1. Sanitize the owner label to a filesystem-safe stem,
     *      append the short fingerprint for disambiguation (two
     *      contacts called "Jane Smith" would otherwise collide),
     *      and append "_public.asc".
     *   2. Write the armored text to context.cacheDir/exports/.
     *      Android sweeps cacheDir under storage pressure; the file
     *      is overwritten on each re-export of the same key.
     *   3. Wrap in a content:// URI via FileProvider with the
     *      authority declared in AndroidManifest.xml
     *      (${applicationId}.fileprovider, path config in
     *      res/xml/file_paths.xml — both shipped in A7 Fix3).
     *   4. Build Intent.ACTION_SEND with EXTRA_STREAM and MIME
     *      application/pgp-keys. IANA-registered type for OpenPGP
     *      keys (RFC 3156). Drive, Files, Gmail all accept it.
     *
     * Unlike the private-key share, no biometric or AlertDialog
     * gate is required — public keys are meant to be distributed.
     * Users who want raw text can use the Copy button on the
     * accompanying ExportPublicKeyResultSheet.
     */
    fun sharePublicKey(
        context: Context,
        armored: String,
        keyOwnerLabel: String,
        shortFingerprint: String
    ): Boolean {
        val filename = buildExportFilename(
            ownerLabel = keyOwnerLabel,
            shortFingerprint = shortFingerprint,
            suffix = "_public"
        )

        val uri = try {
            val exportsDir = File(context.cacheDir, "exports").apply { mkdirs() }
            val file = File(exportsDir, filename)
            file.writeText(armored, Charsets.UTF_8)
            FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                file
            )
        } catch (e: Exception) {
            return false
        }

        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "application/pgp-keys"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "$keyOwnerLabel — PGP Public Key")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(sendIntent, context.getString(R.string.share_intent_chooser_public_key))
        return try {
            context.startActivity(chooser)
            true
        } catch (e: ActivityNotFoundException) {
            false
        }
    }

    /**
     * Build a filesystem-safe export filename from an owner label +
     * short fingerprint + suffix. Centralized in A8.6 because all
     * three share helpers use the same pattern.
     *
     * Output shape: `{safe_owner}_{safe_fp}{suffix}.asc`
     * e.g.  `ffff_1AC7C311_public.asc`
     *       `Jane_Smith_ABCD9876_private.asc`
     *       `kgstew96_DEAD1234_revocation.asc`
     */
    private fun buildExportFilename(
        ownerLabel: String,
        shortFingerprint: String,
        suffix: String
    ): String {
        val safeLabel = ownerLabel
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .take(40)
            .ifEmpty { "key" }
        val safeFp = shortFingerprint
            .replace(Regex("[^A-Za-z0-9]"), "")
            .ifEmpty { "unknown" }
        return "${safeLabel}_${safeFp}${suffix}.asc"
    }

    /**
     * Phase A8.6 — share an armored revocation certificate as a
     * downloadable `.asc` file via FileProvider. Same pattern as
     * [sharePublicKey] but with a different EXTRA_SUBJECT and a
     * "_revocation" filename suffix. Used by:
     *   • RevocationResultSheet's Save File button immediately after
     *     applyRevocation succeeds
     *   • Danger Zone's "Export Revocation Certificate" row, once a
     *     key is revoked, for re-sharing later (post-A8.6 also goes
     *     through the result sheet for Copy + Save consistency)
     *
     * Filename: `{owner}_{shortFP}_revocation.asc`. EXTRA_SUBJECT
     * uses the standard "X — Key Revocation Certificate" convention
     * GnuPG users recognize.
     */
    fun shareRevocationCertificate(
        context: Context,
        armoredCert: String,
        keyOwnerLabel: String,
        shortFingerprint: String
    ): Boolean {
        val filename = buildExportFilename(
            ownerLabel = keyOwnerLabel,
            shortFingerprint = shortFingerprint,
            suffix = "_revocation"
        )

        val uri = try {
            val exportsDir = File(context.cacheDir, "exports").apply { mkdirs() }
            val file = File(exportsDir, filename)
            file.writeText(armoredCert, Charsets.UTF_8)
            FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                file
            )
        } catch (e: Exception) {
            return false
        }

        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "application/pgp-keys"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "$keyOwnerLabel — Key Revocation Certificate")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(sendIntent, context.getString(R.string.share_intent_chooser_revocation_cert))
        return try {
            context.startActivity(chooser)
            true
        } catch (e: ActivityNotFoundException) {
            false
        }
    }

    /**
     * Phase A7 (Fix3) — share an armored private key as a downloadable
     * `.asc` file via FileProvider.
     *
     * The pre-Fix3 implementation built a text/plain Intent with
     * EXTRA_TEXT. That only surfaced text-handling targets in the
     * share sheet (Messages, Drive-as-Google-Doc, Chrome), with no way
     * to actually save the key as a `.asc` file. Backing it with a
     * real file via FileProvider unlocks Drive-as-file, the Files app,
     * mail attachments, and other backup destinations — which are the
     * correct destinations for "I am exporting my private key for
     * safekeeping."
     *
     * Mechanics:
     *   1. Sanitize the owner label into a filesystem-safe filename
     *      stub, append the short fingerprint for disambiguation
     *      (two contacts called "ffff" would otherwise collide), and
     *      append "_private.asc" as the final type hint.
     *   2. Write the armored text to context.cacheDir/exports/. Using
     *      cacheDir means Android can sweep it when storage runs low;
     *      we don't need explicit cleanup. The file is overwritten on
     *      each re-export of the same key.
     *   3. Wrap in a content:// URI via FileProvider with the
     *      authority declared in AndroidManifest.xml
     *      (${applicationId}.fileprovider, path config in
     *      res/xml/file_paths.xml).
     *   4. Build Intent.ACTION_SEND with EXTRA_STREAM and MIME
     *      application/pgp-keys. The IANA-registered type for OpenPGP
     *      keys; targets that understand PGP attach it correctly, and
     *      it filters Messages out of the chooser (which is good —
     *      private keys should not be SMS-ed).
     *   5. FLAG_GRANT_READ_URI_PERMISSION lets the receiving app read
     *      the URI for the duration of its Activity.
     *
     * Caller (KeyDetailScreen) has already passed the AlertDialog
     * confirm and the biometric gate, so this helper does no auth
     * checks — it just builds the Intent.
     */
    fun shareArmoredPrivateKey(
        context: Context,
        armoredPrivate: String,
        keyOwnerLabel: String,
        shortFingerprint: String
    ): Boolean {
        // Filename via the shared A8.6 helper. Consistent shape across
        // all three share helpers: {safe_owner}_{safe_fp}_private.asc
        val filename = buildExportFilename(
            ownerLabel = keyOwnerLabel,
            shortFingerprint = shortFingerprint,
            suffix = "_private"
        )

        // Materialize the file in cacheDir/exports/. Try-catch wraps
        // the I/O so a full disk or sandbox quirk surfaces as a clean
        // "false" return instead of a crash.
        val uri = try {
            val exportsDir = File(context.cacheDir, "exports").apply { mkdirs() }
            val file = File(exportsDir, filename)
            file.writeText(armoredPrivate, Charsets.UTF_8)
            FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                file
            )
        } catch (e: Exception) {
            // Most likely IllegalArgumentException (FileProvider
            // misconfig) or IOException (disk full). Either way we
            // can't share — caller surfaces an error snackbar.
            return false
        }

        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            // application/pgp-keys is the IANA-registered MIME for
            // OpenPGP key files (RFC 3156). Drive, Files, Gmail all
            // accept it; Messages doesn't, which filters out a
            // destination we shouldn't be encouraging anyway.
            type = "application/pgp-keys"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "$keyOwnerLabel — PGP PRIVATE KEY (sensitive)")
            // Receiving app needs read access to the content:// URI
            // for the duration of its Activity. Without this flag the
            // target gets a SecurityException on first read.
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(sendIntent, context.getString(R.string.share_intent_chooser_private_key))
        return try {
            context.startActivity(chooser)
            true
        } catch (e: ActivityNotFoundException) {
            false
        }
    }

    /**
     * Phase A7 Fix4 — copy an armored private key to the system
     * clipboard with the sensitive-content flag set on Android 13+.
     *
     * Why this helper exists rather than the screen calling
     * ClipboardManager directly:
     *   • The EXTRA_IS_SENSITIVE flag has to be attached to the
     *     ClipDescription, not the ClipData itself, and the call has
     *     a Build.VERSION_CODES.TIRAMISU floor. Centralizing the
     *     branchy code keeps the screen-level Compose code clean.
     *   • Symmetry with shareArmoredPrivateKey — both helpers receive
     *     an armored string + the gate-cleared caller, and either
     *     produce a destination or report failure.
     *
     * Sensitive flag effects on API 33+:
     *   • Android suppresses the clipboard preview overlay that
     *     normally appears at the bottom of the screen on paste
     *     (the one that shows the clip's first ~80 chars). This
     *     prevents shoulder-surfing the armored block from a paste
     *     preview.
     *   • Some launchers also auto-purge sensitive clips after about
     *     1 hour; the exact behavior is OEM-specific. Pre-API-33 the
     *     clip persists until the user clears it.
     *
     * Returns true on success, false if the clipboard service is
     * somehow unavailable (extremely rare — only possible in
     * restricted-profile contexts where clipboard access is denied).
     */
    fun copyPrivateKeyToClipboard(context: Context, armoredPrivate: String): Boolean {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            ?: return false

        // Label is shown in some clipboard manager UIs (e.g. Gboard's
        // clipboard history). "PGPony Private Key" is honest and a
        // dead giveaway to the user that they have sensitive material
        // pending if they paste-by-accident later.
        val clip = ClipData.newPlainText(context.getString(R.string.share_intent_clip_label_private_key), armoredPrivate)

        // EXTRA_IS_SENSITIVE was added in API 33 (Tiramisu / Android
        // 13). On older versions the flag has no effect even if set,
        // so guard the version check at the API call site. The string
        // literal "android.content.extra.IS_SENSITIVE" is the same
        // value as ClipDescription.EXTRA_IS_SENSITIVE — using the
        // constant directly when available is cleaner.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }

        return try {
            cm.setPrimaryClip(clip)
            true
        } catch (e: SecurityException) {
            // Edge case: some MDM / restricted profiles disable
            // clipboard access entirely. Caller surfaces a snackbar.
            false
        }
    }

    /**
     * Phase A8.6 — copy an armored public key to the system clipboard.
     *
     * Differs from [copyPrivateKeyToClipboard] in NOT setting the
     * EXTRA_IS_SENSITIVE flag. Public keys are meant to be
     * distributed; suppressing the Android clipboard-preview overlay
     * would actively hurt UX by hiding what the user is about to
     * paste from themselves. Users WANT to see "PGPony Public Key"
     * in the preview when pasting into Signal / Mastodon / etc.
     *
     * Returns true on success, false if the clipboard service is
     * unavailable (extremely rare).
     */
    fun copyPublicKeyToClipboard(context: Context, armoredPublic: String): Boolean {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            ?: return false
        val clip = ClipData.newPlainText(context.getString(R.string.share_intent_clip_label_public_key), armoredPublic)
        return try {
            cm.setPrimaryClip(clip)
            true
        } catch (e: SecurityException) {
            false
        }
    }

    /**
     * Phase A8.6 — copy an armored revocation certificate to the
     * clipboard. Like [copyPublicKeyToClipboard], no sensitive flag —
     * revocation certs are public material meant to be distributed
     * widely so contacts update their keyrings.
     *
     * Label is "PGPony Revocation Certificate" so the clipboard
     * preview and any clipboard-history UI surface a meaningful
     * description rather than a base64 blob.
     */
    fun copyRevocationCertToClipboard(context: Context, armoredCert: String): Boolean {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            ?: return false
        val clip = ClipData.newPlainText(context.getString(R.string.share_intent_clip_label_revocation_cert), armoredCert)
        return try {
            cm.setPrimaryClip(clip)
            true
        } catch (e: SecurityException) {
            false
        }
    }
}
