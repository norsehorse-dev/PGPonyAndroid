// EncryptDecryptViewModel.kt
// PGPony Android
//
// Shared ViewModel for Encrypt and Decrypt tabs.
// Routes to PGPCryptoService through KeyRepository for key lookup.
//
// Phase A2: added EncryptMode (TEXT / SIGN), `signOnly()` action that
// produces RFC 4880 §7 clear-signed text via SigningService, and the
// matching SignSuccess event for haptics on the sign path. File mode
// is reserved by name in the enum but its UI path lands in Phase A10
// alongside the rest of the encrypt/decrypt feature-parity work.
//
// Phase A10b: file-mode encrypt is now wired up. New state on
// EncryptUiState — selectedFileName/Size/Bytes for the picked input
// file, encryptedFileBytes for the produced ciphertext, plus
// showEncryptResultSheet/showFileEncryptResultSheet flags so the
// dedicated result screens can be shown on success. Actions:
// setFileToEncrypt() (call with the bytes the ImportKeyScreen-style
// content://-read path produced), clearFile(), encryptFile(),
// dismissEncryptResult(), dismissFileEncryptResult(). The text-mode
// encrypt() path now flips showEncryptResultSheet on success in
// addition to its existing outputText update — the legacy inline
// result block in Screens.kt stays for now and renders the same
// data the sheet does.
//
// Phase A10c: file-mode decrypt now ships alongside file-mode
// encrypt. New DecryptMode enum (TEXT / FILE), state additions on
// DecryptUiState mirror the encrypt side — selectedFile{Name,Size,
// Bytes} for the picked encrypted .pgp/.gpg/.asc, decryptedFile-
// Bytes for the produced plaintext, decryptedOutputFilename for
// the save-dialog suggestion. Actions: setDecryptMode(),
// setFileToDecrypt(), clearDecryptFile(), decryptFile(),
// dismissFileDecryptResult(). The internal decryptFileAndVerify-
// Path() mirrors decryptAndVerifyPath() but feeds raw bytes to
// crypto.decrypt() (which sniffs armored vs binary via
// isArmored()) instead of armored text to decryptArmored().

package com.pgpony.android.ui.encrypt

import androidx.lifecycle.ViewModel
import com.pgpony.android.ui.util.ProgressInputStream
import com.pgpony.android.ui.util.ScratchFiles
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.pqc.CompositeDocumentSigner
import com.pgpony.android.crypto.pqc.CompositeDocumentVerifier
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SignedInputType
import com.pgpony.android.crypto.SigningError
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.ui.settings.DefaultRecipientPrefs
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.network.KeyServerRepository
import com.pgpony.android.crypto.mime.MimeBuilder
import com.pgpony.android.crypto.mime.MimeFileAttachment
import com.pgpony.android.crypto.mime.MimeStreamExtractor
import com.pgpony.android.ui.decrypt.SignerLookupState
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
// 3.1.0 Phase 4 (J1/J2) — PGP/MIME core (Phase 3 J-core modules).
import com.pgpony.android.crypto.mime.MimeEnvelope
import com.pgpony.android.crypto.mime.MimeParser
import com.pgpony.android.crypto.mime.MimeAttachment

// ── Mode picker (Phase A2) ─────────────────────────────────────────────
//
// Top-level Encrypt-tab mode. Phase A2 ships TEXT and SIGN; FILE is
// declared so the Composable's segmented control can render its slot
// even though the file flow lands in Phase A10. Selecting FILE in A2
// surfaces a "coming soon" placeholder rather than a working picker.

enum class EncryptMode(val displayName: String) {
    TEXT("Text"),
    SIGN("Sign"),
    FILE("File"),
    // RC3 §J (#16): file-only signing, promoted from a File-mode sheet
    // (SignFileSheet) to a first-class top-level mode, for parity with
    // Decrypt's Verify tab — same promotion, same reasoning.
    SIGN_FILE("Sign File"),
    // Phase A1: symmetric / passphrase-only encryption (`gpg -c`). No
    // recipient keypair — the message is sealed to a passphrase via
    // PGPCryptoService.encryptSymmetric.
    PASSWORD("Password"),
    // 3.1.0 Phase 5 (J3): PGP/MIME compose — a message body plus
    // multiple attachments encrypted together (iOS EncryptMode.message,
    // labelled "Bundle").
    BUNDLE("Bundle")
}

// ── 3.1.0 Phase 2 (C4, origin Wenzel): file-mode encrypt method ────────
//
// iOS 7.1.x parity: the File encrypt flow gets an "Encrypt with" toggle
// (iOS FileEncryptMethod in Views/Encrypt/EncryptView.swift). RECIPIENTS
// is the existing public-key path; PASSWORD seals the file to a
// passphrase (`gpg -c`) via PGPCryptoService.encryptSymmetric — keyless,
// so recipients, signing, and the hardware-key path are all skipped.
enum class FileEncryptMethod {
    RECIPIENTS,
    PASSWORD
}

/**
 * Phase A10c: top-level mode picker for the Decrypt tab. iOS has the
 * same two-mode shape (text/file) and we mirror it for parity. Sign-
 * only doesn't exist on this side — clear-signed verification is
 * routed automatically by [VerifyService.detectInputType] within the
 * text path, and the file path is binary-only for now (a future
 * extension could detect clear-signed text inside an .asc file too).
 */
enum class DecryptMode(val displayName: String) {
    TEXT("Text"),
    FILE("File"),
    // RC3 §J (#16): "Verify a file" promoted from a mode-agnostic sheet
    // button to its own top-level tab, for parity with Encrypt's Sign /
    // Sign File modes.
    VERIFY("Verify")
}

data class EncryptUiState(
    val inputText: String = "",
    val outputText: String = "",
    val selectedRecipients: List<PGPKeyEntity> = emptyList(),
    val availableRecipients: List<PGPKeyEntity> = emptyList(),
    val signingKey: PGPKeyEntity? = null,
    // §4.5 (#22): signing-subkey choices for the chosen signer (first entry
    // is the automatic pick); selectedSigningKeyId is the user's choice,
    // null = automatic. Only populated for software key pairs with 2+
    // signing-capable keys; the picker hides otherwise.
    val signingSubkeyOptions: List<com.pgpony.android.crypto.SigningKeyOption> = emptyList(),
    val selectedSigningKeyId: Long? = null,
    val availableSigningKeys: List<PGPKeyEntity> = emptyList(),
    // v4.0.0 (iOS parity) — persisted default signer fingerprint; preselected
    // on open ahead of the generic isDefault flag. Empty = none pinned.
    val defaultSignerFingerprint: String = "",
    val signMessage: Boolean = false,
    // Sign tab: produce a standalone detached signature block instead of
    // a clear-signed message. Only consulted in EncryptMode.SIGN.
    val detachedSignature: Boolean = false,
    val isProcessing: Boolean = false,
    val errorMessage: String? = null,
    val isFileMode: Boolean = false,
    val filename: String? = null,
    // Phase A2: top-level mode + sign-only passphrase prompt state.
    // The passphrase fields parallel DecryptUiState's pattern so the UI
    // layer can reuse the same dialog Composable shape.
    val mode: EncryptMode = EncryptMode.TEXT,
    val signPassphrase: String = "",
    val showSignPassphraseDialog: Boolean = false,
    // ── Phase A10b: file-mode encrypt state ────────────────────────
    //
    // selectedFileBytes is the raw input file content read via the
    // system file picker (DocumentPicker → contentResolver). We keep
    // bytes in memory rather than a URI because the URI's read-grant
    // is scoped to the activity and would need re-validation across
    // process death; encrypt() is fast enough that holding the bytes
    // around until the user taps Encrypt is fine for typical file
    // sizes (<10 MB). Larger files would warrant streaming — out of
    // scope for A10b.
    //
    // encryptedFileBytes is the produced ciphertext. armor=false is
    // implied for file mode (we want binary, not ASCII-armored, to
    // keep file size small and match standard .pgp convention). The
    // file save flow in FileEncryptionResultScreen writes these bytes
    // to a content:// URI obtained via ACTION_CREATE_DOCUMENT.
    //
    // ── 4.0.4 ─────────────────────────────────────────────────────────
    //
    // The note above about holding bytes rather than a URI ("larger
    // files would warrant streaming — out of scope for A10b") is now
    // only true up to INLINE_FILE_LIMIT. Past it, selectedFileUri
    // carries the input and encryptedFile carries the ciphertext, and
    // PGPCryptoService.encryptStream() runs between them so neither
    // side is ever fully in memory. Same fork, same reasoning, as the
    // decrypt side — see DecryptUiState.
    //
    // The URI read-grant caveat above still applies: it is scoped to
    // the activity and does not survive process death. Neither did the
    // bytes, which lived in ViewModel state, so nothing regresses.
    val selectedFileName: String? = null,
    val selectedFileSize: Long? = null,
    val selectedFileBytes: ByteArray? = null,
    val selectedFileUri: android.net.Uri? = null,
    val encryptedFileBytes: ByteArray? = null,
    val encryptedFile: java.io.File? = null,
    // 4.0.4 — streamed progress. Both zero means "no measurable
    // progress to show", which is the case for every buffered
    // operation; those finish too fast to be worth reporting.
    val processedBytes: Long = 0L,
    val totalBytes: Long = 0L,
    // Result-sheet visibility. Mutually exclusive in practice — only
    // one of them is ever true at a time — but kept as separate flags
    // so the screen layer can render two distinct Composables without
    // coupling them via an enum.
    val showEncryptResultSheet: Boolean = false,
    val showFileEncryptResultSheet: Boolean = false,
    // ── A15 preflight fix ──────────────────────────────────────────────
    //
    // Screens.kt references state.asciiArmor + viewModel.setAsciiArmor(...)
    // for the toggle UI added during A13 string extraction. The toggle
    // was wired into the Composable but the backing state field +
    // setter were never added to EncryptDecryptViewModel, so the call
    // sites failed to resolve.
    //
    // Default true: text-mode encrypt has always emitted armored output;
    // file-mode encrypt now also defaults to armored (which is what
    // the toggle UI implies — flipping it off opts the user into
    // smaller binary output for large files). Behavior change from
    // pre-A15 file-mode (was hard-coded armor=false): minor — the file
    // output is now armored by default, which means a slightly larger
    // .pgp file but more portable / pasteable into email.
    val asciiArmor: Boolean = true,
    // ── Phase A1: symmetric / passphrase-only (Password) mode ──────────
    //
    // Independent of the sign-passphrase dialog (that unlocks a signing
    // key). These back the in-body passphrase + confirm fields shown in
    // EncryptMode.PASSWORD. The passphrase never leaves the device and is
    // cleared from state after a successful encrypt.
    val passwordPassphrase: String = "",
    val passwordConfirm: String = "",
    val passwordVisible: Boolean = false,
    // ── 3.1.0 Phase 2 (C4): file-mode "Encrypt with" toggle ────────────
    //
    // PASSWORD reuses the Phase A1 passphrase/confirm/visible fields
    // above (they're mode-scoped inputs, and the two password surfaces
    // are never on screen together). fileEncryptedWithPassword tells the
    // file result sheet to show the "Password protected" badge instead
    // of the recipient count.
    val fileEncryptMethod: FileEncryptMethod = FileEncryptMethod.RECIPIENTS,
    val fileEncryptedWithPassword: Boolean = false,
    // ── 3.1.0 Phase 5 (J3/J4): Bundle compose ──────────────────────────
    val bundleBody: String = "",
    // 4.2.0 RC6 (#32): refs, not bytes. A picker add stores only the
    // uri + metadata; the bytes are streamed at encrypt time by
    // MimeBuilder.writeMixedSources, so a 350 MB attachment is never
    // resident. Share-seeded and legacy adds stay ByteArray-backed via
    // the `data` slot.
    val bundleAttachments: List<BundleAttachmentRef> = emptyList(),
    val encryptedBundleArmored: String? = null,
    // 4.2.0 RC6 (#32, tail): above BUNDLE_RESULT_INLINE_LIMIT the
    // armored result stays in this scratch file instead of a String —
    // a 750 MB bundle armors to ~1.4 GB, and the readText() that used
    // to produce encryptedBundleArmored was the last OOM in the path.
    // Exactly one of the two is non-null when the result sheet shows.
    val encryptedBundleFile: java.io.File? = null,
    val showBundleResultSheet: Boolean = false,
    // ── Phase A5: "Sign a file" (detached signature, software key) ─────
    //
    // Sign a file on its own (no encryption) → standalone detached signature
    // (.asc or .sig) to share alongside the original. Lives on the Encrypt
    // tab's FILE mode, next to the existing sign-a-message flow. Card-backed
    // signing is deferred to the card phase.
    val signFileName: String? = null,
    val signFileUri: android.net.Uri? = null,
    val signFileSelectedKey: PGPKeyEntity? = null,
    val showSignFileKeyPicker: Boolean = false,
    val signFilePassphrase: String = "",
    /** true = armored .asc; false = binary .sig. Default armored (portable). */
    val signFileArmor: Boolean = true,
    val signFileResultBytes: ByteArray? = null,
    val signFileResultName: String? = null,
    val signFileProcessing: Boolean = false,
) {
    /**
     * 4.0.4 — "the user has picked a file", regardless of which side of
     * INLINE_FILE_LIMIT it fell on. Button-enablement checks must use
     * this rather than `selectedFileBytes != null`, which is null by
     * design for a large file and would leave Encrypt greyed out.
     */
    val hasSelectedFile: Boolean get() = selectedFileBytes != null || selectedFileUri != null

    /**
     * True when the picked file was too large to buffer, which is what a
     * card operation needs — the NFC session holds the card for the whole
     * operation, so the card paths cannot stream.
     */
    val fileTooLargeForCard: Boolean get() = selectedFileBytes == null && selectedFileUri != null
}

data class DecryptUiState(
    val inputText: String = "",
    val outputText: String = "",
    val outputData: ByteArray? = null,
    val availableKeys: List<PGPKeyEntity> = emptyList(),
    val selectedKeyFingerprint: String? = null,
    val passphrase: String = "",
    val showPassphraseDialog: Boolean = false,
    val isProcessing: Boolean = false,
    val errorMessage: String? = null,
    val signatureVerified: Boolean = false,
    val signerKeyID: String? = null,
    // HW Phase 3 — set when the input message is encrypted to a card-backed
    // key (a recipient key ID matches a card key's encryption subkey). The
    // Decrypt tab then hides the passphrase field and offers PIN + tap
    // instead. cardMessageKeyName is the display name for the prompt.
    val isCardMessage: Boolean = false,
    val cardMessageKeyFingerprint: String? = null,
    val cardMessageKeyName: String? = null,
    // ── 4.1.0: hidden-recipient (`gpg -R`) fallback ────────────────────
    //
    // A wildcard PKESK names nobody, so detectCardRecipient cannot route the
    // message to a card by key ID the way an addressed message is routed.
    // Prompting for a tap on every hidden-recipient message would be the easy
    // answer and the wrong one: the software keys can be trialled for free
    // (PGPCryptoService.resolvePkesk), and most hidden-recipient mail is for a
    // software key. So the software path runs first, and only when it comes
    // back with NoMatchingKey are these promoted into isCardMessage /
    // cardMessageKey*, which swaps the tab to PIN + tap for a one-press retry.
    val isHiddenRecipientMessage: Boolean = false,
    val hiddenRecipientCardFingerprint: String? = null,
    val hiddenRecipientCardName: String? = null,
    // Phase A1: set when the pasted/loaded message is password-encrypted
    // (symmetric SKESK, `gpg -c`) and addressed to no public key. The Decrypt
    // tab then hides the key picker and shows a "Password-encrypted" note +
    // the passphrase field, since no keypair applies.
    val isPasswordMessage: Boolean = false,
    // ── 3.1.0 Phase 4 (J1): structured PGP/MIME decrypt result ─────────
    //
    // Set when the decrypted plaintext parses as multipart/mixed WITH
    // attachments: the structured sheet shows mimeBody on top and one
    // row per attachment. Body-only MIME renders as plain text via
    // outputText; non-MIME keeps the existing result paths untouched.
    val mimeBody: String? = null,
    val mimeAttachments: List<MimeAttachment> = emptyList(),
    // ── 4.1.0 Phase 14 (issue #10): the file backed twin ──────────────
    //
    // Above INLINE_FILE_LIMIT the plaintext is on disk and never
    // resident, so its attachments cannot be MimeAttachments (those
    // carry bytes). The streamed decrypt path fills this list instead,
    // with one scratch file per attachment. Exactly one of the two is
    // ever non empty; the result sheet renders both the same way.
    val mimeFileAttachments: List<MimeFileAttachment> = emptyList(),
    val showStructuredResultSheet: Boolean = false,
    val decryptedFilename: String? = null,
    // Phase A3: full verification result for the 4-state banner. Populated
    // by both the clear-signed verify path AND the encrypted-and-signed
    // path (derived from PGPCryptoService.decryptArmored output). Null
    // means no result yet — banner is hidden.
    val verificationResult: VerificationResult? = null,
    // Phase A3: signer-lookup modal sheet state.
    val showSignerLookup: Boolean = false,
    val signerLookupState: SignerLookupState = SignerLookupState.Searching,
    // Phase A3: remember the claimed fingerprint of the unknown signer so
    // we can re-verify after the user imports the discovered key.
    val pendingUnknownClaimedFingerprint: String? = null,
    // ── Phase A10c: file-mode decrypt state ────────────────────────
    //
    // Mirrors the encrypt-side fields on EncryptUiState.
    // decryptedOutputFilename pre-seeds the save-dialog suggestion
    // (encrypted name minus .pgp/.gpg/.asc extension, or
    // "decrypted_<name>" if there was no recognized extension to strip).
    //
    // ── 4.0.4: two paths, chosen by input size ─────────────────────
    //
    // Up to INLINE_FILE_LIMIT the behaviour is exactly what it was:
    // the picked file is read into selectedFileBytes at pick time,
    // PGPCryptoService.decrypt() sniffs armored vs. binary, and the
    // plaintext lands in decryptedFileBytes. That keeps the RFC 3156
    // envelope unwrap, MIME routing to the structured sheet, the
    // inline preview and clipboard copy all working as before, which
    // is what nearly every real message needs.
    //
    // Above that limit none of it fits in memory. Issue #6: a 13 MB
    // file meant ~13 MB of ciphertext in state, a ByteArrayOutputStream
    // doubling its way to ~13 MB of plaintext plus a full copy on
    // toByteArray(), and another ~13 MB back in state — roughly 60 MB
    // of mostly contiguous allocation, which OOMs on a modest heap. So
    // the large path holds only selectedFileUri, streams through
    // PGPCryptoService.decryptStream() into decryptedFile under
    // cacheDir/scratch, and the result sheet saves and shares straight
    // from that file. Peak memory is the 64 KiB chunk buffer.
    //
    // Exactly one of (selectedFileBytes, selectedFileUri) drives a
    // given decrypt, and exactly one of (decryptedFileBytes,
    // decryptedFile) carries its output.
    val mode: DecryptMode = DecryptMode.TEXT,
    val selectedFileName: String? = null,
    val selectedFileSize: Long? = null,
    val selectedFileBytes: ByteArray? = null,
    val selectedFileUri: android.net.Uri? = null,
    val decryptedFileBytes: ByteArray? = null,
    val decryptedFile: java.io.File? = null,
    /** 4.0.4 — streamed progress; see EncryptUiState. */
    val processedBytes: Long = 0L,
    val totalBytes: Long = 0L,
    val decryptedOutputFilename: String? = null,
    val showFileDecryptResultSheet: Boolean = false,
    // ── Phase A3: "Verify a file" (detached signature) sheet ───────────
    //
    // Self-contained from the decrypt result above: the user picks the
    // original file + its detached .sig/.asc, and VerifyService checks them.
    // Reuses the shared signer-lookup fields (showSignerLookup /
    // pendingUnknownClaimedFingerprint) since decrypt and verify-file are
    // never active at the same time.
    val verifyFileSignedName: String? = null,
    val verifyFileSignedUri: android.net.Uri? = null,
    val verifyFileSigName: String? = null,
    val verifyFileSigBytes: ByteArray? = null,
    val verifyFileResult: VerificationResult? = null,
    val verifyFileProcessing: Boolean = false,
) {
    /**
     * 4.0.4 — "the user has picked a file", regardless of which side of
     * INLINE_FILE_LIMIT it fell on. Button-enablement checks must use
     * this rather than `selectedFileBytes != null`, which is null by
     * design for a large file and would leave Decrypt greyed out.
     */
    val hasSelectedFile: Boolean get() = selectedFileBytes != null || selectedFileUri != null

    /** True when the picked file is too large to hand to a card operation. */
    val fileTooLargeForCard: Boolean get() = selectedFileBytes == null && selectedFileUri != null
}

/**
 * 4.0.4 — the cut-off between "read the whole file into memory" and
 * "stream it through a scratch file" on the Encrypt and Decrypt tabs.
 *
 * Below this, the buffered paths run exactly as they did before, which
 * keeps the RFC 3156 envelope unwrap, MIME routing, the inline preview
 * and clipboard copy all working. Above it, none of that fits in a
 * modest heap anyway (issue #6), so the streaming paths take over.
 *
 * 4 MiB is chosen so that the worst case for the buffered path — the
 * input array, a ByteArrayOutputStream at 2x while it doubles, its
 * toByteArray() copy, and the output array — stays comfortably inside
 * even a 128 MB heap with Compose resident.
 */
internal const val INLINE_FILE_LIMIT: Long = 4L * 1024 * 1024

/**
 * 4.2.0 RC6 (#32, tail): largest armored bundle result held as an
 * in-memory String (which is what enables Copy Inline Block). Past it
 * the result stays on disk and the sheet streams shares/saves from the
 * file; copying multi-hundred-MB text into the clipboard was never
 * going to work anyway.
 */
internal const val BUNDLE_RESULT_INLINE_LIMIT: Long = 8L * 1024 * 1024

/**
 * 4.2.0 RC6 (#32, AraafRoyall): one bundle attachment, byte- or
 * uri-backed. Exactly one of [data] / [uri] is non-null. [size] is the
 * byte count ([data].size for byte-backed; the picker's declared size
 * for uri-backed, -1 when the provider declares none, e.g. some cloud
 * documents). Deliberately NOT MimeAttachment: that is a transport
 * model shared with the MIME parser and has no business knowing about
 * content:// URIs (its own header says so); this type is compose-state
 * only and converts to a MimeSource at encrypt time.
 */
class BundleAttachmentRef(
    val filename: String,
    val contentType: String,
    val size: Long,
    val data: ByteArray? = null,
    val uri: android.net.Uri? = null
) {
    /** Open the backing bytes for one streaming pass. */
    fun openStream(): java.io.InputStream =
        data?.let { java.io.ByteArrayInputStream(it) }
            ?: PGPonyApp.instance.contentResolver.openInputStream(uri!!)
            ?: throw java.io.IOException("Cannot open attachment: $filename")

    fun toMimeSource() = com.pgpony.android.crypto.mime.MimeBuilder.MimeSource(
        filename, contentType, ::openStream
    )
}

/**
 * 4.1.0 Phase 16. How much ciphertext the card decrypt path will
 * buffer, since CardDecryptService has no streaming entry point yet.
 *
 * Higher than INLINE_FILE_LIMIT on purpose. That limit exists to keep
 * the ordinary pick-time read cheap for every file the user touches;
 * this one is paid once, deliberately, for a message the card is the
 * only way to open. A card bundle of a dozen photos lands around
 * 12 MB and was refused outright before this.
 *
 * Peak is this plus the recovered plaintext, so 32 MB here means about
 * 64 MB worst case before the plaintext goes to scratch. Raising it
 * further wants the streaming decrypt, not a bigger number.
 */
internal const val CARD_BUFFER_LIMIT: Long = 32L * 1024 * 1024

/**
 * RC3 §J (#16), matching the iOS 8.1.0 §3a resolution: Sign File and
 * Verify no longer buffer the picked FILE at all — the pickers store its
 * Uri and the run-time paths hash it from disk in 64 KiB chunks via
 * signDetachedStream / verifyDetachedStream (both sitting in the crypto
 * layer since 4.0.0 P2d, previously only used by the OpenPGP API
 * provider). No ceiling on the signed content, same as iOS's
 * signDetachedFile path.
 *
 * The detached SIGNATURE file is the one thing still read into memory,
 * because parseFirstSignatureBytes needs the whole packet — and a real
 * signature is a few hundred bytes. This cap exists purely so picking
 * the wrong file (a video, an ISO) as the "signature" fails fast at
 * read time instead of buffering it all and then failing to parse.
 */
internal const val SIGNATURE_FILE_BUFFER_LIMIT: Long = 1L * 1024 * 1024

/**
 * 4.1.0 Phase 16. What a large card decrypt left on disk: either the
 * plaintext as a single scratch file, or an extracted bundle with one
 * scratch file per attachment. Never both.
 */
internal class CardScratchOutcome(
    val file: java.io.File?,
    val bundle: com.pgpony.android.crypto.mime.MimeFileMessage?
)

/**
 * 4.0.4 — above this, file encrypt skips ZLIB.
 *
 * Deflate runs single-threaded over every byte and is the slowest stage
 * in the pipeline by a wide margin — well behind AES and the integrity
 * hash. On the files that get this big (video, photos, archives,
 * anything already compressed) it buys close to nothing, so paying
 * minutes for it is a bad trade. PGPCryptoService.encryptStream already
 * took enableCompression as a parameter for the card path, which skips
 * it for the same reason: to keep the card-held time short.
 *
 * Decrypt is unaffected — it decompresses whatever it is given.
 */
internal const val COMPRESSION_LIMIT: Long = 16L * 1024 * 1024

class EncryptDecryptViewModel(private val repo: KeyRepository) : ViewModel() {

    private val crypto = PGPCryptoService.shared
    // Phase A2: dedicated signing service (separate from PGPCryptoService
    // so we can grow clear-sign / detached / revocation / per-key export
    // without further bloating the crypto service).
    private val signing = SigningService.shared

    // Phase A4 — app prefs for the default/remembered recipient.
    private val appPrefs by lazy {
        PGPonyApp.instance.getSharedPreferences(
            "pgpony_prefs", android.content.Context.MODE_PRIVATE
        )
    }
    // darkvegas interop: passphrase encryption defaults to iterated-salted
    // SHA-256 (S2K type 3) so any gpg on Linux can read it. Argon2id (type 4,
    // needs GnuPG 2.4+ / libgcrypt 1.10+) is opt-in via Settings.
    private val useArgon2Pref: Boolean get() = appPrefs.getBoolean("use_argon2", false)
    // Phase A3: verification service for clear-signed input. Encrypted-
    // and-signed messages still go through PGPCryptoService.decryptArmored
    // (which parses one-pass-signature packets inline); the VerifyService
    // result is then derived from the DecryptResult for banner display.
    private val verify = VerifyService.shared
    // Phase A3: keyserver client used by the unknown-signer lookup flow.
    // Lazy-instantiated because constructing the HTTP client has a small
    // up-front cost we'd rather defer to first use.
    private val keyServer by lazy { KeyServerRepository() }

    private val _encryptState = MutableStateFlow(EncryptUiState())
    val encryptState: StateFlow<EncryptUiState> = _encryptState.asStateFlow()

    private val _decryptState = MutableStateFlow(DecryptUiState())
    val decryptState: StateFlow<DecryptUiState> = _decryptState.asStateFlow()

    // Public rings cached on key load so the card-decrypt NFC lambda can
    // verify embedded one-pass signatures without touching suspend DB calls
    // on the binder thread. Refreshed every loadKeys().
    private var verifyRingsCache: List<org.bouncycastle.openpgp.PGPPublicKeyRing> = emptyList()

    /** Public rings for verifying a card-decrypted message's signature. */
    fun cardVerificationRings(): List<org.bouncycastle.openpgp.PGPPublicKeyRing> = verifyRingsCache

    // One-shot events for UI side effects (haptics, snackbars, etc.).
    // SharedFlow with replay=0 so late subscribers don't re-fire past events.
    private val _events = MutableSharedFlow<Event>(extraBufferCapacity = 4)
    val events: SharedFlow<Event> = _events.asSharedFlow()

    sealed class Event {
        object EncryptSuccess : Event()
        object DecryptSuccess : Event()
        // Phase A2: separate event so the Sign-mode button can fire its
        // own haptic without piggy-backing on EncryptSuccess (different
        // user-perceived action).
        object SignSuccess : Event()
    }

    init {
        loadKeys()
        // 3.1.0 Phase 8 (E5 F-item): sign-by-default. Applied ONCE at
        // creation — the user can still flip the toggle off for a given
        // message without it snapping back (loadKeys re-runs on tab
        // return and must not reassert the preference). encrypt() already
        // guards the signing leg with signingKey != null, so a true here
        // with an empty keyring is inert until a signing key exists.
        if (appPrefs.getBoolean("sign_by_default", false)) {
            _encryptState.value = _encryptState.value.copy(signMessage = true)
        }
    }

    private fun loadKeys() {
        viewModelScope.launch {
            val allKeys = repo.getAllKeys()
            // Cache public rings so the card-decrypt NFC lambda (which runs
            // on a non-suspend binder thread) can verify embedded signatures
            // synchronously.
            //
            // 4.0.4 — this used to run undispatched, with a comment claiming
            // loadPublicKeyRing "reads the in-memory store". It does not: it
            // is an EncryptedSharedPreferences read (Tink AES-GCM per entry)
            // plus a Base64 decode plus a Bouncy Castle parse, once per key.
            // Building this cache therefore walked the ENTIRE keyring on the
            // main thread — at startup, and again after every import or
            // delete, before the user had done anything.
            verifyRingsCache = withContext(Dispatchers.IO) {
                allKeys.mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
            }
            val keyPairs = allKeys.filter { it.isKeyPair }

            // Phase A6 — revoked keys are excluded from the encrypt-side
            // selection pools. Reason: encrypting NEW messages to a
            // revoked recipient or signing NEW messages with a revoked
            // key is exactly what revocation is supposed to prevent.
            // They stay available for decrypt though (see below) — the
            // secret material is intact, just no longer trusted for new
            // operations.
            //
            // HW Phase 1.5 — also exclude card-backed entries that have
            // no public key yet. A freshly-scanned OpenPGP card is stored
            // as identity + fingerprints only (armoredPublicKey == null);
            // there's nothing to encrypt to until the user pairs it with
            // a real public key (import / keyserver / WKD). Offering it as
            // a recipient before then produces a confusing "no encryption
            // methods" failure. Once paired, armoredPublicKey is set and
            // it reappears here automatically. Normal (non-card) keys
            // always have armoredPublicKey, so this only affects unpaired
            // cards.
            val unrevokedRecipients = allKeys.filter {
                !it.isRevoked && (!it.isCardBacked || it.armoredPublicKey != null)
            }
            val unrevokedKeyPairs = keyPairs.filter { !it.isRevoked }

            // HW Phase 2b-step2 — card-backed keys that are paired (have a
            // public key) can sign too: the private key lives on the card,
            // so they're public-only records (isKeyPair == false) but still
            // signable via the NFC card-sign path. Include them in the
            // signing pool after the software key pairs. The UI branches on
            // signingKey.isCardBacked to drive PIN + tap instead of the
            // passphrase/secret-key path.
            val cardSigners = allKeys.filter {
                !it.isRevoked && it.isCardBacked && !it.isKeyPair && it.armoredPublicKey != null
            }
            val signableKeys = unrevokedKeyPairs + cardSigners
            val defaultSignerFpr = appPrefs.getString("pgpony_default_signer_fpr", "") ?: ""
            // §4.5 (#22): resolve the signer once so the subkey-option
            // refresh can tell whether it changed.
            val resolvedSigner = signableKeys.firstOrNull { it.fingerprint == defaultSignerFpr }
                ?: signableKeys.firstOrNull { it.isDefault }
                ?: signableKeys.firstOrNull()
            val signerChanged = resolvedSigner?.fingerprint != _encryptState.value.signingKey?.fingerprint

            // Phase A4 — default/remembered recipient pre-selection. Only seed
            // when nothing is selected yet (loadKeys also runs on tab return,
            // and we must not clobber an in-progress selection). The saved
            // fingerprint is matched against the LIVE recipient pool, so a
            // deleted/stale key simply pre-selects nothing.
            val preselectedRecipients = if (_encryptState.value.selectedRecipients.isEmpty()) {
                DefaultRecipientPrefs.preselectFingerprint(appPrefs)
                    ?.let { fp -> unrevokedRecipients.firstOrNull { it.fingerprint == fp } }
                    ?.let { listOf(it) }
                    ?: emptyList()
            } else {
                _encryptState.value.selectedRecipients
            }

            _encryptState.value = _encryptState.value.copy(
                availableRecipients = unrevokedRecipients,
                availableSigningKeys = signableKeys,
                selectedRecipients = preselectedRecipients,
                // If the currently-selected signing key was just revoked
                // (loadKeys runs on tab return, so this can happen), bump
                // it back to default-or-first to avoid the user signing
                // with a revoked key on autopilot.
                signingKey = resolvedSigner,
                // §4.5 (#22): reset the subkey choice only when the signer
                // actually changed, so a tab-return doesn't clobber a pick.
                selectedSigningKeyId = if (signerChanged) null else _encryptState.value.selectedSigningKeyId,
                signingSubkeyOptions = if (signerChanged) emptyList() else _encryptState.value.signingSubkeyOptions,
                defaultSignerFingerprint = defaultSignerFpr
            )
            if (signerChanged) refreshSigningSubkeyOptions(resolvedSigner)
            // Phase A6 — DECRYPT side keeps revoked keys available.
            // A user can still legitimately decrypt messages that were
            // encrypted to them BEFORE revocation; the private material
            // is unchanged. Stripping them here would lock users out of
            // their own past correspondence.
            // HW — card-backed paired keys can decrypt via PIN + tap (the
            // private key lives on the card). They're public-only records
            // (isKeyPair == false) so the keyPairs filter above misses them;
            // add them to the decrypt pool so the picker offers them when
            // auto-detection doesn't fire and the user picks the card
            // manually. They carry no secret ring, so the software decrypt
            // path harmlessly skips them; selecting one routes to the card
            // PIN+tap flow (see selectDecryptKey).
            val cardDecryptors = allKeys.filter {
                it.isCardBacked && !it.isKeyPair && it.armoredPublicKey != null
            }
            // Phase AU-1 — order the decrypt pool for the "Decrypt With"
            // picker: hardware (card) keys first, then most-used
            // (decryptUseCount desc), then the default key, then name. The top
            // of this order is the pre-selection when no message is loaded;
            // auto-detection overrides it once a message addressed to a
            // specific key is pasted (see detectCardRecipient).
            val orderedKeys = (keyPairs + cardDecryptors).sortedWith(
                compareByDescending<PGPKeyEntity> { it.isCardBacked }
                    .thenByDescending { it.decryptUseCount }
                    .thenByDescending { it.isDefault }
                    .thenBy { it.userName.ifBlank { it.userEmail }.lowercase() }
            )
            _decryptState.value = _decryptState.value.copy(
                availableKeys = orderedKeys,
                selectedKeyFingerprint = _decryptState.value.selectedKeyFingerprint
                    ?: orderedKeys.firstOrNull()?.fingerprint
            )
        }
    }

    // ── Encrypt ────────────────────────────────────────────────────────

    fun updateEncryptInput(text: String) {
        _encryptState.value = _encryptState.value.copy(inputText = text, outputText = "", errorMessage = null)
    }

    fun toggleRecipient(key: PGPKeyEntity) {
        val current = _encryptState.value.selectedRecipients.toMutableList()
        if (current.any { it.fingerprint == key.fingerprint }) {
            current.removeAll { it.fingerprint == key.fingerprint }
        } else {
            current.add(key)
        }
        _encryptState.value = _encryptState.value.copy(selectedRecipients = current)
    }

    // ── A15 preflight fix ──────────────────────────────────────────────
    //
    // Screens.kt references these helpers in the recipient picker row
    // ("Select all" / "Clear" text buttons that appear when the user
    // has more than one key in their ring). Both were added to the UI
    // layer during A13 string extraction but never to the ViewModel.
    fun selectAllRecipients() {
        val all = _encryptState.value.availableRecipients
        _encryptState.value = _encryptState.value.copy(selectedRecipients = all.toList())
    }

    fun clearRecipients() {
        _encryptState.value = _encryptState.value.copy(selectedRecipients = emptyList())
    }

    fun setAsciiArmor(value: Boolean) {
        _encryptState.value = _encryptState.value.copy(asciiArmor = value)
    }

    fun setSigningKey(key: PGPKeyEntity?) {
        _encryptState.value = _encryptState.value.copy(
            signingKey = key,
            selectedSigningKeyId = null,
            signingSubkeyOptions = emptyList()
        )
        refreshSigningSubkeyOptions(key)
    }

    /** §4.5 (#22): choose which signing subkey signs; null = automatic. */
    fun setSigningSubkey(keyId: Long?) {
        _encryptState.value = _encryptState.value.copy(selectedSigningKeyId = keyId)
    }

    /** §4.5 (#22): recompute the signing-subkey choices for [key]. Only
     *  software key pairs have selectable signing subkeys; a card-backed
     *  signer signs on the card, so there is no software subkey choice. */
    private fun refreshSigningSubkeyOptions(key: PGPKeyEntity?) {
        if (key == null || !key.isKeyPair || key.isCardBacked) return
        viewModelScope.launch {
            val options = withContext(Dispatchers.IO) {
                repo.loadSecretKeyRing(key.fingerprint)?.let { crypto.signingKeyOptions(it) } ?: emptyList()
            }
            if (_encryptState.value.signingKey?.fingerprint == key.fingerprint) {
                _encryptState.value = _encryptState.value.copy(signingSubkeyOptions = options)
            }
        }
    }

    /** v4.0.0 (iOS parity) — pin [key] as the default signer, preselected
     *  on every Sign + Encrypt open. Persisted in app prefs. */
    fun setDefaultSigner(key: PGPKeyEntity) {
        appPrefs.edit().putString("pgpony_default_signer_fpr", key.fingerprint).apply()
        val changed = _encryptState.value.signingKey?.fingerprint != key.fingerprint
        _encryptState.value = _encryptState.value.copy(
            defaultSignerFingerprint = key.fingerprint,
            signingKey = key,
            selectedSigningKeyId = if (changed) null else _encryptState.value.selectedSigningKeyId,
            signingSubkeyOptions = if (changed) emptyList() else _encryptState.value.signingSubkeyOptions
        )
        if (changed) refreshSigningSubkeyOptions(key)
    }

    fun setDetachedSignature(enabled: Boolean) {
        _encryptState.value = _encryptState.value.copy(detachedSignature = enabled)
    }

    fun toggleSign(enabled: Boolean) {
        _encryptState.value = _encryptState.value.copy(signMessage = enabled)
    }

    // Phase A2: mode picker + sign-only path
    //
    // Switching modes clears any in-flight result and error, but preserves
    // the input text (users often want to switch Text -> Sign and re-use
    // the same message body) and the selected signing key (a deliberate
    // choice — the user picked it; flipping modes shouldn't reset their
    // selection).

    fun setMode(mode: EncryptMode) {
        _encryptState.value = _encryptState.value.copy(
            mode = mode,
            outputText = "",
            errorMessage = null,
            // RC3 §J (#16): Sign File promoted from a sheet (opened fresh
            // each time via openSignFileSheet) to a tab — reset the same
            // fields on every mode switch instead, and preselect the
            // current signing key the same way the sheet used to on open.
            signFileName = null,
            signFileUri = null,
            signFileSelectedKey = if (mode == EncryptMode.SIGN_FILE)
                _encryptState.value.signingKey
            else
                _encryptState.value.signFileSelectedKey,
            showSignFileKeyPicker = false,
            signFilePassphrase = "",
            signFileResultBytes = null,
            signFileResultName = null,
            signFileProcessing = false
        )
    }

    fun updateSignPassphrase(passphrase: String) {
        _encryptState.value = _encryptState.value.copy(signPassphrase = passphrase)
    }

    fun dismissSignPassphraseDialog() {
        _encryptState.value = _encryptState.value.copy(
            showSignPassphraseDialog = false,
            signPassphrase = ""
        )
    }

    // ── A15 preflight fix ──────────────────────────────────────────────
    //
    // Escape hatch wired into Screens.kt from the sign-passphrase
    // dialog: when the user can't recall the signing-key passphrase
    // (or just doesn't want to sign), they tap "Encrypt without
    // signing" and we proceed with the recipient set, skipping the
    // signing leg. signMessage is flipped off in state and the encrypt
    // is re-dispatched without a passphrase.
    //
    // 4.0.4 — dispatch by mode. This unconditionally called encrypt(),
    // the TEXT-mode entry point, whatever mode the user was actually
    // in. From the Encrypt tab in FILE mode it therefore ran the text
    // encryptor over the (empty) message box instead of the picked
    // file, and the same for BUNDLE. The dialog's primary button has
    // always dispatched by mode; this is the same when-block.
    fun encryptWithoutSigning() {
        _encryptState.value = _encryptState.value.copy(
            signMessage = false,
            showSignPassphraseDialog = false,
            signPassphrase = "",
            errorMessage = null,
        )
        when (_encryptState.value.mode) {
            EncryptMode.FILE -> encryptFile(passphrase = null)
            EncryptMode.BUNDLE -> encryptBundle(passphrase = null)
            // SIGN is signing-only — "without signing" is meaningless
            // there, and Screens.kt hides the button for that mode.
            // PASSWORD never involves a signing key.
            EncryptMode.SIGN, EncryptMode.PASSWORD -> Unit
            // RC3 §J (#16): SIGN_FILE has no encrypt leg either (it's a
            // standalone detached-signature flow) and Screens.kt hides
            // this escape hatch for that mode too.
            EncryptMode.SIGN_FILE -> Unit
            EncryptMode.TEXT -> encrypt(passphrase = null)
        }
    }

    /**
     * Phase A2: produce an RFC 4880 §7 clear-signed message using the
     * currently-selected `signingKey`. Output lands in `outputText` and
     * SignSuccess is emitted for haptics. Errors map to user-friendly
     * messages on `errorMessage`; missing/wrong passphrases route through
     * `showSignPassphraseDialog` so the UI can prompt and retry.
     *
     * If `passphrase` is null and the dialog isn't already showing, we
     * make a first attempt with an empty passphrase — that succeeds for
     * unprotected keys (the common onboarding case) without ever
     * surfacing a prompt.
     */
    // ── HW Phase 2b-step2: card sign result hooks ─────────────────────
    //
    // Card signing needs an NFC tap, which only the Activity can drive, so
    // the UI layer (Screens.kt) runs the PIN + tap + CardSigningService and
    // reports back here. These mirror the success/error tail of signOnly so
    // the output sheet, haptics, and error surface behave identically.

    fun onCardSignStarted() {
        _encryptState.value = _encryptState.value.copy(isProcessing = true, errorMessage = null)
    }

    fun onCardSignSuccess(signed: String) {
        _encryptState.value = _encryptState.value.copy(
            outputText = signed,
            isProcessing = false,
            showEncryptResultSheet = true
        )
        _events.tryEmit(Event.SignSuccess)
    }

    fun onCardSignFailure(message: String) {
        _encryptState.value = _encryptState.value.copy(
            isProcessing = false,
            errorMessage = message
        )
    }

    /**
     * HW Phase 3 — file-mode encrypt-and-sign with a card key. The Encrypt
     * screen runs the NFC op (PGPCryptoService.encrypt with cardSession,
     * armor=false) and reports the encrypted file bytes back here. Mirrors
     * the success tail of encryptFile() (file result sheet).
     */
    /**
     * 4.1.0 Phase 15. The card twin of [encryptBundle]'s crypto half.
     *
     * Deliberately blocking and deliberately not a coroutine: it runs
     * inside an active card session on MainActivity.startCardOperation's
     * worker thread, and the session has to stay open for the whole
     * call because CardPGPContentSigner taps the card at the very end.
     *
     * Unlike the TEXT and FILE card routes, which hand
     * PGPCryptoService.encrypt a whole ByteArray from Screens.kt, this
     * assembles the container to a scratch file and streams it through
     * encryptStream. A bundle is the one card payload that can be tens
     * of megabytes; Phase 14 measured the buffered form of ten 2 MB
     * attachments at about 240 MB of peak allocation, which is why
     * encryptBundle stopped doing it. There is no reason for the card
     * route to reintroduce it.
     *
     * Progress reporting matches encryptBundle. Cancellation does not:
     * ProgressInputStream is given a constant false because an NFC
     * operation in flight is torn down by endCardOperation, not by the
     * progress row's Cancel button.
     */
    fun encryptBundleWithCard(
        session: com.pgpony.android.crypto.card.OpenPgpCardSession,
        pin: ByteArray,
        cardSigningPublicKey: org.bouncycastle.openpgp.PGPPublicKey,
        recipientRings: List<org.bouncycastle.openpgp.PGPPublicKeyRing>
    ): String {
        val s = _encryptState.value
        val payloadBytes = s.bundleAttachments.sumOf { it.size.coerceAtLeast(0L) }
        _encryptState.value = _encryptState.value.copy(
            processedBytes = 0L,
            totalBytes = payloadBytes + payloadBytes * 4 / 3 + 1024
        )
        val mimeFile = ScratchFiles.allocate(
            PGPonyApp.instance, "bundle.mime", ScratchFiles.SCOPE_ENCRYPT
        )
        try {
            mimeFile.outputStream().buffered().use { sink ->
                MimeBuilder.writeMixedSources(
                    out = sink,
                    body = s.bundleBody.takeIf { it.isNotBlank() },
                    sources = s.bundleAttachments.map { it.toMimeSource() }
                ) { done ->
                    _encryptState.value = _encryptState.value.copy(processedBytes = done)
                }
            }
            _encryptState.value = _encryptState.value.copy(
                totalBytes = payloadBytes + mimeFile.length()
            )
            val cipherFile = java.io.File(mimeFile.parentFile, "message.asc")
            try {
                ProgressInputStream(
                    delegate = mimeFile.inputStream(),
                    isCancelled = { false },
                ) { read ->
                    _encryptState.value = _encryptState.value.copy(
                        processedBytes = payloadBytes + read
                    )
                }.use { source ->
                    cipherFile.outputStream().buffered().use { sink ->
                        crypto.encryptStream(
                            input = source,
                            output = sink,
                            recipientPublicKeys = recipientRings,
                            cardSession = session,
                            cardPin = pin,
                            cardSigningPublicKey = cardSigningPublicKey,
                            filename = null,
                            armor = true
                        )
                    }
                }
                return cipherFile.readText(Charsets.UTF_8)
            } finally {
                runCatching { cipherFile.delete() }
            }
        } finally {
            runCatching { mimeFile.delete() }
        }
    }

    /**
     * 4.1.0 Phase 15. Success tail for the Bundle card route, mirroring
     * encryptBundle's. Separate from [onCardSignSuccess] because that
     * one lands in the text output sheet and a bundle lands in the
     * bundle result sheet.
     */
    fun onCardBundleSuccess(armored: String) {
        _encryptState.value = _encryptState.value.copy(
            encryptedBundleArmored = armored,
            isProcessing = false,
            processedBytes = 0L,
            totalBytes = 0L,
            showBundleResultSheet = true
        )
        _events.tryEmit(Event.EncryptSuccess)
    }

    fun onCardEncryptFileSuccess(bytes: ByteArray) {
        _encryptState.value = _encryptState.value.copy(
            encryptedFileBytes = bytes,
            isProcessing = false,
            // 4.0.4 — see encryptFile(): dismiss the sign-passphrase
            // prompt so it can't sit over the result sheet.
            showSignPassphraseDialog = false,
            signPassphrase = "",
            showFileEncryptResultSheet = true
        )
        _events.tryEmit(Event.EncryptSuccess)
    }

    /** True when the no-input guard should block a card sign. */
    fun signInputIsBlank(): Boolean = _encryptState.value.inputText.isBlank()

    fun reportNoSignInput() {
        _encryptState.value = _encryptState.value.copy(
            errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_sign_no_input)
        )
    }

    /**
     * RC3 §N (#34): backwards-compatible signing defaults. Consults the
     * signing_defaults row of the key that would OTHERWISE sign ([base],
     * the user's resolved signingKey) and substitutes per context:
     * sign-only → the sign-without-encrypting picker; encrypting where
     * EVERY recipient is PQC/composite → the PQC picker; ANY classical
     * recipient → the classical picker (a classical recipient is the one
     * who needs the backwards-compatible signature, so mixed recipient
     * sets take the classical choice). Null / missing / non-software
     * picks resolve to [base] — the issue's "defaults to the key whose
     * Key Detail view is open", and no behavior change until configured.
     * Card-backed substitutes are refused because the UI routed
     * card-vs-software BEFORE this resolver runs.
     */
    private suspend fun resolveEffectiveSigner(
        base: PGPKeyEntity,
        recipients: List<PGPKeyEntity>,
        signOnly: Boolean
    ): PGPKeyEntity {
        val row = withContext(Dispatchers.IO) { repo.signingDefaultsFor(base.fingerprint) }
            ?: return base
        val pickedFp = when {
            signOnly -> row.signOnlySignerFingerprint
            recipients.isNotEmpty() && recipients.all { it.algorithm.isComposite } ->
                row.pqcSignerFingerprint
            else -> row.classicalSignerFingerprint
        } ?: return base
        if (pickedFp == base.fingerprint) return base
        val picked = withContext(Dispatchers.IO) { repo.getByFingerprint(pickedFp) }
        return if (picked != null && picked.isKeyPair && !picked.isCardBacked && !picked.isRevoked) {
            picked
        } else {
            base
        }
    }

    fun signOnly(passphrase: String? = null) {
        val s = _encryptState.value
        if (s.inputText.isBlank()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_sign_no_input))
            return
        }
        val signingKey = s.signingKey ?: run {
            _encryptState.value = s.copy(
                errorMessage = "No signing key available. Generate or import a key pair first."
            )
            return
        }

        viewModelScope.launch {
            _encryptState.value = _encryptState.value.copy(
                isProcessing = true,
                errorMessage = null,
                // 4.0.4 — close the passphrase prompt as soon as the
                // work starts, not when it finishes. The unlock has
                // already happened by the time anything slow runs, so
                // leaving the dialog up just hid the progress bar behind
                // a modal for the whole operation — on a large file that
                // is tens of seconds of apparent hang. If the passphrase
                // turns out to be wrong, the catch below puts the dialog
                // straight back with an error, which is the only case
                // where it should reappear.
                showSignPassphraseDialog = false,
            )
            // RC3 §N (#34): sign-without-encrypting default.
            val effectiveSigner = resolveEffectiveSigner(
                base = signingKey, recipients = emptyList(), signOnly = true
            )
            val signFp = effectiveSigner.fingerprint
            // §3 (#15): reuse a cached in-app passphrase when the caller has
            // none, so a second in-app op on the same key does not re-prompt.
            val effPass = passphrase ?: com.pgpony.android.session.InAppPassphraseCache.get(signFp)
            try {
                // 4.4.0 RC3 (#30/#31): a composite ML-DSA + EdDSA key cannot be
                // loaded as a PGPSecretKeyRing, so it signs through the raw-bytes
                // composite path instead of BouncyCastle's SigningService.
                val signed = if (effectiveSigner.algorithm.isCompositeSign) {
                    val info = repo.loadCompositeKeyInfo(signFp)
                        ?: throw SigningError.NoSigningKey()
                    val secret = info.compositeSecret
                        ?: throw SigningError.NoSigningKey()
                    if (s.detachedSignature) {
                        CompositeDocumentSigner.signDetachedArmored(
                            info.suite, secret, info.fingerprint,
                            s.inputText.toByteArray(Charsets.UTF_8)
                        )
                    } else {
                        CompositeDocumentSigner.signCleartext(
                            info.suite, secret, info.fingerprint, s.inputText
                        )
                    }
                } else {
                    val secRing = repo.loadSecretKeyRing(signFp)
                        ?: throw SigningError.NoSigningKey()

                    if (s.detachedSignature) {
                        // Detached: standalone armored signature block over the
                        // UTF-8 bytes of the message (BINARY_DOCUMENT).
                        String(
                            signing.signDetached(
                                data = s.inputText.toByteArray(Charsets.UTF_8),
                                secretKeyRing = secRing,
                                passphrase = effPass,
                                signingKeyId = s.selectedSigningKeyId
                            ),
                            Charsets.UTF_8
                        )
                    } else {
                        signing.signClear(
                            text = s.inputText,
                            secretKeyRing = secRing,
                            passphrase = effPass,
                            signingKeyId = s.selectedSigningKeyId
                        )
                    }
                }

                // §3 (#15): remember the working passphrase for the session
                // (skip unprotected keys, which need none).
                if (!effPass.isNullOrEmpty()) com.pgpony.android.session.InAppPassphraseCache.put(signFp, effPass)
                _encryptState.value = _encryptState.value.copy(
                    outputText = signed,
                    isProcessing = false,
                    showSignPassphraseDialog = false,
                    signPassphrase = "",
                    // Phase A10b: same result-sheet flow as the text
                    // encrypt path. EncryptionResultScreen's title
                    // and badges adapt via the mode field passed
                    // alongside it.
                    showEncryptResultSheet = true
                )
                _events.tryEmit(Event.SignSuccess)
            } catch (e: SigningError.PassphraseRequired) {
                // Surface the passphrase prompt; caller can retry signOnly
                // with the user-entered passphrase via the dialog's
                // confirm action.
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    errorMessage = null
                )
            } catch (e: SigningError.InvalidPassphrase) {
                // §3 (#15): a wrong cached/entered passphrase must not loop.
                com.pgpony.android.session.InAppPassphraseCache.clear(signFp)
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    // Keep the dialog visible so the user can correct the
                    // passphrase without retyping the message.
                    showSignPassphraseDialog = true,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase)
                )
            } catch (e: SigningError) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    errorMessage = e.message
                )
            } catch (e: Exception) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_signing_failed_format, e.message ?: "")
                )
            }
        }
    }

    fun encrypt(passphrase: String? = null) {
        val s = _encryptState.value
        if (s.inputText.isBlank()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_encrypt_no_input))
            return
        }
        if (s.selectedRecipients.isEmpty()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_recipients))
            return
        }
        // Phase A4 — remember the recipient just used (for REMEMBER_LAST mode).
        DefaultRecipientPrefs.recordLastUsed(appPrefs, s.selectedRecipients.firstOrNull()?.fingerprint)
        // HW Phase 3 — encrypt-and-sign with a card key is now supported,
        // but it needs an NFC tap mid-pipeline, so the Encrypt screen
        // routes that case to the card path (PGPCryptoService.encrypt with
        // cardSession set) BEFORE calling encrypt(). This software path is
        // reached only for software signing keys or no signing.

        viewModelScope.launch {
            _encryptState.value = _encryptState.value.copy(
                isProcessing = true,
                errorMessage = null,
                // 4.0.4 — close the passphrase prompt as soon as the
                // work starts, not when it finishes. The unlock has
                // already happened by the time anything slow runs, so
                // leaving the dialog up just hid the progress bar behind
                // a modal for the whole operation — on a large file that
                // is tens of seconds of apparent hang. If the passphrase
                // turns out to be wrong, the catch below puts the dialog
                // straight back with an error, which is the only case
                // where it should reappear.
                showSignPassphraseDialog = false,
            )
            try {
                // 4.0.4 — off the main thread. Only the symmetric and
                // bundle encrypt paths were dispatched; the ordinary
                // recipient encrypt ran its ring loads AND the encryption
                // itself on Dispatchers.Main.
                val recipientRings = withContext(Dispatchers.IO) {
                    s.selectedRecipients.mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
                }
                val signingRing = withContext(Dispatchers.IO) {
                    if (s.signMessage && s.signingKey != null) {
                        // RC3 §N (#34): PQC/classical-recipient default.
                        val effective = resolveEffectiveSigner(
                            base = s.signingKey,
                            recipients = s.selectedRecipients,
                            signOnly = false
                        )
                        repo.loadSecretKeyRing(effective.fingerprint)
                    } else null
                }

                val encrypted = withContext(Dispatchers.Default) {
                    crypto.encrypt(
                        data = s.inputText.toByteArray(Charsets.UTF_8),
                        recipientPublicKeys = recipientRings,
                        signingSecretKey = signingRing,
                        passphrase = passphrase,
                        filename = s.filename,
                        armor = s.asciiArmor,
                        signingKeyId = s.selectedSigningKeyId
                    )
                }
                if (!s.asciiArmor) {
                    // #46: armor toggle off produces binary ciphertext, which
                    // is not displayable text. Route it to the file result
                    // sheet (the save/share surface the file-encrypt path
                    // already uses) instead of forcing raw bytes through
                    // String() into the inline result box, which showed
                    // mojibake and could not round-trip. Save name follows the
                    // C2 convention in FileEncryptionResultScreen
                    // (selectedFileName + ".gpg").
                    _encryptState.value = _encryptState.value.copy(
                        encryptedFileBytes = encrypted,
                        outputText = "",
                        showEncryptResultSheet = false,
                        selectedFileName = s.filename ?: "message",
                        isProcessing = false,
                        showSignPassphraseDialog = false,
                        signPassphrase = "",
                        fileEncryptedWithPassword = false,
                        showFileEncryptResultSheet = true
                    )
                    _events.tryEmit(Event.EncryptSuccess)
                    return@launch
                }
                _encryptState.value = _encryptState.value.copy(
                    outputText = String(encrypted, Charsets.UTF_8),
                    isProcessing = false,
                    // 4.0.4 — dismiss the sign-passphrase prompt on
                    // success. signOnly() was the only mode that did
                    // this; every other one left the AlertDialog on
                    // screen, sitting over the result sheet it had just
                    // opened, so entering a correct passphrase and
                    // pressing Encrypt looked like it did nothing.
                    // Only reachable with a passphrase-protected
                    // signing key, which is why it went unnoticed.
                    showSignPassphraseDialog = false,
                    signPassphrase = "",
                    // Phase A10b: also flip the sheet flag so the
                    // dedicated EncryptionResultScreen renders. Inline
                    // result block in Screens.kt keeps rendering too —
                    // both code paths show the same outputText.
                    // #46: clear any binary file-sheet result from a prior
                    // encrypt so the two result surfaces are never both shown.
                    encryptedFileBytes = null,
                    showFileEncryptResultSheet = false,
                    showEncryptResultSheet = true
                )
                _events.tryEmit(Event.EncryptSuccess)
            } catch (e: SigningError.PassphraseRequired) {
                // Phase A10b Fix1: imported keys (or anything with
                // s2KUsage != 0) need a passphrase to unlock for
                // signing. Surface the existing sign-passphrase
                // dialog instead of the BC-internal "checksum
                // mismatch" wrap. The dialog's confirm button (see
                // Screens.kt) dispatches back to encrypt(passphrase)
                // by reading state.mode == TEXT.
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    signPassphrase = "",
                    errorMessage = null
                )
            } catch (e: SigningError.InvalidPassphrase) {
                // Re-show the dialog with an error message — the
                // dialog body renders state.errorMessage inline so
                // the user doesn't lose their typed passphrase
                // context.
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    signPassphrase = "",
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase_retry)
                )
            } catch (e: Throwable) {
                // 4.0.4 — Throwable, not Exception. A streamed operation
                // can fail with an Error (OutOfMemoryError above all), and
                // an Error escaping this catch left isProcessing true with
                // nothing to clear it: the spinner ran forever, so a
                // failed operation was indistinguishable from a hung one.
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_ENCRYPT)
                // Cancellation is not identifiable by exception type here
                // — encryptStream wraps the cancelling
                // InterruptedIOException in its own error type — but the
                // Job is, and cancelFileOperation() owns the UI reset.
                if (!isActive) return@launch
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    errorMessage = if (e is OutOfMemoryError) {
                        PGPonyApp.instance.getString(R.string.encdec_error_file_too_large)
                    } else {
                        PGPonyApp.instance.getString(R.string.encdec_error_encryption_failed_format, e.message ?: "")
                    }
                )
            }
        }
    }

    // ── Phase A10b: file-mode encrypt actions ──────────────────────────
    //
    // The UI hands bytes (already read from a content:// URI on its
    // side via contentResolver.openInputStream) rather than a URI so
    // we don't have to thread Context through the ViewModel. This
    // does mean the entire file sits in memory during the encrypt
    // round-trip — fine for typical key/document sizes, would need
    // streaming refactor for multi-MB files.

    /**
     * Phase A10b: store the picked input file's metadata and bytes
     * in encrypt state. Called by the UI after the system file
     * picker returns a URI and the bytes have been read from
     * contentResolver. Clears any pending output bytes so a fresh
     * encrypt() runs against the new input.
     */
    fun setFileToEncrypt(name: String, size: Long, bytes: ByteArray) {
        _encryptState.value = _encryptState.value.copy(
            selectedFileName = name,
            selectedFileSize = size,
            selectedFileBytes = bytes,
            selectedFileUri = null,
            encryptedFileBytes = null,
            encryptedFile = null,
            errorMessage = null
        )
    }

    /**
     * 4.0.4 — URI-taking counterpart, mirroring setFileToDecrypt. Small
     * inputs are read here so the buffered path runs unchanged; large
     * ones stay on disk until encryptFile() streams them.
     */
    fun setFileToEncrypt(name: String, size: Long, uri: android.net.Uri) {
        val inline: ByteArray? = if (size <= INLINE_FILE_LIMIT) {
            readAtMost(uri, INLINE_FILE_LIMIT)
        } else {
            null
        }
        _encryptState.value = _encryptState.value.copy(
            selectedFileName = name,
            selectedFileSize = size,
            selectedFileBytes = inline,
            selectedFileUri = if (inline == null) uri else null,
            encryptedFileBytes = null,
            encryptedFile = null,
            errorMessage = null
        )
    }

    /**
     * 4.0.4 — the in-flight streamed file operation, so the user can
     * cancel one. Only ever one at a time: the Encrypt and Decrypt tabs
     * both disable their action button while isProcessing.
     */
    private var fileOpJob: kotlinx.coroutines.Job? = null

    /**
     * 4.0.4 — abandon a running streamed encrypt or decrypt.
     *
     * Cancelling the Job alone would not stop it. The crypto call is a
     * blocking loop that never suspends, so it never hits a cancellation
     * point; ProgressInputStream is what actually breaks the loop, by
     * checking the Job on each chunk and throwing. Cancel here, and the
     * read aborts within one 64 KiB chunk.
     */
    fun cancelFileOperation() {
        fileOpJob?.cancel()
        fileOpJob = null
        ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_ENCRYPT)
        ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_DECRYPT)
        _encryptState.value = _encryptState.value.copy(
            isProcessing = false, processedBytes = 0L, totalBytes = 0L
        )
        _decryptState.value = _decryptState.value.copy(
            isProcessing = false, processedBytes = 0L, totalBytes = 0L
        )
    }

    /**
     * 4.0.4 — shared by both large-file encrypt entry points. Streams
     * the picked URI through PGPCryptoService.encryptStream() into a
     * scratch file. [messagePassword] set means Password mode (SKESK);
     * null means the recipients in [recipientRings].
     *
     * armor = false matches the buffered file path: file mode produces
     * binary .pgp, and armoring a large file would inflate it by a
     * third for no benefit.
     */
    private suspend fun streamEncryptToScratch(
        uri: android.net.Uri,
        outName: String,
        recipientRings: List<org.bouncycastle.openpgp.PGPPublicKeyRing>,
        signingRing: org.bouncycastle.openpgp.PGPSecretKeyRing?,
        signPassphrase: String?,
        literalFilename: String?,
        messagePassword: String?,
        signingKeyId: Long? = null,
        totalBytes: Long
    ): java.io.File = withContext(Dispatchers.IO) {
        val job = coroutineContext[kotlinx.coroutines.Job]
        val out = ScratchFiles.allocate(PGPonyApp.instance, outName, ScratchFiles.SCOPE_ENCRYPT)
        val resolver = PGPonyApp.instance.contentResolver
        val raw = resolver.openInputStream(uri)
            ?: throw java.io.IOException("Could not open the selected file")
        val input = ProgressInputStream(
            delegate = raw,
            isCancelled = { job?.isActive == false },
        ) { read ->
            _encryptState.value = _encryptState.value.copy(processedBytes = read)
        }
        input.use { source ->
            out.outputStream().buffered().use { sink ->
                crypto.encryptStream(
                    input = source,
                    output = sink,
                    recipientPublicKeys = recipientRings,
                    signingSecretKey = signingRing,
                    passphrase = signPassphrase,
                    filename = literalFilename,
                    armor = false,
                    // 4.0.4 — see COMPRESSION_LIMIT. Deflate over a
                    // 105 MB archive costs minutes and saves nothing.
                    enableCompression = totalBytes in 0..COMPRESSION_LIMIT,
                    messagePassword = messagePassword,
                    useArgon2 = useArgon2Pref,
                    signingKeyId = signingKeyId
                )
            }
        }
        out
    }

    /** Phase A10b: clear the picked file. */
    fun clearFile() {
        // 4.0.4 — also drops any streamed ciphertext from cacheDir.
        ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_ENCRYPT)
        _encryptState.value = _encryptState.value.copy(
            selectedFileName = null,
            selectedFileSize = null,
            selectedFileBytes = null,
            selectedFileUri = null,
            encryptedFileBytes = null,
            encryptedFile = null,
            errorMessage = null
        )
    }

    /**
     * Phase A10b: encrypt the currently-selected file. armor=false
     * because file mode produces binary .pgp ciphertext (the iOS app
     * does the same — text mode uses ASCII armor, file mode does
     * not). Recipients and the signing-key/sign-message toggle work
     * the same way as text-mode encrypt.
     */
    fun encryptFile(passphrase: String? = null) {
        val s = _encryptState.value
        // 4.0.4 — one file operation at a time. Nothing stopped a second
        // tap from launching another job: each got its own
        // ProgressInputStream writing to the same processedBytes, so the
        // progress bar jumped between two independent counts, and the
        // losing job's completion could overwrite the winner's result.
        if (fileOpJob?.isActive == true) return
        val bytes = s.selectedFileBytes
        val srcUri = s.selectedFileUri
        if (bytes == null && srcUri == null) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_file_to_encrypt))
            return
        }
        if (s.selectedRecipients.isEmpty()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_recipients))
            return
        }
        // Phase A4 — remember the recipient just used (for REMEMBER_LAST mode).
        DefaultRecipientPrefs.recordLastUsed(appPrefs, s.selectedRecipients.firstOrNull()?.fingerprint)
        // HW Phase 3 — file encrypt-and-sign with a card key is routed to
        // the card path by the Encrypt screen (PGPCryptoService.encrypt with
        // cardSession set, armor=false) before encryptFile() is called. This
        // software path handles software signing keys or no signing.
        fileOpJob = viewModelScope.launch {
            _encryptState.value = _encryptState.value.copy(
                isProcessing = true,
                errorMessage = null,
                processedBytes = 0L,
                totalBytes = if (srcUri != null) (s.selectedFileSize ?: 0L) else 0L,
                // 4.0.4 — close the passphrase prompt as soon as the
                // work starts, not when it finishes. The unlock has
                // already happened by the time anything slow runs, so
                // leaving the dialog up just hid the progress bar behind
                // a modal for the whole operation — on a large file that
                // is tens of seconds of apparent hang. If the passphrase
                // turns out to be wrong, the catch below puts the dialog
                // straight back with an error, which is the only case
                // where it should reappear.
                showSignPassphraseDialog = false,
            )
            try {
                // 4.0.4 — off the main thread; see encryptText above. File
                // encrypt is the worse of the two, because the payload is
                // whatever the user picked rather than a text box.
                val recipientRings = withContext(Dispatchers.IO) {
                    s.selectedRecipients.mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
                }
                val signingRing = withContext(Dispatchers.IO) {
                    if (s.signMessage && s.signingKey != null) {
                        // RC3 §N (#34): PQC/classical-recipient default.
                        val effective = resolveEffectiveSigner(
                            base = s.signingKey,
                            recipients = s.selectedRecipients,
                            signOnly = false
                        )
                        repo.loadSecretKeyRing(effective.fingerprint)
                    } else null
                }

                // 4.0.4 — buffered below INLINE_FILE_LIMIT (unchanged),
                // streamed above it (issue #6).
                val encrypted = if (bytes != null) {
                    withContext(Dispatchers.Default) {
                        crypto.encrypt(
                            data = bytes,
                            recipientPublicKeys = recipientRings,
                            signingSecretKey = signingRing,
                            passphrase = passphrase,
                            filename = s.selectedFileName,
                            armor = false,
                            signingKeyId = s.selectedSigningKeyId
                        )
                    }
                } else null
                val streamedOut = if (bytes == null) {
                    streamEncryptToScratch(
                        uri = srcUri!!,
                        outName = "${s.selectedFileName ?: "file"}.gpg",
                        recipientRings = recipientRings,
                        signingRing = signingRing,
                        signPassphrase = passphrase,
                        literalFilename = s.selectedFileName,
                        messagePassword = null,
                        signingKeyId = s.selectedSigningKeyId,
                        totalBytes = s.selectedFileSize ?: 0L
                    )
                } else null
                _encryptState.value = _encryptState.value.copy(
                    encryptedFileBytes = encrypted,
                    encryptedFile = streamedOut,
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    // 4.0.4 — dismiss the sign-passphrase prompt on
                    // success. signOnly() was the only mode that did
                    // this; every other one left the AlertDialog on
                    // screen, sitting over the result sheet it had just
                    // opened, so entering a correct passphrase and
                    // pressing Encrypt looked like it did nothing.
                    // Only reachable with a passphrase-protected
                    // signing key, which is why it went unnoticed.
                    showSignPassphraseDialog = false,
                    signPassphrase = "",
                    // 3.1.0 Phase 2 (C4): recipient encrypt resets the
                    // password badge on the result sheet.
                    fileEncryptedWithPassword = false,
                    showFileEncryptResultSheet = true
                )
                _events.tryEmit(Event.EncryptSuccess)
            } catch (e: SigningError.PassphraseRequired) {
                // Phase A10b Fix1: same passphrase-prompt routing as
                // text-mode encrypt. Dialog confirm in Screens.kt
                // dispatches back to encryptFile(passphrase) by
                // reading state.mode == FILE.
                //
                // 4.0.4 — say something when this is a RETRY. The first
                // attempt passes no passphrase, so landing here is
                // expected and the bare prompt is right. Arriving here
                // again after the user typed one meant the field simply
                // blanked with no message: the button looked dead.
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    showSignPassphraseDialog = true,
                    signPassphrase = "",
                    errorMessage = if (passphrase.isNullOrEmpty()) null else {
                        PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase_retry)
                    }
                )
            } catch (e: SigningError.InvalidPassphrase) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    signPassphrase = "",
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase_retry)
                )
            } catch (e: Throwable) {
                // 4.0.4 — Throwable, not Exception. A streamed operation
                // can fail with an Error (OutOfMemoryError above all), and
                // an Error escaping this catch left isProcessing true with
                // nothing to clear it: the spinner ran forever, so a
                // failed operation was indistinguishable from a hung one.
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_ENCRYPT)
                // Cancellation is not identifiable by exception type here
                // — encryptStream wraps the cancelling
                // InterruptedIOException in its own error type — but the
                // Job is, and cancelFileOperation() owns the UI reset.
                if (!isActive) return@launch
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    errorMessage = if (e is OutOfMemoryError) {
                        PGPonyApp.instance.getString(R.string.encdec_error_file_too_large)
                    } else {
                        PGPonyApp.instance.getString(R.string.encdec_error_encryption_failed_format, e.message ?: "")
                    }
                )
            }
        }
    }

    // ── Phase A1: symmetric / passphrase-only (Password) mode ──────────

    fun updatePasswordPassphrase(pp: String) {
        _encryptState.value = _encryptState.value.copy(passwordPassphrase = pp, errorMessage = null)
    }

    fun updatePasswordConfirm(pp: String) {
        _encryptState.value = _encryptState.value.copy(passwordConfirm = pp, errorMessage = null)
    }

    fun togglePasswordVisible() {
        _encryptState.value = _encryptState.value.copy(passwordVisible = !_encryptState.value.passwordVisible)
    }

    /**
     * Phase A1: encrypt the text input to a passphrase only (`gpg -c`),
     * with no recipient keypair. Validates non-empty input, a non-empty
     * passphrase, and that the confirm field matches. On success the
     * armored ciphertext lands in outputText (same surface as text-mode
     * encrypt) and the passphrase fields are cleared. Symmetric + file is
     * a planned fast-follow; this v1 covers the text input.
     */
    fun encryptWithPassword() {
        val s = _encryptState.value
        if (s.inputText.isBlank()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_encrypt_no_input))
            return
        }
        if (s.passwordPassphrase.isEmpty()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_password_required))
            return
        }
        if (s.passwordPassphrase != s.passwordConfirm) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_password_mismatch))
            return
        }

        viewModelScope.launch {
            _encryptState.value = _encryptState.value.copy(isProcessing = true, errorMessage = null)
            try {
                val encrypted = crypto.encryptSymmetricMessage(
                    message = s.inputText,
                    passphrase = s.passwordPassphrase,
                    useArgon2 = useArgon2Pref
                )
                _encryptState.value = _encryptState.value.copy(
                    outputText = encrypted,
                    isProcessing = false,
                    // Clear the secret from state once it has done its job.
                    passwordPassphrase = "",
                    passwordConfirm = "",
                    passwordVisible = false,
                    showEncryptResultSheet = true
                )
                _events.tryEmit(Event.EncryptSuccess)
            } catch (e: Throwable) {
                // 4.0.4 — Throwable, not Exception. A streamed operation
                // can fail with an Error (OutOfMemoryError above all), and
                // an Error escaping this catch left isProcessing true with
                // nothing to clear it: the spinner ran forever, so a
                // failed operation was indistinguishable from a hung one.
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_ENCRYPT)
                // Cancellation is not identifiable by exception type here
                // — encryptStream wraps the cancelling
                // InterruptedIOException in its own error type — but the
                // Job is, and cancelFileOperation() owns the UI reset.
                if (!isActive) return@launch
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    errorMessage = if (e is OutOfMemoryError) {
                        PGPonyApp.instance.getString(R.string.encdec_error_file_too_large)
                    } else {
                        PGPonyApp.instance.getString(R.string.encdec_error_encryption_failed_format, e.message ?: "")
                    }
                )
            }
        }
    }

    // ── 3.1.0 Phase 2 (C4): file-mode password encryption ──────────────

    /** Switch the File flow between recipient and password encryption. */
    fun setFileEncryptMethod(m: FileEncryptMethod) {
        _encryptState.value = _encryptState.value.copy(
            fileEncryptMethod = m,
            errorMessage = null
        )
    }

    /**
     * 3.1.0 Phase 2 (C4, origin Wenzel): encrypt the picked file to a
     * passphrase only (`gpg -c`), producing a binary .gpg. Mirrors iOS
     * FileEncryptMethod.password: keyless — no recipients, no signing,
     * no hardware-key path. Validates a picked file, a non-empty
     * passphrase, and a matching confirm; on success the ciphertext
     * lands in encryptedFileBytes (same surface as recipient file
     * encrypt, so the C2 .gpg naming and the save/share flows are
     * reused) and the passphrase fields are cleared. The symmetric
     * core (SEIPDv1 + Argon2id S2K by default) already shipped in
     * Phase A1; this is the missing encrypt-side entry point.
     */
    fun encryptFileWithPassword() {
        val s = _encryptState.value
        // 4.0.4 — see encryptFile(): one file operation at a time.
        if (fileOpJob?.isActive == true) return
        val bytes = s.selectedFileBytes
        val srcUri = s.selectedFileUri
        if (bytes == null && srcUri == null) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_file_to_encrypt))
            return
        }
        if (s.passwordPassphrase.isEmpty()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_password_required))
            return
        }
        if (s.passwordPassphrase != s.passwordConfirm) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_password_mismatch))
            return
        }

        viewModelScope.launch {
            _encryptState.value = _encryptState.value.copy(
                isProcessing = true,
                errorMessage = null,
                processedBytes = 0L,
                totalBytes = if (srcUri != null) (s.selectedFileSize ?: 0L) else 0L,
            )
            try {
                // Off the main thread: Argon2id key derivation (64 MiB,
                // 3 passes) takes real time by design.
                // 4.0.4 — buffered below INLINE_FILE_LIMIT, streamed above.
                // encryptStream's messagePassword uses the same Argon2id S2K
                // parameters as encryptSymmetric, so the two produce
                // interchangeable output.
                val encrypted = if (bytes != null) {
                    withContext(Dispatchers.Default) {
                        crypto.encryptSymmetric(
                            data = bytes,
                            passphrase = s.passwordPassphrase,
                            filename = s.selectedFileName,
                            armor = false,
                            useArgon2 = useArgon2Pref
                        )
                    }
                } else null
                val streamedOut = if (bytes == null) {
                    streamEncryptToScratch(
                        uri = srcUri!!,
                        outName = "${s.selectedFileName ?: "file"}.gpg",
                        recipientRings = emptyList(),
                        signingRing = null,
                        signPassphrase = null,
                        literalFilename = s.selectedFileName,
                        messagePassword = s.passwordPassphrase,
                        totalBytes = s.selectedFileSize ?: 0L
                    )
                } else null
                _encryptState.value = _encryptState.value.copy(
                    encryptedFileBytes = encrypted,
                    encryptedFile = streamedOut,
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    fileEncryptedWithPassword = true,
                    // Clear the secret from state once it has done its job.
                    passwordPassphrase = "",
                    passwordConfirm = "",
                    passwordVisible = false,
                    showFileEncryptResultSheet = true
                )
                _events.tryEmit(Event.EncryptSuccess)
            } catch (e: Throwable) {
                // 4.0.4 — Throwable, not Exception. A streamed operation
                // can fail with an Error (OutOfMemoryError above all), and
                // an Error escaping this catch left isProcessing true with
                // nothing to clear it: the spinner ran forever, so a
                // failed operation was indistinguishable from a hung one.
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_ENCRYPT)
                // Cancellation is not identifiable by exception type here
                // — encryptStream wraps the cancelling
                // InterruptedIOException in its own error type — but the
                // Job is, and cancelFileOperation() owns the UI reset.
                if (!isActive) return@launch
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    errorMessage = if (e is OutOfMemoryError) {
                        PGPonyApp.instance.getString(R.string.encdec_error_file_too_large)
                    } else {
                        PGPonyApp.instance.getString(R.string.encdec_error_encryption_failed_format, e.message ?: "")
                    }
                )
            }
        }
    }

    /**
     * Phase A10b: dismiss the text/sign result sheet. The outputText
     * in state stays so the inline result block in Screens.kt keeps
     * showing it after dismissal — the sheet is a one-shot "you just
     * encrypted something" celebration, not the authoritative copy
     * surface.
     *
     * 3.1.0 Phase 5 (privacy, iOS 7.1.x parity): closing any encrypt
     * result now clears the inputs — message text, picked file, bundle
     * body and attachments — so nothing lingers between sessions.
     */
    fun dismissEncryptResult() {
        _encryptState.value = _encryptState.value.copy(
            showEncryptResultSheet = false
        )
        clearEncryptInputsIfEnabled()
    }

    // ── 3.1.0 Phase 5 (J3/J4): Bundle compose ──────────────────────────

    fun updateBundleBody(text: String) {
        _encryptState.value = _encryptState.value.copy(bundleBody = text, errorMessage = null)
    }

    /**
     * 4.1.0 Phase 14 (issue #12, AraafRoyall): "if i click add photos
     * again to add more it add the same files again".
     *
     * The append was unconditional. Android's photo picker does not
     * remember a previous selection, so a user who reopens it to add one
     * more file has to reselect the ones already staged, and every one of
     * them landed a second time. Nothing in the compose flow removed
     * them, so the list, the encrypt payload and the recipient's bundle
     * all carried the duplicates.
     *
     * Name plus size is the key. The source URI would be sharper, but it
     * would have to be carried on MimeAttachment, which is a transport
     * model shared with the parser and the share path and has no business
     * knowing about content:// URIs. Two genuinely different files with
     * the same name AND the same byte count in one bundle is not a case
     * worth widening that type for.
     */
    fun addBundleAttachment(filename: String, contentType: String, bytes: ByteArray) {
        val existing = _encryptState.value.bundleAttachments
        if (existing.any { it.filename == filename && it.size == bytes.size.toLong() }) return
        _encryptState.value = _encryptState.value.copy(
            bundleAttachments = existing + BundleAttachmentRef(
                filename, contentType, bytes.size.toLong(), data = bytes
            ),
            errorMessage = null
        )
    }

    /**
     * 4.2.0 RC6 (#32): the streaming counterpart — store the pick as a
     * uri + metadata and never read it here. The SAF read grant from
     * the picker lasts for the process lifetime, which covers the
     * encrypt that streams it later; an unreadable uri (revoked grant,
     * removed cloud file) surfaces as an encrypt error rather than a
     * silent skip.
     */
    fun addBundleAttachmentRef(
        filename: String,
        contentType: String,
        size: Long,
        uri: android.net.Uri
    ) {
        val existing = _encryptState.value.bundleAttachments
        if (existing.any { it.filename == filename && it.size == size }) return
        _encryptState.value = _encryptState.value.copy(
            bundleAttachments = existing + BundleAttachmentRef(
                filename, contentType, size, uri = uri
            ),
            errorMessage = null
        )
    }

    /**
     * 3.1.0 Phase 6 (J5): seed the Bundle compose from a multi-file
     * share. REPLACES any prior bundle contents (a share is a fresh
     * intent, not an append to a draft) and switches to BUNDLE mode.
     */
    fun startBundleFromShare(attachments: List<MimeAttachment>) {
        _encryptState.value = _encryptState.value.copy(
            mode = EncryptMode.BUNDLE,
            bundleBody = "",
            bundleAttachments = attachments.map {
                BundleAttachmentRef(
                    it.filename, it.contentType, it.data.size.toLong(), data = it.data
                )
            },
            outputText = "",
            errorMessage = null
        )
    }

    fun removeBundleAttachment(index: Int) {
        val current = _encryptState.value.bundleAttachments
        if (index !in current.indices) return
        _encryptState.value = _encryptState.value.copy(
            bundleAttachments = current.filterIndexed { i, _ -> i != index }
        )
    }

    /**
     * 3.1.0 Phase 5 (J3): encrypt the composed Bundle. Assembles
     * `multipart/mixed` with MimeBuilder, encrypts to the selected
     * recipients (optional SOFTWARE signing; the card path is
     * deliberately out of Bundle v1 — an NFC tap mid-compose adds
     * failure modes the feature doesn't need yet), and lands the
     * armored result for the J4 output sheet (.eml / .asc / inline).
     */
    fun encryptBundle(passphrase: String? = null) {
        val s = _encryptState.value
        // 4.1.0 Phase 14: one file operation at a time, same rule the
        // file paths have had since 4.0.4. Bundle encrypt was the last
        // long running operation still launching a bare coroutine: a
        // second tap started a second encrypt writing to the same
        // progress fields, and the Cancel button under the progress row
        // had no job to cancel.
        if (fileOpJob?.isActive == true) return
        if (s.selectedRecipients.isEmpty()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_recipients))
            return
        }
        if (s.bundleBody.isBlank() && s.bundleAttachments.isEmpty()) {
            _encryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_bundle_empty))
            return
        }
        DefaultRecipientPrefs.recordLastUsed(appPrefs, s.selectedRecipients.firstOrNull()?.fingerprint)
        // 4.1.0 Phase 14 (issue #12): "no progress bar showing while
        // encrypting". Correct. encryptBundle set isProcessing and never
        // touched processedBytes or totalBytes, so the UI had nothing to
        // draw but an indeterminate spinner, while the single file path
        // got a real byte counter with Cancel in 4.0.4.
        //
        // Two passes cross the payload: assemble the container, then
        // encrypt it. Counting both means the bar advances the whole way
        // instead of filling halfway and then appearing to hang. The
        // second pass reads the assembled container, which is about four
        // thirds of the input after base64, so the total is an estimate
        // until the assembly finishes and it is corrected to the exact
        // figure below.
        val payloadBytes = s.bundleAttachments.sumOf { it.size.coerceAtLeast(0L) }
        fileOpJob = viewModelScope.launch {
            _encryptState.value = _encryptState.value.copy(
                isProcessing = true,
                errorMessage = null,
                processedBytes = 0L,
                totalBytes = payloadBytes + payloadBytes * 4 / 3 + 1024,
                // 4.0.4 — close the passphrase prompt as soon as the
                // work starts, not when it finishes. The unlock has
                // already happened by the time anything slow runs, so
                // leaving the dialog up just hid the progress bar behind
                // a modal for the whole operation — on a large file that
                // is tens of seconds of apparent hang. If the passphrase
                // turns out to be wrong, the catch below puts the dialog
                // straight back with an error, which is the only case
                // where it should reappear.
                showSignPassphraseDialog = false,
            )
            try {
                // 4.0.4 — the crypto below was already on Dispatchers.Default,
                // but the ring loads feeding it were not.
                val recipientRings = withContext(Dispatchers.IO) {
                    s.selectedRecipients.mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
                }
                val signingRing = withContext(Dispatchers.IO) {
                    if (
                        s.signMessage && s.signingKey != null && s.signingKey.isCardBacked != true
                    ) {
                        // RC3 §N (#34): PQC/classical-recipient default.
                        val effective = resolveEffectiveSigner(
                            base = s.signingKey,
                            recipients = s.selectedRecipients,
                            signOnly = false
                        )
                        repo.loadSecretKeyRing(effective.fingerprint)
                    } else null
                }

                // 4.1.0 Phase 14c. The ring load above returns null if
                // loadSecretKeyRing fails for any other reason too. Either
                // way, carrying on produced an unsigned bundle while the
                // toggle on the compose screen said "Also sign this file".
                // The sender is told it was signed and the recipient is
                // told it was not, which is the worst pair of outcomes a
                // crypto app can hand you, and it is precisely the failure
                // AraafRoyall's screenshots were suspected of showing.
                // Refuse loudly instead.
                if (s.signMessage && s.signingKey != null && signingRing == null) {
                    _encryptState.value = _encryptState.value.copy(
                        isProcessing = false,
                        processedBytes = 0L,
                        totalBytes = 0L,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.encdec_error_bundle_signing_key
                        )
                    )
                    return@launch
                }

                // 4.1.0 Phase 14 (issue #12): "please try to encrypt 10+
                // files of 2mb+ each file and test yourself".
                //
                // Measured on that exact input, the old line below peaked
                // at about 240 MB of transient allocation before the
                // encrypt had even started. buildMixed assembled the whole
                // container in a StringBuilder: base64 expands the payload
                // by a third, a StringBuilder holds it as UTF-16 at two
                // bytes per character, growing it copies, toString copies
                // again and toByteArray once more. Then crypto.encrypt
                // took the result as a ByteArray and accumulated the
                // armored output in a ByteArrayOutputStream on top.
                //
                // Assembling straight to a scratch file and streaming that
                // through encryptStream holds the same input at about
                // 39 MB, and it is what makes the byte progress above
                // real rather than synthetic.
                val armoredOut = withContext(Dispatchers.IO) {
                    val job = coroutineContext[kotlinx.coroutines.Job]
                    val mimeFile = ScratchFiles.allocate(
                        PGPonyApp.instance, "bundle.mime", ScratchFiles.SCOPE_ENCRYPT
                    )
                    mimeFile.outputStream().buffered().use { sink ->
                        MimeBuilder.writeMixedSources(
                            out = sink,
                            body = s.bundleBody.takeIf { it.isNotBlank() },
                            sources = s.bundleAttachments.map { it.toMimeSource() }
                        ) { done ->
                            if (job?.isActive == false) {
                                throw java.io.InterruptedIOException("cancelled")
                            }
                            _encryptState.value =
                                _encryptState.value.copy(processedBytes = done)
                        }
                    }
                    // Assembly done: the estimate can now be replaced with
                    // the figure the second pass will actually count to.
                    _encryptState.value = _encryptState.value.copy(
                        totalBytes = payloadBytes + mimeFile.length()
                    )
                    val cipherFile = java.io.File(mimeFile.parentFile, "message.asc")
                    val input = ProgressInputStream(
                        delegate = mimeFile.inputStream(),
                        isCancelled = { job?.isActive == false },
                    ) { read ->
                        _encryptState.value = _encryptState.value.copy(
                            processedBytes = payloadBytes + read
                        )
                    }
                    input.use { source ->
                        cipherFile.outputStream().buffered().use { sink ->
                            crypto.encryptStream(
                                input = source,
                                output = sink,
                                recipientPublicKeys = recipientRings,
                                signingSecretKey = signingRing,
                                passphrase = passphrase,
                                filename = null,
                                armor = true,
                                signingKeyId = s.selectedSigningKeyId
                            )
                        }
                    }
                    // The container is plaintext and its job is done.
                    runCatching { mimeFile.delete() }
                    // 4.2.0 RC6 (#32, tail): only inline a result the
                    // heap can afford; larger ones stay on disk for the
                    // sheet to stream. The readText() below on a 1.4 GB
                    // armored file was the OOM behind "file is too
                    // large" after a successful streamed encrypt.
                    if (cipherFile.length() <= BUNDLE_RESULT_INLINE_LIMIT) {
                        val text = cipherFile.readText(Charsets.UTF_8)
                        runCatching { cipherFile.delete() }
                        Pair(text, null)
                    } else {
                        Pair(null, cipherFile)
                    }
                }
                _encryptState.value = _encryptState.value.copy(
                    encryptedBundleArmored = armoredOut.first,
                    encryptedBundleFile = armoredOut.second,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    isProcessing = false,
                    // 4.0.4 — dismiss the sign-passphrase prompt on
                    // success. signOnly() was the only mode that did
                    // this; every other one left the AlertDialog on
                    // screen, sitting over the result sheet it had just
                    // opened, so entering a correct passphrase and
                    // pressing Encrypt looked like it did nothing.
                    // Only reachable with a passphrase-protected
                    // signing key, which is why it went unnoticed.
                    showSignPassphraseDialog = false,
                    signPassphrase = "",
                    showBundleResultSheet = true
                )
                _events.tryEmit(Event.EncryptSuccess)
            } catch (e: SigningError.PassphraseRequired) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    signPassphrase = "",
                    errorMessage = null
                )
            } catch (e: SigningError.InvalidPassphrase) {
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    showSignPassphraseDialog = true,
                    signPassphrase = "",
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase_retry)
                )
            } catch (e: Throwable) {
                // 4.0.4 — Throwable, not Exception. A streamed operation
                // can fail with an Error (OutOfMemoryError above all), and
                // an Error escaping this catch left isProcessing true with
                // nothing to clear it: the spinner ran forever, so a
                // failed operation was indistinguishable from a hung one.
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_ENCRYPT)
                // Cancellation is not identifiable by exception type here
                // — encryptStream wraps the cancelling
                // InterruptedIOException in its own error type — but the
                // Job is, and cancelFileOperation() owns the UI reset.
                if (!isActive) return@launch
                _encryptState.value = _encryptState.value.copy(
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    errorMessage = if (e is OutOfMemoryError) {
                        PGPonyApp.instance.getString(R.string.encdec_error_file_too_large)
                    } else {
                        PGPonyApp.instance.getString(R.string.encdec_error_encryption_failed_format, e.message ?: "")
                    }
                )
            }
        }
    }

    /** 3.1.0 Phase 5 (J4): dismiss the Bundle result. Clears the armored
     *  output and, per the privacy behavior, the composed inputs. */
    fun dismissBundleResult() {
        // 4.2.0 RC6 (#32, tail): a file-backed result is scratch — gone
        // with the sheet.
        _encryptState.value.encryptedBundleFile?.let { runCatching { it.delete() } }
        _encryptState.value = _encryptState.value.copy(
            showBundleResultSheet = false,
            encryptedBundleArmored = null,
            encryptedBundleFile = null
        )
        clearEncryptInputsIfEnabled()
    }

    /**
     * 4.0.0 Phase 9b (iOS v7.1.1 parity) — the auto-wipe is now a user
     * setting ("Clear inputs after encrypting", Settings → Security).
     * Default ON preserves the 3.1.0 Phase 5 always-on behavior every
     * existing install has today; iOS gained the same toggle in 7.1.1.
     * Read live from prefs at each dismissal so a Settings change
     * applies to the very next result close, no restart.
     */
    private fun clearEncryptInputsIfEnabled() {
        if (appPrefs.getBoolean("clear_inputs_after_encrypt", true)) {
            clearEncryptInputsForPrivacy()
        }
    }

    /**
     * 3.1.0 Phase 5 (privacy, iOS 7.1.x parity): "the Encrypt screen now
     * clears your message, files, and attachments automatically after
     * you close the result, so nothing lingers between sessions." One
     * place, called from every encrypt-result dismissal.
     * 4.0.0 Phase 9b: dismissals route through
     * [clearEncryptInputsIfEnabled] so the wipe honors the new setting.
     */
    private fun clearEncryptInputsForPrivacy() {
        // 4.0.4 — a streamed ciphertext is an input artefact too.
        ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_ENCRYPT)
        _encryptState.value = _encryptState.value.copy(
            inputText = "",
            outputText = "",
            selectedFileName = null,
            selectedFileSize = null,
            selectedFileBytes = null,
            selectedFileUri = null,
            encryptedFile = null,
            bundleBody = "",
            bundleAttachments = emptyList(),
            passwordPassphrase = "",
            passwordConfirm = "",
            passwordVisible = false
        )
    }

    /**
     * Phase A10b: dismiss the file-mode result sheet. Unlike the
     * text-mode dismissal we clear the encrypted bytes — there's no
     * inline display of binary output, so once the sheet closes the
     * user has either saved/shared the ciphertext or they haven't.
     */
    fun dismissFileEncryptResult() {
        // 4.0.4 — the streaming path put the ciphertext on disk.
        ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_ENCRYPT)
        _encryptState.value = _encryptState.value.copy(
            showFileEncryptResultSheet = false,
            encryptedFileBytes = null,
            encryptedFile = null
        )
        // 3.1.0 Phase 5 (privacy): see clearEncryptInputsForPrivacy.
        // 4.0.0 Phase 9b: honors the "Clear inputs after encrypting" setting.
        clearEncryptInputsIfEnabled()
    }

    // ── Decrypt ────────────────────────────────────────────────────────

    fun updateDecryptInput(text: String) {
        _decryptState.value = _decryptState.value.copy(
            inputText = text, outputText = "", outputData = null,
            errorMessage = null, signatureVerified = false,
            // Phase A3: clear any stale verification result when input changes
            verificationResult = null
        )
        detectCardRecipient(text)
    }

    /**
     * HW Phase 3 — decide whether [text] is encrypted to a card-backed key
     * so the Decrypt tab can swap the passphrase field for a PIN + tap
     * flow. Cheap: reads the message's recipient key IDs (no decryption)
     * and checks them against the encryption subkeys of card-backed keys
     * in the ring. Runs only once a full PGP MESSAGE block is present, and
     * guards against races by re-checking the input hasn't changed before
     * publishing the result.
     */
    private fun detectCardRecipient(text: String) {
        if (!text.contains("BEGIN PGP MESSAGE")) {
            val cur = _decryptState.value
            if (cur.isCardMessage || cur.cardMessageKeyFingerprint != null ||
                cur.isPasswordMessage || cur.isHiddenRecipientMessage
            ) {
                _decryptState.value = cur.copy(
                    isCardMessage = false,
                    cardMessageKeyFingerprint = null,
                    cardMessageKeyName = null,
                    isPasswordMessage = false,
                    isHiddenRecipientMessage = false,
                    hiddenRecipientCardFingerprint = null,
                    hiddenRecipientCardName = null
                )
            }
            return
        }
        viewModelScope.launch {
            // Snapshot the picker's software keys here, on the main thread,
            // so the detection below never reads live UI state off-dispatcher.
            val softwareCandidates = _decryptState.value.availableKeys
                .filter { !it.isCardBacked }

            // 4.1.0, issue #10 (AraafRoyall) — OFF THE MAIN THREAD.
            //
            // This is reached from updateDecryptInput, so it runs every time
            // the decrypt box changes. Every ring load inside it is a blocking
            // EncryptedSharedPreferences read (Tink AES-GCM per entry) plus a
            // Bouncy Castle parse — KeyRepository.loadPublicKeyRing is a plain
            // fun, not a suspend one. On a keyring of any size that is dozens
            // of decrypt-and-parse round trips on Dispatchers.Main.immediate
            // before the pasted text can render. That is the lag in the report.
            //
            // 4.0.4 moved the decrypt paths off the main thread and its own
            // note says the remaining ones "were missed": the streaming file
            // detector was fixed, the text and byte detectors were not.
            val d = withContext(Dispatchers.IO) {
                detectCardRecipientBlocking(text, softwareCandidates)
            }
            val cardMatch = d.cardMatch
            val softwareMatchFp = d.softwareMatchFp
            val isPassword = d.isPassword
            val hidden = d.hidden

            // Only publish if the input still matches what we inspected.
            if (_decryptState.value.inputText == text) {
                val match = cardMatch
                val hiddenFallback = d.hiddenCard
                _decryptState.value = _decryptState.value.copy(
                    isCardMessage = match != null,
                    cardMessageKeyFingerprint = match?.fingerprint,
                    cardMessageKeyName = match?.let { it.userName.ifBlank { it.userEmail } },
                    // 4.1.0 — armed, not fired. See [offerCardForHiddenRecipient].
                    isHiddenRecipientMessage = hidden,
                    hiddenRecipientCardFingerprint = hiddenFallback?.fingerprint,
                    hiddenRecipientCardName = hiddenFallback
                        ?.let { it.userName.ifBlank { it.userEmail } },
                    // Phase A1: a password-encrypted message has no recipient,
                    // so this is independent of card/software matching.
                    isPasswordMessage = isPassword,
                    // Snap the picker selection: a card recipient → its
                    // fingerprint; else a software recipient when found; else
                    // leave the existing (most-used default) selection.
                    selectedKeyFingerprint = match?.fingerprint
                        ?: softwareMatchFp
                        ?: _decryptState.value.selectedKeyFingerprint
                )
            }
        }
    }

    /** What [detectCardRecipient] resolves. See its dispatcher note. */
    private data class CardDetection(
        val cardMatch: PGPKeyEntity? = null,
        val softwareMatchFp: String? = null,
        val isPassword: Boolean = false,
        val hidden: Boolean = false,
        val hiddenCard: PGPKeyEntity? = null
    )

    /**
     * 4.1.0, issue #10 — the blocking half of [detectCardRecipient], split out
     * so it can be handed to Dispatchers.IO whole.
     *
     * Everything here either parses packets or loads a key ring, and a ring
     * load costs a Tink-decrypted preferences read plus a BouncyCastle parse.
     * Nothing in it touches UI state: [softwareCandidates] is passed in,
     * already snapshotted on the main thread.
     *
     * Ring loads are also now skipped entirely for a message with nothing to
     * look up — a `gpg -c` password message, or anything unparseable. Those
     * used to pay for a full keyring walk to reach the same answer, which on
     * a per-keystroke path is exactly the wrong trade.
     */
    private suspend fun detectCardRecipientBlocking(
        text: String,
        softwareCandidates: List<PGPKeyEntity>
    ): CardDetection = try {
        // Phase A1: one inspection yields both the public-key recipient IDs
        // (for card/software matching) and whether the message is
        // password-encrypted (SKESK, `gpg -c`).
        // 3.1.0 Phase 4 (J2): inspect the unwrapped payload so card/password
        // detection works on pasted .eml too.
        val info = crypto.inspectEncryptedMessage(
            effectiveDecryptInput(text).toByteArray(Charsets.UTF_8)
        )
        val hidden = info.hasHiddenRecipient
        // 4.1.0 — match on the ADDRESSED ids only. The wildcard is the one
        // recipient id guaranteed to match nothing on the ring, so feeding it
        // into the lookups below would only ever waste ring loads.
        val recipientIds = info.addressedKeyIDs

        if (recipientIds.isEmpty() && !hidden) {
            CardDetection(isPassword = info.isSymmetricOnly)
        } else {
            val cardEntities = repo.getAllKeys().filter {
                it.isCardBacked && it.armoredPublicKey != null
            }
            var cardMatch: PGPKeyEntity? = null
            var softwareMatchFp: String? = null
            if (recipientIds.isNotEmpty()) {
                cardMatch = cardEntities.firstOrNull { entity ->
                    val ring = repo.loadPublicKeyRing(entity.fingerprint)
                    ring != null && ringContainsAnyKeyId(ring, recipientIds)
                }
                if (cardMatch == null) {
                    softwareMatchFp = softwareCandidates.firstOrNull { entity ->
                        val ring = repo.loadPublicKeyRing(entity.fingerprint)
                        ring != null && ringContainsAnyKeyId(ring, recipientIds)
                    }?.fingerprint
                }
            }
            // Hidden recipient with no addressed match: remember a card that
            // COULD hold the key, for the fallback offer. First paired card
            // with an encryption-capable key; on the usual one-card ring there
            // is nothing to choose between.
            val hiddenCard = if (hidden && cardMatch == null) {
                cardEntities.firstOrNull { entity ->
                    repo.loadPublicKeyRing(entity.fingerprint)
                        ?.let { ringHasEncryptionKey(it) } == true
                }
            } else null
            CardDetection(
                cardMatch = cardMatch,
                softwareMatchFp = softwareMatchFp,
                isPassword = info.isSymmetricOnly,
                hidden = hidden,
                hiddenCard = hiddenCard
            )
        }
    } catch (e: Exception) {
        CardDetection()
    }

    /** True when [ring] carries any encryption-capable key (primary or subkey). */
    private fun ringHasEncryptionKey(
        ring: org.bouncycastle.openpgp.PGPPublicKeyRing
    ): Boolean {
        val it = ring.publicKeys
        while (it.hasNext()) {
            if (it.next().isEncryptionKey) return true
        }
        return false
    }

    /**
     * 4.1.0 — offer the hardware key after a hidden-recipient message has
     * defeated every software key.
     *
     * By the time this runs, PGPCryptoService.resolvePkesk has already
     * trialled each software key against the wildcard packet and come back
     * with NoMatchingKey. A card-backed key cannot be trialled that way — it
     * has no local private material, which is the whole point of it — so it
     * is the one candidate left, and asking for a tap is now justified rather
     * than gratuitous. Promoting the fingerprint into the card fields swaps
     * the tab to the PIN + tap flow, so the retry is one button press.
     *
     * Returns true when the offer was made, so the caller can suppress the
     * raw failure text. With no card to offer it returns false and the
     * honest "nothing here opened it" error stands.
     */
    private fun offerCardForHiddenRecipient(): Boolean {
        val s = _decryptState.value
        if (!s.isHiddenRecipientMessage) return false
        // Already in card mode: the tap itself failed, and the card layer's
        // own message is more specific than anything this could add. Offering
        // again would just loop the user between two prompts.
        if (s.isCardMessage) return false
        val fp = s.hiddenRecipientCardFingerprint ?: return false
        val name = s.hiddenRecipientCardName
            ?: PGPonyApp.instance.getString(R.string.decrypt_card_message_fallback_name)
        _decryptState.value = s.copy(
            isProcessing = false,
            isCardMessage = true,
            cardMessageKeyFingerprint = fp,
            cardMessageKeyName = name,
            selectedKeyFingerprint = fp,
            // The note beside the PIN field says what to DO; this says what
            // just happened, which is a real failure and reads as one.
            errorMessage = PGPonyApp.instance.getString(
                R.string.decrypt_hidden_recipient_no_software_key
            )
        )
        return true
    }

    private fun ringContainsAnyKeyId(
        ring: org.bouncycastle.openpgp.PGPPublicKeyRing,
        keyIds: List<Long>
    ): Boolean {
        val it = ring.publicKeys
        while (it.hasNext()) {
            if (keyIds.contains(it.next().keyID)) return true
        }
        return false
    }

    /**
     * HW Phase 3 — result hooks for the Decrypt tab's card path. The screen
     * runs the NFC operation (CardDecryptService.decrypt) and reports back
     * here. Card decryption returns plaintext only; inline signature
     * verification isn't performed, so the verification banner stays hidden.
     */
    fun onCardDecryptStarted() {
        _decryptState.value = _decryptState.value.copy(isProcessing = true, errorMessage = null)
    }

    fun onCardDecryptSuccess(result: com.pgpony.android.crypto.card.CardDecryptResult) {
        val plaintext = result.data.toString(Charsets.UTF_8)
        // 3.1.0 Phase 4 (J1): same content routing as the software path —
        // the card is just a different session-key source.
        val cardMime = mimeRouteWithAttachments(result.data)
        val cardBodyOnly = if (cardMime == null) mimeBodyOnly(result.data) else null
        // Show the recovered text immediately; verification (a suspend
        // keyring lookup for the signer's identity) resolves a beat later
        // and fills in the banner.
        _decryptState.value = _decryptState.value.copy(
            isProcessing = false,
            outputText = cardBodyOnly ?: plaintext,
            outputData = result.data,
            mimeBody = cardMime?.body,
            mimeAttachments = cardMime?.attachments ?: emptyList(),
            showStructuredResultSheet = cardMime != null,
            verificationResult = null,
            signatureVerified = result.signatureVerified,
            signerKeyID = result.signerKeyID,
            errorMessage = null
        )
        _events.tryEmit(Event.DecryptSuccess)
        recordDecryptUsage(
            _decryptState.value.cardMessageKeyFingerprint
                ?: _decryptState.value.selectedKeyFingerprint
        )
        viewModelScope.launch {
            val verResult = buildVerificationResultForCard(result, plaintext)
            _decryptState.value = _decryptState.value.copy(verificationResult = verResult)
        }
    }

    /**
     * Build a VerificationResult from a card-decrypt result, mirroring the
     * software path's buildVerificationResultForEncrypted: Unsigned when no
     * signature, Verified (with signer identity from the keyring) when it
     * checks out, UnknownSigner when the signer isn't in the keyring, and
     * Invalid when a known signer's signature fails to verify.
     */
    private suspend fun buildVerificationResultForCard(
        result: com.pgpony.android.crypto.card.CardDecryptResult,
        plaintext: String
    ): VerificationResult {
        if (!result.hadSignature) return VerificationResult.Unsigned(plaintext)
        val signerKeyId = result.signerKeyID
        if (signerKeyId == null || !result.signerKnown) {
            return VerificationResult.UnknownSigner(
                signerKeyID = signerKeyId ?: "",
                claimedFingerprint = null,
                signedContent = null
            )
        }
        if (!result.signatureVerified) {
            return VerificationResult.Invalid(
                reason = PGPonyApp.instance.getString(R.string.encdec_error_signer_not_in_keyring),
                signerKeyID = signerKeyId,
                signedContent = null
            )
        }
        val signer = resolveSignerEntity(signerKeyId)
        return VerificationResult.Verified(
            signerKeyID = signerKeyId,
            signerFingerprint = signer?.fingerprint ?: "",
            signerName = signer?.userName?.ifBlank { null },
            signerEmail = signer?.userEmail?.ifBlank { null },
            signedContent = null
        )
    }

    fun onCardDecryptFailure(message: String) {
        _decryptState.value = _decryptState.value.copy(
            isProcessing = false,
            errorMessage = message
        )
    }

    /**
     * Phase AU-1 — record a successful decrypt against [fingerprint] so the
     * "Decrypt With" picker can default to the most-used key. Fire-and-forget
     * on the VM scope: a DB hiccup must never fail a decrypt the user already
     * completed, and a null/blank fingerprint (e.g. clear-signed verify) is a
     * no-op.
     */
    private fun recordDecryptUsage(fingerprint: String?) {
        val fp = fingerprint?.takeIf { it.isNotBlank() } ?: return
        viewModelScope.launch {
            runCatching { repo.incrementDecryptUseCount(fp) }
        }
    }

    fun updatePassphrase(pp: String) {
        _decryptState.value = _decryptState.value.copy(passphrase = pp)
    }

    fun selectDecryptKey(fingerprint: String) {
        val key = _decryptState.value.availableKeys.firstOrNull { it.fingerprint == fingerprint }
        if (key != null && key.isCardBacked) {
            // Card key picked manually: flip to the PIN + tap path by setting
            // the same card-message state that auto-detection would, so the
            // existing card decrypt UI + NFC flow take over. (Decrypt only
            // succeeds if the message is actually encrypted to this card.)
            _decryptState.value = _decryptState.value.copy(
                selectedKeyFingerprint = fingerprint,
                isCardMessage = true,
                cardMessageKeyFingerprint = fingerprint,
                cardMessageKeyName = key.userName.ifBlank { key.userEmail }
            )
        } else {
            // Software key: clear any card-message state and select normally.
            _decryptState.value = _decryptState.value.copy(
                selectedKeyFingerprint = fingerprint,
                isCardMessage = false,
                cardMessageKeyFingerprint = null,
                cardMessageKeyName = null
            )
        }
    }

    /**
     * Phase A3 entry point. Inspects the input text to decide whether to
     * route through verify-only (clear-signed), decrypt+verify (encrypted,
     * optionally signed), or surface an error (detached-sig-alone, garbage
     * input). Keeping a single public action surface lets the UI keep its
     * single "Decrypt" button regardless of input type.
     */
    fun decrypt() {
        val s = _decryptState.value
        if (s.inputText.isBlank()) {
            _decryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_decrypt_input))
            return
        }

        // 4.4.0 RC3 (#30/#31): an inline one-pass composite signed message is
        // a PGP MESSAGE that BouncyCastle cannot parse (algo-30/31 signature);
        // detect and verify it through the composite path before routing.
        val inlineBytes = if (s.inputText.contains("-----BEGIN PGP MESSAGE-----")) {
            try { com.pgpony.android.crypto.pqc.CompositeSigPacket.dearmor(s.inputText) } catch (_: Exception) { null }
        } else null
        if (inlineBytes != null && CompositeDocumentVerifier.isCompositeInline(inlineBytes)) {
            verifyCompositeInlinePath(inlineBytes)
            return
        }

        when (verify.detectInputType(s.inputText)) {
            SignedInputType.CLEAR_SIGNED       -> verifyClearSignedPath(s)
            SignedInputType.ENCRYPTED          -> decryptAndVerifyPath(s)
            SignedInputType.DETACHED_SIGNATURE -> {
                _decryptState.value = s.copy(
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_detached_signature)
                )
            }
            SignedInputType.UNKNOWN -> {
                _decryptState.value = s.copy(
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_not_pgp_message)
                )
            }
        }
    }

    /**
     * Phase A3 verify-only path for clear-signed input. No decryption
     * happens — the cleartext is already visible to anyone holding the
     * input. We just verify the signature and surface the result.
     */
    private fun verifyClearSignedPath(s: DecryptUiState) = runClearSignedVerify(s.inputText)

    /** §5.6.10 (CertainBot) — verify a cleartext-signed .asc picked into the
     *  decrypt file slot, using the same verification surface as pasted text. */
    private fun verifyClearSignedFile(armored: String) = runClearSignedVerify(armored)

    /**
     * 4.4.0 RC3 (#30/#31): verify a clear-signed message whose signature is a
     * composite ML-DSA + EdDSA signature. BouncyCastle throws on the algo-30/31
     * packet, so composite messages are verified through CompositeDocumentVerifier
     * against the stored composite public keys. Returns null when the message is
     * not composite, so the caller falls back to the BouncyCastle path.
     */
    private suspend fun compositeClearSignedResult(armored: String): VerificationResult? {
        if (!CompositeDocumentVerifier.isCompositeCleartext(armored)) return null
        val content = CompositeDocumentVerifier.cleartextContent(armored)
        val claimedFp = CompositeDocumentVerifier.claimedSignerOfCleartext(armored)

        // Load every composite cert and its signing components (primary + any
        // composite subkeys). sequoia signs with a dedicated signing subkey,
        // PGPony's own keys sign with the primary, so match the signature's
        // issuer fingerprint to whichever component actually made it.
        val certs = withContext(Dispatchers.IO) {
            repo.getAllKeys()
                .filter { it.algorithm.isCompositeSign }
                .mapNotNull { e -> repo.loadCompositePublicInfo(e.fingerprint)?.let { e to it } }
        }
        val matched: Pair<com.pgpony.android.data.PGPKeyEntity, com.pgpony.android.crypto.pqc.CompositeKeyFacade.CompositeComponent>? =
            run {
                for ((entity, info) in certs) {
                    for (component in info.compositeSigners) {
                        if (component.fingerprintHex.equals(claimedFp, ignoreCase = true)) {
                            return@run entity to component
                        }
                    }
                }
                null
            }

        if (matched != null) {
            val (entity, component) = matched
            val ok = withContext(Dispatchers.Default) {
                CompositeDocumentVerifier.verifyCleartext(component.publicMaterial, armored).valid
            }
            return if (ok) {
                VerificationResult.Verified(
                    signerKeyID = claimedFp?.take(16) ?: entity.longKeyId,
                    signerFingerprint = entity.fingerprint,
                    signerName = entity.userName.ifBlank { null },
                    signerEmail = entity.userEmail.ifBlank { null },
                    signedContent = content
                )
            } else {
                VerificationResult.Invalid(
                    reason = "Composite signature did not verify",
                    signerKeyID = claimedFp?.take(16),
                    signedContent = content
                )
            }
        }
        return VerificationResult.UnknownSigner(
            signerKeyID = claimedFp?.take(16) ?: "",
            claimedFingerprint = claimedFp,
            signedContent = content
        )
    }

    /** Find the composite cert + component whose fingerprint matches [claimedFp]. */
    private suspend fun resolveCompositeSigner(
        claimedFp: String?
    ): Pair<com.pgpony.android.data.PGPKeyEntity, com.pgpony.android.crypto.pqc.CompositeKeyFacade.CompositeComponent>? {
        if (claimedFp == null) return null
        val certs = withContext(Dispatchers.IO) {
            repo.getAllKeys()
                .filter { it.algorithm.isCompositeSign }
                .mapNotNull { e -> repo.loadCompositePublicInfo(e.fingerprint)?.let { e to it } }
        }
        for ((entity, info) in certs) {
            for (component in info.compositeSigners) {
                if (component.fingerprintHex.equals(claimedFp, ignoreCase = true)) return entity to component
            }
        }
        return null
    }

    /**
     * 4.4.0 RC3 (#30/#31): verify a detached composite signature over the file
     * at [signedUri]. Returns null when the signature is not composite, so the
     * caller falls back to the BouncyCastle detached-verify path. The signed
     * content is read whole (composite verify hashes the full document).
     */
    private suspend fun compositeDetachedFileResult(
        sig: ByteArray,
        signedUri: android.net.Uri
    ): VerificationResult? {
        val sigPacket = CompositeDocumentVerifier.rawSignaturePacket(sig)
        if (!CompositeDocumentVerifier.isCompositeSignature(sigPacket)) return null
        val data = withContext(Dispatchers.IO) {
            PGPonyApp.instance.contentResolver.openInputStream(signedUri)?.use { it.readBytes() }
        } ?: return VerificationResult.Invalid(
            reason = PGPonyApp.instance.getString(R.string.sign_verify_error_file_unreadable),
            signerKeyID = null,
            signedContent = null
        )
        val claimedFp = CompositeDocumentVerifier.claimedSignerOfDetached(sig)
        val matched = resolveCompositeSigner(claimedFp)
        if (matched != null) {
            val (entity, component) = matched
            val ok = withContext(Dispatchers.Default) {
                CompositeDocumentVerifier.verifyDetached(component.publicMaterial, sigPacket, data).valid
            }
            return if (ok) {
                VerificationResult.Verified(
                    signerKeyID = claimedFp?.take(16) ?: entity.longKeyId,
                    signerFingerprint = entity.fingerprint,
                    signerName = entity.userName.ifBlank { null },
                    signerEmail = entity.userEmail.ifBlank { null },
                    signedContent = null
                )
            } else {
                VerificationResult.Invalid(
                    reason = "Composite signature did not verify",
                    signerKeyID = claimedFp?.take(16),
                    signedContent = null
                )
            }
        }
        return VerificationResult.UnknownSigner(
            signerKeyID = claimedFp?.take(16) ?: "",
            claimedFingerprint = claimedFp,
            signedContent = null
        )
    }

    /**
     * 4.4.0 RC3 (#30/#31): verify an inline one-pass composite signed message
     * (One-Pass Signature + Literal Data + composite Signature) and surface its
     * literal content.
     */
    private fun verifyCompositeInlinePath(message: ByteArray) {
        viewModelScope.launch {
            _decryptState.value = _decryptState.value.copy(isProcessing = true, errorMessage = null)
            val content = CompositeDocumentVerifier.inlineContent(message)
                ?.let { String(it, Charsets.UTF_8) }
            val claimedFp = CompositeDocumentVerifier.claimedSignerOfInline(message)
            val matched = resolveCompositeSigner(claimedFp)
            val result: VerificationResult = if (matched != null) {
                val (entity, component) = matched
                val ok = withContext(Dispatchers.Default) {
                    CompositeDocumentVerifier.verifyInline(component.publicMaterial, message).valid
                }
                if (ok) {
                    VerificationResult.Verified(
                        signerKeyID = claimedFp?.take(16) ?: entity.longKeyId,
                        signerFingerprint = entity.fingerprint,
                        signerName = entity.userName.ifBlank { null },
                        signerEmail = entity.userEmail.ifBlank { null },
                        signedContent = content
                    )
                } else {
                    VerificationResult.Invalid(
                        reason = "Composite signature did not verify",
                        signerKeyID = claimedFp?.take(16),
                        signedContent = content
                    )
                }
            } else {
                VerificationResult.UnknownSigner(
                    signerKeyID = claimedFp?.take(16) ?: "",
                    claimedFingerprint = claimedFp,
                    signedContent = content
                )
            }
            _decryptState.value = _decryptState.value.copy(
                outputText = content.orEmpty(),
                isProcessing = false,
                verificationResult = result,
                signatureVerified = result is VerificationResult.Verified,
                pendingUnknownClaimedFingerprint =
                    (result as? VerificationResult.UnknownSigner)?.claimedFingerprint,
            )
        }
    }

    private fun runClearSignedVerify(armored: String) {
        viewModelScope.launch {
            _decryptState.value = _decryptState.value.copy(isProcessing = true, errorMessage = null)
            // 4.0.4 — off the main thread. viewModelScope.launch runs on
            // Dispatchers.Main.immediate, and loadPublicKeyRing is a plain
            // blocking call: an EncryptedSharedPreferences read (Tink
            // AES-GCM per entry) plus a Bouncy Castle parse, repeated for
            // EVERY key in the keyring. verifyDetached below already wraps
            // this exact expression; these paths were missed.
            // 4.4.0 RC3 (#30/#31): composite signatures cannot go through
            // BouncyCastle; verify them through the raw-bytes composite path.
            val result = compositeClearSignedResult(armored) ?: run {
                val publicRings = withContext(Dispatchers.IO) {
                    repo.getAllKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
                }
                withContext(Dispatchers.Default) {
                    verify.verifyClearSigned(armored, publicRings)
                }
            }

            val outputText = when (result) {
                is VerificationResult.Verified      -> result.signedContent.orEmpty()
                is VerificationResult.Invalid       -> result.signedContent.orEmpty()
                is VerificationResult.UnknownSigner -> result.signedContent.orEmpty()
                is VerificationResult.Unsigned      -> result.content
            }
            val pendingFp = (result as? VerificationResult.UnknownSigner)?.claimedFingerprint

            _decryptState.value = _decryptState.value.copy(
                outputText = outputText,
                isProcessing = false,
                verificationResult = result,
                pendingUnknownClaimedFingerprint = pendingFp,
                // For clear-signed there's no signer-keyID-via-decrypt path
                // to surface; the verificationResult holds everything.
                signatureVerified = result is VerificationResult.Verified,
                signerKeyID = when (result) {
                    is VerificationResult.Verified      -> result.signerKeyID
                    is VerificationResult.UnknownSigner -> result.signerKeyID
                    is VerificationResult.Invalid       -> result.signerKeyID
                    else                                 -> null
                },
                errorMessage = null
            )
            _events.tryEmit(Event.DecryptSuccess)
        }
    }

    /**
     * Phase A3 decrypt-and-verify path for encrypted messages. The
     * existing PGPCryptoService.decryptArmored already parses one-pass-
     * signature packets inline; this method wraps its output into a
     * VerificationResult so the banner has uniform rendering across
     * clear-signed and encrypted-signed paths.
     *
     * Note: the existing decryptArmored can't distinguish "signature
     * present but key not in keyring" from "signature present but
     * verification failed" — both end up with signatureVerified=false.
     * Phase A10 will revisit this to give encrypted-signed messages
     * the same UnknownSigner-with-lookup affordance clear-signed gets
     * today.
     */
    /**
     * 4.0.0 Phase 4 — app-side Autocrypt. Pull the sender's key from an
     * `Autocrypt:` header on a decrypted email (and any `Autocrypt-Gossip`
     * from the decrypted MIME) into the peer store, so PGPony's own decrypt
     * acquires keys automatically like the provider does. Guarded on the
     * header string so non-Autocrypt decrypts pay nothing.
     */
    private fun ingestAutocrypt(rawInput: String?, decrypted: ByteArray?) {
        if (rawInput == null || !rawInput.contains("Autocrypt", ignoreCase = true)) return
        val decText = decrypted?.toString(Charsets.UTF_8)
        viewModelScope.launch {
            runCatching {
                PGPonyApp.instance.autocryptPeerStore.ingestEmail(rawInput, decText)
            }
        }
    }

    /**
     * RC3 §N (#34): decryption trial order for the current primary key —
     * the primary itself first, then its ENABLED fallbacks in the user's
     * chosen order (fallback_keys table; absent = off, the issue's
     * default), then every remaining available key. The tail preserves
     * the pre-#34 "all keys go along" behavior exactly, so a key with no
     * fallbacks configured decrypts everything it could before.
     */
    private suspend fun fallbackOrderedKeys(s: DecryptUiState): List<PGPKeyEntity> {
        val byFingerprint = s.availableKeys.associateBy { it.fingerprint }
        val ordered = mutableListOf<PGPKeyEntity>()
        fun addUnique(k: PGPKeyEntity) {
            if (ordered.none { it.fingerprint == k.fingerprint }) ordered.add(k)
        }
        val primary = s.selectedKeyFingerprint
        if (primary != null) {
            byFingerprint[primary]?.let { addUnique(it) }
            repo.fallbacksFor(primary).forEach { fp ->
                byFingerprint[fp]?.let { addUnique(it) }
            }
            // RC4 O3 (#34): strict mode drops the remaining-keys net —
            // only this key and its enabled fallbacks are tried.
            if (com.pgpony.android.crypto.FallbackPrefs.isStrict(primary) && ordered.isNotEmpty()) {
                return ordered
            }
        }
        s.availableKeys.forEach { addUnique(it) }
        return ordered
    }

    /**
     * RC3 §N (#34): the cascade rule decided 8 August — ANY exception on
     * a ring moves to the next enabled fallback, no special-casing
     * wrong-passphrase or corrupt input differently from a wrong-key
     * failure. Each ring is tried ALONE in list order; the FINAL attempt
     * is the full list (key-ID lookup + the existing wildcard trial,
     * i.e. exactly the pre-#34 call), and only that attempt's exception
     * propagates — so the error UX (passphrase dialog, hidden-recipient
     * card offer, error strings) is byte-for-byte what it was. With a
     * single ring the per-ring pass is skipped entirely.
     */
    private inline fun <T> decryptWithFallbackCascade(
        rings: List<org.bouncycastle.openpgp.PGPSecretKeyRing>,
        attempt: (List<org.bouncycastle.openpgp.PGPSecretKeyRing>) -> T
    ): T {
        if (rings.size > 1) {
            for (ring in rings) {
                try {
                    return attempt(listOf(ring))
                } catch (e: kotlin.coroutines.cancellation.CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    // Decided rule: any exception → next fallback.
                }
            }
        }
        return attempt(rings)
    }

    private fun decryptAndVerifyPath(s: DecryptUiState) {
        viewModelScope.launch {
            _decryptState.value = _decryptState.value.copy(isProcessing = true, errorMessage = null)
            // §3 (#15): reuse a cached in-app passphrase for a repeat decrypt
            // on the selected key; remember a freshly entered one on success.
            val cacheFp = s.selectedKeyFingerprint
            val effPass = s.passphrase.ifBlank { null }
                ?: cacheFp?.let { com.pgpony.android.session.InAppPassphraseCache.get(it) }
            try {
                // Put selected key first, then include the rest as fallbacks
                // RC3 §N (#34): primary first, then its enabled fallbacks in
                // the user's order, then everything else (pre-#34 behavior as
                // the safety net) — see fallbackOrderedKeys.
                val orderedKeys = fallbackOrderedKeys(s)
                // 4.0.4 — off the main thread. See the note in
                // verifyClearSignedPath: every ring load is a blocking
                // EncryptedSharedPreferences read plus a BC parse, and the
                // verify list loads the WHOLE keyring before the decrypt
                // even starts. The encrypt paths were already dispatched;
                // decrypt was not, which is why decrypt was the side that
                // froze.
                val secretRings = withContext(Dispatchers.IO) {
                    orderedKeys.mapNotNull { repo.loadSecretKeyRing(it.fingerprint) }
                }
                val verifyRings = withContext(Dispatchers.IO) {
                    repo.getAllKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
                }

                val result = withContext(Dispatchers.Default) {
                    // RC3 §N (#34): per-ring cascade, any exception → next.
                    decryptWithFallbackCascade(secretRings) { rings ->
                        crypto.decryptArmored(
                            // 3.1.0 Phase 4 (J2): unwrap an RFC 3156 envelope
                            // (pasted .eml) before dearmor; plain input passes
                            // through unchanged.
                            armoredMessage = effectiveDecryptInput(s.inputText),
                            secretKeyRings = rings,
                            passphrase = effPass,
                            verificationKeys = verifyRings
                        )
                    }
                }

                val verResult = buildVerificationResultForEncrypted(result)

                // 3.1.0 Phase 4 (J1): content-based routing. Attachments →
                // structured sheet; body-only MIME → readable body as the
                // text result; non-MIME → unchanged.
                // MIME parse of the full plaintext — also off main.
                val mime = withContext(Dispatchers.Default) {
                    mimeRouteWithAttachments(result.data)
                }
                val bodyOnly = if (mime == null) {
                    withContext(Dispatchers.Default) { mimeBodyOnly(result.data) }
                } else null

                _decryptState.value = _decryptState.value.copy(
                    outputText = bodyOnly ?: result.plaintext,
                    outputData = result.data,
                    isProcessing = false,
                    signatureVerified = result.signatureVerified,
                    signerKeyID = result.signerKeyID,
                    decryptedFilename = result.filename,
                    showPassphraseDialog = false,
                    verificationResult = verResult,
                    mimeBody = mime?.body,
                    mimeAttachments = mime?.attachments ?: emptyList(),
                    showStructuredResultSheet = mime != null
                )
                _events.tryEmit(Event.DecryptSuccess)
                ingestAutocrypt(s.inputText, result.data)
                recordDecryptUsage(s.selectedKeyFingerprint)
                if (cacheFp != null && !effPass.isNullOrEmpty()) com.pgpony.android.session.InAppPassphraseCache.put(cacheFp, effPass)
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.PassphraseRequired) {
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    showPassphraseDialog = true,
                    errorMessage = null
                )
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.InvalidPassphrase) {
                if (cacheFp != null) com.pgpony.android.session.InAppPassphraseCache.clear(cacheFp)
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase)
                )
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.NoMatchingKey) {
                // 4.1.0 — the one failure worth turning into an offer.
                if (!offerCardForHiddenRecipient()) {
                    _decryptState.value = _decryptState.value.copy(
                        isProcessing = false,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.encdec_error_decryption_failed_format, e.message ?: ""
                        )
                    )
                }
            } catch (e: Exception) {
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_decryption_failed_format, e.message ?: "")
                )
            }
        }
    }

    /**
     * Map a DecryptResult into the same VerificationResult shape the
     * clear-signed path produces, so VerificationBanner can render both
     * uniformly. The signer's user ID is looked up from the local keyring
     * by 16-hex-char key ID (matches the last 16 chars of a v4 fingerprint).
     */
    /**
     * V6-6: Resolve the local key entity that produced a signature with key
     * ID [signerKeyId]. First tries a direct primary-key match (the fast path
     * for v4 keys that sign with the primary). That misses for v6 keys and any
     * key signing with a dedicated subkey — the signature carries the subkey's
     * key ID, which no primary record equals — so it then walks the cached
     * public key rings with BC's getPublicKey(keyId) (which matches subkeys)
     * and maps the owning ring's primary key ID back to the stored entity.
     * Mirrors VerifyService.resolveSignerIdentity so the decrypt banner names a
     * subkey signer the same way detached verification already does. Returns
     * null when the signer isn't local (caller then shows the key ID alone).
     */
    private suspend fun resolveSignerEntity(signerKeyId: String): PGPKeyEntity? {
        val all = repo.getAllKeys()
        all.firstOrNull { it.longKeyId.equals(signerKeyId, ignoreCase = true) }?.let { return it }
        val keyIdLong = signerKeyId.toULongOrNull(16)?.toLong() ?: return null
        val ownerPrimaryKeyId = verifyRingsCache
            .firstOrNull { ring -> ring.getPublicKey(keyIdLong) != null }
            ?.let { String.format("%016X", it.publicKey.keyID) }
            ?: return null
        return all.firstOrNull { it.longKeyId.equals(ownerPrimaryKeyId, ignoreCase = true) }
    }

    private suspend fun buildVerificationResultForEncrypted(
        result: com.pgpony.android.crypto.DecryptResult
    ): VerificationResult {
        val signerKeyId = result.signerKeyID
        if (signerKeyId == null) {
            // 4.1.0 Phase 14b. This returned Unsigned, which is a false
            // statement whenever the message carried a signature from
            // someone whose key is not in the keyring: signerKeyID is
            // only populated when findPublicKey located the signer, so
            // "not in my keyring" and "not signed" arrived here looking
            // identical. hasSignature and signatureKeyIDRaw were added in
            // 4.0.0 Phase P2b-1 to tell them apart for the provider API
            // (RESULT_NO_SIGNATURE vs RESULT_KEY_MISSING) and this screen
            // never used them.
            //
            // UnknownSigner is the right state and it already exists:
            // yellow banner, tappable, opens the signer lookup so the
            // certificate can be fetched and the signature re-checked.
            // buildVerificationResultForCard has done exactly this since
            // HW Phase 3; its own doc comment says it mirrors the
            // software path, which turned out not to be true.
            //
            // claimedFingerprint stays null because the decrypt results
            // do not carry the issuer-fingerprint subpacket. The lookup
            // falls back to the key ID, which is what UnknownSigner
            // documents for old signatures.
            if (result.hasSignature) {
                return VerificationResult.UnknownSigner(
                    signerKeyID = result.signatureKeyIDRaw
                        ?.let { String.format("%016X", it) } ?: "",
                    claimedFingerprint = null,
                    signedContent = null
                )
            }
            return VerificationResult.Unsigned(result.plaintext)
        }
        if (!result.signatureVerified) {
            return VerificationResult.Invalid(
                reason = PGPonyApp.instance.getString(R.string.encdec_error_signer_not_in_keyring),
                signerKeyID = signerKeyId,
                signedContent = null
            )
        }
        // Verified — resolve the signer (primary key, or a signing subkey via
        // its owning ring) to a local entity for name/email/fingerprint.
        val signer = resolveSignerEntity(signerKeyId)
        return VerificationResult.Verified(
            signerKeyID = signerKeyId,
            signerFingerprint = signer?.fingerprint ?: "",
            signerName = signer?.userName?.ifBlank { null },
            signerEmail = signer?.userEmail?.ifBlank { null },
            signedContent = null
        )
    }

    /**
     * 4.0.4 — the DecryptStreamResult counterpart. Identical logic to
     * [buildVerificationResultForEncrypted]; it exists only because the
     * streaming result carries no plaintext to hand to Unsigned (the
     * plaintext is on disk, and signedContent is unused for file mode
     * in either path).
     */
    private suspend fun buildVerificationResultForStream(
        result: com.pgpony.android.crypto.DecryptStreamResult
    ): VerificationResult {
        val signerKeyId = result.signerKeyID
        if (signerKeyId == null) {
            // 4.1.0 Phase 14b. This returned Unsigned, which is a false
            // statement whenever the message carried a signature from
            // someone whose key is not in the keyring: signerKeyID is
            // only populated when findPublicKey located the signer, so
            // "not in my keyring" and "not signed" arrived here looking
            // identical. hasSignature and signatureKeyIDRaw were added in
            // 4.0.0 Phase P2b-1 to tell them apart for the provider API
            // (RESULT_NO_SIGNATURE vs RESULT_KEY_MISSING) and this screen
            // never used them.
            //
            // UnknownSigner is the right state and it already exists:
            // yellow banner, tappable, opens the signer lookup so the
            // certificate can be fetched and the signature re-checked.
            // buildVerificationResultForCard has done exactly this since
            // HW Phase 3; its own doc comment says it mirrors the
            // software path, which turned out not to be true.
            //
            // claimedFingerprint stays null because the decrypt results
            // do not carry the issuer-fingerprint subpacket. The lookup
            // falls back to the key ID, which is what UnknownSigner
            // documents for old signatures.
            if (result.hasSignature) {
                return VerificationResult.UnknownSigner(
                    signerKeyID = result.signatureKeyIDRaw
                        ?.let { String.format("%016X", it) } ?: "",
                    claimedFingerprint = null,
                    signedContent = null
                )
            }
            return VerificationResult.Unsigned("")
        }
        if (!result.signatureVerified) {
            return VerificationResult.Invalid(
                reason = PGPonyApp.instance.getString(R.string.encdec_error_signer_not_in_keyring),
                signerKeyID = signerKeyId,
                signedContent = null
            )
        }
        val signer = resolveSignerEntity(signerKeyId)
        return VerificationResult.Verified(
            signerKeyID = signerKeyId,
            signerFingerprint = signer?.fingerprint ?: "",
            signerName = signer?.userName?.ifBlank { null },
            signerEmail = signer?.userEmail?.ifBlank { null },
            signedContent = null
        )
    }

    // ── Phase A10c: file-mode decrypt actions ──────────────────────────
    //
    // Parallel to the A10b encrypt-side helpers. UI hands raw bytes
    // read from the SAF content:// URI; PGPCryptoService.decrypt()
    // figures out armored-vs-binary on its own via isArmored().

    /**
     * Phase A10c: switch the Decrypt tab between text and file modes.
     * Clears the opposite mode's transient state so a half-completed
     * text decrypt doesn't bleed into a fresh file decrypt (or vice
     * versa). Output state (outputText / decryptedFileBytes) is
     * cleared too — a fresh mode means a fresh operation.
     */
    fun setDecryptMode(m: DecryptMode) {
        _decryptState.value = _decryptState.value.copy(
            mode = m,
            outputText = "",
            outputData = null,
            errorMessage = null,
            verificationResult = null,
            signatureVerified = false,
            signerKeyID = null,
            // HW Phase 3 — card-message detection is per-input; clear it on
            // mode switch so a stale TEXT detection doesn't leak into FILE
            // (and vice-versa). Re-runs when new input/file is provided.
            isCardMessage = false,
            cardMessageKeyFingerprint = null,
            cardMessageKeyName = null,
            decryptedFilename = null,
            decryptedFileBytes = null,
            decryptedFile = null,
            mimeFileAttachments = emptyList(),
            showFileDecryptResultSheet = false,
            // RC3 §J (#16): Verify promoted from a sheet (reset fresh via
            // openVerifyFileSheet each open) to a tab — reset the same
            // fields on every mode switch instead.
            verifyFileSignedName = null,
            verifyFileSignedUri = null,
            verifyFileSigName = null,
            verifyFileSigBytes = null,
            verifyFileResult = null,
            verifyFileProcessing = false
        )
        // 4.0.4 — a mode switch abandons any streamed plaintext.
        ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_DECRYPT)
    }

    /**
     * Phase A10c: store the picked encrypted file's metadata and
     * bytes in decrypt state. Same shape as setFileToEncrypt() on
     * the encrypt side.
     */
    fun setFileToDecrypt(name: String, size: Long, bytes: ByteArray) {
        _decryptState.value = _decryptState.value.copy(
            selectedFileName = name,
            selectedFileSize = size,
            selectedFileBytes = bytes,
            selectedFileUri = null,
            decryptedFileBytes = null,
            decryptedFile = null,
            errorMessage = null
        )
        detectCardRecipientFile(bytes)
    }

    /**
     * 4.0.4 — URI-taking counterpart, and the one the file picker and
     * the share/view intent handlers now call.
     *
     * Small inputs are read here so everything downstream sees the
     * pre-4.0.4 shape and behaves identically. Large ones are left on
     * disk and carried as a URI; nothing reads them until
     * decryptFile() streams through them. [size] is the picker's
     * metadata, which can be absent or wrong for some
     * DocumentsProviders, so the read is additionally bounded and
     * falls back to the streaming path if the file turns out to be
     * bigger than advertised.
     */
    fun setFileToDecrypt(name: String, size: Long, uri: android.net.Uri) {
        val inline: ByteArray? = if (size <= INLINE_FILE_LIMIT) {
            // Covers a negative/absent size too: some DocumentsProviders
            // don't report one, and readAtMost is bounded anyway.
            readAtMost(uri, INLINE_FILE_LIMIT)
        } else {
            null
        }
        _decryptState.value = _decryptState.value.copy(
            selectedFileName = name,
            selectedFileSize = size,
            selectedFileBytes = inline,
            selectedFileUri = if (inline == null) uri else null,
            decryptedFileBytes = null,
            decryptedFile = null,
            errorMessage = null
        )
        if (inline != null) {
            detectCardRecipientFile(inline)
        } else {
            detectCardRecipientFileStreaming(uri)
        }
    }

    /**
     * Read [uri] fully, but only if it comes in at or under [limit];
     * returns null the moment it goes over. Avoids trusting the
     * picker's reported size, and avoids allocating a 13 MB array to
     * discover the file is 13 MB.
     */
    fun readAtMost(uri: android.net.Uri, limit: Long): ByteArray? {
        return try {
            PGPonyApp.instance.contentResolver.openInputStream(uri)?.use { input ->
                val buffer = java.io.ByteArrayOutputStream()
                val chunk = ByteArray(64 * 1024)
                var total = 0L
                var overLimit = false
                while (true) {
                    val n = input.read(chunk)
                    if (n <= 0) break
                    total += n
                    if (total > limit) {
                        overLimit = true
                        break
                    }
                    buffer.write(chunk, 0, n)
                }
                if (overLimit) null else buffer.toByteArray()
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 4.0.4 — card-recipient detection for the large path. The
     * session-key packets sit at the front of the message, so this
     * reads a few KB off the stream instead of the whole file.
     */
    private fun detectCardRecipientFileStreaming(uri: android.net.Uri) {
        viewModelScope.launch {
            var isPassword = false
            val match: PGPKeyEntity? = try {
                val info = withContext(Dispatchers.IO) {
                    PGPonyApp.instance.contentResolver.openInputStream(uri)?.use { input ->
                        crypto.inspectEncryptedMessage(input)
                    }
                }
                isPassword = info?.isSymmetricOnly ?: false
                val recipientIds = info?.publicKeyIDs ?: emptyList()
                if (recipientIds.isEmpty()) {
                    null
                } else {
                    withContext(Dispatchers.IO) {
                        val cardEntities = repo.getAllKeys().filter {
                            it.isCardBacked && it.armoredPublicKey != null
                        }
                        cardEntities.firstOrNull { entity ->
                            val ring = repo.loadPublicKeyRing(entity.fingerprint)
                            ring != null && ringContainsAnyKeyId(ring, recipientIds)
                        }
                    }
                }
            } catch (e: Exception) {
                isPassword = false
                null
            }
            if (_decryptState.value.selectedFileUri == uri) {
                _decryptState.value = _decryptState.value.copy(
                    isCardMessage = match != null,
                    cardMessageKeyFingerprint = match?.fingerprint,
                    cardMessageKeyName = match?.let { it.userName.ifBlank { it.userEmail } },
                    isPasswordMessage = isPassword
                )
            }
        }
    }

    /**
     * HW Phase 3 — file-mode counterpart to detectCardRecipient. Reads the
     * picked file's recipient key IDs (binary-aware) and flags a card match
     * so the Decrypt tab shows PIN + tap instead of the passphrase field.
     */
    private fun detectCardRecipientFile(bytes: ByteArray) {
        viewModelScope.launch {
            // 4.1.0, issue #10 — the byte-mode twin of the dispatcher fix in
            // [detectCardRecipient]. Same blocking ring loads, same reason.
            // A picked file can be large, so the inspection itself is worth
            // moving too, not just the key lookups.
            var isPassword = false
            val match: PGPKeyEntity? = withContext(Dispatchers.IO) {
                try {
                    val info = crypto.inspectEncryptedMessage(bytes)
                    isPassword = info.isSymmetricOnly
                    val recipientIds = info.addressedKeyIDs
                    if (recipientIds.isEmpty()) {
                        null
                    } else {
                        val cardEntities = repo.getAllKeys().filter {
                            it.isCardBacked && it.armoredPublicKey != null
                        }
                        cardEntities.firstOrNull { entity ->
                            val ring = repo.loadPublicKeyRing(entity.fingerprint)
                            ring != null && ringContainsAnyKeyId(ring, recipientIds)
                        }
                    }
                } catch (e: Exception) {
                    isPassword = false
                    null
                }
            }
            // Only publish if this file is still the selected one.
            if (_decryptState.value.selectedFileBytes === bytes) {
                _decryptState.value = _decryptState.value.copy(
                    isCardMessage = match != null,
                    cardMessageKeyFingerprint = match?.fingerprint,
                    cardMessageKeyName = match?.let { it.userName.ifBlank { it.userEmail } },
                    isPasswordMessage = isPassword
                )
            }
        }
    }

    /**
     * HW Phase 3 — file-mode card decrypt result. The Decrypt screen runs
     * CardDecryptService.decryptBytes over the NFC op and reports the
     * recovered bytes + embedded filename. Mirrors the file-result tail of
     * decryptFileAndVerifyPath (output filename derivation, result sheet).
     */
    /**
     * 4.1.0 Phase 16. Ciphertext for the card decrypt path, read on
     * demand rather than at pick time.
     *
     * Above INLINE_FILE_LIMIT the picker deliberately keeps only the URI
     * (4.0.4), which the card path read as "too large for a hardware
     * key". It is not: the card only unwraps the session key, and the
     * message it cannot open is the one the user most needs opened.
     * Returns null past [CARD_BUFFER_LIMIT] or when the read fails.
     *
     * Called from inside the card session block, so it is already off
     * the main thread.
     */
    fun cardDecryptInputBytes(): ByteArray? {
        val s = _decryptState.value
        s.selectedFileBytes?.let { return it }
        val uri = s.selectedFileUri ?: return null
        val size = s.selectedFileSize ?: -1L
        if (size > CARD_BUFFER_LIMIT) return null
        // 4.1.0 Phase 17: chunked rather than readBytes() so the card
        // dialog has something to draw. This is the only phase of a card
        // decrypt that can be measured: the session-key unwrap is a
        // single APDU exchange with no progress to report, and
        // CardDecryptService.decryptBytes has no callback.
        return runCatching {
            val out = java.io.ByteArrayOutputStream(
                if (size in 1..Int.MAX_VALUE.toLong()) size.toInt() else 64 * 1024
            )
            PGPonyApp.instance.contentResolver.openInputStream(uri)?.use { input ->
                _decryptState.value = _decryptState.value.copy(
                    processedBytes = 0L,
                    totalBytes = if (size > 0) size else 0L
                )
                val buf = ByteArray(64 * 1024)
                var read = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    read += n
                    _decryptState.value = _decryptState.value.copy(processedBytes = read)
                }
            } ?: return@runCatching null
            // The measurable phase is over; drop back to the spinner
            // rather than leaving a full bar sitting there through the
            // card operation.
            _decryptState.value = _decryptState.value.copy(
                processedBytes = 0L, totalBytes = 0L
            )
            out.toByteArray()
        }.getOrNull()
    }

    fun onCardDecryptFileSuccess(result: com.pgpony.android.crypto.card.CardDecryptResult) {
        val s = _decryptState.value
        val bytes = result.data
        val filename = result.filename
        val literalName = filename?.takeIf { it.isNotBlank() }
        val stripped = s.selectedFileName?.let { stripPgpExtension(it) }
        val outName = literalName
            ?: stripped
            ?: s.selectedFileName?.let { "decrypted_$it" }
            ?: "decrypted_output"
        // 4.1.0 Phase 17b. startCardOperation's completion callback runs
        // on the main thread. Everything below used to run there too,
        // which for a 12 MB card bundle meant an 11 MB scratch write and
        // a full MIME extraction on the UI thread: an ANR waiting to
        // happen, and the reason Phase 17's progress bar never appeared.
        // A blocked main thread cannot paint the bar describing what is
        // blocking it.
        //
        // The buffered mimeRouteWithAttachments has always run here too,
        // parsing the whole container on this thread; Phase 16 only made
        // the load heavier. Both move off now, and the phase becomes
        // measurable while it does.
        _decryptState.value = s.copy(
            isProcessing = true,
            processedBytes = 0L,
            // 4.1.0 Phase 17c: two phases, write then extract, and the
            // second is the slow one. Counting only the first left the
            // bar full for the whole of the second.
            totalBytes = bytes.size.toLong() * 2,
            errorMessage = null
        )
        viewModelScope.launch {
            // 4.1.0 Phase 16. A card bundle now reaches here at a size
            // where mimeRouteWithAttachments is the wrong tool: it parses
            // the whole container in memory and hands back every
            // attachment as a ByteArray, on top of the ciphertext and
            // plaintext already resident. Above INLINE_FILE_LIMIT the
            // plaintext goes to scratch and the Phase 14 extractor lists
            // the attachments from disk, exactly as the software
            // streaming path does. Below it, nothing changes: small card
            // results stay entirely in memory, which is the
            // privacy-preferable behaviour and what every existing card
            // decrypt does today.
            val cardBundle = if (bytes.size.toLong() > INLINE_FILE_LIMIT) {
                withContext(Dispatchers.IO) {
                    runCatching {
                        val scratch = ScratchFiles.allocate(
                            PGPonyApp.instance, outName, ScratchFiles.SCOPE_DECRYPT
                        )
                        // Chunked so the write is the measurable phase the
                        // card's own work never can be.
                        scratch.outputStream().buffered().use { out ->
                            var off = 0
                            while (off < bytes.size) {
                                val n = minOf(256 * 1024, bytes.size - off)
                                out.write(bytes, off, n)
                                off += n
                                _decryptState.value =
                                    _decryptState.value.copy(processedBytes = off.toLong())
                            }
                        }
                        if (!MimeStreamExtractor.looksLikeBundle(scratch)) {
                            // No extraction phase to run, so close the bar
                            // rather than leaving it stopped at half.
                            _decryptState.value = _decryptState.value.copy(
                                processedBytes = bytes.size.toLong() * 2
                            )
                            // Not a bundle: keep the plaintext on disk
                            // anyway, it is too big to want a second copy
                            // of, and let the file result sheet read it
                            // from there.
                            CardScratchOutcome(scratch, null)
                        } else {
                            val dir = java.io.File(scratch.parentFile, "attachments")
                            dir.mkdirs()
                            val extracted = MimeStreamExtractor.extract(scratch, dir) { consumed ->
                                _decryptState.value = _decryptState.value.copy(
                                    processedBytes = bytes.size.toLong() + consumed
                                )
                            }
                            if (extracted != null) {
                                runCatching { scratch.delete() }
                                CardScratchOutcome(null, extracted)
                            } else {
                                CardScratchOutcome(scratch, null)
                            }
                        }
                    }.getOrNull()
                }
            } else null

            // 3.1.0 Phase 4 (J1): attachments → structured sheet, matching
            // the software file path.
            val cardFileMime = if (cardBundle == null) {
                withContext(Dispatchers.Default) { mimeRouteWithAttachments(bytes) }
            } else null
            val extractedBundle = cardBundle?.bundle
            _decryptState.value = _decryptState.value.copy(
                isProcessing = false,
                processedBytes = 0L,
                totalBytes = 0L,
                decryptedFileBytes = if (cardBundle == null) bytes else null,
                decryptedFile = cardBundle?.file,
                decryptedOutputFilename = outName,
                mimeBody = extractedBundle?.body ?: cardFileMime?.body,
                mimeAttachments = cardFileMime?.attachments ?: emptyList(),
                mimeFileAttachments = extractedBundle?.attachments ?: emptyList(),
                showStructuredResultSheet = cardFileMime != null || extractedBundle != null,
                showFileDecryptResultSheet = cardFileMime == null && extractedBundle == null,
                verificationResult = null,
                signatureVerified = result.signatureVerified,
                signerKeyID = result.signerKeyID,
                errorMessage = null
            )
            _events.tryEmit(Event.DecryptSuccess)
            recordDecryptUsage(
                _decryptState.value.cardMessageKeyFingerprint
                    ?: _decryptState.value.selectedKeyFingerprint
            )
            // 4.1.0 Phase 16: only the Unsigned banner carries the
            // plaintext, and only the text paths render it, so a large
            // card result does not need a second UTF-8 copy of itself
            // made just to build a banner.
            val plaintext = if (cardBundle != null) "" else {
                withContext(Dispatchers.Default) {
                    try { bytes.toString(Charsets.UTF_8) } catch (_: Exception) { "" }
                }
            }
            val verResult = buildVerificationResultForCard(result, plaintext)
            _decryptState.value = _decryptState.value.copy(verificationResult = verResult)
        }
    }

    /** Phase A10c: clear the picked encrypted file. */
    fun clearDecryptFile() {
        // 4.0.4 — also drops any streamed plaintext from cacheDir.
        ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_DECRYPT)
        _decryptState.value = _decryptState.value.copy(
            selectedFileName = null,
            selectedFileSize = null,
            selectedFileBytes = null,
            selectedFileUri = null,
            decryptedFileBytes = null,
            decryptedFile = null,
            errorMessage = null,
            // HW Phase 3 — drop any card-message detection from the cleared file.
            isCardMessage = false,
            cardMessageKeyFingerprint = null,
            cardMessageKeyName = null,
            // Phase A1 — drop password-message detection too.
            isPasswordMessage = false
        )
    }

    /**
     * Phase A10c: decrypt the currently-selected encrypted file.
     * Mirrors decrypt() for text mode but skips the
     * verify.detectInputType() routing — file mode only supports
     * encrypted input (clear-signed-as-file would be a future
     * extension). Routes to decryptFileAndVerifyPath() which
     * mirrors decryptAndVerifyPath() but feeds bytes to
     * crypto.decrypt() instead of armored text to decryptArmored().
     */
    fun decryptFile(passphrase: String? = null) {
        val s = _decryptState.value
        // 4.0.4 — see encryptFile(): one file operation at a time.
        if (fileOpJob?.isActive == true) return
        val bytes = s.selectedFileBytes
        val uri = s.selectedFileUri
        if (bytes == null && uri == null) {
            _decryptState.value = s.copy(errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_no_file_to_decrypt))
            return
        }
        if (passphrase != null) {
            _decryptState.value = s.copy(passphrase = passphrase)
        }
        // §5.6.3 (#31): unwrap a zip-wrapped ciphertext, then re-enter with the
        // extracted PGP entry as the input.
        val zipName = s.selectedFileName?.lowercase()
        val looksZip = (zipName != null && zipName.endsWith(".zip")) ||
            (bytes != null && com.pgpony.android.ui.util.ZipPackaging.looksLikeZip(bytes))
        if (looksZip) {
            unwrapZipAndReenter(passphrase)
            return
        }
        // §5.6.10 (CertainBot): a signed-but-not-encrypted .asc (Thunderbird
        // saves signed plain text this way) can't be decrypted. Detect a
        // cleartext-signed file and verify it in place instead of erroring
        // "not encrypted". Small files load inline (INLINE_FILE_LIMIT), which
        // is where signed plain text lands; larger inputs are ciphertext for
        // the streaming path.
        if (bytes != null) {
            val asText = signedFileTextOrNull(bytes)
            if (asText != null) {
                when (verify.detectInputType(asText)) {
                    SignedInputType.CLEAR_SIGNED -> { verifyClearSignedFile(asText); return }
                    SignedInputType.DETACHED_SIGNATURE -> {
                        _decryptState.value = _decryptState.value.copy(
                            errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_detached_signature)
                        )
                        return
                    }
                    else -> {}
                }
                // 4.4.0 RC3 (#30/#31): a composite inline one-pass signed message
                // is a PGP MESSAGE BouncyCastle cannot parse; verify it here.
                val inlineBytes = if (asText.contains("-----BEGIN PGP MESSAGE-----")) {
                    try { com.pgpony.android.crypto.pqc.CompositeSigPacket.dearmor(asText) } catch (_: Exception) { null }
                } else null
                if (inlineBytes != null && CompositeDocumentVerifier.isCompositeInline(inlineBytes)) {
                    verifyCompositeInlinePath(inlineBytes)
                    return
                }
            }
        }
        if (bytes != null) {
            decryptFileAndVerifyPath(_decryptState.value, bytes)
        } else {
            decryptFileStreamingPath(_decryptState.value, uri!!)
        }
    }

    /**
     * §5.6.10 — decode a small selected file to text if it is ASCII-armored
     * PGP, so the signed-message classifier can run on it. Returns null for
     * binary ciphertext (.gpg) or anything without armor, which routes to
     * decrypt as before.
     */
    private fun signedFileTextOrNull(bytes: ByteArray): String? {
        if (bytes.isEmpty()) return null
        val head = String(bytes, 0, minOf(64, bytes.size), Charsets.US_ASCII)
        if (!head.contains("-----BEGIN PGP")) return null
        return try { String(bytes, Charsets.UTF_8) } catch (e: Exception) { null }
    }

    /**
     * §5.6.3 (#31): the selected input is a zip. Scan it (streamed), extract
     * the single PGP-ciphertext entry to a scratch file, and re-enter
     * [decryptFile] with that entry as the input. Zero PGP entries, or
     * several, are reported rather than guessed at.
     */
    private fun unwrapZipAndReenter(passphrase: String?) {
        val s = _decryptState.value
        fileOpJob = viewModelScope.launch(Dispatchers.IO) {
            _decryptState.value = _decryptState.value.copy(isProcessing = true, errorMessage = null)
            try {
                val entryFile = com.pgpony.android.ui.util.ScratchFiles.allocate(
                    PGPonyApp.instance, "zip-payload", "decrypt-zip"
                )
                var count = 0
                var entryName: String? = null
                val raw = if (s.selectedFileBytes != null) {
                    java.io.ByteArrayInputStream(s.selectedFileBytes)
                } else {
                    PGPonyApp.instance.contentResolver.openInputStream(s.selectedFileUri!!)
                }
                raw?.use { input ->
                    java.util.zip.ZipInputStream(input).use { zip ->
                        var e = zip.nextEntry
                        while (e != null) {
                            val nm = e.name
                            val isPgp = !e.isDirectory &&
                                listOf(".gpg", ".pgp", ".asc").any { nm.lowercase().endsWith(it) }
                            if (isPgp) {
                                count++
                                if (entryName == null) {
                                    entryName = nm.substringAfterLast('/')
                                    java.io.FileOutputStream(entryFile).use { zip.copyTo(it) }
                                }
                            }
                            zip.closeEntry()
                            e = zip.nextEntry
                        }
                    }
                }
                val finalName = entryName
                val errorRes = when {
                    finalName == null -> R.string.decrypt_zip_no_pgp
                    count > 1 -> R.string.decrypt_zip_multiple
                    else -> 0
                }
                kotlinx.coroutines.withContext(Dispatchers.Main) {
                    fileOpJob = null
                    if (errorRes != 0) {
                        _decryptState.value = _decryptState.value.copy(
                            isProcessing = false,
                            errorMessage = PGPonyApp.instance.getString(errorRes)
                        )
                    } else {
                        _decryptState.value = _decryptState.value.copy(
                            isProcessing = false,
                            errorMessage = null,
                            selectedFileBytes = null,
                            selectedFileUri = android.net.Uri.fromFile(entryFile),
                            selectedFileName = finalName,
                            selectedFileSize = entryFile.length()
                        )
                        decryptFile(passphrase)
                    }
                }
            } catch (t: Throwable) {
                kotlinx.coroutines.withContext(Dispatchers.Main) {
                    fileOpJob = null
                    _decryptState.value = _decryptState.value.copy(
                        isProcessing = false,
                        errorMessage = PGPonyApp.instance.getString(R.string.decrypt_zip_failed)
                    )
                }
            }
        }
    }

    /**
     * 4.0.4 — the large-file counterpart to decryptFileAndVerifyPath.
     *
     * Streams the picked URI through PGPCryptoService.decryptStream()
     * into a scratch file and never materialises either side. What it
     * gives up relative to the buffered path, all of which needs the
     * whole plaintext in memory and none of which is meaningful at
     * this size:
     *
     *   • the RFC 3156 .eml envelope unwrap (an encrypted email is
     *     not tens of megabytes; if one ever is, it decrypts to a
     *     file the user can save and open)
     *   • MIME routing to the structured attachments sheet
     *   • outputText / outputData, so the text box stays empty
     *
     * Signature verification is unaffected: decryptStream() runs the
     * same decompress-before-verify walk and the same mandatory
     * integrity gate as decrypt().
     */
    private fun decryptFileStreamingPath(s: DecryptUiState, uri: android.net.Uri) {
        fileOpJob = viewModelScope.launch {
            _decryptState.value = _decryptState.value.copy(
                isProcessing = true,
                errorMessage = null,
                processedBytes = 0L,
                totalBytes = s.selectedFileSize ?: 0L,
            )
            var scratch: java.io.File? = null
            // §3 (#15): reuse a cached in-app passphrase for a repeat decrypt
            // on the selected key; remember a freshly entered one on success.
            val cacheFp = s.selectedKeyFingerprint
            val effPass = s.passphrase.ifBlank { null }
                ?: cacheFp?.let { com.pgpony.android.session.InAppPassphraseCache.get(it) }
            try {
                // RC3 §N (#34): primary first, then its enabled fallbacks in
                // the user's order, then everything else (pre-#34 behavior as
                // the safety net) — see fallbackOrderedKeys.
                val orderedKeys = fallbackOrderedKeys(s)
                val secretRings = withContext(Dispatchers.IO) {
                    orderedKeys.mapNotNull { repo.loadSecretKeyRing(it.fingerprint) }
                }
                val verifyRings = withContext(Dispatchers.IO) {
                    repo.getAllKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
                }

                val provisionalName = s.selectedFileName?.let { stripPgpExtension(it) }
                    ?: s.selectedFileName?.let { "decrypted_$it" }
                    ?: "decrypted_output"

                val result = withContext(Dispatchers.IO) {
                    val job = coroutineContext[kotlinx.coroutines.Job]
                    val out = ScratchFiles.allocate(
                        PGPonyApp.instance, provisionalName, ScratchFiles.SCOPE_DECRYPT
                    )
                    scratch = out
                    val resolver = PGPonyApp.instance.contentResolver
                    // 4.2.0 RC6 (#32, tail-4): a large .eml never had its
                    // RFC 3156 envelope unwrapped on this path — only the
                    // buffered (≤4 MB) decrypt did that — so the armor
                    // parser saw "MIME-Version: 1.0" and failed with
                    // "invalid header encountered". Probe pass finds the
                    // armored payload's offset (0 for a plain armored
                    // file, -1 → no skip for binary), real pass skips to
                    // it. See MimeEnvelope.armoredPayloadOffset.
                    val envelopeOffset = resolver.openInputStream(uri)?.use {
                        MimeEnvelope.armoredPayloadOffset(it)
                    } ?: -1L
                    val raw = resolver.openInputStream(uri)
                        ?: throw java.io.IOException("Could not open the selected file")
                    if (envelopeOffset > 0) {
                        var remaining = envelopeOffset
                        while (remaining > 0) {
                            val skipped = raw.skip(remaining)
                            if (skipped <= 0) {
                                if (raw.read() < 0) break
                                remaining--
                            } else remaining -= skipped
                        }
                    }
                    // 4.0.4 — counts ciphertext bytes consumed, which is
                    // the only figure we can report: the plaintext size
                    // is unknown until the literal packet ends.
                    val input = ProgressInputStream(
                        delegate = raw,
                        isCancelled = { job?.isActive == false },
                    ) { read ->
                        _decryptState.value = _decryptState.value.copy(processedBytes = read)
                    }
                    input.use { source ->
                        out.outputStream().buffered().use { sink ->
                            crypto.decryptStream(
                                input = source,
                                output = sink,
                                secretKeyRings = secretRings,
                                passphrase = effPass,
                                verificationKeys = verifyRings
                            )
                        }
                    }
                }

                // The literal-data packet carries the original name; prefer
                // it over the stripped ciphertext name now that we have it.
                // ScratchFiles.allocate sanitises the name, and this rename
                // stays inside the same slot directory.
                val literalName = result.filename?.takeIf { it.isNotBlank() }
                val outFile = if (literalName != null && literalName != provisionalName) {
                    val renamed = java.io.File(
                        scratch!!.parentFile,
                        literalName.substringAfterLast('/').substringAfterLast('\\')
                    )
                    if (withContext(Dispatchers.IO) { scratch!!.renameTo(renamed) }) renamed else scratch!!
                } else {
                    scratch!!
                }

                val verResult = buildVerificationResultForStream(result)

                // 4.1.0 Phase 14 (issue #10, AraafRoyall). This is where
                // the streamed path used to stop, hardcoding
                // showStructuredResultSheet false and presenting the
                // plaintext as a single file. For a Bundle that plaintext
                // IS the multipart/mixed container, so every bundle over
                // INLINE_FILE_LIMIT showed one opaque extensionless file
                // (which nothing can open, hence "corrupted") while every
                // bundle under the limit listed its attachments correctly.
                // Not intermittent: a straight fork on size.
                //
                // The fix is NOT to raise the limit or to call
                // mimeRouteWithAttachments here. Both need the whole
                // plaintext in memory, which is the out of memory bug
                // issue #6 was about. The container is walked on disk and
                // each attachment written out as its own scratch file, so
                // the fixed 64 KiB ceiling the streaming path exists for
                // is preserved end to end.
                val bundle = withContext(Dispatchers.IO) {
                    if (!MimeStreamExtractor.looksLikeBundle(outFile)) {
                        null
                    } else {
                        val dir = java.io.File(outFile.parentFile, "attachments")
                        dir.mkdirs()
                        MimeStreamExtractor.extract(outFile, dir)
                    }
                }
                // The container is now a duplicate of material sitting in
                // the extracted files, and it is plaintext. Drop it. It
                // stays put when extraction did not apply, because then it
                // is the result the user asked for.
                if (bundle != null) runCatching { outFile.delete() }

                _decryptState.value = _decryptState.value.copy(
                    outputText = "",
                    outputData = null,
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    signatureVerified = result.signatureVerified,
                    signerKeyID = result.signerKeyID,
                    decryptedFilename = result.filename,
                    showPassphraseDialog = false,
                    verificationResult = verResult,
                    decryptedFileBytes = null,
                    decryptedFile = if (bundle != null) null else outFile,
                    decryptedOutputFilename = outFile.name,
                    mimeBody = bundle?.body,
                    mimeAttachments = emptyList(),
                    mimeFileAttachments = bundle?.attachments ?: emptyList(),
                    showStructuredResultSheet = bundle != null,
                    showFileDecryptResultSheet = bundle == null
                )
                _events.tryEmit(Event.DecryptSuccess)
                recordDecryptUsage(s.selectedKeyFingerprint)
                if (cacheFp != null && !effPass.isNullOrEmpty()) com.pgpony.android.session.InAppPassphraseCache.put(cacheFp, effPass)
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.PassphraseRequired) {
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_DECRYPT)
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    showPassphraseDialog = true,
                    errorMessage = null
                )
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.InvalidPassphrase) {
                if (cacheFp != null) com.pgpony.android.session.InAppPassphraseCache.clear(cacheFp)
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_DECRYPT)
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase)
                )
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.NoMatchingKey) {
                // 4.1.0 — hidden-recipient offer, streaming twin. The partial
                // plaintext goes either way: nothing was decrypted, and the
                // card retry starts from the picked file again.
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_DECRYPT)
                _decryptState.value = _decryptState.value.copy(
                    processedBytes = 0L,
                    totalBytes = 0L
                )
                if (!offerCardForHiddenRecipient()) {
                    _decryptState.value = _decryptState.value.copy(
                        isProcessing = false,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.encdec_error_decryption_failed_format, e.message ?: ""
                        )
                    )
                }
            } catch (e: Throwable) {
                // 4.0.4 — Throwable, not Exception: an Error escaping here
                // would leave isProcessing true with nothing to clear it,
                // so a failed decrypt would present as a hung one.
                // A partially-written plaintext must never survive either.
                ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_DECRYPT)
                // Cancellation is not identifiable by exception type —
                // decryptStream wraps it — but the Job tells us, and
                // cancelFileOperation() has already reset the UI.
                if (!isActive) return@launch
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    processedBytes = 0L,
                    totalBytes = 0L,
                    errorMessage = if (e is OutOfMemoryError) {
                        PGPonyApp.instance.getString(R.string.encdec_error_file_too_large)
                    } else {
                        PGPonyApp.instance.getString(R.string.encdec_error_decryption_failed_format, e.message ?: "")
                    }
                )
            }
        }
    }

    /**
     * Phase A10c: dismiss the file-decrypt result sheet. Clears the
     * decrypted bytes — once the sheet closes the user has either
     * saved/shared the plaintext or they haven't, and we don't want
     * decrypted material lingering in memory longer than necessary.
     */
    fun dismissFileDecryptResult() {
        // 4.0.4 — the streaming path put the plaintext on disk, so
        // dropping the reference is no longer enough. Same intent as
        // before: once the sheet closes, the user has either saved or
        // shared it or they haven't, and we don't keep it around.
        ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_DECRYPT)
        _decryptState.value = _decryptState.value.copy(
            showFileDecryptResultSheet = false,
            decryptedFileBytes = null,
            decryptedFile = null,
            mimeFileAttachments = emptyList()
        )
    }

    /**
     * Phase A10c: file-mode counterpart to decryptAndVerifyPath(). Same
     * structure — order keys, load secret rings, gather verify rings,
     * call crypto.decrypt() (binary-aware), build VerificationResult,
     * push state, fire haptic event. Differs in:
     *   • input is raw bytes (sniffed by isArmored) not armored text
     *   • on success, flips showFileDecryptResultSheet and stores
     *     decryptedFileBytes + decryptedOutputFilename for the
     *     FileDecryptionResultScreen to render
     *   • passphrase prompt dispatches by mode in Screens.kt so the
     *     existing showPassphraseDialog is reused (same as encrypt
     *     A10b Fix1 pattern)
     */
    private fun decryptFileAndVerifyPath(s: DecryptUiState, bytes: ByteArray) {
        viewModelScope.launch {
            _decryptState.value = _decryptState.value.copy(isProcessing = true, errorMessage = null)
            // §3 (#15): reuse a cached in-app passphrase for a repeat decrypt
            // on the selected key; remember a freshly entered one on success.
            val cacheFp = s.selectedKeyFingerprint
            val effPass = s.passphrase.ifBlank { null }
                ?: cacheFp?.let { com.pgpony.android.session.InAppPassphraseCache.get(it) }
            try {
                // RC3 §N (#34): primary first, then its enabled fallbacks in
                // the user's order, then everything else (pre-#34 behavior as
                // the safety net) — see fallbackOrderedKeys.
                val orderedKeys = fallbackOrderedKeys(s)
                // 4.0.4 — off the main thread. This is the path in the
                // Android 12 / MIUI freeze report: file decrypt loaded every
                // secret ring, then every public ring in the keyring, then
                // ran the decryption itself, all on Dispatchers.Main.
                // Seconds of UI-thread work is an ANR, which presents as
                // either a freeze or a "close app" dialog depending on how
                // aggressively the OEM's watchdog fires.
                val secretRings = withContext(Dispatchers.IO) {
                    orderedKeys.mapNotNull { repo.loadSecretKeyRing(it.fingerprint) }
                }
                val verifyRings = withContext(Dispatchers.IO) {
                    repo.getAllKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
                }

                val result = withContext(Dispatchers.Default) {
                    // RC3 §N (#34): per-ring cascade, any exception → next.
                    decryptWithFallbackCascade(secretRings) { rings ->
                        crypto.decrypt(
                            // 3.1.0 Phase 4 (J2): an encrypted .eml opened as a
                            // file carries the RFC 3156 envelope — unwrap to the
                            // armored payload; binary/plain files pass through.
                            encryptedData = effectiveDecryptFileBytes(bytes),
                            secretKeyRings = rings,
                            passphrase = effPass,
                            verificationKeys = verifyRings
                        )
                    }
                }

                val verResult = buildVerificationResultForEncrypted(result)

                // Derive the suggested output filename. Prefer the
                // OpenPGP literal-data filename (carries the original
                // name embedded by the encrypt-time encoder). Fall
                // back to stripping .pgp/.gpg/.asc from the picked
                // encrypted filename; if neither yields a usable
                // name, prefix "decrypted_" — matches iOS behavior.
                val literalName = result.filename?.takeIf { it.isNotBlank() }
                val stripped = s.selectedFileName?.let { stripPgpExtension(it) }
                val outName = literalName
                    ?: stripped
                    ?: s.selectedFileName?.let { "decrypted_$it" }
                    ?: "decrypted_output"

                // 3.1.0 Phase 4 (J1): content-based routing for file decrypt.
                // MIME parse of the full plaintext — also off main.
                val fileMime = withContext(Dispatchers.Default) {
                    mimeRouteWithAttachments(result.data)
                }
                _decryptState.value = _decryptState.value.copy(
                    outputText = result.plaintext,
                    outputData = result.data,
                    isProcessing = false,
                    signatureVerified = result.signatureVerified,
                    signerKeyID = result.signerKeyID,
                    decryptedFilename = result.filename,
                    showPassphraseDialog = false,
                    verificationResult = verResult,
                    decryptedFileBytes = result.data,
                    decryptedOutputFilename = outName,
                    // 3.1.0 Phase 4 (J1): a decrypted multipart/mixed with
                    // attachments opens the structured sheet instead of
                    // the single-file result.
                    mimeBody = fileMime?.body,
                    mimeAttachments = fileMime?.attachments ?: emptyList(),
                    showStructuredResultSheet = fileMime != null,
                    showFileDecryptResultSheet = fileMime == null
                )
                _events.tryEmit(Event.DecryptSuccess)
                recordDecryptUsage(s.selectedKeyFingerprint)
                if (cacheFp != null && !effPass.isNullOrEmpty()) com.pgpony.android.session.InAppPassphraseCache.put(cacheFp, effPass)
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.PassphraseRequired) {
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    showPassphraseDialog = true,
                    errorMessage = null
                )
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.InvalidPassphrase) {
                if (cacheFp != null) com.pgpony.android.session.InAppPassphraseCache.clear(cacheFp)
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase)
                )
            } catch (e: com.pgpony.android.crypto.PGPCryptoError.NoMatchingKey) {
                // 4.1.0 — the one failure worth turning into an offer.
                if (!offerCardForHiddenRecipient()) {
                    _decryptState.value = _decryptState.value.copy(
                        isProcessing = false,
                        errorMessage = PGPonyApp.instance.getString(
                            R.string.encdec_error_decryption_failed_format, e.message ?: ""
                        )
                    )
                }
            } catch (e: Exception) {
                _decryptState.value = _decryptState.value.copy(
                    isProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_decryption_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── 3.1.0 Phase 4 (J2): RFC 3156 envelope unwrap at decrypt entry ──

    /**
     * If [raw] is an RFC 3156 `multipart/encrypted` entity (an .eml
     * pasted, opened, or shared in — with or without leading email
     * headers), return the armored PGP MESSAGE inside it; otherwise
     * return [raw] unchanged. Called before dearmor at every decrypt
     * entry, mirroring iOS MIMEParser.pgpMIMEEncryptedPayload(in:). A
     * bare armored block is NOT an envelope and passes through as-is.
     */
    private fun effectiveDecryptInput(raw: String): String =
        MimeEnvelope.unwrapText(raw)

    /**
     * 3.1.0 Phase 4 (J2) — file-mode variant: an encrypted .eml opened
     * as a FILE is text carrying the envelope. Unwrap to the armored
     * bytes when present; otherwise return [bytes] unchanged (binary
     * ciphertext, plain armored files).
     *
     * 4.1.0 Phase 7: the body moved to MimeEnvelope. It was duplicated
     * byte for byte in ShareTargetViewModel.unwrapEnvelopeBytes, and
     * Phase 6's fix had to be applied to both copies by hand. See that
     * file for why the fixed-prefix marker scan was replaced outright
     * rather than given a larger number.
     */
    private fun effectiveDecryptFileBytes(bytes: ByteArray): ByteArray =
        MimeEnvelope.unwrapBytes(bytes)

    // ── 3.1.0 Phase 4 (J1): content-based routing after decrypt ────────

    /**
     * Parse decrypted plaintext as MIME and return the message when it
     * carries attachments (→ structured sheet). Body-only and non-MIME
     * return null (existing text/file result paths). Mirrors iOS
     * DecryptView.routeDecrypted.
     */
    private fun mimeRouteWithAttachments(data: ByteArray?): com.pgpony.android.crypto.mime.MimeMessage? {
        val bytes = data ?: return null
        return try {
            MimeParser.parse(bytes)?.takeIf { it.hasAttachments }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Body-only MIME: return the body text so the plain result shows
     * readable content instead of raw MIME; null when not applicable.
     */
    private fun mimeBodyOnly(data: ByteArray?): String? {
        val bytes = data ?: return null
        return try {
            MimeParser.parse(bytes)?.takeIf { !it.hasAttachments }?.body
        } catch (_: Exception) {
            null
        }
    }

    /** 3.1.0 Phase 4 (J1): dismiss the structured result sheet. Clears
     *  the decrypted attachment bytes — same hygiene as the file sheet. */
    fun dismissStructuredResult() {
        // 4.1.0 Phase 14: the streamed bundle path put the extracted
        // attachments on disk, so dropping the list is no longer enough.
        // Same intent the buffered path always had: once the sheet is
        // closed the user has saved or shared them or they have not, and
        // decrypted material does not linger past that.
        ScratchFiles.clearScope(PGPonyApp.instance, ScratchFiles.SCOPE_DECRYPT)
        _decryptState.value = _decryptState.value.copy(
            showStructuredResultSheet = false,
            mimeBody = null,
            mimeAttachments = emptyList(),
            mimeFileAttachments = emptyList()
        )
    }

    /**
     * Phase A10c: helper that strips the OpenPGP-encrypted-file
     * extension off a name and returns the remainder, or null if
     * the name doesn't end in one of the recognized extensions.
     * Mirrors iOS FileDecryptionResultView's originalFileName logic.
     */
    private fun stripPgpExtension(name: String): String? {
        val extensions = listOf(".pgp", ".gpg", ".asc")
        for (ext in extensions) {
            if (name.lowercase().endsWith(ext)) {
                return name.dropLast(ext.length)
            }
        }
        return null
    }

    // ── Phase A3: Signer lookup actions ───────────────────────────────

    /**
     * Open the SignerLookupSheet and kick off a Hagrid keyserver query
     * for the supplied fingerprint. Phase A8 will add WKD discovery in
     * front of this (try WKD by email if we can extract one, fall back
     * to Hagrid by fingerprint). For A3 the only source is Hagrid.
     */
    fun lookupSigner() {
        val s = _decryptState.value
        val claimedFp = s.pendingUnknownClaimedFingerprint
        // 4.1.0 Phase 14d. This used to return here when there was no
        // claimed fingerprint, with a comment reasoning that the banner
        // would not be tappable in that case. The banner is tappable
        // unconditionally (VerificationBanner.kt:86), so on the decrypt
        // path the yellow row simply did nothing when tapped: the
        // decrypt results carry the signature's key ID but not the
        // issuer fingerprint subpacket, so claimedFingerprint is null
        // there. Only the clear-signed path, which goes through
        // VerifyService, ever supplied one.
        //
        // Fall back to the key ID, which is what UnknownSigner's own doc
        // comment prescribes for signatures lacking the subpacket.
        val signerKeyId = (s.verificationResult as? VerificationResult.UnknownSigner)
            ?.signerKeyID?.takeIf { it.isNotBlank() }
        val query = claimedFp ?: signerKeyId ?: return
        _decryptState.value = _decryptState.value.copy(
            showSignerLookup = true,
            signerLookupState = SignerLookupState.Searching
        )
        viewModelScope.launch {
            val armored = try {
                // 4.1.0 Phase 14e. These were the Hagrid-only helpers, so
                // the signer lookup searched keys.openpgp.org and nothing
                // else. findByFingerprint has walked the configured
                // directory (first-party keys.pgpony.app first) since
                // Phase 6 and the import and exchange paths have used it
                // all along; this one screen was still going direct, so a
                // key published only to the first-party server, or a v6
                // or PQC key that keys.openpgp.org will not serve at all,
                // read as "not found".
                if (claimedFp != null) {
                    keyServer.findByFingerprint(claimedFp)?.armoredKey
                } else {
                    keyServer.findByKeyId(query)?.armoredKey
                }
            } catch (e: Exception) {
                _decryptState.value = _decryptState.value.copy(
                    signerLookupState = SignerLookupState.Failed(
                        e.message ?: PGPonyApp.instance.getString(R.string.encdec_error_keyserver_network)
                    )
                )
                return@launch
            }
            if (armored.isNullOrBlank()) {
                _decryptState.value = _decryptState.value.copy(
                    signerLookupState = SignerLookupState.NotFound(query)
                )
                return@launch
            }
            // Parse for preview without saving — we want the user to confirm
            // before adding anything to the keyring.
            val preview = try {
                crypto.importKeyData(armored.toByteArray(Charsets.UTF_8))
            } catch (e: Exception) {
                _decryptState.value = _decryptState.value.copy(
                    signerLookupState = SignerLookupState.Failed(
                        PGPonyApp.instance.getString(R.string.encdec_error_keyserver_parse_format, e.message ?: "")
                    )
                )
                return@launch
            }
            _decryptState.value = _decryptState.value.copy(
                signerLookupState = SignerLookupState.Found(
                    armoredKey = armored,
                    previewUserId = preview.userID,
                    previewFingerprint = preview.fingerprint,
                    previewAlgorithm = preview.algorithm.displayName
                )
            )
        }
    }

    /**
     * Import the key fetched by lookupSigner, then re-verify the
     * currently-pasted clear-signed input. The banner should flip to
     * green Verified once the freshly-imported key is in the rings.
     */
    fun importDiscoveredSigner(armoredKey: String) {
        viewModelScope.launch {
            try {
                val imported = repo.importArmoredKey(armoredKey)
                _decryptState.value = _decryptState.value.copy(
                    signerLookupState = SignerLookupState.ImportSuccess(
                        previewUserId = imported.userID
                    )
                )
                // Refresh keys + re-verify with the larger keyring. The
                // sheet stays on ImportSuccess until the user explicitly
                // closes it so they see confirmation; the banner update
                // happens regardless.
                refreshKeys()
                val cur = _decryptState.value
                if (cur.inputText.isNotBlank()) {
                    // Re-run decrypt(), which will re-route based on input type
                    decrypt()
                }
            } catch (e: Exception) {
                _decryptState.value = _decryptState.value.copy(
                    signerLookupState = SignerLookupState.Failed(
                        "Could not import key: ${e.message}"
                    )
                )
            }
        }
    }

    fun dismissSignerLookup() {
        _decryptState.value = _decryptState.value.copy(
            showSignerLookup = false,
            signerLookupState = SignerLookupState.Searching
        )
    }

    // ── Phase A3: "Verify a file" (detached signature) ─────────────────

    fun openVerifyFileSheet() {
        _decryptState.value = _decryptState.value.copy(
            mode = DecryptMode.VERIFY,
            verifyFileSignedName = null,
            verifyFileSignedUri = null,
            verifyFileSigName = null,
            verifyFileSigBytes = null,
            verifyFileResult = null,
            verifyFileProcessing = false,
            errorMessage = null,
        )
    }

    fun dismissVerifyFileSheet() {
        _decryptState.value = _decryptState.value.copy(
            mode = DecryptMode.TEXT,
            verifyFileSignedName = null,
            verifyFileSignedUri = null,
            verifyFileSigName = null,
            verifyFileSigBytes = null,
            verifyFileResult = null,
            verifyFileProcessing = false,
        )
    }

    /**
     * RC3 §J (#16): reports a SIGNATURE file over
     * [SIGNATURE_FILE_BUFFER_LIMIT] — which, at 1 MiB, means the user
     * picked something that isn't a detached signature. The signed
     * CONTENT file has no limit; it streams (see runVerifyFile).
     */
    fun reportVerifyFileTooLarge() {
        _decryptState.value = _decryptState.value.copy(
            errorMessage = PGPonyApp.instance.getString(R.string.verify_file_error_sig_not_signature)
        )
    }

    /** The original (signed) file the user picked — held as a Uri and
     *  streamed at verify time; never buffered (RC3 §J #16). */
    fun setVerifyFileSigned(name: String, uri: android.net.Uri) {
        _decryptState.value = _decryptState.value.copy(
            verifyFileSignedName = name,
            verifyFileSignedUri = uri,
            verifyFileResult = null,
            errorMessage = null,
        )
    }

    /** The detached signature file (.sig / .asc) the user picked. */
    fun setVerifyFileSignature(name: String, bytes: ByteArray) {
        _decryptState.value = _decryptState.value.copy(
            verifyFileSigName = name,
            verifyFileSigBytes = bytes,
            verifyFileResult = null,
            errorMessage = null,
        )
    }

    /**
     * Verify the picked detached signature against the picked original file.
     * Uses the binary-aware `verifyDetached(ByteArray, …)` overload (A3) so a
     * downloaded `.sig` (binary) or `.asc` (armored) both work. On
     * UnknownSigner, the claimed fingerprint is stashed so the banner's
     * keyserver/WKD lookup (shared with the decrypt flow) can run.
     */
    fun runVerifyFile() {
        val s = _decryptState.value
        val signedUri = s.verifyFileSignedUri
        val sig = s.verifyFileSigBytes
        if (signedUri == null || sig == null) {
            _decryptState.value = s.copy(
                errorMessage = PGPonyApp.instance.getString(R.string.verify_file_error_pick_both)
            )
            return
        }
        _decryptState.value = s.copy(verifyFileProcessing = true, errorMessage = null)
        viewModelScope.launch {
            // 4.4.0 RC3 (#30/#31): a composite detached signature cannot go
            // through BouncyCastle; verify it through the composite path.
            val compositeResult = compositeDetachedFileResult(sig, signedUri)
            if (compositeResult != null) {
                val cfp = (compositeResult as? VerificationResult.UnknownSigner)?.claimedFingerprint
                _decryptState.value = _decryptState.value.copy(
                    verifyFileProcessing = false,
                    verifyFileResult = compositeResult,
                    pendingUnknownClaimedFingerprint = cfp
                        ?: _decryptState.value.pendingUnknownClaimedFingerprint,
                )
                return@launch
            }
            val rings = withContext(Dispatchers.IO) {
                repo.getAllKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
            }
            // RC3 §J (#16): the signed content streams from its Uri in
            // 64 KiB chunks — no whole-file buffer, no size ceiling.
            // Dispatchers.IO because the verify is now disk-bound.
            val result = withContext(Dispatchers.IO) {
                PGPonyApp.instance.contentResolver.openInputStream(signedUri)?.use { input ->
                    verify.verifyDetachedStream(sig, input, rings)
                } ?: VerificationResult.Invalid(
                    reason = PGPonyApp.instance.getString(R.string.sign_verify_error_file_unreadable),
                    signerKeyID = null,
                    signedContent = null
                )
            }
            val claimedFp = (result as? VerificationResult.UnknownSigner)?.claimedFingerprint
            _decryptState.value = _decryptState.value.copy(
                verifyFileProcessing = false,
                verifyFileResult = result,
                pendingUnknownClaimedFingerprint = claimedFp
                    ?: _decryptState.value.pendingUnknownClaimedFingerprint,
            )
        }
    }

    // ── Phase A5: "Sign a file" (detached signature, software key) ─────

    fun openSignFileSheet() {
        val softwareKeys = _encryptState.value.availableSigningKeys.filter {
            it.isKeyPair && !it.isCardBacked
        }
        _encryptState.value = _encryptState.value.copy(
            mode = EncryptMode.SIGN_FILE,
            signFileName = null,
            signFileUri = null,
            // Default to the already-selected signing key if it's software,
            // else the first software key pair.
            signFileSelectedKey = _encryptState.value.signingKey
                ?.takeIf { it.isKeyPair && !it.isCardBacked }
                ?: softwareKeys.firstOrNull(),
            showSignFileKeyPicker = false,
            signFilePassphrase = "",
            signFileArmor = true,
            signFileResultBytes = null,
            signFileResultName = null,
            signFileProcessing = false,
            errorMessage = null,
        )
    }

    fun dismissSignFileSheet() {
        _encryptState.value = _encryptState.value.copy(
            mode = EncryptMode.TEXT,
            signFileName = null,
            signFileUri = null,
            showSignFileKeyPicker = false,
            signFilePassphrase = "",
            signFileResultBytes = null,
            signFileResultName = null,
            signFileProcessing = false,
        )
    }

    /** Software signing key pairs eligible for file signing (no card). */
    fun signableFileKeys(): List<PGPKeyEntity> =
        _encryptState.value.availableSigningKeys.filter {
            it.isKeyPair && !it.isCardBacked
        }

    fun setSignFile(name: String, uri: android.net.Uri) {
        _encryptState.value = _encryptState.value.copy(
            signFileName = name,
            signFileUri = uri,
            signFileResultBytes = null,
            signFileResultName = null,
            errorMessage = null,
        )
    }

    fun showSignFileKeyPicker() {
        _encryptState.value = _encryptState.value.copy(showSignFileKeyPicker = true)
    }

    fun dismissSignFileKeyPicker() {
        _encryptState.value = _encryptState.value.copy(showSignFileKeyPicker = false)
    }

    fun setSignFileKey(key: PGPKeyEntity) {
        _encryptState.value = _encryptState.value.copy(
            signFileSelectedKey = key,
            showSignFileKeyPicker = false,
            signFileResultBytes = null,
            errorMessage = null,
        )
    }

    fun setSignFilePassphrase(text: String) {
        _encryptState.value = _encryptState.value.copy(signFilePassphrase = text)
    }

    fun setSignFileArmor(armor: Boolean) {
        _encryptState.value = _encryptState.value.copy(
            signFileArmor = armor,
            // Result is form-specific; invalidate so the user re-signs.
            signFileResultBytes = null,
            signFileResultName = null,
        )
    }

    /**
     * Phase A5 — produce a detached signature over the picked file with the
     * selected software key. `.asc` (armored) or `.sig` (binary) per
     * [EncryptUiState.signFileArmor]; output named `original.ext.asc/.sig` so
     * `gpg --verify` finds it. The original file is never modified.
     */
    fun runSignFile() {
        val s = _encryptState.value
        val uri = s.signFileUri
        val key = s.signFileSelectedKey
        if (uri == null) {
            _encryptState.value = s.copy(
                errorMessage = PGPonyApp.instance.getString(R.string.sign_file_error_pick_file)
            )
            return
        }
        if (key == null) {
            _encryptState.value = s.copy(
                errorMessage = PGPonyApp.instance.getString(R.string.sign_file_error_pick_key)
            )
            return
        }
        _encryptState.value = s.copy(signFileProcessing = true, errorMessage = null)
        viewModelScope.launch {
            try {
                val secRing = withContext(Dispatchers.IO) {
                    repo.loadSecretKeyRing(key.fingerprint)
                } ?: throw SigningError.NoSigningKey()
                // RC3 §J (#16): stream from the picked Uri — hashes in
                // 64 KiB chunks, no whole-file buffer, no size ceiling
                // (iOS 8.1.0 §3a parity; see SIGNATURE_FILE_BUFFER_LIMIT's
                // doc for the history). Dispatchers.IO because this is
                // now disk-bound, not CPU-bound.
                val sig = withContext(Dispatchers.IO) {
                    PGPonyApp.instance.contentResolver.openInputStream(uri)?.use { input ->
                        signing.signDetachedStream(
                            input = input,
                            secretKeyRing = secRing,
                            passphrase = s.signFilePassphrase.ifEmpty { null },
                            armor = s.signFileArmor,
                        )
                    } ?: throw SigningError.SigningFailed(
                        PGPonyApp.instance.getString(R.string.sign_verify_error_file_unreadable)
                    )
                }
                val ext = if (s.signFileArmor) ".asc" else ".sig"
                val outName = (s.signFileName ?: "file") + ext
                _encryptState.value = _encryptState.value.copy(
                    signFileProcessing = false,
                    signFileResultBytes = sig,
                    signFileResultName = outName,
                    signFilePassphrase = "",
                    errorMessage = null,
                )
            } catch (e: SigningError.PassphraseRequired) {
                _encryptState.value = _encryptState.value.copy(
                    signFileProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.sign_file_error_passphrase_required),
                )
            } catch (e: SigningError.InvalidPassphrase) {
                _encryptState.value = _encryptState.value.copy(
                    signFileProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.encdec_error_incorrect_passphrase),
                )
            } catch (e: Exception) {
                _encryptState.value = _encryptState.value.copy(
                    signFileProcessing = false,
                    errorMessage = PGPonyApp.instance.getString(
                        R.string.sign_file_error_failed_format, e.message ?: e.javaClass.simpleName
                    ),
                )
            }
        }
    }

    fun dismissPassphraseDialog() {
        _decryptState.value = _decryptState.value.copy(showPassphraseDialog = false)
    }

    fun clearEncryptError() {
        _encryptState.value = _encryptState.value.copy(errorMessage = null)
    }

    fun clearDecryptError() {
        _decryptState.value = _decryptState.value.copy(errorMessage = null)
    }

    /**
     * Reset the Encrypt tab to its fresh-app-start state: a brand-new
     * EncryptUiState (clears input, output, file, recipients selection,
     * toggles, mode — everything) then reload the key lists, exactly as
     * happens on launch. Resetting the whole object avoids missing any
     * field that holds displayed content.
     */
    fun clearEncrypt() {
        _encryptState.value = EncryptUiState()
        loadKeys()
    }

    /**
     * Reset the Decrypt tab to its fresh-app-start state: a brand-new
     * DecryptUiState (clears input, output, passphrase, file, verification
     * banner, card-message detection, mode) then reload the key lists.
     */
    fun clearDecrypt() {
        _decryptState.value = DecryptUiState()
        loadKeys()
    }

    fun refreshKeys() = loadKeys()
}
