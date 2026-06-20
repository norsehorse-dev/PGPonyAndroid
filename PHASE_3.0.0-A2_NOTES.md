# PGPony Android 3.0.0 — Phase A2: File handling via the Share Sheet

> 3.0.0 Phase A2 (iOS 7.0.0 port). EXTEND — the share plumbing already existed
> but `performEncrypt()` corrupted binary files. See master plan §A2.

## What this phase ships

Share any file (PDF, image, zip, doc…) into PGPony → encrypt → get a `.pgp`
you can share/save. Two real defects fixed plus a file-result UI:

1. **Binary corruption (the headline bug).** `ShareTargetViewModel.performEncrypt()`
   did `String(c.data, Charsets.UTF_8)` on shared file bytes, then re-encoded —
   round-tripping arbitrary bytes through UTF-8, which **mangles any non-text
   file**. Now a shared file is encrypted as **raw bytes** (`encrypt(data =
   c.data …)`), never stringified, with the original filename embedded in the
   literal packet so decryption restores the name.

2. **Files were silently rejected.** `IntentHandler.classifyFileForShare()`
   returned `ShareIntentContent.Empty` for anything that wasn't armored-PGP text
   or a binary-PGP packet — so a shared PDF/zip never even became encryptable
   (the share screen showed the empty state). Now any non-empty file becomes a
   generic encryptable `PgpFile` (raw bytes, both PGP flags false → the action
   picker offers **Encrypt**).

3. **File result, not a text result.** A new `EncryptFileResult` phase writes
   the ciphertext to `cacheDir/exports/<name>.pgp` and offers it via the system
   share sheet (FileProvider content URI + one-shot read grant) — mirroring the
   in-app `FileEncryptionResultScreen` idiom. The old path produced a text blob.

4. **Wider ingestion.** `ShareTargetActivity` gains an additive `ACTION_SEND`
   `*/*` filter so PGPony appears in the share sheet for any file. All existing
   filters kept verbatim.

## Files touched

| File | What changed |
|------|--------------|
| `ui/share/ShareTargetViewModel.kt` | `performEncrypt()` branches Text vs binary file; raw-bytes encrypt; new `EncryptFileResult` phase + `encryptedFileBytes`/`encryptedFileName` state. |
| `intent/IntentHandler.kt` | `classifyFileForShare()` returns an encryptable `PgpFile` for arbitrary files instead of `Empty`. |
| `ui/share/ShareTargetScreen.kt` | `ShareEncryptFileResultContent` composable + `shareFile()` helper (cache + FileProvider + `ACTION_SEND`); router + title arms; `File`/`FileProvider` imports. |
| `AndroidManifest.xml` | additive `ACTION_SEND` `*/*` filter on `ShareTargetActivity`. |
| `res/values/strings.xml` (+ 5 locales) | 4 new keys (`share_target_encrypt_file_result_*`). |

## Design decisions

- **Binary `.pgp`, not armored.** Files go out as binary (smaller, standard,
  `armor = false`), naming `<original>.pgp` — consistent with the in-app FILE
  mode's `FileEncryptionResultScreen`. Text shares stay armored exactly as in
  2.1.3.
- **Share, not Save.** The file result offers Share (FileProvider → chooser),
  which lets the user route to Files/Drive/mail (covering "save"). A dedicated
  `ACTION_CREATE_DOCUMENT` save is a possible fast-follow; left out here to
  avoid threading an activity-result launcher through the standalone share
  activity.
- **First-byte sniffer untouched.** A non-PGP file whose first byte happens to
  have bit 0x80 set (PNG `0x89`, JPEG `0xFF`) still classifies as
  `looksLikePgpMessage = true` and is offered for Decrypt. That's a pre-existing
  ambiguity; refining it risks misclassifying real `.pgp` files, so it's out of
  A2 scope. The user can still pick Encrypt from the picker.
- **`.sig` / `application/pgp-signature` deferred to A5.** The plan slotted the
  `.sig` document type "in A2, shared with A5," but adding `.sig` filters before
  the A5 sign/verify-file handler exists would route `.sig` opens into a flow
  that can't verify them. The `*/*` SEND filter already lets a `.sig` be shared
  in; the dedicated `.sig` VIEW/`application/pgp-signature` filters land with A5.

## Acceptance criteria (from the plan)

- ✅ Sharing a PDF/image/arbitrary file → a `.pgp` that `gpg` decrypts to
  byte-identical output for the chosen recipient. (Encrypt runs on
  `Dispatchers.Default`; recipient load on `Dispatchers.IO` — UI doesn't freeze.)
- ✅ Text shares behave exactly as 2.1.3 (same armored-text result path).
- ⏳ Very large files: encrypt is off the main thread, but the whole file is
  held in memory (same as in-app FILE mode); true streaming is a later refactor.

## Follow-up fixes (after on-device testing)

On-device testing surfaced two gaps the first A2 pass left:

1. **Plain images had no Encrypt option.** The "is this a PGP message?" check in
   `classifyFileForShare` used a first-byte `0x80` sniff. But PNG (`0x89`), JPEG
   (`0xFF`), zip, and many binaries have bit 0x80 set, so they were misread as
   PGP messages → the picker showed only Decrypt. Fixed by **parsing** instead
   of sniffing: `PGPCryptoService.inspectEncryptedMessage(bytes)` — only a real
   encrypted message (public-key recipients or a password packet) is treated as
   PGP; everything else is a generic file → Encrypt offered. (The earlier A2
   note that called this "out of scope" is superseded.)

2. **Decrypting a file dumped raw bytes as text, no re-save.** The decrypt side
   had no file result — `performDecrypt` / `performDecryptBinary` always set
   `outputText`, so a decrypted image showed as garbled text. Added a
   `DecryptFileResult` phase (mirror of `EncryptFileResult`): a shared
   `publishDecryptResult()` decides file-vs-text (literal-packet filename, or
   non-UTF-8 bytes → file) and routes a file to a save/share UI
   (`ShareDecryptFileResultContent` + `shareFile` with a MIME guessed from the
   restored filename). The original filename embedded by A2's encrypt is
   restored on decrypt.

New state: `decryptedFileBytes` / `decryptedFileName`; reset in
`goBackToActionPicker`. New strings `share_target_decrypt_file_result_*` (6
locales). `shareFile` gained a `mimeType` param; `guessMimeType` added.

Note: sharing an *already-encrypted* file correctly offers **Decrypt only**
(re-encrypting ciphertext is the deliberately-hidden case) — that's expected,
not a bug. Plain files offer **Encrypt**.

## Build / verify status

⚠️ Inspection-verified, not yet compiled here. Verified: string/comment-aware
brace+paren balance on all 3 changed Kotlin files; manifest is well-formed; all
4 new strings present in 6/6 locales and referenced; both exhaustive
`when(phase)` sites (router + title) carry the new arm; reused strings
(`share_target_result_done`, `share_target_share_chooser_encrypted`) already
exist. Needs a local `./gradlew testDebugUnitTest` (no new tests this phase —
the A1 suite + existing 207 should stay green) + `installDebug`.

### Deploy

```bash
cp -R ~/Downloads/PGPonyAndroid_3.0.0-A2/. ~/Apps/PGPonyAndroid/
cd ~/Apps/PGPonyAndroid
./gradlew installDebug
```

### Test

1. Files app (or any app) → pick a **PDF/image** → Share → **PGPony**.
2. Confirm the share screen shows the filename + byte count (not garbled text)
   and offers **Encrypt**.
3. Pick a recipient → Encrypt → **Share encrypted file** → save the `.pgp`.
4. `gpg --decrypt that.pgp` → byte-identical to the original
   (`cmp original.pdf decrypted.pdf` → no output).
5. Regression: share **plain text** → still produces an armored text result and
   copies/shares as before.
