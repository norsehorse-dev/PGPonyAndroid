# PGPony Android 3.0.0 — Phase A3: "Verify a file" (detached signatures)

> 3.0.0 Phase A3 (iOS 7.0.0 port). EXTEND — `verifyDetached` already took bytes,
> but there was no file-input entry and no binary `.sig` support. See master
> plan §A3.

## What this phase ships

The classic mobile PGP task: verify a downloaded file against its detached
signature. New "Verify a file" entry on the Decrypt screen → pick the original
file + its `.sig`/`.asc` → PASS / FAIL / UNKNOWN-SIGNER with signer identity.

## Changes

1. **Binary `.sig` overload (DIVERGES).** `VerifyService.verifyDetached` only
   took an armored `String`. A real release `.sig` is usually a *binary*
   signature packet. Added `verifyDetached(signatureBytes: ByteArray,
   signedBytes, rings)` that sniffs for the armor header and parses either form
   (`parseFirstSignatureBytes`). Both overloads now share one verify core
   (`verifyParsedSignature`) — resolve signer → cryptographic check → PASS /
   FAIL / UNKNOWN. The armored-`String` overload stays for the pasted/clear-
   signed text path.

2. **"Verify a file" UI.** A self-contained `VerifyFileSheet`
   (`ModalBottomSheet`) with two SAF pickers (original file + signature),
   reached from a new "Verify a file" button under the Decrypt action. Reuses
   the existing `VerificationBanner` for the result and, on UNKNOWN-SIGNER, the
   existing `SignerLookupSheet` (via the shared `lookupSigner()` /
   `pendingUnknownClaimedFingerprint`) so the user can fetch the signer's key
   from a keyserver/WKD and re-verify.

3. **ViewModel.** New verify-file state on `DecryptUiState`
   (`verifyFile*` fields) and actions: `openVerifyFileSheet`,
   `dismissVerifyFileSheet`, `setVerifyFileSigned`, `setVerifyFileSignature`,
   `runVerifyFile`. Verification runs off the main thread
   (`withContext(Dispatchers.IO)` to load rings, `Dispatchers.Default` to
   verify).

## Files touched + iOS counterparts

| File | What changed | iOS counterpart |
|------|--------------|-----------------|
| `crypto/VerifyService.kt` | binary `.sig` overload + shared verify core + `parseFirstSignatureBytes` | `SigningService` / verify path |
| `ui/encrypt/EncryptDecryptViewModel.kt` | verify-file state + 5 actions | `DecryptView` model |
| `ui/encrypt/Screens.kt` | "Verify a file" button + `VerifyFileSheet`/`VerifyFilePickRow` | `DetachedVerifyView` / `VerifyDownloadView` |
| `app/src/test/.../VerifyServiceTest.kt` | 4 binary-overload tests | — |
| `res/values/strings.xml` (+ 5 locales) | 7 new `verify_file_*` keys | — |

## Tests added (VerifyServiceTest)

- `verifyDetachedBytesReturnsVerifiedForBinarySig` — sign `armor=false` → verify
  bytes → PASS.
- `verifyDetachedBytesAlsoHandlesArmoredSigBytes` — `armor=true` bytes through
  the byte overload (sniffer detects armor) → PASS.
- `verifyDetachedBytesReturnsInvalidForTamperedData` — wrong content → FAIL.
- `verifyDetachedBytesReturnsUnknownSignerWhenSignerNotInRings` → UNKNOWN with a
  populated claimed fingerprint.

## Design notes

- **One verify core.** Extracting `verifyParsedSignature` means the armored and
  binary paths can't drift; the only difference is parsing the input.
- **Reuse, don't rebuild.** The banner and signer-lookup sheet already existed
  for clear-signed verify; the verify-file flow plugs into the same components
  and the same `lookupSigner()` action. The shared signer-lookup fields are safe
  to reuse because decrypt and verify-file are never active simultaneously.
- **Re-verify after import is manual (v1).** After fetching an unknown signer's
  key via the lookup sheet, tap **Verify** again — the freshly imported key is
  now in the ring. Auto-re-verify would require touching `importDiscoveredSigner`
  (which currently re-runs decrypt), so it's deferred.
- **Pickers are sequential.** `MainActivity.startDocumentPicker` uses a single
  pending callback; picking the file then the signature works because each pick
  completes before the next.

## Acceptance criteria (from the plan)

- ✅ A release artifact + its detached `.asc` **or** `.sig` verifies PASS against
  the signer's key; a tampered file → FAIL (covered by the 4 new tests + manual).
- ✅ Signer identified by fingerprint and, when known, by contact name
  (`resolveSignerIdentity`, already wired into `VerificationResult.Verified`).

## Build / verify status

⚠️ Inspection-verified, not yet compiled here. Verified: string/comment-aware
brace+paren balance on all 3 changed Kotlin files + the test; 7 new strings in
6/6 locales and referenced; `VerificationBanner`/`SignerLookupSheet` already
imported; `Dispatchers`/`withContext` imports added to the VM (they were
previously unused there). Needs local `./gradlew testDebugUnitTest`
(the 4 new VerifyService tests should pass) + `installDebug`.

### Deploy

```bash
cp -R ~/Downloads/PGPonyAndroid_3.0.0-A3/. ~/Apps/PGPonyAndroid/
cd ~/Apps/PGPonyAndroid
./gradlew testDebugUnitTest installDebug
```

### Test

1. On a desktop, sign a file with GnuPG: `gpg --detach-sign --armor file.bin`
   (→ `file.bin.asc`) and also `gpg --detach-sign file.bin` (→ `file.bin.sig`,
   binary). Export your public key and import it into PGPony.
2. PGPony → Decrypt tab → **Verify a file** → pick `file.bin` and `file.bin.sig`
   → **Verify** → green PASS with your name.
3. Repeat with `file.bin.asc` (armored) → PASS.
4. Edit `file.bin` by a byte → Verify again → red FAIL.
5. Verify a file signed by a key you don't have → yellow UNKNOWN-SIGNER; tap it
   to look up the signer, import, then tap Verify again → PASS.
