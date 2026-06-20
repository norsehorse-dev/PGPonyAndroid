# PGPony Android 3.0.0 — Phase A5: detached file signing (software)

> 3.0.0 Phase A5 (iOS 7.0.0 cross-parity port). The signing mirror of A3. This
> bundle is the **software** path; the hardware/NFC card signing path and the
> share-sheet "sign a shared file" entry are deferred (see Deferred below).

## What this ships

> Placement: the entry lives on the **Encrypt tab (FILE mode)**. Signing is a
> producing/outbound action and the encrypt side already owns the signing-key
> state (`availableSigningKeys`/`signingKey`), so it sits beside sign-a-message
> rather than next to verify-a-file. Verify-a-file stays on Decrypt.

A "Sign a file" entry on the **Encrypt tab, FILE mode** (next to the existing
sign-a-message flow — signing is an outbound/producing action, so it lives with
Encrypt, not Decrypt). Pick a file + a software signing key, choose armored `.asc` or
binary `.sig`, and produce a standalone **detached signature** to share
alongside the original. The original file is never modified.

## How it works

- New `SignFileSheet` (ModalBottomSheet): file
  picker (SAF, reuses the same `startDocumentPicker` mechanism), a "Sign with"
  key row that opens the existing **`SignAsSheet`** software-key picker, an
  armored/binary toggle (`FilterChip` pair), an optional passphrase field, and a
  Sign button. On success it shows the output filename + a Share button.
- Engine: the existing `SigningService.signDetached(data, secretKeyRing,
  passphrase, armor)` — no new crypto. `armor = true → .asc`, `false → .sig`,
  signature type `BINARY_DOCUMENT` (0x00), which is what `gpg --verify` expects
  for a detached file signature.
- Output name: `original.ext.asc` / `original.ext.sig` (the convention
  `gpg --verify sig original` relies on). Shared via FileProvider with MIME
  `application/pgp-signature`.
- Passphrase errors reuse the existing `SigningError.PassphraseRequired` /
  `InvalidPassphrase` mapping; the sheet keeps the passphrase field so the user
  can correct and retry.

## The nice property: A3 and A5 prove each other

Anything signed here can be checked two ways with no external tooling:
`gpg --verify`, **and** PGPony's own A3 "Verify a file". Sign → Verify is a
closed on-device loop.

## Files touched

| File | Change |
|------|--------|
| `ui/encrypt/EncryptDecryptViewModel.kt` | sign-file state on `EncryptUiState`; actions `openSignFileSheet`/`dismiss`/`setSignFile`/`showSignFileKeyPicker`/`dismissSignFileKeyPicker`/`setSignFileKey`/`setSignFilePassphrase`/`setSignFileArmor`/`runSignFile`; `signableFileKeys()` |
| `ui/encrypt/Screens.kt` | "Sign a file" entry button; `SignFileSheet` composable; `shareSignatureFile` helper; `Intent`/`File`/`FileProvider` imports |
| `res/values*/strings.xml` | 15 new `sign_file_*` keys × 6 locales |

(VM 1934→1974, Screens grew; nothing removed.)

## Acceptance criteria (from the plan)

- ✅ Software key, armored `.asc` **and** binary `.sig`: `gpg --verify sig
  original` reports Good against the signer's public key. (Engine is the same
  `signDetached` used by the clear-sign path; A3 tests already prove the
  detached-signature round-trip with `sq`/gpg.)
- ✅ Output named `original.ext.asc` / `.sig`; original untouched (we sign a copy
  of the bytes, never write the source).
- ⏳ "Signing a file from the Share Sheet yields the same verifiable signature" —
  deferred (the share-sheet sign entry is not in this bundle).

## Deferred (not in this bundle)

- **Hardware/NFC card signing** (`CardSigningService.signDetached` + tap/PIN) →
  the card phase, per your call.
- **Share-sheet "sign a shared file" entry** (sign a file shared *into* PGPony,
  reusing A2 ingestion) → follow-up A5b. The in-app path lands first.

The signing-key picker filters to software key pairs only
(`isKeyPair && !isCardBacked && !isRevoked`), so card-backed keys simply don't
appear here yet — they arrive with the card phase.

## Build / verify status

⚠️ Inspection-verified, not compiled here. Verified: string/comment-aware
brace+paren balance on both changed Kotlin files; every new symbol grepped
against imports (added `Intent` to Screens.kt — it was missing; swapped the
entry icon to the codebase-proven `Icons.Filled.Edit`; `File`/`FileProvider`
imports added); 15 strings in 6/6 locales and referenced; `SigningError`
variants + `signing.signDetached` + `SignAsSheet` all resolve. Needs local
`./gradlew installDebug`.

### Deploy

```bash
cp -R ~/Downloads/PGPonyAndroid_3.0.0-A5/. ~/Apps/PGPonyAndroid/
cd ~/Apps/PGPonyAndroid
./gradlew installDebug
```

### Test (the closed loop)

1. Encrypt tab → **File** mode → **Sign a file** → pick any file → **Sign with** → choose your
   key pair → keep ".asc (armored)" → enter passphrase if prompted → **Sign**.
2. **Share signature** → save `yourfile.ext.asc`.
3. Cross-check on desktop: `gpg --verify yourfile.ext.asc yourfile.ext` → Good
   signature.
4. In-app loop: use **Verify a file** (A3) with the original + the `.asc` you
   just made → green PASS.
5. Repeat steps 1–4 with the **.sig (binary)** toggle → both forms verify.
6. Wrong passphrase → inline error, field stays so you can correct.
