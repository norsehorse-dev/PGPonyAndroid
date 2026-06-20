# PGPony Android 3.0.0 — Phase C1: browse + software decrypt

> 3.0.0 Phase C1 · builds on C0. Browse a pass store's folder tree and decrypt
> entries with a software key. Hardware-key decrypt is C2; write/edit is C3.

## What this ships

- **Browse:** tapping a store opens its folder tree (folders + entries, built
  from filenames only — never bulk-decrypts). Folder navigation is an in-memory
  path stack so arbitrary depth works; system Back pops folders before leaving.
- **Decrypt + view:** tapping an entry opens a detail screen. "Decrypt entry"
  (gated by the optional pass-store biometric) decrypts lazily with a software
  key, then shows the password (reveal/copy), `key: value` metadata (per-field
  copy), any detected `otpauth://` URI (read-only — no code generation), and
  freeform notes. Passphrase-protected keys prompt once and retry.
- Every copy goes through the auto-clearing ClipboardService. FLAG_SECURE blocks
  screenshots / recents thumbnails while an entry is open. Plaintext lives only
  in composable state and is dropped when the screen closes.

## Components

| File | Role |
|---|---|
| crypto/pass/PassDecryptCoordinator.kt | new — software secret-ring gather + PGPCryptoService.decrypt; hasCardKey for C2 routing |
| ui/pass/PassBrowserScreen.kt | new — folder tree (walkTree off main thread) + in-memory path stack |
| ui/pass/PassEntryScreen.kt | new — gate → decrypt → display; passphrase retry; reveal/copy; FLAG_SECURE |
| ui/pass/PassStoreListScreen.kt | store rows re-enabled to navigate into the browser |
| MainActivity.kt | pass_browser/{storeId} + pass_entry/{storeId}/{relPath} routes (relPath URL-encoded) |
| res/values/strings.xml | 23 strings (English-only, matching iOS + C0) |

## Decrypt path (port of iOS, software half)

readEntryBytes -> PGPCryptoService.decrypt(bytes, softwareRings, passphrase).
decrypt() sniffs armored vs binary and selects the matching secret key by PKESK
key id, so all software keypair rings are passed and BC picks the right one. On a
first failure with no passphrase, the key is likely passphrase-protected -> prompt
once, retry. If there are NO software keypairs but a card key exists, the entry
reports "needs a hardware key" (C2); otherwise "no matching key."

## Biometric gate

Mirrors the existing decrypt gate: if `biometric_pass_store` (default on) and
biometric is available, BiometricGate.authenticate precedes the decrypt; else it
proceeds. Reuses BiometricGate + BiometricAvailability.

## Files touched

crypto/pass/PassDecryptCoordinator.kt (new); ui/pass/PassBrowserScreen.kt,
PassEntryScreen.kt (new); ui/pass/PassStoreListScreen.kt (row navigation);
MainActivity.kt (2 routes + imports + onOpenStore); res/values/strings.xml (23).

## Build / verify status

Inspection-verified; not compiled here. Verified: brace/paren balance on all
changed/new files; icons resolve via material-icons-extended (Visibility/
VisibilityOff are canonical reveal icons); all 23 strings present once +
referenced; routes + imports + onOpenStore wired; no unescaped apostrophes
(standing check). Needs local ./gradlew installDebug.

### Deploy

```bash
cd ~/Downloads
unzip -o PGPonyAndroid_3.0.0-C1.zip
cp -R ~/Downloads/PGPonyAndroid_3.0.0-C1/. ~/Apps/PGPonyAndroid/
cd ~/Apps/PGPonyAndroid
./gradlew installDebug
```

### Test (with a real pass store synced to the device)

1. Settings -> Password Store -> enable -> Open Password Store -> import a store
   (if not already from C0).
2. Tap the store -> the folder tree appears (folders + entries). Navigate into a
   subfolder; Back returns up the tree, then out.
3. Tap an entry -> "Decrypt entry". If biometric gate is on, authenticate. If the
   key is passphrase-protected, enter the passphrase.
4. Verify: password reveals/copies; metadata fields copy; an otpauth entry shows
   the URI read-only; copies auto-clear from the clipboard.
5. **Interop:** decrypt an entry you can also `pass show` on the desktop — the
   password + fields must match exactly.
6. Try to screenshot an open entry -> blocked (FLAG_SECURE).

Note: an entry encrypted only to a hardware key reports that hardware decryption
is coming next — that's C2.

## Next: C2 — hardware-key decrypt

Route an entry encrypted to a card key through CardDecryptService.decryptBytes
(NFC + PW1 PIN + tap), reusing the existing card-decrypt flow, honoring the
pass-store biometric gate. PassDecryptCoordinator.hasCardKey + recipient matching
decide software-vs-card routing.
