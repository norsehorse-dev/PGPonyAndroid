# PGPony Android 3.0.0 — Phase C0: Password Store foundations

> 3.0.0 Phase C0 · NET-NEW. Foundations for read-only `pass` (password-store)
> integration: the data models, the tolerant entry parser, SAF folder access,
> persistence, the Settings opt-in, and a store list/import screen. Browsing +
> decryption are C1; hardware decrypt C2; write/edit C3.

## What this ships

- A **Password Store** section in Settings (opt-in, default OFF). When enabled it
  reveals a "Require biometric" toggle (default ON) and an "Open Password Store"
  action.
- A **Password Store** screen: import an existing `pass` folder via the system
  folder picker, see imported stores listed (name + recipient count from the root
  `.gpg-id`), and remove a store reference. Read-only; PGPony never modifies the
  folder.

## Architecture (port of iOS, DIVERGES on file access)

| Piece | File | Notes |
|---|---|---|
| Models | crypto/pass/PassModels.kt | PassStoreRef (treeUri, not iOS bookmark), PassNode, PassField, PassEntryContent |
| Parser | crypto/pass/PassEntryParser.kt | byte-for-byte port of iOS PassEntryParser |
| Persistence | crypto/pass/PassStorePrefs.kt | store refs as JSON in pgpony_prefs (SharedPreferences) |
| File access | crypto/pass/PassStoreService.kt | SAF: OpenDocumentTree + takePersistableUriPermission + DocumentFile tree walk, .gpg-id read, leaf byte read |
| UI | ui/pass/PassStoreListScreen.kt | list + import (OpenDocumentTree launcher) + remove |
| Settings | SettingsViewModel + SettingsScreen | pass_store_enabled (off), biometric_pass_store (on) |
| Route | MainActivity | composable("pass_store"), reached from Settings (NOT a bottom-nav tab) |

**DIVERGES from iOS:** Android uses the **Storage Access Framework** (persistable
tree URI + androidx.documentfile) instead of iOS security-scoped bookmarks. The
store is referenced in place, so it reflects whatever the user syncs in.

**DIVERGES on nav:** the Android bottom nav is already at 6 tabs, so Password
Store is an opt-in Settings entry + non-tab route (like the card_* screens), not
a 7th tab. Reinforces "PGP tool that reads pass," not a password manager.

## Parser validated offline

Replicated the parser logic and ran the plan's edge cases: empty, password-only,
no trailing newline, CRLF/LF, multi-colon values (first colon only), bare URL
lines (kept freeform via the "//"-after-colon rule), `url: https://…` correctly a
field, otpauth case-insensitive + first-wins, empty-key colon falls through. All
behave as intended.

## Decisions (flagged)

- **Strings are English-only in values/** for the pass feature, matching iOS,
  which hardcodes the pass UI in English (e.g. Text("No Stores Yet")) rather than
  localizing it. This follows the card-subsystem precedent (English-only ships
  fine; no lint enforcement). If you want full 6-locale translation for the pass
  feature, say so and I'll mirror them — but iOS itself doesn't.
- Store rows are **non-clickable in C0** (display + remove only); tapping to
  browse is wired in C1 when PassBrowserScreen exists.
- `requireBiometricForPassStore` (default on) is stored now; it GATES store entry
  in C1 (no gate to apply yet in C0 since there's no decryption surface).

## Carried forward for C1/C2/C3 (already in PassStoreService, unused in C0)

walkTree (filenames-only PassNode tree), readEntryBytes (leaf bytes for decrypt),
recipientsForEntry (nearest .gpg-id, for C3 writes), resolveRoot (revoked-grant
re-pick). PassEntryParser is ready for C1.

## Files touched

app/build.gradle.kts (+documentfile 1.0.1); crypto/pass/{PassModels,
PassEntryParser, PassStorePrefs, PassStoreService}.kt (new);
ui/pass/PassStoreListScreen.kt (new); ui/settings/SettingsViewModel.kt (2 flags);
ui/settings/SettingsScreen.kt (Password Store section); MainActivity.kt
(pass_store route + onOpenPassStore); res/values/strings.xml (17 strings + 1
plural, English-only).

## Build / verify status

Inspection-verified; parser logic validated offline; not compiled here. Verified:
brace/paren balance on all 8 changed/new Kotlin files; every icon proven in the
codebase; all pass strings present once + referenced; plural + documentfile dep
present; pass_store route + Settings wiring intact; no unescaped apostrophes in
strings.xml (the B1 lesson, now a standing check). Needs local ./gradlew
installDebug.

### Deploy

```bash
cd ~/Downloads
unzip -o PGPonyAndroid_3.0.0-C0.zip
cp -R ~/Downloads/PGPonyAndroid_3.0.0-C0/. ~/Apps/PGPonyAndroid/
cd ~/Apps/PGPonyAndroid
./gradlew installDebug
```

### Test

1. Settings -> Password Store -> enable. The biometric toggle + "Open Password
   Store" appear.
2. Open Password Store -> Import store -> pick a real `pass` folder (e.g. a synced
   ~/.password-store). The store appears with its name and "N recipients" from the
   root `.gpg-id`.
3. Re-open the app -> the store is still listed (persisted tree URI + permission).
4. Remove a store -> only the reference is removed; the folder is untouched.

Note: browsing into a store and decrypting entries is C1 — store rows don't
navigate yet.

## Next: C1 — browse + software decrypt

PassBrowserScreen (folder nav from walkTree), PassDecryptCoordinator (route to
PGPCryptoService.decrypt), PassEntryScreen (password reveal/copy via
ClipboardService, fields, otpauth display), biometric gate on entry.
