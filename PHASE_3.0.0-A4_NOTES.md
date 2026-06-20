# PGPony Android 3.0.0 — Phase A4: default / remembered recipient

> 3.0.0 Phase A4 · NET-NEW. The last item in Phase A — with this, A1–A5 + A4
> (+ the KS1 feature request) are all shipped and Phase A is closed.

## What this ships

Stop re-picking the recipient on every encrypt. A persisted Settings option with
three modes:

- **None** — current behavior, no pre-selection.
- **Pinned** — always pre-select one chosen recipient key (the "encrypt to me"
  case; a key dropdown appears under the mode picker).
- **Last used** — pre-select whoever you last encrypted to.

The pre-selection applies on the **Encrypt** tab and in the **Share** flow. The
user can always change it per-encrypt.

## How it works

- **`DefaultRecipientPrefs`** (new) — single source of truth for the three
  pref keys (`default_recipient_mode`, `default_recipient_fp`,
  `last_recipient_fp`) + the `DefaultRecipientMode` enum, shared by all three
  view models so the logic can't drift. `preselectFingerprint(prefs)` returns
  the fingerprint to seed given the current mode.
- **Encrypt:** `EncryptDecryptViewModel.loadKeys()` seeds `selectedRecipients`
  from `preselectFingerprint`, matched against the **live** recipient pool (a
  deleted/stale key seeds nothing). Only seeds when nothing is selected yet, so
  it never clobbers an in-progress selection on tab return. `encrypt()` /
  `encryptFile()` call `recordLastUsed` on the first recipient (drives Last-used).
- **Share:** `ShareTargetViewModel.initialize()` applies the same pre-selection.
- **Settings:** `SettingsViewModel` loads mode + pinned fp + candidate keys;
  `setDefaultRecipientMode` / `setDefaultRecipientKey` persist. Choosing PINNED
  with no key yet auto-pins the first key pair (the common self-encrypt case).
  `SettingsScreen` renders a mode picker (3 FilterChips mirroring the theme
  picker) + a key dropdown when PINNED.

Distinct from the `isDefault` **signing** identity — this is the *recipient*
default.

## Files touched

| File | Change |
|------|--------|
| `ui/settings/DefaultRecipientPrefs.kt` | **new** — `DefaultRecipientMode` enum + prefs helper |
| `ui/encrypt/EncryptDecryptViewModel.kt` | pre-select in `loadKeys`; `recordLastUsed` in `encrypt`/`encryptFile`; `appPrefs` field + import |
| `ui/share/ShareTargetViewModel.kt` | pre-select in `initialize` |
| `ui/settings/SettingsViewModel.kt` | state + load + `setDefaultRecipientMode`/`setDefaultRecipientKey`; `PGPKeyEntity` import |
| `ui/settings/SettingsScreen.kt` | "Default recipient" section (mode picker + pinned-key dropdown) |
| `res/values*/strings.xml` | 6 new `settings_default_recipient_*` keys × 6 locales |

## Acceptance criteria (from the plan)

- ✅ Pinned default → opening Encrypt shows that recipient pre-selected;
  Last-used → the previous recipient; None → unchanged.
- ✅ Setting survives process death (SharedPreferences) and applies in the share
  flow (`ShareTargetViewModel.initialize`).

## Build / verify status

⚠️ Inspection-verified, not compiled here. Verified: string/comment-aware
brace+paren balance on all 5 changed/new Kotlin files; every new symbol grepped
against imports (`DefaultRecipientPrefs` imported in the encrypt VM;
`PGPKeyEntity` imported in `SettingsViewModel` — it was missing once I named the
type; `DefaultRecipientMode` is same-package in Settings; dropdown widgets all
under existing wildcards); 6 strings in 6/6 locales and referenced. Needs local
`./gradlew installDebug`.

### Deploy

```bash
cp -R ~/Downloads/PGPonyAndroid_3.0.0-A4/. ~/Apps/PGPonyAndroid/
cd ~/Apps/PGPonyAndroid
./gradlew installDebug
```

### Test

1. Settings → **Default recipient** → **Pinned** → pick your own key. Open
   Encrypt → that recipient is pre-selected. Encrypt works without touching the
   picker.
2. Switch to **Last used**. Encrypt to contact A, then to contact B. Reopen
   Encrypt → B is pre-selected.
3. **None** → Encrypt opens with no recipient pre-selected (old behavior).
4. Force-stop + reopen → the chosen mode persists.
5. Share a file/text into PGPony → the same recipient is pre-selected in the
   share flow.
6. Pin a key, then delete that key → Encrypt opens with nothing pre-selected (no
   crash, stale fp simply matches nothing).

## Phase A is closed

A1 (symmetric) · A2 (share-sheet files) · A3 (verify a file) · A5 (sign a file,
software) · A4 (default recipient) — all shipped, plus KS1 (keyserver
timestamps). Deferred within Phase A: A5 card-signing + the share-sheet "sign a
shared file" entry → the card phase / A5b. Next up: **Phase B** (hardware card
provisioning — B3 status → B2 admin-PIN/reset → B1 on-card keygen).
