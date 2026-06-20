# Phase A4a — KeyDetailScreen (read-only layout)

## What this phase ships

The "big missing screen" — a full key-detail surface reached by tapping
any key card on the Keyring tab. A4a is the read-only layout pass:
every section renders with live data, navigation works, the QR sheet
generates and displays, and the fingerprint is tap-to-copy. Action
buttons (Trust picker, Contact link, Notes editor, Share / Export /
Set Default / Upload / Revoke / Delete) are rendered with full visual
fidelity to iOS but route through a single "Coming in the next update"
snackbar — A4b replaces each stub with its real handler.

### User-facing change

**Keyring tab key cards become tappable.** Before A4a, tapping a key
card was a no-op (the `onClick` was an empty TODO). Now tapping
navigates to `keyring/{fingerprint}` and renders the detail screen.

**KeyDetailScreen content (top to bottom):**

| Section | Status |
|---------|--------|
| **Header** — hero avatar, name, email, Key Pair / Public Key chip, DEFAULT pill | Live |
| **Fingerprint** — formatted hex groups, tap-to-copy with green "Copied!" feedback for 2s | Live |
| **Details** — Algorithm, Created, Expires (red if expired, amber if < 30 days), Trust Level (tappable, stubbed), Drive Backup (if synced), Key Server (if uploaded) | Live data, Trust tap stubbed |
| **Contact** — Linked contact name + checkmark, OR Link to Contact / Auto-match stubs | Live read, actions stubbed |
| **Notes** — Existing notes rendered, OR Add notes stub | Live read, edit stubbed |
| **QR Code** — Show QR Code button → opens modal sheet with 800x800 QR + formatted fingerprint + Copy / Share buttons | Live (QR + Copy fingerprint); Share stubbed |
| **Actions** — Share Public Key, Export Private Key (orange, key pairs only), Set as Default (key pairs not yet default), Upload to Key Server (key pairs not yet uploaded) | All stubbed |
| **Danger Zone** — Revoke Key (red, key pairs only), Delete Key (red) | All stubbed |

**Top app bar:** back arrow → returns to Keyring tab via
`navController.popBackStack()`.

**Snackbar:** Whatever action the user taps that isn't wired surfaces
as "{Action} — coming in the next update". A4b removes the snackbar
host as each handler lands.

### New files (5)

| File | Lines | Purpose |
|------|------:|---------|
| `ui/keyring/KeyAvatarHero.kt` | 53 | 80dp circular hero avatar; mirrors KeyCard's 44dp version with bigger fonts |
| `ui/keyring/KeyDetailViewModel.kt` | 168 | State + load by fingerprint, ZXing QR encoding, copy-feedback timer, coming-soon channel |
| `ui/keyring/KeyDetailSections.kt` | 633 | All 8 sections + SectionGroup wrapper + DetailRow + ActionRow + date formatter |
| `ui/keyring/KeyDetailQRSheet.kt` | 161 | Modal bottom sheet — QR bitmap + fingerprint label + Copy / Share row |
| `ui/keyring/KeyDetailScreen.kt` | 219 | Scaffold + LazyColumn orchestrator + Loading / NotFound / Loaded branches |

Total new code: 1,234 lines.

### Modified files (additive only)

| File | Before | After | Δ | Purpose |
|------|------:|------:|--:|---------|
| `MainActivity.kt` | 260 | 292 | +32 | Adds `keyring/{fingerprint}` composable with NavType.StringType nav arg, wires `onKeyClick` for `KeyringScreen` |
| `ui/ViewModelFactory.kt` | 38 | 45 | +7 | Adds `KeyDetailViewModel(repo)` factory case |
| `ui/keyring/KeyringScreen.kt` | 342 | 348 | +6 | Adds `onKeyClick` parameter, wires it to the two `KeyCard` rendering sites |

Total additive: +45 lines.

## Architectural notes

### Per-screen VM lifecycle

KeyDetailViewModel is instantiated via `viewModel(factory = factory)`
inside the composable for the detail route. Compose's
back-stack-entry-scoped VM machinery gives us:
- Fresh instance per navigation entry (different fingerprints don't
  share state)
- Automatic disposal when the entry is popped (no manual cleanup)
- Same factory used by all other VMs, so the route doesn't need
  custom DI wiring

The `load(fingerprint)` call is idempotent — re-entering the same
fingerprint after rotation doesn't trigger a re-fetch.

### Section composables — visual fidelity to iOS

The iOS KeyDetailView uses SwiftUI's `List` with `.insetGrouped`
style, which gives each `Section { }` a rounded-corner surface variant
background and a small uppercase label above it. The Compose
equivalent is `SectionGroup` (private composable in
`KeyDetailSections.kt`) — a `Surface` with `RoundedCornerShape(12.dp)`
on `surfaceVariant.copy(alpha = 0.5f)`, with an optional title above.

Adjacent sections separate via 16dp vertical spacing in the parent
`LazyColumn`'s `Arrangement.spacedBy`.

DetailRow and ActionRow are private to `KeyDetailSections.kt` — they
don't need to be promoted to a shared components module yet. If
TrustLevelPicker (A4b) or other future screens need a similar row,
we'll promote then.

### QR generation reuse

QR encoding via ZXing's `QRCodeWriter` was already in the codebase in
`ExchangeViewModel.generateQR()`. KeyDetailViewModel mirrors that
exact pattern (800x800, `EncodeHintType.MARGIN to 1`, RGB_565 bitmap)
so QR sheets from both surfaces produce visually equivalent codes that
scan identically.

In a future cleanup pass (A14?) the QR encoding should probably move
to a shared utility — but for A4a inlining it in the VM is fine.

### Action-button "stub via snackbar" pattern

Each section composable that has actions takes an
`onComingSoon: (String) -> Unit` callback. The screen plumbs that
through to `viewModel.showComingSoon(label)`, which sets
`state.comingSoonLabel`. A `LaunchedEffect` keyed on `comingSoonLabel`
shows the snackbar and immediately clears the label.

In A4b each call site of `onComingSoon` gets replaced by its real
handler. The plumbing stays — the snackbar host just goes unused for
the wired actions.

The Trust Level tap is a special case: it's NOT in a stubbed
ActionRow, it's in DetailsSection's `TrustLevelRow` (the row has its
own chevron and current-trust display). Same `onComingSoon` pattern,
but A4b will replace it with `viewModel.showTrustPicker()` instead.

### "Revoked" state — deferred

iOS KeyDetailView has a revoked-banner section between Header and
Fingerprint when `key.isRevoked`. Android `PGPKeyEntity` doesn't yet
have a revoked field — iOS v5.0 Phase 4 added that and Android hasn't
ported the revocation feature. The banner is therefore omitted in
A4a. Whenever revocation lands on Android (A11 or A12), the banner
slots into KeyDetailSections.kt without touching the rest of the
screen.

## Verified

Structural preservation checks pass:
- `MainActivity.kt`: all 6 bottom-nav screen objects, MainActivity
  class, PGPonyMainScreen + PGPonyTheme, all 4 IntentAction handlers,
  bottomNavScreens, OnboardingScreen — all present
- `KeyringScreen.kt`: KeyringScreen function, FloatingActionButton,
  ProGateSheet, all sheet show/hide handlers, both myKeys and
  contactKeys rendering — all present, KeyCard onClicks now wired
- `ViewModelFactory.kt`: 6 isAssignableFrom branches (was 5)

Manual code review:
- No removals from any modified file
- All new files use Material 3 `material3.*` imports consistently
- No new dependencies needed (ZXing was already in for ExchangeViewModel)
- Compose Material Icons Extended provides all referenced icons

## How to test on device

1. **Tap navigation:** Keyring tab → tap any key card → expect smooth
   navigation to detail screen with back arrow in top bar.
2. **Header:** Avatar circle (purple for key pair, indigo for public
   only), name + email below, "Key Pair" or "Public Key" chip with
   icon, DEFAULT pill if default.
3. **Fingerprint:** Tap anywhere on the formatted fingerprint row →
   green "Copied!" feedback appears for 2 seconds; paste somewhere to
   verify it's the full 40-char hex.
4. **Expires row:** For keys with no expiry shows "Never". If you have
   a key with an expiry < 30 days, the value should render in amber;
   if expired, in red.
5. **Trust Level row:** Tap → snackbar "Change Trust Level — coming
   in the next update".
6. **Contact section:** If no contact linked, see "Link to Contact" +
   "Auto-match by email" buttons; tap either → snackbar. If a contact
   IS linked (rare — needs prior ContactsService link), see the linked
   name + green check + "Unlink Contact" button.
7. **Notes:** If notes exist (likely empty for fresh keys), see
   "Add notes…" stub; tap → snackbar.
8. **QR Code:** Tap "Show QR Code" → modal bottom sheet slides up
   with a large QR + fingerprint below + Copy / Share buttons. Copy →
   snackbar stub (full copy + share lands in A4b along with the rest
   of the action wiring). Dismiss by swiping down or tapping outside.
9. **Actions:** Every action button shows the right tint
   (purple/orange/error-red). All show "Coming in the next update"
   snackbars.
10. **Danger Zone:** Revoke (only if key pair) and Delete both render
    in error-red. Both stubbed.
11. **Back navigation:** Top bar back arrow returns to Keyring tab
    with state preserved (same scroll position, same key list).

## Pending after A4a

**Phase A4b — Actions wired (2-3 weeks)**:
- TrustLevelPicker sheet (4 radio buttons, Save → repo.updateTrustLevel)
- ContactPickerSheet (Android CONTACT_READ permission flow + system picker)
- Auto-match by email (lookup via ContactsService)
- Notes editor (TextField in ModalBottomSheet → repo.updateNotes)
- Share Public Key (Intent.ACTION_SEND with armored key)
- Export Private Key (biometric prompt → Intent.ACTION_SEND)
- Set as Default (repo.setDefaultKey)
- Upload to Key Server (KeyServerRepository.upload)
- QR sheet "Copy" — proper armored copy via repo.exportArmoredPublicKey
- QR sheet "Share" — Intent.ACTION_SEND with bitmap
- Delete (move workflow from KeyringScreen here, surface confirmation)
- Revoke (waits for SigningService.generateRevocationCertificate — new crypto work)

**Phase A11 area** — full revocation feature (revoked banner, isRevoked
field on PGPKeyEntity, revocation cert generation in SigningService).

## Suggested entry for NorseHorse_Android_Update_Log.md

```
## PGPony Android Phase A4a — KeyDetailScreen read-only layout (2026-05-27)

The big missing screen lands. Tapping any key card on the Keyring
tab now navigates to a full key-detail surface with 8 sections of
iOS-parity layout. A4a is the read-only pass — every section
renders with live data, the QR sheet works, the fingerprint
tap-to-copy is fully wired. Action buttons render but route through
a "Coming in next update" snackbar; A4b replaces each stub.

### Added
- ui/keyring/KeyDetailScreen.kt — Scaffold + LazyColumn orchestrator
- ui/keyring/KeyDetailSections.kt — Header, Fingerprint, Details,
  Contact, Notes, QR, Actions, Danger Zone composables
- ui/keyring/KeyDetailQRSheet.kt — Modal QR bottom sheet
- ui/keyring/KeyDetailViewModel.kt — per-screen VM
- ui/keyring/KeyAvatarHero.kt — 80dp hero avatar

### Modified (additive)
- MainActivity.kt: +32 lines. New keyring/{fingerprint} composable
  route with NavType.StringType arg, KeyringScreen wired with
  onKeyClick handler.
- ui/ViewModelFactory.kt: +7 lines. KeyDetailViewModel(repo) case.
- ui/keyring/KeyringScreen.kt: +6 lines. onKeyClick parameter
  threaded through both KeyCard rendering sites.

### iOS port equivalents
- KeyDetailScreen              = iOS KeyDetailView (1103 lines;
                                 Android: ~219 lines because
                                 SwiftUI Section magic is replaced
                                 by explicit SectionGroup composable)
- KeyHeaderSection             = iOS "Header Section"
- FingerprintSection           = iOS "Fingerprint" tap-to-copy
- DetailsSection               = iOS "Details" with iCloud→Drive label
- ContactSection               = iOS "Contact" link/unlink
- NotesSection                 = iOS "Notes" with editor stub
- KeyDetailQRSheet             = iOS QRCodeSheet
- ActionsSection               = iOS "Actions"
- DangerZoneSection            = iOS "Danger Zone"
- KeyAvatarHero                = iOS ContactAvatarView(size: 80)

### Deferred to A4b / later
- Trust picker, contact picker, notes editor, share, export, set
  default, upload, revoke, delete — all stubbed via onComingSoon
- Revoked banner — waits for revocation crypto on Android (post-A11)
```
