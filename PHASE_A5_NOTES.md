# Phase A5 — Sign-as picker for Encrypt tab

## What this phase ships

Replaces the implicit "auto-pick default key" behavior from A2 with a
proper picker in both signing surfaces:

| Surface | Before A5 | After A5 |
|---------|-----------|----------|
| **EncryptModeBody** sign-while-encrypting toggle | Toggle says "Recipients can verify it came from {default-key-owner}" — no way to override | Toggle + tappable Sign-as row when 2+ key pairs exist → SignAsSheet picker |
| **SignModeBody** sign-only mode | Read-only display of the auto-picked default key | Tappable Sign-as row + sheet when 2+ key pairs; static row when 1 key pair |

The 1-key-pair case keeps the static visual — no UI churn for users
with a single identity.

iOS reference is `EncryptView.swift`'s `signingKeyPicker` (a SwiftUI
Picker with `.pickerStyle(.menu)`); Android uses a `ModalBottomSheet`
instead of a dropdown because the per-row content is richer (avatar +
name + email + fingerprint + DEFAULT pill + selection check).

### User-facing change

- Multi-key-pair users now see a "Sign as: {owner}" row directly below
  the "Also sign this message" toggle (Text mode) or as the main
  selection row (Sign mode).
- Tapping the row opens a bottom sheet listing every key pair on the
  device, each with their name/email/short-fingerprint, a DEFAULT pill
  next to the user's default key, and a check icon next to the
  currently selected key.
- Tapping a row applies the selection and dismisses the sheet. The
  next encrypt or sign-only operation uses that key.
- Single-key-pair users see the same visual as before (no choice to
  make).

### No ViewModel changes

A2 already added `signingKey: PGPKeyEntity?`, `availableSigningKeys:
List<PGPKeyEntity>`, `setSigningKey(key)`, and `loadKeys()` already
auto-defaults `signingKey = keyPairs.firstOrNull { it.isDefault } ?:
keyPairs.firstOrNull()`. A5 is purely a UI layer that wires those
existing primitives.

## New files (1)

| File | Lines | Purpose |
|------|------:|---------|
| `ui/encrypt/SignAsSheet.kt` | 259 | ModalBottomSheet listing key pairs; per-row avatar + name + email + fingerprint + DEFAULT pill + selection check |

## Modified files (additive)

| File | Before | After | Δ |
|------|------:|------:|--:|
| `ui/encrypt/Screens.kt` | 614 | 749 | +135 |

Touches:
- New `clickable` import (wildcard `foundation.layout.*` didn't cover it)
- New `SignAsRow` private composable — tappable surface-backed row with
  Sign-as label / current selection / short fingerprint / chevron
- `EncryptModeBody` extended: when `signMessage && availableSigningKeys.size > 1`,
  show `SignAsRow` below the toggle; sheet visibility managed via
  `remember { mutableStateOf(false) }` local to the composable
- `SignModeBody` extended: signature gains `viewModel` parameter; when
  `availableSigningKeys.size > 1` show `SignAsRow`, else render the
  same A2 static row
- The `SignModeBody` call site in `EncryptScreen` updated to pass
  `viewModel`

## Architectural notes

### Why ModalBottomSheet over DropdownMenu

SwiftUI's `Picker(.menu)` style on iOS renders as a popup menu anchored
to the trigger control. Android's equivalent is `DropdownMenu` or
`ExposedDropdownMenuBox`. I considered both and picked ModalBottomSheet
for two reasons:

1. **Row visual density.** A dropdown menu row is essentially a single
   line of text — fine for "Alice (ABCD1234)" but cramped for the
   richer multi-line layout (avatar + 3 stacked text rows + status
   icons) we want here. Sheets accommodate this naturally.
2. **Consistency.** Every other picker added in A3-A4b is a sheet
   (SignerLookupSheet, TrustLevelSheet, NotesEditorSheet,
   ContactLinkSheet, KeyDetailQRSheet). Adding a dropdown for this
   one would break the pattern users have built up.

The one tradeoff: a sheet requires an explicit tap (vs. dropdowns that
expand right under the trigger), but the row's chevron tells the user
"this opens something" — same affordance KeyDetailScreen uses for
tappable rows.

### Sheet visibility is local state

The sheet's open/closed state lives in a `remember { mutableStateOf
(false) }` inside the consuming composable (EncryptModeBody and
SignModeBody each have their own). It's pure UI state with no business
significance — survives recomposition but not process death, which is
the right semantic for a picker. Survived process death would mean the
sheet stays open after Android killed and restored the app, which
nobody wants.

The actual selection write (`setSigningKey`) goes through the VM
because `signingKey` IS business state — it determines what key the
next encrypt operation uses.

### Subkey selection: deferred

The A4b summary mentioned "BC's `PGPSecretKeyRing.secretKey` returns
primary; A5 will add proper SubkeyCapability-based picker". On reading
the actual iOS reference (`EncryptView.swift`), iOS doesn't surface
subkey selection either — it picks the primary signing key and trusts
that for the v1 keys PGPony generates (Ed25519 primary + Cv25519
encryption subkey), that's always correct.

For PGPony-generated keys the primary IS the signing key, full stop.
For imported keys with multiple signing-capable subkeys, picking the
primary is what GnuPG does by default too. If/when v6 multi-subkey
scenarios arrive, a second-level subkey picker can land as its own
small phase; it doesn't gate v1.0.

A5 ships KEY-PAIR-level selection only, matching iOS exactly.

### Single-key-pair vs. multi-key-pair branching

`state.availableSigningKeys.size > 1` is the gate. The asymmetric UX:

- **0 keys:** "No key pair available" placeholder text. Same as A2.
- **1 key:** Static informational row (the A2 visual). No picker —
  there's no choice to make.
- **2+ keys:** Tappable Sign-as row that opens the picker sheet.

The 2-key threshold matches iOS exactly (`keyPairs.count > 1`).

## Verified

Structural preservation checks pass:
- All 5 original Composable functions still present in `Screens.kt`:
  EncryptScreen, DecryptScreen, EncryptModeBody, SignModeBody,
  FileModePlaceholder
- All A3-era integrations preserved: VerificationBanner (2 refs),
  SignerLookupSheet (4 refs), ScreenTooltip (3 refs)
- A5 integration sites: 2 `SignAsSheet` renderings + 2 `SignAsRow`
  invocations + 1 private SignAsRow definition

Line counts grew (no removals): Screens.kt 614 → 749 (+135 lines).
New file SignAsSheet.kt is 259 lines.

## How to test on device

Quick acceptance flow:

1. **Single-key-pair user (NorseHorse's current setup):**
   - Encrypt tab → Text mode → toggle "Also sign this message" on →
     **no Sign-as row appears** below the toggle (only 1 key, nothing
     to choose). Static text continues to read "Recipients can verify
     it came from NorseHorse".
   - Encrypt tab → Sign mode → "Sign as" section shows the same A2
     static surface-backed row with NorseHorse's name + fingerprint.

2. **Multi-key-pair user (generate or import a second key pair to
   test):**
   - Encrypt tab → Text mode → toggle "Also sign this message" on →
     **tappable Sign-as row appears** below the toggle with the
     current selection (default key) shown.
   - Tap the row → bottom sheet slides up listing all key pairs.
   - Default key has the DEFAULT pill next to its name.
   - Currently selected key has a check icon on the right.
   - Tap a different key → sheet dismisses → row updates to show the
     new selection → tapping Encrypt now signs with that key.
   - Encrypt tab → Sign mode → "Sign as" section directly renders the
     tappable picker row (no toggle to flip first).

3. **Persistence:** Pick a non-default key → leave the Encrypt tab →
   come back. The selection persists for the lifetime of the VM
   (process). On a fresh process the auto-default kicks back in.
   Phase A6+ can add SharedPreferences persistence of last-used
   signing key if desired (not in scope for A5).

## Pending after A5

Per the plan v2: **Phase A6** — recipient-side parity work, then
**A7-A14** in sequence. Nothing follow-up directly on A5.

If multi-signing-subkey selection becomes a need (post-v1.0, when v6
keys with multiple signing subkeys land), a second-level subkey picker
can be added to SignAsSheet as a per-row expansion or as a separate
follow-on sheet.

## Suggested entry for NorseHorse_Android_Update_Log.md

```
## PGPony Android Phase A5 — Sign-as picker (2026-05-27)

Replaces the implicit "auto-pick default key" behavior with a proper
picker. Multi-key-pair users can now choose which identity to sign
as on a per-message basis, in both the sign-while-encrypting and
sign-only flows.

### Added
- ui/encrypt/SignAsSheet.kt — ModalBottomSheet listing all key pairs
  with per-row avatar + name + email + fingerprint + DEFAULT pill +
  selection check. iOS-parity reference: EncryptView.swift's
  `signingKeyPicker` (uses .pickerStyle(.menu) on iOS; we picked
  ModalBottomSheet for visual consistency with other A3-A4b sheets).

### Modified (additive)
- ui/encrypt/Screens.kt: +135 lines. New SignAsRow private
  composable. EncryptModeBody renders the row below the
  sign-while-encrypting toggle when 2+ key pairs exist. SignModeBody
  renders the picker row when 2+ key pairs exist; keeps the static
  A2 visual when only 1 key pair. New foundation.clickable import.

### iOS port equivalents
- SignAsSheet                = iOS EncryptView.signingKeyPicker
- SignAsRow                  = (no direct iOS equivalent — iOS uses
                               Picker label inline; Android needs an
                               explicit trigger surface for the sheet)

### Deferred
- Subkey-level selection within a key pair: not needed for v1.0 keys
  (PGPony-generated Ed25519+Cv25519 primary IS the signing key).
  Revisit if multi-signing-subkey scenarios arise post-v1.0.
```
