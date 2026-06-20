# Phase A4b — KeyDetailScreen actions wired

## What this phase ships

All A4a action stubs replaced with real handlers. Tapping any of these
in the key-detail screen now does the actual thing instead of showing
the "Coming in next update" snackbar:

| Action | Wired behavior |
|--------|----------------|
| **Trust Level row** | Opens TrustLevelSheet → tap a level → `repo.updateTrustLevel` → "Trust level updated" snackbar |
| **Add / Edit notes** | Opens NotesEditorSheet → save → `repo.updateNotes` → "Notes saved" |
| **Link to Contact** | Requests READ_CONTACTS at runtime → opens ContactLinkSheet (full picker) → tap a contact → `repo.updateContactLink` → "Linked to X" |
| **Auto-match by email** | Requests READ_CONTACTS → matches `ContactsService.fetchContactsWithEmail()` by email → 1 hit links directly; 0 or 2+ hits open the picker pre-filtered |
| **Unlink Contact** | AlertDialog confirmation → `repo.updateContactLink(null, null, null)` |
| **Share Public Key** | `Intent.ACTION_SEND` chooser with armored key in EXTRA_TEXT + key owner in EXTRA_SUBJECT |
| **Set as Default Key** | `repo.setDefaultKey` → "X is now your default key" + DEFAULT pill appears in header |
| **Upload to Key Server** | Inline spinner row → `KeyServerRepository.upload` → `repo.markKeyServerUploaded` → success snackbar |
| **QR Sheet "Copy"** | Armored public key → clipboard → "Public key copied to clipboard" snackbar |
| **QR Sheet "Share"** | Same Intent.ACTION_SEND chooser as the Actions section button |
| **Delete Key** | AlertDialog with key-pair-aware message → `repo.deleteByFingerprint` → `KeyDetailEvent.KeyDeleted` → pop back to Keyring tab |

### Stubs that remain in A4b

Two actions stay routed through the coming-soon channel:

1. **Export Private Key** — waits for biometric integration (Phase A11
   when passphrase change + per-key export lands). BiometricPrompt
   requires bumping MainActivity from ComponentActivity to
   FragmentActivity, and the export flow itself needs careful
   confirmation/auth ordering. Keeping it scoped to A11 keeps that
   phase coherent.

2. **Revoke Key** — needs new crypto work (revocation certificate
   generation in SigningService) AND schema fields on PGPKeyEntity
   (`isRevoked`, `revokedAt`, `revocationReason`, `revocationCertificate`).
   Schema change → Room migration → revocation primitives → UI flow
   is at least a full phase on its own; deferred to post-A11.

The "Coming in a later update" snackbar copy reflects this (was "next
update" in A4a — language softened since A4b doesn't fully clear the
backlog).

## New files (4)

| File | Lines | Purpose |
|------|------:|---------|
| `TrustLevelSheet.kt` | 151 | Modal sheet — 4 trust levels with descriptive blurbs; tap = apply + dismiss |
| `NotesEditorSheet.kt` | 129 | Modal sheet — TextField with 500-char cap, Cancel / Save |
| `ContactLinkSheet.kt` | 237 | Modal sheet — scrollable contact list (LazyColumn) with avatars, supports full-picker and auto-match-filtered modes |
| `KeyShareIntents.kt` | 75 | Object with `sharePublicKey(context, armored, label)` helper — wraps Intent.ACTION_SEND + chooser |

Total new code: 592 lines.

## Modified files (additive)

| File | Before | After | Δ | Notes |
|------|------:|------:|--:|-------|
| `KeyDetailScreen.kt` | 219 | 457 | +238 | Action dispatcher, permission launcher, 4 sheet renderings, 2 AlertDialogs, event subscription for KeyDeleted, snackbar feedback for QR copy |
| `KeyDetailViewModel.kt` | 168 | 492 | +324 | 14 new public actions + 12 new state fields + KeyDetailEvent sealed class + ContactsService + KeyServerRepository deps |
| `KeyDetailSections.kt` | 633 | 635 | +2 | Notes section Edit icon swapped from ContentCopy placeholder to proper pencil |
| `KeyDetailQRSheet.kt` | 161 | 161 | 0 | Unchanged — caller now passes real callbacks instead of stubs |
| `ViewModelFactory.kt` | 45 | 48 | +3 | Pass `contactsService` to KeyDetailViewModel constructor |

Total additive: +567 lines.

## Architectural notes

### Action dispatcher pattern preserves A4a section signatures

Each section composable (Header, Fingerprint, Details, Contact, Notes,
QR, Actions, DangerZone) still takes the same `onComingSoon: (String) -> Unit`
parameter it did in A4a. The dispatcher in `KeyDetailScreen` maps each
label to its real handler:

```kotlin
val dispatchAction: (String) -> Unit = { label ->
    when (label) {
        "Change Trust Level" -> viewModel.showTrustSheet()
        "Add notes", "Edit notes" -> viewModel.showNotesSheet()
        "Link to Contact" -> ensureContactsPermission(...)
        "Set as Default Key" -> viewModel.setAsDefault()
        ...
        "Export Private Key", "Revoke Key" -> viewModel.showComingSoon(label)
    }
}
```

This kept the section composables strictly additive — A4b's diff vs
A4a only touched `KeyDetailSections.kt` for the Notes icon swap (+2
lines), no signature changes. If a future phase needs typed callbacks
instead of string labels, that's a separate refactor; for now the
dispatcher pattern is fine.

### Runtime permission flow

`rememberLauncherForActivityResult` lives at the Composable layer
(ViewModels don't have Activity context), so the permission check
needed to flow from the dispatcher through a helper:

```kotlin
"Link to Contact" -> ensureContactsPermission(
    context,
    onAlreadyGranted = { viewModel.showContactPicker() },
    onNeedRequest = {
        pendingContactAction = ContactAction.Link
        contactPermissionLauncher.launch(Manifest.permission.READ_CONTACTS)
    }
)
```

Two contact actions (Link, AutoMatch) share the same launcher; a
remembered `pendingContactAction` enum disambiguates which to resume
once the user grants permission. Denied → `reportContactsPermissionDenied`
surfaces a snackbar explaining why; the user can retry from the same
action row.

`READ_CONTACTS` was already in the manifest from earlier phases — no
manifest change needed.

### ContactsService snapshot semantics

`fetchContactsWithEmail()` is a synchronous content-provider query
that runs on `Dispatchers.IO` via the surrounding `viewModelScope.launch`.
Fetching happens on each contact-sheet open rather than caching —
contacts can change between visits, and the cost is bounded by the
size of the user's address book (typically hundreds, not millions).

The sheet itself is a pure presentation layer over the resulting
snapshot — no Android Contacts API calls inside `ContactLinkSheet.kt`.
This keeps the sheet testable as a pure Composable.

### Share intent via FLAG_ACTIVITY_NEW_DOCUMENT

`Intent.ACTION_SEND` chooser launched with `FLAG_ACTIVITY_NEW_DOCUMENT`
so the chooser activity doesn't show up in recents alongside PGPony.
Same pattern that the existing Exchange tab uses for QR-imported keys
— consistency across share surfaces.

EXTRA_SUBJECT carries the key owner's name/email so mail apps fill in
a sensible Subject line. EXTRA_TEXT carries the armored public key.
Recipient apps that handle text/plain (Gmail, Signal, Telegram, Notes,
Drive, clipboard managers, etc.) all pick it up correctly.

### Delete flow uses a SharedFlow event for navigation

Pop-back-stack after delete needs to fire from `viewModelScope` after
the delete coroutine completes, but `onBack` is owned by the screen.
The pattern: VM emits `KeyDetailEvent.KeyDeleted` on a `SharedFlow`;
the screen collects via `LaunchedEffect(viewModel)` and calls `onBack()`.

`SharedFlow` with `extraBufferCapacity = 1` is the right fit —
single-shot signals, no replay needed (subscriber is always already
attached by the time delete completes).

### Success snackbar surface unified through VM state

Write actions (set trust, save notes, link contact, set default,
upload, unlink) all set `state.successMessage` to a human-readable
string. The screen has a `LaunchedEffect(state.successMessage)` that
shows the snackbar and clears via `viewModel.clearSuccess()`.

The QR copy is the one exception — it uses `rememberCoroutineScope` +
`snackbarHostState.showSnackbar` directly because routing through the
VM for a trivial clipboard-feedback message would be over-engineered.

## Verified

### Structural preservation
All A4a structural elements preserved in modified files:
- ViewModel: data class, class declaration, all 10 original methods +
  computed property all present
- Screen: KeyDetailScreen / LoadingBody / NotFoundBody / LoadedBody
  composables, Scaffold, TopAppBar, ArrowBack — all present
- Sections: unchanged signatures except for the Notes icon swap

### Line counts grew
All modified files grew in line count — no removals.

### Permission manifest
`READ_CONTACTS` was already declared in AndroidManifest.xml from
earlier phases; no manifest changes required for A4b.

## How to test on device

1. **Trust Level:** Open any key → Details → tap "Trust Level" row →
   sheet opens with current selection checked → tap "Verified" →
   sheet dismisses → row updates to "Verified" + green check badge.
2. **Notes (add):** On a key with no notes → Notes section → tap "Add
   notes…" → sheet opens with empty TextField → type "Test note" →
   Save → sheet dismisses → notes appear in section.
3. **Notes (edit):** On a key with notes → tap "Edit notes…" → sheet
   opens with existing text pre-filled → modify or clear → Save.
   Empty save clears the notes entirely.
4. **Link contact (first time):** On a key not yet linked → Contact
   section → "Link to Contact" → system permission dialog appears →
   tap Allow → ContactLinkSheet opens showing all contacts with email
   → tap one → sheet dismisses → Contact section now shows the linked
   contact with green check.
5. **Link contact (permission denied):** Tap "Link to Contact" → deny
   → snackbar "Contacts permission is needed…". Retry → permission
   dialog reappears (Android handles this for you).
6. **Auto-match (single hit):** On a key whose email matches exactly
   one device contact → Contact section → "Auto-match by email" →
   permission flow if needed → directly links with snackbar "Linked
   to X".
7. **Auto-match (zero hits):** On a key whose email matches no
   contact → "Auto-match by email" → permission flow → sheet opens
   in empty state explaining no match. Close.
8. **Unlink:** On a linked key → "Unlink Contact" → AlertDialog
   confirming → Unlink → row reverts to "Link to Contact" CTA.
9. **Share Public Key:** Actions section → "Share Public Key" →
   system share sheet appears with Gmail, Signal, etc. as options.
   Sharing to Gmail should pre-fill the Subject as
   "<key owner> — PGP Public Key" and the body with the armored key.
10. **Set as Default:** On a key pair that isn't already default →
    "Set as Default Key" → snackbar "X is now your default key" →
    header DEFAULT pill appears.
11. **Upload to Key Server:** On a key pair not yet uploaded →
    "Upload to Key Server" → wait briefly for the network call →
    snackbar "Uploaded to keys.openpgp.org" → Details section now
    shows the "Key Server: Published" row.
12. **QR Copy:** Show QR Code → Copy → sheet dismisses → snackbar
    "Public key copied to clipboard" → paste somewhere to verify
    armored block.
13. **QR Share:** Show QR Code → Share → same share chooser as #9.
14. **Delete Key:** Danger Zone → "Delete Key" → AlertDialog with
    key-pair-aware message → Delete → screen pops back to Keyring
    tab → key is gone from the list.
15. **Export Private Key:** Still routes to "Coming in a later
    update" snackbar (waits for A11).
16. **Revoke Key:** Still routes to "Coming in a later update"
    snackbar (waits for revocation schema + crypto).

## Pending after A4b

**Phase A11** — passphrase change + per-key private export with biometric:
- Bump MainActivity to FragmentActivity for BiometricPrompt
- "Export Private Key" alert dialog with two-step confirmation +
  biometric re-auth
- Armored private key → Intent.ACTION_SEND
- Passphrase change flow

**Post-A11** — full revocation feature:
- PGPKeyEntity schema fields: isRevoked, revokedAt, revocationReason,
  revocationCertificate (Room migration v2)
- SigningService.generateRevocationCertificate (new crypto)
- RevokeKeySheet (reason picker + comment field + passphrase if needed)
- RevocationResultSheet (display + share generated cert)
- Revoked banner in KeyDetailScreen header

## Suggested entry for NorseHorse_Android_Update_Log.md

```
## PGPony Android Phase A4b — KeyDetailScreen actions wired (2026-05-27)

All A4a action stubs replaced with real handlers. The key-detail
screen is now fully functional except for Export Private Key (waits
for biometric in Phase A11) and Revoke Key (waits for revocation
crypto + schema fields).

### Added
- ui/keyring/TrustLevelSheet.kt — 4-level picker
- ui/keyring/NotesEditorSheet.kt — TextField + Cancel/Save
- ui/keyring/ContactLinkSheet.kt — contact picker, full and
  auto-match-filtered modes
- ui/keyring/KeyShareIntents.kt — Intent.ACTION_SEND helpers

### Modified (additive)
- ui/keyring/KeyDetailViewModel.kt: +324 lines. 14 new actions
  (trust, notes, contact link, auto-match, unlink, set-default,
  upload, delete + show/hide companions) + KeyDetailEvent sealed
  class + ContactsService + KeyServerRepository deps.
- ui/keyring/KeyDetailScreen.kt: +238 lines. Action dispatcher
  pattern, READ_CONTACTS permission launcher, 4 sheets + 2
  AlertDialogs rendered conditionally, event subscription for
  KeyDeleted → popBackStack, rememberCoroutineScope for QR copy
  snackbar.
- ui/keyring/KeyDetailSections.kt: +2 lines. Notes edit icon
  swapped from ContentCopy placeholder to Edit (pencil) now that
  the action is wired.
- ui/ViewModelFactory.kt: +3 lines. ContactsService passed to
  KeyDetailViewModel.

### iOS port equivalents
- TrustLevelSheet              = iOS TrustLevelPicker
- NotesEditorSheet             = iOS (no equivalent — iOS uses
                                 inline TextField on detail row)
- ContactLinkSheet             = iOS ContactPickerSheet
                                 (Android uses ContactsService
                                 snapshot + custom list vs. iOS
                                 ContactsUI system picker)
- KeyShareIntents              = iOS share sheet via
                                 ShareSheet UIActivityViewController
- Delete confirmation          = iOS .alert("Delete Key", ...)

### Deferred to later phases
- Export Private Key           → A11 (biometric)
- Revoke Key                   → post-A11 (schema + crypto)
```
