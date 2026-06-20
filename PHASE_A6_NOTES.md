# Phase A6 — Revocation certificates

## What this phase ships

Full revocation lifecycle: pre-cache at key generation, user-initiated
revocation through KeyDetailScreen, post-revocation banner + filtered
selection + exportable certificate.

### User-facing acceptance flows

1. **Generate a key** → a revocation certificate is pre-cached on the
   PGPKeyEntity with `reason = NO_REASON`. Invisible until needed.
2. **Revoke an existing key pair** → Danger Zone → "Revoke Key…" →
   RevokeKeySheet (reason picker + optional comment + passphrase
   field) → Revoke → spinner → RevocationResultSheet displays the
   freshly-generated armored cert with Copy / Share / Done. Key now
   shows Revoked banner above fingerprint, "REVOKED" pill in KeyCard
   in the Keyring list, and disappears from recipient + signer
   pickers in the Encrypt tab.
3. **Export the cert later** → revoked key's Danger Zone now reads
   "Export Revocation Certificate" instead of "Revoke Key…" → tap →
   Intent.ACTION_SEND chooser with the stored armored cert.

### What's NOT removed when revoked

A revoked key keeps its secret material and stays selectable in the
**Decrypt** key list. The user can still legitimately decrypt past
messages encrypted to them before revocation. Stripping the key from
decrypt would lock users out of their own correspondence — that's
the wrong tradeoff. Encrypt-side filtering is the meaningful
protection (no new messages to/from the revoked identity).

## New files (3)

| File | Lines | Purpose |
|------|------:|---------|
| `crypto/RevocationService.kt` | 260 | `generateRevocationCertificate` and `applyRevocation` on top of Bouncy Castle. KEY_REVOCATION (type 0x20) signature with issuer-fingerprint subpacket + RFC 4880 §5.2.3.23 revocation-reason subpacket, ASCII-armored output |
| `ui/keyring/RevokeKeySheet.kt` | 256 | Modal sheet: 5-option reason radio picker + optional comment field + passphrase field + Revoke button (red, with spinner during processing) |
| `ui/keyring/RevocationResultSheet.kt` | 159 | Modal sheet shown after successful revocation: green check + armored cert displayed in monospace OutlinedTextField + Copy / Share buttons + Done |

## Modified files (additive)

| File | Before | After | Δ | Notes |
|------|------:|------:|--:|-------|
| `data/PGPKeyEntity.kt` | 143 | 240 | +97 | `RevocationReason` enum + converter, 4 new entity fields (isRevoked, revokedAt, revocationReason, revocationCertificate), `@Database(version = 2)`, MIGRATION_1_2 with 4 ALTER TABLE statements |
| `PGPonyApp.kt` | 62 | 67 | +5 | `.addMigrations(MIGRATION_1_2)` wired into the Room builder |
| `data/repository/KeyRepository.kt` | 232 | 354 | +122 | `generateKey()` pre-caches a NO_REASON cert; new `applyRevocation(fp, reason, comment, passphrase): String` and `exportRevocationCertificate(fp): String?` methods |
| `ui/keyring/KeyDetailViewModel.kt` | 492 | 620 | +128 | 5 new state fields (showRevokeSheet, showRevocationResultSheet, isRevoking, revokeError, pendingRevocationCert); 5 new actions (showRevokeSheet, dismissRevokeSheet, applyRevocation, dismissRevocationResultSheet, exportRevocationCertificate) |
| `ui/keyring/KeyDetailScreen.kt` | 460 | 550 | +90 | Dispatcher entries for "Revoke Key" and "Export Revocation Certificate"; RevokeKeySheet + RevocationResultSheet rendered when their state flags are set; RevokedBanner inserted into LoadedBody between header and fingerprint |
| `ui/keyring/KeyDetailSections.kt` | 635 | 725 | +90 | DangerZoneSection branches on `key.isRevoked` — revoked keys hide Revoke and show Export Revocation Certificate; new RevokedBanner composable |
| `ui/keyring/KeyShareIntents.kt` | 75 | 110 | +35 | New `shareRevocationCertificate(context, armoredCert, keyOwnerLabel)` helper (same Intent.ACTION_SEND pattern with revocation-aware EXTRA_SUBJECT) |
| `ui/components/KeyCard.kt` | 164 | 199 | +35 | "REVOKED" red pill in the algorithm/fingerprint row (next to "Expired"); new `RevokedPill` composable |
| `ui/encrypt/EncryptDecryptViewModel.kt` | 630 | 651 | +21 | `loadKeys()` filters revoked keys from `availableRecipients` and `availableSigningKeys`; decrypt list unfiltered |

Total: 3 new files (675 lines), 9 modified files (+623 lines additive).

## Architectural notes

### Pre-caching at key generation

`generateKey()` calls `RevocationService.generateRevocationCertificate
(secretKeyRing, reason=NO_REASON, comment=null, passphrase=...)` while
the passphrase (if any) is still in scope. The result is stored on
`PGPKeyEntity.revocationCertificate` so the user has a fallback even
if they later lose access to their passphrase but still want to
declare the key revoked (e.g. hand the pre-cached cert to a friend
who can `gpg --import` it). 

If pre-cache generation fails (non-fatal — same crypto path that just
succeeded at key gen), the entity gets `null` for the cert and the
user can still revoke later via the sheet, which generates fresh
on-demand.

### Why the BC native path beats iOS-style byte-slinging

iOS hand-rolls revocation packet bytes (see SigningService.swift's
`generateKeyRevocation`). Android's Bouncy Castle handles subpacket
assembly natively via `PGPSignatureSubpacketGenerator.setRevocationReason
(critical, reasonTag, descriptionString)`. Using BC's API avoids:
- Re-implementing RFC 4880 §5.2.3.23 subpacket layout
- Re-computing hash inputs for the signature
- Armor framing (BC's ArmoredOutputStream handles it)

The trade-off — BC's API surface is slightly different across versions
— is acceptable because PGPony pins bcpg-jdk18on:1.78.1 explicitly.

### applyRevocation persists in TWO places

After generating + applying the cert, `KeyRepository.applyRevocation`
writes the updated armored public key ring to:

1. **`SecureKeyStore.storePublicKey(fp, bytes)`** — so future
   `loadPublicKeyRing(fp)` reads return the post-revocation ring
   (with the KEY_REVOCATION signature attached to the primary).
   Required for any future re-export to be honest about the revoked
   state.
2. **`PGPKeyEntity.armoredPublicKey`** — so QR sheets and "Share
   Public Key" actions surface the post-revocation form too. Any
   recipient who scans the QR after revocation gets an already-revoked
   public key and can't be tricked into encrypting to it.

The DB write also stamps `isRevoked`, `revokedAt`, `revocationReason`,
and the new `revocationCertificate` in the same atomic update.

### RevokedBanner placement: directly under header

Inserted into `LoadedBody` between `KeyHeaderSection` and
`FingerprintSection`. Reasoning: a user landing on a revoked key
should see the state immediately, not have to scroll to Danger Zone to
notice. The banner is non-interactive (status surface, not CTA — the
re-export action lives in Danger Zone), and `RevokedBanner` no-ops
internally when `!key.isRevoked`, so unconditional inclusion in
LoadedBody is safe.

### Recipient + signer filtering is encrypt-side only

`EncryptDecryptViewModel.loadKeys()` filters revoked keys out of:
- `availableRecipients` (encrypt-to picker in EncryptModeBody)
- `availableSigningKeys` (sign-as picker added in A5)

Decrypt-side `availableKeys` is intentionally NOT filtered — see "What's
NOT removed when revoked" above. A user keeps the ability to decrypt
past messages indefinitely.

Auto-default-bump-back: if the currently-selected `signingKey` was
just revoked, `loadKeys()` reassigns to the default-or-first unrevoked
key pair. The next encrypt operation won't quietly sign with a
revoked key.

### Schema migration

```sql
ALTER TABLE pgp_keys ADD COLUMN isRevoked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pgp_keys ADD COLUMN revokedAt INTEGER;
ALTER TABLE pgp_keys ADD COLUMN revocationReason TEXT;
ALTER TABLE pgp_keys ADD COLUMN revocationCertificate TEXT;
```

Existing rows get `isRevoked = false` (NOT NULL DEFAULT 0) and NULLs
for the other three. No backfill needed — pre-A6 keys without a
pre-cached cert simply have `revocationCertificate = null` and the UI
handles that gracefully (the user can still revoke; the cert is
generated fresh on demand at revoke time).

`MIGRATION_1_2` lives at the bottom of `PGPKeyEntity.kt` and is wired
into the Room builder via `.addMigrations(MIGRATION_1_2)` in
`PGPonyApp.kt`'s `onCreate`.

## Verified

- Structural preservation in all modified files (all original
  Composables / functions / classes still present)
- Additive delta on every modified file (no removals)
- Imports for RevokedBanner (Surface, Spacer, Row, Column, Icon,
  Report, errorContainer, FontWeight, fillMaxWidth, padding, size,
  width, height, Modifier) already present in KeyDetailSections.kt
- `RevocationError` correctly imported in KeyDetailViewModel from
  `com.pgpony.android.crypto`
- `RevocationReason` imported from `com.pgpony.android.data`
- `KeyShareIntents.shareRevocationCertificate` callable from
  KeyDetailScreen.kt (same package)

## How to test on device

1. **Pre-cache verification** (silent — no visible UI):
   - Keyring tab → Generate → make a new key.
   - In SQLite: open the DB and confirm the new row has
     `revocationCertificate` populated with a BEGIN/END PGP PUBLIC
     KEY BLOCK string and `isRevoked = 0`.
2. **Revoke flow (NO_REASON):**
   - Tap the new key → Danger Zone → "Revoke Key…"
   - Sheet opens with NO_REASON selected by default, comment field
     empty, passphrase field empty (the key is unprotected — PGPony's
     default).
   - Tap Revoke → spinner → RevocationResultSheet slides up with
     green CheckCircle + "Key Revoked" header + armored cert in a
     read-only TextField + Copy / Share / Done.
   - Tap Copy → "Revocation certificate copied to clipboard" snackbar.
   - Tap Done → result sheet dismisses → KeyDetailScreen now renders
     the red Revoked banner between the header and the fingerprint
     section.
3. **Danger Zone post-revocation:**
   - Scroll down on the same key → Danger Zone now reads "Export
     Revocation Certificate" instead of "Revoke Key…".
   - Tap → Intent.ACTION_SEND chooser with the stored cert.
4. **Encrypt-side filtering:**
   - Tap back → Keyring list now shows the key with a red "REVOKED"
     pill in the algorithm/fingerprint row.
   - Encrypt tab → Recipients section: the revoked key is gone.
   - Encrypt tab → Sign-as picker (after toggling sign-while-encrypt
     on, or in Sign-only mode): the revoked key is gone from the
     picker.
5. **Decrypt still works:**
   - Decrypt tab → key selector: the revoked key IS still listed (so
     past messages still decrypt).
6. **Revoke with passphrase + reason:**
   - Import an existing passphrase-protected key from outside PGPony
     (or generate one with a passphrase set).
   - Detail → Danger Zone → Revoke Key… → pick "Key compromised" →
     add a comment "test compromise scenario" → enter the wrong
     passphrase → tap Revoke → "Incorrect passphrase" inline error
     in the sheet.
   - Enter the correct passphrase → Revoke → success.

## Pending after A6

Only one user-facing stub remains in KeyDetailScreen:

- **Export Private Key** → routes to "coming in a later update"
  snackbar. Waits for **Phase A7** (per-key private export with
  biometric — bumps MainActivity from ComponentActivity to
  FragmentActivity, adds BiometricPrompt flow).

## Suggested entry for NorseHorse_Android_Update_Log.md

```
## PGPony Android Phase A6 — Revocation certificates (2026-05-27)

Full revocation lifecycle. Pre-cache at key generation, user-initiated
revocation through KeyDetailScreen with reason picker and passphrase
field, post-revocation Revoked banner + filtered encrypt-side
selection + re-exportable cert.

### Added
- crypto/RevocationService.kt — BC-based generateRevocationCertificate
  + applyRevocation + armorPublicKeyRing. KEY_REVOCATION signature
  type 0x20 with issuer-fingerprint and revocation-reason subpackets.
- ui/keyring/RevokeKeySheet.kt — 5-option reason picker + comment
  field + passphrase field + Revoke button (red).
- ui/keyring/RevocationResultSheet.kt — post-revocation cert display
  with Copy / Share / Done.

### Modified (additive)
- data/PGPKeyEntity.kt: +97 lines. RevocationReason enum + converter,
  4 new entity fields (isRevoked, revokedAt, revocationReason,
  revocationCertificate), schema bump v1→v2 with MIGRATION_1_2.
- PGPonyApp.kt: +5 lines. .addMigrations(MIGRATION_1_2) wired in.
- data/repository/KeyRepository.kt: +122 lines. generateKey()
  pre-caches NO_REASON cert; new applyRevocation +
  exportRevocationCertificate.
- ui/keyring/KeyDetailViewModel.kt: +128 lines. Revocation state
  fields + 5 actions.
- ui/keyring/KeyDetailScreen.kt: +90 lines. Revoke action + Export
  Revocation Certificate dispatcher entries; both sheets rendered;
  RevokedBanner inserted into LoadedBody.
- ui/keyring/KeyDetailSections.kt: +90 lines. DangerZoneSection
  branches on isRevoked; new RevokedBanner composable.
- ui/keyring/KeyShareIntents.kt: +35 lines. shareRevocationCertificate.
- ui/components/KeyCard.kt: +35 lines. RevokedPill in list cards.
- ui/encrypt/EncryptDecryptViewModel.kt: +21 lines. loadKeys()
  filters revoked from encrypt-side; decrypt list unfiltered.

### iOS port equivalents
- RevocationService.generateRevocationCertificate
                            = iOS SigningService.generateKeyRevocation
                              (iOS hand-rolls bytes, Android uses BC's
                              PGPSignatureSubpacketGenerator natively)
- RevokeKeySheet            = iOS RevokeKeyView
- RevocationResultSheet     = iOS RevocationResultView
- RevokedBanner             = iOS revoked banner in KeyDetailView

### Deferred (post-A6)
- Export Private Key with biometric → Phase A7 (bumps MainActivity
  to FragmentActivity for BiometricPrompt).
```
