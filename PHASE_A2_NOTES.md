# Phase A2 — Native v4 SigningService + Sign-only mode

## What this phase ships

A dedicated `SigningService` that produces RFC 4880 §7 clear-signed
text and §5.2.3 detached signatures via Bouncy Castle, plus a new
Sign mode in the Encrypt screen so users can produce clear-signed
messages without recipients.

### User-facing change

Encrypt screen gains a 3-segment mode picker at the top: **Text** /
**Sign** / **File**.

- **Text** (default) — existing encrypt flow, unchanged
- **Sign** — produces an RFC 4880 §7 clear-signed message (no
  encryption). Recipient picker is replaced with a read-only "Sign as"
  row showing the first available key pair. Button label changes from
  "Encrypt" to "Sign".
- **File** — rendered but disabled until Phase A10. Tapping it shows
  a "File encryption arrives in the next update" placeholder.

If the signing key is passphrase-protected, a passphrase prompt
dialog appears. Wrong passphrase keeps the dialog open with an error
inline so the user doesn't have to retype the message.

### New files (2)

| File | Lines | Purpose |
|------|------:|---------|
| `app/src/main/java/com/pgpony/android/crypto/SigningService.kt` | 278 | Clear-sign + detached sign via BC's `PGPSignatureGenerator`. Always sets issuer-fingerprint subpacket (type 33). Hashes canonical form per RFC 4880 §7.1. |
| `app/src/test/kotlin/com/pgpony/android/crypto/SigningServiceTest.kt` | 326 | 14 tests: detached armored roundtrip, detached binary roundtrip, issuer-fingerprint subpacket present, clear-sign frame format, dash-escaping, end-to-end clear-sign verify, passphrase paths (success/required/invalid), canonical-form pure-function tests including the RFC 4880 §7.1 trailing-terminator-excluded rule. |

### Modified files (additive only)

| File | Before | After | Δ |
|------|------:|------:|--:|
| `app/src/main/java/com/pgpony/android/ui/encrypt/EncryptDecryptViewModel.kt` | 252 | 389 | +137 |
| `app/src/main/java/com/pgpony/android/ui/encrypt/Screens.kt` | 338 | 547 | +209 |

**No original lines removed.** Every existing function (`encrypt`,
`decrypt`, `updateEncryptInput`, `toggleRecipient`, etc.), state
field, DAO call, and Composable structure is preserved. Additions:
new `EncryptMode` enum, `mode`/`signPassphrase`/`showSignPassphraseDialog`
fields on `EncryptUiState`, `setMode`/`signOnly`/`updateSignPassphrase`/
`dismissSignPassphraseDialog` action methods, new `SignSuccess` event,
new sub-Composables `EncryptModeBody`/`SignModeBody`/`FileModePlaceholder`,
new passphrase prompt dialog block.

## Architectural notes

### Why a separate SigningService

`PGPCryptoService` already has a `sign()` method for sign+encrypt
inline operation. It hardcodes SHA-256 and produces `BINARY_DOCUMENT`
signatures inside the encrypted payload. Phases A3 (verify UI), A5
(sign-as picker), A6 (revocation), A7 (per-key export) all need:

- Clear-sign output (different framing: §7 vs §5.2.3)
- Detached output independent of encryption
- Configurable hash algorithm (Phase A6 may want SHA-512)
- Different error surface (passphrase distinct from generic crypto error)
- Subkey selection logic (Phase A5)
- Revocation signatures (Phase A6, signature type 0x20, not 0x00)

Folding all of that into `PGPCryptoService` would push it past 1500
lines and entangle clear-sign concerns with encryption concerns.
`SigningService` is its own service for these reasons.

### Canonical form for clear-sign hash (RFC 4880 §7.1)

The hash is computed over a canonical form of the cleartext:

- Line endings normalized to `<CR><LF>`
- Trailing whitespace (spaces, tabs, CRs) stripped per line
- **Trailing line terminator excluded** — this trips up naive
  implementations because "foo\n" and "foo" must hash identically
- BC does NOT canonicalize for us; the caller (us) supplies the
  bytes that get fed to `PGPSignatureGenerator.update`

The `canonicalizeForClearSign` function implements this and is
exercised by 3 pure-function tests + 1 end-to-end roundtrip test.

### Subkey selection (deferred to Phase A5)

`pickSigningKey(ring)` currently returns `ring.secretKey` (primary).
This is correct for every key shape PGPony generates:

- RSA primary = Certify+Sign+Encrypt → primary can sign
- Ed25519 primary = Certify+Sign → primary can sign (Cv25519 subkey
  is encrypt-only)

For imported keys with a certify-only primary + separate sign subkey,
A5 will read `SubkeyCapability.fromPgpPublicKey` (from Phase A1) on
each subkey, prefer one with the Sign bit set, and only fall back to
the primary if no signing subkey is found.

### Issuer fingerprint subpacket

Every signature emitted by A2 carries an issuer-fingerprint subpacket
(RFC 4880bis subpacket type 33, non-critical). This matters for
Phase A3's "unknown signer" lookup flow — when verification fails
because the signer's key isn't in the keyring, the UI uses the
claimed fingerprint to query WKD/keyserver and offer to import.

## Verified

- 14 unit tests including:
  - Detached armored signature roundtrip-verifies against BC's own
    `PGPSignature.verify`
  - Detached binary signature roundtrip-verifies
  - Issuer-fingerprint subpacket is present on emitted signatures
  - Clear-sign output has the right armor frame, hash header, body,
    and signature block
  - Dash-escaping applied to lines starting with `-`
  - End-to-end clear-sign verify (sign → parse cleartext → re-canonicalize
    → BC verify)
  - Passphrase-protected key signs with correct passphrase, throws
    `PassphraseRequired` for null, throws `InvalidPassphrase` for wrong
  - Canonical form: trailing whitespace stripped per line, CRLF
    normalization, trailing terminator excluded (so "foo\n" and "foo"
    hash identically)
- All modified files diff-clean: 252→389 and 338→547 lines, all
  structural elements preserved.

## Pending after A2

These ride into later phases:

- **Phase A3** — verify-side UI: 4-state banner (Verified / Invalid /
  Unknown signer / Unsigned), tap-to-fetch unknown signer, route
  clear-signed input through verify (not decrypt).
- **Phase A5** — proper "Sign as" picker (currently A2 just uses the
  first available key pair), Default key in Settings.
- **Phase A10** — File mode unlock.

## Suggested entry for NorseHorse_Android_Update_Log.md

```
## PGPony Android Phase A2 — Native v4 SigningService + Sign-only mode (2026-05-27)

First v5.0 user-visible signing feature. Encrypt screen gets a 3-segment
mode picker (Text / Sign / File); Sign mode produces RFC 4880 §7
clear-signed text via a new dedicated SigningService.

### Added
- crypto/SigningService.kt -- clear-sign + detached sign via BC's
  PGPSignatureGenerator. Always emits issuer-fingerprint subpacket
  (type 33). Hashes canonical form per RFC 4880 §7.1.
- SigningServiceTest -- 14 cases including roundtrip verify against
  BC, passphrase paths, canonical-form pure-function tests.

### Modified (additive)
- EncryptDecryptViewModel.kt: +137 lines (EncryptMode enum,
  signOnly action, SignSuccess event, passphrase dialog state).
- Screens.kt: +209 lines (3-segment mode picker, SignModeBody,
  FileModePlaceholder, passphrase prompt dialog).

### iOS port equivalents
- SigningService              = iOS SigningService.swift (1399 lines)
                                The Android version is ~280 lines
                                because BC handles all packet building.
- EncryptMode.SIGN            = iOS EncryptMode.signOnly
- Sign-only Compose flow      = iOS EncryptView lines ~500-606
- Sign-as picker (deferred A5)= iOS selectedSigningKey + picker

### Deferred to later phases
- Verify-side UI (banner, tap-to-fetch)   -> Phase A3
- Proper Sign-as picker + Default key UI  -> Phase A5
- File mode                                -> Phase A10
```
