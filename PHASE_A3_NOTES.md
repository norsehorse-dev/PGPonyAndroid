# Phase A3 — Decrypt verify + 4-state banner + tap-to-fetch

## What this phase ships

Verify-side parity for clear-signed messages. The Decrypt screen now
detects what kind of PGP content was pasted (encrypted / clear-signed /
detached-sig-alone) and routes accordingly. After verification, a
4-state colored banner renders above the result — and when the signer
isn't in the local keyring, tapping the banner opens a sheet that
fetches the key from keys.openpgp.org and re-verifies automatically.

### User-facing change

**Decrypt input field label:** now reads "Paste encrypted or signed
message" — covers both flows since the action auto-detects.

**One Decrypt button, three behaviors:**

- Pasted `-----BEGIN PGP SIGNED MESSAGE-----` (clear-signed text from
  Phase A2's Sign mode, GnuPG `--clearsign`, etc.) → verifies, no
  decryption (the cleartext was already readable)
- Pasted `-----BEGIN PGP MESSAGE-----` (encrypted) → decrypts as
  before, signature status now surfaced via the same banner
- Pasted `-----BEGIN PGP SIGNATURE-----` alone → friendly error
  asking for the signed content too (file-based detached verify lands
  in Phase A10)
- Garbage → friendly error asking for full BEGIN/END markers

**4-state verification banner above the output:**

| State | Color | Meaning | Interactive |
|-------|-------|---------|-------------|
| Verified | green | Signer in keyring, math checks out | no |
| Invalid | red | Signature did not match the content | no |
| Unknown signer | yellow | Math checks, but signer's key isn't local | **yes — tap to look up** |
| No signature | gray | Content decrypted but unsigned | no |

The yellow "Unknown signer" banner shows the claimed fingerprint
(from the RFC 4880bis issuer-fingerprint subpacket that every PGPony
A2-signed message carries) and a chevron hint. Tapping opens the
SignerLookupSheet.

**SignerLookupSheet (modal bottom sheet):**

State machine:
1. **Searching** — spinner + "Looking up `B91A 02D6 …` on keys.openpgp.org"
2. **Found** — preview of discovered key (user ID, formatted
   fingerprint, algorithm) + Cancel / Import buttons. Trust-warning
   subtitle: "The key's identity is not yet vetted — only the math
   is being checked"
3. **Not found** — "No key was found for `…`. The signer may not have
   uploaded their key to a public keyserver" + Close button
4. **Failed** — network/parse error message + Close button
5. **Import success** — "Imported. The signature will be re-verified
   automatically" + Done button

After successful import, the host screen re-runs decrypt() with the
now-larger keyring; the banner typically flips from yellow to green
without further user action.

### New files (5)

| File | Lines | Purpose |
|------|------:|---------|
| `crypto/ClearSignedParser.kt` | 122 | Internal utility — slices clear-signed armored input into (hash algo, cleartext, signature block) via string scanning. Strips dash-escaping. Handles both LF and CRLF wire formats. |
| `crypto/VerifyService.kt` | 378 | Public verification API. `detectInputType()`, `verifyClearSigned()`, `verifyDetached()`. Returns typed `VerificationResult` (Verified / Invalid / UnknownSigner / Unsigned). Looks up signer keys by 64-bit key ID across all supplied rings; pulls claimed fingerprint from issuer-fingerprint subpacket for UnknownSigner. |
| `ui/decrypt/VerificationBanner.kt` | 203 | Compose banner rendering all four states with appropriate colors, icons, subtitles. Click handler invoked only for UnknownSigner. |
| `ui/decrypt/SignerLookupSheet.kt` | 324 | ModalBottomSheet wrapping the lookup state machine. State sealed class lives at top of file; consumed by the ViewModel. |
| `app/src/test/kotlin/com/pgpony/android/crypto/VerifyServiceTest.kt` | 300 | 18 tests: detectInputType across 4 input shapes; verifyClearSigned for Verified / UnknownSigner / Invalid (tampered + truncated + malformed); verifyDetached for Verified / Invalid / UnknownSigner; ClearSignedParser smoke (hash algo extraction, malformed input, dash-escape stripping). |

### Modified files (additive only)

| File | Before | After | Δ |
|------|------:|------:|--:|
| `ui/encrypt/EncryptDecryptViewModel.kt` | 389 | 630 | +241 |
| `ui/encrypt/Screens.kt` | 588 | 614 | +26 |

VM additions (all existing functions preserved):

- `DecryptUiState` gains `verificationResult`, `showSignerLookup`,
  `signerLookupState`, `pendingUnknownClaimedFingerprint`
- `decrypt()` now dispatches on `VerifyService.detectInputType`
  rather than always running the encrypt path
- Three new private path methods: `verifyClearSignedPath`,
  `decryptAndVerifyPath`, `buildVerificationResultForEncrypted`
- Three new public actions: `lookupSigner()`,
  `importDiscoveredSigner(armoredKey)`, `dismissSignerLookup()`
- Two new fields: `verify` (VerifyService.shared) and `keyServer`
  (lazy KeyServerRepository)

Screens.kt additions:

- Three new imports (VerificationBanner, SignerLookupSheet,
  VerificationResult sealed class)
- Updated input label
- VerificationBanner rendered in place of the inline "Signature
  verified" check icon
- SignerLookupSheet rendered at the end conditional on
  `state.showSignerLookup`

## Architectural notes

### Why a separate VerifyService

`PGPCryptoService.decryptArmored` already handles signature
verification for encrypted-and-signed messages inline — it parses
one-pass-signature packets while reading the encrypted payload. That
path is unchanged in A3.

What was missing: clear-signed verification (no encryption layer to
attach the signature to), detached signature verification (file
verify, deferred to A10 UI but the service method is here), and the
"unknown signer" identification flow that needs the issuer-fingerprint
subpacket to be extracted distinctly from the signer-key-not-found
case.

These needed their own service for clean separation between encrypt
concerns and verify concerns.

### Why manual cleartext parsing instead of BC's
ClearSignedFileProcessor

The Bouncy Castle reference pattern uses ArmoredInputStream lookahead
to read cleartext and signature off the same stream. The Kotlin port
of that pattern empirically failed in A2 test infrastructure (NPE on
`fact.nextObject() as PGPSignatureList`), and rather than re-debug
the BC stream-state semantics in production code, A3 uses
`ClearSignedParser` to slice the armored input into substrings via
indexOf on the well-defined armor markers. The signature block is then
parsed via a **fresh** ArmoredInputStream over that substring alone —
no shared stream state.

This is empirically robust and ~70 lines of straightforward Kotlin.
If a future phase needs to handle truly enormous clear-signed
documents (where holding the entire signed text as a String would be
wasteful), the BC pattern can be revisited with proper test
infrastructure to debug the original port issue. For typical
clear-signed messages (chat-size, email-size) the string-based approach
is fine.

### "Unknown signer" relies on the issuer-fingerprint subpacket

Every signature PGPony Android produces since Phase A2 carries an
RFC 4880bis subpacket type 33 (issuer fingerprint, non-critical).
That's what makes the "unknown signer" lookup possible — without it,
we'd have only the 64-bit key ID to search keys.openpgp.org with,
which is technically supported but precision-degraded.

Signatures produced by other PGP clients may or may not include this
subpacket:
- GnuPG 2.2.21+ emits it by default for v4 signatures.
- v6 signatures (RFC 9580) require it.
- Very old PGP clients (pre-2017) may omit it.

When the subpacket is absent, `UnknownSigner.claimedFingerprint`
is null and the UI falls back to the 64-bit key ID for keyserver
search. Phase A8's WKD support won't help in that case (WKD requires
an email, which isn't part of any signature subpacket).

### Re-verify after import

`importDiscoveredSigner` calls `repo.importArmoredKey` to add the key
to the local keyring, then immediately calls `refreshKeys()` and
`decrypt()`. The second decrypt() call re-routes through the same
detect-and-dispatch logic, but now `verify.verifyClearSigned` finds
the signer in the (now larger) ring list and returns Verified instead
of UnknownSigner. The banner updates from yellow to green; no user
action required.

There's a brief window between import-success and re-verify-complete
where the sheet shows "Imported" and the banner still shows the old
UnknownSigner state. The user typically taps Done to dismiss the
sheet, by which point re-verify has completed.

## Verified

- 18 unit tests covering:
  - `detectInputType` across all four input shapes including the
    "clear-signed contains both markers, must classify as CLEAR_SIGNED
    not DETACHED_SIGNATURE" tricky case
  - `verifyClearSigned` end-to-end roundtrip: sign with SigningService,
    verify with VerifyService → Verified with correct name/email/key ID
  - `verifyClearSigned` UnknownSigner case: sign with key not in
    verifying keyring → yellow UnknownSigner with claimed fingerprint
    that matches the actual signer's primary key fingerprint
  - `verifyClearSigned` tampered content → Invalid
  - `verifyClearSigned` malformed input + truncated signature → Invalid
    without crashing
  - `verifyDetached` for both Verified and UnknownSigner paths
  - `ClearSignedParser` smoke tests (hash algo extraction, null on
    bad input, dash-escape stripping)

- All modified files diff-clean:
  - `EncryptDecryptViewModel.kt` 389 → 630, all 27 original
    functions/classes/objects preserved
  - `Screens.kt` 588 → 614, all original Composables and structural
    elements preserved (EncryptScreen, DecryptScreen, EncryptModeBody,
    SignModeBody, FileModePlaceholder, etc.)

## How to test on device

Quick acceptance flow once installed:

1. Generate two keys (Alice on this device — call it Alice; another
   key on iOS PGPony or GnuPG and don't import it — call it Bob).
2. In Encrypt tab → Sign mode → sign a message with Alice → copy.
3. In Decrypt tab → paste the signed message → tap Decrypt.
4. Expected: **green Verified banner** showing "Signed by Alice
   <alice@...>" with the cleartext below.
5. On the other device, sign a different message with Bob → copy.
6. Paste into Android Decrypt → tap Decrypt.
7. Expected: **yellow Unknown signer banner** with Bob's fingerprint
   suffix and a chevron.
8. Tap the yellow banner → SignerLookupSheet opens.
9. If Bob's key is on keys.openpgp.org: sheet shows Found with key
   preview → Import → ImportSuccess → Done → banner flips to **green**.
10. If Bob's key isn't on keys.openpgp.org: sheet shows NotFound.
    Close → banner stays yellow.

## Pending after A3

- **Phase A4a/A4b** — KeyDetailScreen (the big missing screen)
- **Phase A5** — proper Sign-as picker for Encrypt tab
- **Phase A8** — WKD discovery in front of the Hagrid keyserver lookup
  (will improve UnknownSigner lookup precision for signers identified
  by email)
- **Phase A10** — file-verify flow (detached signature against
  uploaded file), encrypted-and-signed UnknownSigner enhancement

## Suggested entry for NorseHorse_Android_Update_Log.md

```
## PGPony Android Phase A3 — Decrypt verify + 4-state banner + tap-to-fetch (2026-05-27)

Verify-side completion of Phase A2. Decrypt screen now routes
clear-signed input to a dedicated verify path, surfaces 4-state
signature status via a colored banner, and lets the user fetch
unknown signers from keys.openpgp.org with one tap.

### Added
- crypto/VerifyService.kt — clear-sign + detached verification.
  Returns typed VerificationResult: Verified / Invalid /
  UnknownSigner / Unsigned. Pulls claimed fingerprint from
  issuer-fingerprint subpacket for unknown-signer lookup.
- crypto/ClearSignedParser.kt — internal utility, slices
  armored input into (hash algo, cleartext, sig block).
- ui/decrypt/VerificationBanner.kt — 4-state colored banner
  (green/red/yellow/gray). Yellow is tappable.
- ui/decrypt/SignerLookupSheet.kt — modal bottom sheet for
  fetching unknown signer keys. State machine: Searching →
  Found/NotFound/Failed → ImportSuccess.
- VerifyServiceTest — 18 cases.

### Modified (additive)
- EncryptDecryptViewModel.kt: +241 lines. decrypt() now
  dispatches by detected input type; verifyClearSignedPath,
  decryptAndVerifyPath, lookupSigner, importDiscoveredSigner,
  dismissSignerLookup.
- Screens.kt: +26 lines. VerificationBanner above output,
  SignerLookupSheet at end. Input label updated.

### iOS port equivalents
- VerifyService                = iOS SigningService.swift verify methods
- VerificationBanner           = iOS DecryptView verification banner
- SignerLookupSheet            = iOS SignerLookupSheet.swift (457 lines)
                                Android version is ~325 lines because
                                BC handles parsing and we don't need
                                custom OpenPGP packet inspection.

### Deferred to later phases
- WKD source for lookup        -> Phase A8 (Hagrid is the only source for now)
- File-verify flow             -> Phase A10
- Encrypted-and-signed UnknownSigner -> Phase A10
```
