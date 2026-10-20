# PGPony Android 4.7.0: Planning

Status: open (Sep 25 2026). Carries what was deferred out of 4.6.0 and 4.6.1 once 4.6.0 was frozen for review,
plus reports that came in during the 4.6.x cycle. Android leads, then iOS mirrors each item once verified.
Items are detailed enough to build against; priorities and the RC breakdown are set once the list settles.

Context: 4.6.0 (versionCode 460) shipped Sep 24 2026 and is the tag submitted for external review. 4.6.1
(versionCode 461) is a small follow-up: share-menu recipients (#67), private key import from the share menu
(#67), and MTE async mode (#70). Anything below is a 4.7.0 change unless it says otherwise.


## 1. Mail apps ignore the passphrase cache duration (#15)

**Status:** Shipped in 4.6.3 (Oct 2026): the duration lives in its own file both processes read; checked on device with Thunderbird. See PLANNING_4.6.3.md item 2.

Priority: high (bug, user-facing). Origin: antviro (#15), on 4.6.0.

Reported: Settings lets you keep a passphrase unlocked for 1 minute to 1 hour, until you clear it, or until the
phone locks, but a passphrase entered while decrypting in Thunderbird through PGPony stays for 5 minutes
whatever is chosen.

Cause: SessionPolicy.durationSec() reads pgpony_prefs with MODE_PRIVATE. The OpenPGP provider and its passphrase
cache run in the :remote_api process, whose SharedPreferences instance caches the file the first time it is
read, so a duration set in the main process is not seen there until the provider process restarts. On a fresh
provider process it may read the right value, which is why it can look intermittent. Same class of bug as the
4.5.3 armor-comment fix and the MODE_MULTI_PROCESS reads already in PGPonyOpenPgpService.

Work:

- SessionPolicy reads (and writes) pgpony_prefs with MODE_MULTI_PROCESS, like the provider's other shared
  settings, so every read in :remote_api sees the current duration. The cache already recomputes expiry from
  the current setting on every read, so held entries follow a change at once.
- Settings shows the held-passphrase countdown from the main process's ProviderPassphraseCache, which is empty
  for anything a mail app unlocked (that lives in :remote_api). Either ask the provider process for its state
  (a small bound call or broadcast reply) or change the copy so it does not claim "none held" for mail-app
  unlocks. Clear already reaches :remote_api through ProviderCacheClearReceiver; confirm the Settings Clear
  button fires that broadcast as well as clearing locally.
- Check the card PIN cache and InAppPassphraseCache for the same stale-read pattern.

Test: a unit test cannot see two processes; cover it on device. Set 1 minute, decrypt in Thunderbird, wait past
a minute, decrypt again: it must ask. Set 1 hour: it must not ask at 6 minutes. Set "until the phone locks":
lock, unlock, it must ask.

Status: the SessionPolicy mode switch shipped in 4.6.1. The Settings display work and the on-device checks above
stay here.

Also: the provider passphrase prompt (provider_passphrase_body_format) hardcodes "remembers it for 5 minutes" and
says "to sign this message" for decrypts too. The reporter's follow-up (force-stop did not help) most likely
reflects this text. Build the sentence from the current SessionPolicy value (timed, until cleared, until the phone
locks) with sign and decrypt variants, in every locale.


## 2. Shared images read as detached signatures, and .gpg / .pgp files route to encrypt (#67)

**Status:** Shipped in 4.6.3: the packet-parse routing (#67). See PLANNING_4.6.3.md item 6.

Priority: high (bug, user-facing). Origin: elnardosa (#67).

Reported: a PNG or JPG shared from Material Files or a banking app lands in the detached-signature field of
Verify, leaving the file field empty; switching tabs does not recover the file. Separately, a shared .gpg or
.pgp file goes to Encrypt instead of Decrypt.

Cause (images): IntentHandler.isBinaryDetachedSignature decides from the first byte alone. It parses that byte
as a packet header and treats tag 2 as a signature. A PNG starts with 0x89, which reads as an old-format
header with tag 2, so every PNG looks like a signature. A JPEG (0xFF) passes for the same reason on some paths.

Work:

- Replace the first-byte sniff with a real check: parse the whole input as OpenPGP packets and accept it as a
  detached signature only when it is one or more signature packets and nothing else, within a size cap.
  Known image and archive magic numbers (PNG, JPEG, GIF, WebP, PDF, ZIP) short-circuit to "not a signature".
- Quick Action file routing: a .gpg / .pgp / .asc file whose content is an encrypted message goes to Decrypt;
  a key goes to import; a signature goes to Verify only with a data file to check it against; anything else
  goes to Encrypt. Decide by content first and use the extension only as a tie-breaker.
- Reuse the one-dialog approach from 4.6.0 item 6 for files: offer the options that fit the file instead of
  guessing one action.

Test: unit tests for the classifier with a real PNG, JPEG, PDF and ZIP header, a binary detached signature, an
armored one, a binary and an armored encrypted message, and a key. On device, share each from a file manager.


## 3. Encrypt the whole shared text, PGP block included (#58)

**Status:** Built for RC1: "Encrypt all of it" opens the whole shared text on Encrypt (new keys share_target_action_encrypt_all and _subtitle; the _other keys are gone from every locale).

Priority: low-medium (behavior). Origin: CertainBot (#58), on 4.6.0 RC1.

Reported: for text with a PGP block inside it, "Encrypt the other text" has no real-world use; offer to encrypt
the whole thing (text plus block) and let the user trim it in the text field.

Work: replace "Encrypt the other text" with "Encrypt all of it", which opens the full shared text on the Encrypt
screen. Keep the block's own action (Import, Decrypt, Verify) as it is. Update the string in all 10 locales.


## 4. Days left on each key in Recently Deleted (#58)

**Status:** Shipped in 4.6.4. See PLANNING_4.6.4.md item 2.

Priority: low (polish). Origin: CertainBot (#58).

Work: each row in Recently Deleted shows how long until it is destroyed ("10 days left", "Less than a day
left"), computed from deletedAt and KeyRepository.RECYCLE_BIN_RETENTION_DAYS, refreshed when the screen opens.
Plurals in all 10 locales.


## 5. Other places that load recipients with the plain BouncyCastle loader

**Status:** Shipped in 4.6.3: every recipient loader that chooses recipients or signers fails on an unloadable key instead of dropping it. See PLANNING_4.6.3.md item 5.

Priority: medium (correctness). Origin: the 4.6.1 share-menu fix (#67).

The share menu used KeyRepository.loadPublicKeyRing to pick recipients, which cannot read a composite ML-DSA key
or a v4 key with an algo-35 subkey, and it silently dropped them. 4.6.1 fixed that path (ShareRecipients). Sweep
every remaining loadPublicKeyRing call that chooses encryption recipients or signer keys (Contacts, Exchange,
bundle encrypt, Autocrypt, the provider) and move each to loadEncryptionRecipientRing plus the v4 algo-35
channel, with the same rule: a selected recipient that cannot be loaded stops the operation, never drops out.


## 6. SSH from Termux follow-ups (#68, #69)

**Status (Oct 13):** the fork's release is out: OkcAgent 0.3.0 (PGPony fork), tag v0.3.0, published Sep 23 with
the APK, its .asc and .sha256; PGPony's link (SshTermuxSheet, releases/latest) opens it. The upstream PR from
provider-picker (one commit on upstream master: the provider setting plus the bundled API sources) was already
opened in September. The on-device check against the release build is not repeated for 4.7.0 (decided Oct 13): the
SSH path was checked in 4.6.0 and RC3 does not touch it. The YubiKey part waits
for a working key.

Priority: medium. Origin: FunctionalHacker (#68), joshcangit (#69).

- Publish the OkcAgent fork's release (v0.3.0) so PGPony's "Set Up SSH in Termux" link has something to open.
  Release-blocking for any announcement that points at it.
- Open the upstream PR from the provider-picker branch (picker plus bundled API libraries only) for visibility.
- On-device check of 4.6.0 item 16b against the fork's release build, including a YubiKey and GrapheneOS with
  the Network permission.
- F-Droid packaging of the fork needs a new package ID, which breaks the stock okc-agents package, so it would
  also need a Termux package fork. Only if users ask for it.


## 7. Key-server and WKD import failure (#41)

Priority: medium. Origin: ThePharaohArt (#41).

A key published through Thunderbird imports fine from a file but fails from WKD / the key server with "Couldn't
parse key". 4.6.0 item 18 rebuilds lookup answers from parsed packets, which may fix it; waiting on the reporter
to retry on 4.6.0 or send the exported key and the address. If it still fails, diff the fetched bytes against
the export and fix whichever side mangles it.


## 8. Interop check for LibrePGP ML-KEM-768 + brainpoolP256r1 keys (carried from 4.6.0 item 13)

Priority: medium. Origin: limbodiver.

The key type generates and round-trips in PGPony but has not been checked against GnuPG 2.5 / Kleopatra. A tester
with gpg 2.5 imports it and encrypts both ways. Fix anything that fails; until then the picker's "Limited app
support" line stands.


## 9. Subkey "Revoke this subkey instead" alignment (#36)

**Status:** Shipped in 4.6.4. See PLANNING_4.6.4.md item 3.

Priority: low (polish). Origin: CertainBot (#36).

The revoke-instead option in the subkey remove dialog may read better aligned to the right, matching the key
delete sheet. Check both dialogs side by side and align them the same way.


## 10. Trust levels: new shields and a "Don't use" level (#75, reopens 4.6.0 item 7)

**Status:** RC2. TrustLevel gains DONT_USE (stored by name, so no migration; kept last so a duplicate merge keeps
it). TrustMark: Unknown grey GppBad (X), Unverified amber GppMaybe (!), Verified green GppGood, Ultimate
blue-violet star on a shield, Don't use red DoNotDisturbOn; check on device that GppBad and GppMaybe draw X and
"!" (the old comments described them the other way round). The Encrypt screen's primary button, Sign File and the
Quick Action encrypt ask before using a Don't use recipient or signer (DontUseConfirmDialog), card paths
included. The provider never picks a Don't use key for an address, refuses one asked for by key ID or as signer
(opportunistic mode reports it as missing), and the Autocrypt status treats it as missing. On device (RC2): mail apps
decide before they ever ask PGPony to encrypt, so Thunderbird does not offer encryption to a Don't use key at
all and FairEmail reports no key found; the send is refused either way, and the explanation lives in the app.
GET_KEY_IDS still returns the key when it is the only one for the address, for a client that goes on to
encrypt and gets the Don't use message. The verify banner
turns red for a valid signature from a Don't use key; decrypt and verify otherwise unchanged. Backups write the
level's name ("Don't use") in metadata as before; restore never applies trust. 9 strings, all 10 locales (ko
without the 2 provider errors). Test: TrustLevelDontUseTest.

Priority: medium (feature). Origin: #75. Status: reopened and accepted for 4.7.0 as proposed.

Ladder:

- Unknown: grey shield with an X (was "?").
- Unverified: yellow/amber shield with "!" (unchanged).
- Verified: green shield with a check (was blue).
- Ultimate: blue-violet shield with a white star (was green). Partly reverses the #36 color swap; Ultimate
  stays distinct by shape.
- Don't use: new level, red no-entry sign.

Defaults: key pairs Ultimate, public keys Unknown. All five can be set on any key.

Work:

- TrustLevel gains DONT_USE (Room migration; existing rows keep their level). TrustColors and TrustMark updated;
  KeyCard, Key Detail, the Contacts badge and the recipient picker all render through TrustMark.
- Behavior for Don't use: encrypting to such a key or signing with one asks for confirmation first. Decrypt and
  verify keep working and show the red mark. Provider (mail app) path: refuse to encrypt to a Don't use key
  without the in-app confirmation rather than silently using it.
- Strings and content descriptions for the new level and the changed symbols, in every locale.
- iOS mirrors the ladder in 8.3.x so both platforms match.

Test: set each level on a public key and a key pair; check every surface shows the same mark; encrypt and sign
with a Don't use key and confirm the prompt; decrypt an older message to it.


## 11. Parallel effort (not release-gated): SOP interoperability wrapper (#64)

Carried from 4.6.0 item 8. A Stateless OpenPGP CLI over PGPony's crypto so it can join the sequoia-pgp interop
test suite; only the core roundtrip commands are needed. Does not gate 4.7.0.


## 12. External review follow-up

Placeholder. If the external review of the 4.6.0 tag goes ahead, its findings land here, under the same rules as
4.6.0 item 17: generic wording in anything committed or public, and the detail kept outside the repository.

### 12a. Internal review before desktop 3.0.0 (Oct 1 2026)

A security review of the shared engine and the pairing core, run before desktop 3.0.0, landed its fixes on main:
the message and signature checks (one grammar walker for in-memory, streaming and card decrypt; signer identity
by fingerprint; expired signatures graded), messages without integrity protection refused, secret key imports
over an existing contact proven before the contact becomes a key pair, verified key-server revocations, proxy
and Tor traffic resolving names through the proxy (a loopback SOCKS bridge), and a pairing protocol revision
(item 21). The keys.pgpony.app onion mirror now defaults to off (an explicit choice is kept), matching desktop
3.0.0. Eleven new error strings with ErrorText rules; Korean falls back to English for them, as for every
other error string.

On device before 4.7.0: Tor mode with Orbot (key search, WKD, update check, publish), a custom proxy with and
without a user name, an OpenKeychain backup restore, importing your own protected key over a contact, and the
OpenPGP provider with Thunderbird (signed, encrypted, signed and encrypted, from a card).

Point release: 4.6.2 predates the grammar work entirely, and its card decrypt reads the literal the same way
the review flagged on main. Check v4.6.2 against ContentWalkerTest's crafted messages; if they get through,
a 4.6.3 on the `4.6.x` branch carries the walker and the card result change (nothing else), ahead of 4.7.0.


## 13. Move an existing key onto an OpenPGP card, like gpg's keytocard (#71)

**Status:** RC4. Key Details menu Move to security key on a v4 classical key pair (MoveToCardSheet): each slot (Signature, Decryption, Authentication) gets one key that fits it, defaulting to the newest subkey for that use, or Leave as it is; keys that cannot move are listed with why (v6, RSA other than 2048/3072/4096, NIST and brainpool curves and RFC 9580 Ed25519/X25519 not supported yet, other types). Before Move: Save a backup first (the Export private key flow) and I have a backup, Replace keys already in the chosen slots, Remove the moved keys from this phone (on by default), the key's passphrase, the admin PIN and the user PIN. The keys are unlocked before any card is touched (a wrong passphrase stops there). Replace is not required to enable Move (on device Oct 14 it read as a statement and kept Move greyed out): the card is read before any PIN is sent, and a chosen slot already holding a different key stops the move with move_to_card_slots_occupied unless Replace is on. crypto/card/KeyToCard.kt (pure): eligibility and slot fit, algorithm attributes (RSA 01 | n bits | e bits | format, keeping an RSA slot's import format; Ed25519 16 + OID; Cv25519 12 + OID), the Extended Header List 4D { CRT 00, 7F48 template, 5F48 values } built in one exactly sized array, RSA parts for formats 00 to 03 (e, p, q, 1/q mod p, d mod p-1, d mod q-1, n), the Ed25519 seed, the X25519 secret in native or stored order, and the divert-to-card stub (GNU S2K 1002 with the card's AID). OpenPgpCardSession.importPrivateKey (PUT DATA odd INS 0xDB, P1P2 3FFF, command chaining past 255 octets) and readAlgorithmAttributes. crypto/card/KeyToCardService.kt, one card operation over NFC or USB: the user PIN (PW1) is checked first, so a wrong user PIN stops before anything is written, then the admin PIN (PW3, a wrong one is reported as the admin PIN with its tries left); then per slot set the algorithm attributes only when they differ from what the slot already has, import, write fingerprint and creation time; then with PW1 use each slot once and check it against the public key (a signature that verifies, a test message that decrypts through CardDecryptService, an INTERNAL AUTHENTICATE that verifies); a Cv25519 slot is written in OpenPGP's stored byte order first and, if its test fails, written again in native X25519 order and tested again; then the card's fingerprints are read back and compared. A card that refuses the attributes or the import gives err_move_to_card_unsupported; a failed check gives err_move_to_card_check_failed and nothing on the phone changes. Only then KeyRepository.finishKeyToCard runs (not through the card scan's matching, which could pick another key pair held in another slot): it first unlinks any other keyring entry from the slots this move overwrote on the same card, then, when Remove is on, replaces the moved keys' secrets with divert-to-card stubs (exports to gpg as ssb>/sec>) and turns the key pair into a key on a card. Remove is offered only when every secret key in the key moves (one per slot, no two slots sharing a key); a partial move keeps the full key pair on the phone and the card holds copies. A certify-only primary may go to the Signature slot, as in gpg. Changing expiry with a security key now checks the card's Signature slot holds this key's primary and says so if not (err_card_expiry_primary_missing). Buffers that held private key bytes are wiped after their APDU (BigInteger values from Bouncy Castle cannot be). Tests: KeyToCardTest (run on the JVM against Bouncy Castle 1.85: BER lengths, the EC and RSA lists, CRT values, attributes, Ed25519 seed and X25519 byte order against Bouncy Castle's own keys, slot fit, the stub read back as a card stub). Left out: ECDSA and ECDH on NIST and brainpool curves (PGPony's card signer does not handle ECDSA yet), checking the card's algorithm information DO before writing (the card's refusal is reported instead), and restoring a backup onto a second card in one step (import the backup, then move again).

Priority: medium-high (feature). Origin: m0a0k0s (#71).

Requested: write an existing secret key from the PGPony keyring onto an OpenPGP card (YubiKey 5 NFC), the way
`gpg --edit-key` then `keytocard` does. Today PGPony can generate a key on the card and use keys already on
it, but cannot transfer one, which leaves a choice between an on-card key that can never be backed up and a
trip to a desktop with gpg.

What exists: the card session already does PUT DATA (0xDA) for the algorithm attributes (C1/C2/C3), the slot
fingerprints (C7/C8/C9) and generation times (CE/CF/D0) as part of on-card keygen, reads the public keys back
from the slots, and pairs a keyring entry with a card (cardSigFingerprint / cardDecFingerprint /
cardAuthFingerprint). What is missing is the key import itself: PUT DATA with odd INS 0xDB and the Extended
Header List (tag 0x4D) that carries the private key.

Work:

- Key Detail > "Move to Security Key" on a key pair. The user picks which subkeys go to which slot, gpg style:
  the signing key to Signature, the encryption subkey to Decryption, the authentication subkey (4.6.0 item 16)
  to Authentication. A primary key that certifies and signs may go to the Signature slot.
- Build the 0x4D Extended Header List per slot and algorithm: RSA (2048/3072/4096, standard or CRT form as the
  card's algorithm information says), ECDSA/ECDH on P-256/384/521 and brainpool, and Ed25519/Cv25519 (EdDSA and
  ECDH with Curve25519, YubiKey firmware 5.2.3 and later). Set the slot's algorithm attributes first when they
  differ, then write the key, fingerprint and generation time. Read the card's algorithm information / extended
  capabilities and refuse cleanly when the card or firmware cannot hold that key type. Composite and
  post-quantum keys cannot go to any current card; say so instead of offering the action.
- Admin PIN (PW3) for the import, through the existing PIN and tap flow. Warn before overwriting a slot that
  already holds a key.
- Verify after writing: read the slot's public key back from the card and compare it to the subkey's public
  material and fingerprint. Only then pair the card with the keyring entry.
- Backup before transfer. The whole point is a key that can be backed up, so before writing, offer an encrypted
  export of the key (the existing backup / export path) and make the user confirm they have a copy.
- After a verified transfer, the user chooses: keep the private key on the phone as well (backup copy, card used
  for daily use) or remove it and keep only a stub pointing at the card, which is what gpg does on save. Default
  to removing it, with the backup step above as the safety net.
- Zeroize every buffer that held private key bytes once the APDUs are sent.

Test: unit tests that build the 0x4D TLV for each algorithm and compare against known-good vectors (gpg's
output for the same key, captured with an APDU trace). On device with a YubiKey 5 NFC and over USB: move an
Ed25519/Cv25519 key and an RSA 4096 key, sign, decrypt and SSH-authenticate with the card, confirm the stub-only
keyring entry uses the card, and restore the backup onto a second card.

Security note: this is new code handling private key bytes and an admin PIN; it goes to the next external
review together with the card code it extends.


## 14. v6 recipient key ID read from the wrong end of the fingerprint (#73)

**Status:** Shipped in 4.6.3. See PLANNING_4.6.3.md item 3.

Priority: high (bug, interop). Origin: #73.

Reported: a message GpgFrontend (rPGP engine) encrypts to a PGPony-generated ML-DSA-65 v6 key fails with "no held
composite secret key for any of the 1 composite recipients". The other direction works.

Cause: the message uses a v3 PKESK, which names the recipient by 8-octet key ID. For a v6 key the key ID is the
first 8 octets of the 32-octet fingerprint (RFC 9580 5.5.4.3). CompositeDecryptor.findRawCompositeByKeyId takes
the last 8 for every fingerprint, which is right only for the v4 algo-35 subkeys it also handles. Confirmed on the
reporter's data: the subkey fingerprint starts 06E6E9D9B8C7E936, the PKESK names 06E6E9D9B8C7E936, and PGPony
compares against DFC7997018237FC7.

Work: derive the key ID by fingerprint length (32 octets: first 8; 20 octets: last 8) in one helper and use it
here and anywhere else a v3 PKESK or issuer key ID is matched against a v6 key. Check findSecretKeyByKeyId for
the same assumption. After the fix, confirm the v3 PKESK + SEIPDv1 composite path decrypts end to end.

Test: unit test with the subkey fingerprint and the PKESK recipient octets only. Do not commit the reporter's key
block (its user ID is personal data). Add a round trip with an in-test v6 ML-DSA-65 key and a v3 PKESK.


## 15. Package mode: ML-DSA signing, and encrypting or signing each file separately (#72)

**Status:** RC3, built with item 38. With several files chosen, the bundle screen offers One package (as before) or Each file on its own: Encrypt, Encrypt and sign, or Sign only (a detached .sig per file, the files unchanged). Output goes to Save to a folder or Share all, one result row per file, and one failed file does not stop the rest. A passphrase asked once is used for the whole batch (Skip the rest stops asking). Signing each file with a card key is refused with a message (a tap per file), so choose a software key or one package. Decrypting several files is item 38. The ML-DSA package signing bug shipped earlier, see the next line.

**Status:** The ML-DSA signing bug shipped in 4.6.3 (PLANNING_4.6.3.md item 5). Encrypting or signing each file separately is still open here.

Priority: high for the bug, medium for the feature. Origin: #72.

Bug: package (bundle) mode loads the signing key through a path that cannot read ML-DSA keys and then reports
that the key could not be unlocked. Same gap 4.5.3 fixed for single files; route the package signer through the
composite signer and verify a signed package on decrypt. Overlaps item 5's loader sweep.

Feature: when several files are chosen, offer one package (as now) or each file on its own: encrypted, encrypted
and signed, or signed only with a detached .sig per file. Output to a picked folder or shared together; one
failed file does not stop the rest. Decrypt and Verify accept several .gpg or .sig files at once.


## 16. Keyring "tap the +" tip flashes on every launch (#74)

**Status:** Shipped in 4.6.3. See PLANNING_4.6.3.md item 7.

Priority: medium (bug, visible). Origin: #74.

Cause: KeyringScreen shows the keyring_fab ScreenTooltip when state.allKeys is empty, and KeyringUiState.isLoading
starts false, so the first frame (before the keys load) looks like an empty keyring. ScreenTooltip marks a tip
seen only on dismiss, so the flash never consumes it and it returns on every start. Surfaced after 4.6.0 made
Reset tips work.

Work: add a loaded-once flag to KeyringUiState (or start isLoading true) and gate both the tooltip and the
empty-keyring state (KeyringScreen around line 233) on it.


## 17. User ID row: Make Primary shifts Revoke and Remove (#76)

**Status:** Shipped in 4.6.4. See PLANNING_4.6.4.md item 4.

Priority: low (polish). Origin: #76.

Work: in KeyDetailSections' user ID row, order the actions Revoke, Remove, then Make Primary when shown, so the
first two line up on every row.


## 18. One PGPony entry in the share menu (#58)

**Status:** Shipped in 4.6.4. See PLANNING_4.6.4.md item 5.

Priority: low (polish). Origin: #58.

The EncryptTextShareAlias ("Encrypt in PGPony", added in 4.5.1) predates the 4.6.0 share sheet, whose Encrypt
option now covers it. Remove the alias so PGPony shows once in the share menu, and drop share_encrypt_text_label
from every locale.

## 19. Play Console: user-perceived ANR rate above the bad behavior threshold

**Status:** Shipped in 4.6.3 (A, B, C, E, F, G, the ProviderCardOpActivity read and StrictMode). D and H stay watch-only. See PLANNING_4.6.3.md item 8.

Priority: high (store standing). Origin: Play Console Android vitals, Sep 28 2026.

State: user-perceived ANR rate 0.63% (28-day, daily), 0.16 points over the 0.47% bad behavior threshold; peers'
median 0.01%. About 11 affected sessions out of about 2K, all phones. Play users are on 4.3.0 to 4.5.2; no 4.5.3
or 4.6.x artifact appears yet, so fixes count only once they reach the Play track (F-Droid and GitHub installs do
not). The early-September spikes leave the 28-day window in early October, but at roughly 70 sessions a day one
ANR moves a day by 1 to 2 points, so the causes have to go.

### ANR clusters (Crashes and ANRs, Sep 28), checked against the current tree

Already fixed, no work:

- PGPCryptoService.buildRSAKeyRingGenerator (3 clusters, 4.3.0) and CompositeKeyGen.addCompositeSubkey (4.3.0):
  new-key generation on the main thread. KeyRepository.generateKey has run on Dispatchers.Default since 4.4.0.
- ContactsService.getContactPhoto (4.5.0): contacts refresh moved to Dispatchers.IO on Sep 16.

Still in the code, fix in 4.7.0:

- A. ClassicalSubkeyGen.rsaKeyPair (4.4.0). Key Detail > Add subkey runs RSA generation on the main thread:
  KeyDetailViewModel.addSubkey launches on viewModelScope (Main) and KeyRepository.addSubkeyEdit has no
  withContext. The same holds for every Key Detail edit in KeyRepository (add composite encryption and signing
  subkeys, add, revoke, remove and set-primary user ID, revoke and remove subkey, expiry, notations,
  changePassphrase). Each unlocks the secret key (S2K, Argon2 on v6 keys) and signs on the caller's thread. Fix
  once at the repository: wrap each public edit function in withContext(Dispatchers.Default), the way
  generateKey already is, so no caller can run them on Main.
- B. EncryptDecryptViewModel.readAtMost ("No focused window", 4.5.2). The document-picker callbacks call
  setFileToEncrypt, setFileToDecrypt and the Verify signature pick (Screens.kt around line 3342), which read up to
  INLINE_FILE_LIMIT from the URI on the main thread. A cloud-backed provider (Drive, Nextcloud) blocks there.
  Read on Dispatchers.IO and show a loading state on the file card until the bytes arrive.
- C. FileEncryptionResultScreen save and share (4.4.0). The Save and Share handlers open the output stream and
  copy the whole encrypted result (streamed files included, which can be very large) on the main thread, zipping
  it too when wrapZip is on. Move the copy into a coroutine on Dispatchers.IO with progress. The text-result and
  file-decrypt sheets save the same way (the code comment says so); fix all three together.
- D. MessageQueue.nativePollOnce (2 clusters, 4.3.0 and 4.4.0): the main thread was idle when sampled, so the
  trace does not name a cause. Usually a slow broadcast, service start or bind in the same process. Re-check
  after A to C ship; if it persists, look at the :remote_api cold start (PGPonyApp.onCreate runs the BouncyCastle
  install, Room builder, SecureKeyStore and ContactsService in every process) and at SessionLockReceiver.

Candidates not in the traces yet, same pattern:

- ProviderCardOpActivity.onCreate does a runBlocking Room read on the main thread in :remote_api. Move it into
  lifecycleScope.
- SessionPolicy reads pgpony_prefs with MODE_MULTI_PROCESS since 4.6.1, a disk read on every durationSec() call,
  including from Settings composition and cache expiry checks. Cache the value with a change listener or read it
  off Main before 4.6.x reaches the Play track.

### Crashes in the same list (separate crash-rate metric, cheap to fix alongside)

- E. MainActivity PGPonyMainScreen, IllegalStateException (4.3.0, 4.5.2). The LaunchedEffect(action) intent
  handler navigates with popUpTo(navController.graph.startDestinationId); reading navController.graph before the
  NavHost has set its graph throws. Likely when PGPony is cold-started from a share or open-with intent while
  the NavHost is not composed yet. Wait for the graph (for example snapshotFlow on currentBackStackEntry, first
  non-null) before handling the action, or pop to a fixed route. Same guard for the other LaunchedEffects that
  navigate.
- F. KeyringViewModel.previewKeyBytes and DocumentBytes.readDetailed, OutOfMemoryError (4.4.0, 4.5.2). Picking or
  sharing a large non-key file as a key reads it whole (readBytes, unbounded), then previewKeyBytes turns it into a
  String and an armored copy, three to four times the file in memory. Cap key-import reads (a few MB is far above
  any real keyring export), fail with "too large to be a key" above it, and only build the String when the head
  looks like armor.
- G. CompositeSigPacket.dearmor, IllegalArgumentException (4.5.2, 3 events). Strict Base64 decode of a damaged or
  edited armored block throws, and CompositeDocumentVerifier calls it unguarded (verifyDetached path and around
  lines 155 and 209). Throw a typed parse error from dearmor and show "the signature block is damaged" instead of
  crashing. Check every caller.
- H. ConfigurationController.updateLocaleListFromAppContext, NullPointerException (4.5.2, 1 event). Platform
  frame, most likely around per-app language handling. Watch it now that 4.6.2 adds locales; no change yet.
- ClipboardService.copyText RuntimeException (4.3.0): already caught since the Play vitals clipboard fix.

### Guard rails

- StrictMode (detectDiskReads, detectDiskWrites, detectNetwork, penaltyLog) in debug builds for both processes, so
  main-thread I/O shows up during RC testing.
- Ship the fixed build to the Play track promptly.

Test: StrictMode clean on a debug build through Add subkey (RSA 4096), every other Key Detail edit, change
passphrase on an Argon2 key, picking files from a cloud provider for Encrypt, Decrypt and Verify, saving and
sharing a large encrypted file, a cold start from a share intent, importing a 100 MB non-key file as a key, and
verifying a cleartext message with a damaged signature block. Then watch the Play ANR rate for the 28 days after
the fixed build reaches most Play users.

## 20. Adding a User ID to a passphrase-protected ML-DSA key always fails

**Status:** Shipped in 4.6.3. See PLANNING_4.6.3.md item 4.

Priority: high (bug, blocks a basic edit). Origin: field report on 4.6.1, Pixel 8, Android 17. Still in 4.6.2.

Reported: Key Detail > Add User ID on a passphrase-protected composite ML-DSA key fails even with the correct
passphrase.

Cause: KeyRepository.addUserIdEdit (composite branch) calls CompositePrimaryKeyGen.addUserId(raw, userId, pass),
which unlocks the primary only to sign the new certification and copies the ring through with its secret still
protected. The repository then calls CompositeKeyFacade.reprotect(updated, null, pass). With a null old
passphrase, CompositeSecretProtection.unlock meets the protected secret and throws ProtectedKeyException
("composite secret key is passphrase-protected"), which Key Detail shows as the add error. The passphrase was
right; the second unlock never gets it. Unprotected keys skip reprotect, which is why only protected keys fail.
The add-subkey paths got this right in 4.5.2 with reprotect(updated, pass, pass).

Same bug: revokeSubkeyEdit's composite branch (KeyRepository around line 1884) also calls
reprotect(updated, null, pass), so revoking a subkey on a protected ML-DSA key fails the same way.

Work: pass the passphrase as the old one in both places, or drop the reprotect call entirely where the ring comes
back already protected with the same passphrase (addUserId and revokeSubkey both copy the secret packet
unchanged). Sweep every other composite edit for a reprotect(..., null, ...) on a ring that is still protected.
Map ProtectedKeyException in Key Detail edits to the normal "wrong passphrase" or "passphrase required" message
rather than the raw text.

Test: unit tests on a passphrase-protected ML-DSA-65+Ed25519 key: add a User ID, revoke a subkey; each succeeds,
the ring still unlocks with the same passphrase afterwards, and the public ring carries the new certification or
revocation. Repeat on an unprotected key. On device, the reported case from Key Detail.

## 21. Pair with PGPony Desktop and move keys over the local network

**Status:** Shipped in 4.6.3, with per-item confirmation rows and a summary on Done (PLANNING_4.6.3.md item 10). Left for main: an optional `"skipped": true` member on RESULT so a skip is not told from a failure by its reason text (unknown members are ignored, so v1 peers are unaffected), and the matching rows in desktop's PairDialog.

Priority: medium (feature, cross-platform). Origin: desktop 3.0.0 F1. Protocol core landed Sep 30 2026; UI not
scheduled, may slip to a later release without holding 4.7.0.

Desktop 3.0.0 pairs two computers on the same network (the host types the six-digit code the joiner shows;
the joiner confirms it matches) and moves
public keys, key pairs and a full backup between them. The protocol is docs/PAIRING_PROTOCOL.md, and its
Kotlin core now lives here as `com.pgpony.android.pair` (PairCrypto, PairWire, PairProtocol, PairSession,
PairInvite), pure JVM with tests and vectors, so desktop vendors it back the way it vendors the engine. No
app code calls it yet, so it costs nothing at runtime; R8 drops it from the APK until the UI uses it.

Work (when scheduled):

- Settings or Keyring overflow: "Pair with another device". Two paths: Scan (camera, ZXing, reads the
  `pgpony-pair:1?...` invite a desktop or phone host shows) and Host (opens a 10 minute window, shows the
  invite QR and the address). Typing `address:port` stays as a fallback.
- Runs on Dispatchers.IO; screen kept on; leaving the screen for good ends the pairing.
- Only local-network peers may connect (`PairPeer.isAllowed`, cellular excluded); show the peer's address.
- The code screen (host: type the joiner's code, three tries; joiner: Same code / Different), then a paired
  screen: offer (key pairs, public keys, backup) and incoming offer
  (accept per item, recovery code field for a backup), mirroring desktop's PairDialog.
- A small controller like desktop's PairController: candidates, prepare (key export under a transfer
  passphrase when the key has none, backup export under a fresh recovery code), apply (import and restore
  through the existing services).
- INFO lists all three kinds in `accepts`.
- Target SDK 37 (Android 17) needs ACCESS_LOCAL_NETWORK, a runtime permission, for the LAN socket; ask on the
  pairing screen. Not needed while targetSdk stays 36.

Test: the unit tests in app/src/test/kotlin/com/pgpony/android/pair/ (loopback end to end, the three vector
files). On device: pair with desktop as joiner (scan) and as host, a wrong typed code and a Different once, move
one item of each kind both ways.


## 22. Offline primary key: secret subkeys only, GnuPG stub primary (iOS 8.4.0 item 1.3)

**Status:** RC2. OfflineStub.isStub (GNU 1001 and 1002 by S2K, else isPrivateKeyEmpty) is checked wherever a
secret key is picked or unlocked: signing skips stubs and says "offline primary" when the only signer is one; the
PKESK scan skips them; User ID, expiry, subkey and revocation edits refuse with the offline message; Key Detail
hides those edits and the Revoke item behind one banner (offline or on a hardware key); the import preview reads
"Key Pair (offline primary)" with a note. Export, the export passphrase and passphrase change keep the stub byte
for byte, and protection is read from the first key with material. A block in which every secret key is a stub
imports as a public key; pairing a 1002 primary with a linked card waits for RC4. One banner explains the hidden
edits instead of a line per action. Re-importing your own key pair now also brings in a secret subkey the stored
ring lacks (one added in gpg where the primary is kept), taking only subkeys the merged certificate binds and never
replacing a held secret; otherwise the newest encryption subkey would have no secret here. Export with a passphrase
leaves already-protected keys as they are and writes S2K usage 254. Fixtures (GnuPG 2.4) and OfflinePrimaryTest
in app/src/test.

On device: import rsa-c and ed-c stub exports, sign, encrypt and sign to self and to others, decrypt, sign
through the provider from a mail app, check the banner and that the hidden edits are gone, export and
`gpg --import` (shows `sec#`), `gpg --verify` the signatures; add a subkey in gpg, re-export the subkeys and
re-import: the new subkey decrypts in PGPony.

Priority: medium (feature, interop). Origin: an email report against iOS 8.3.0 build 7; Android checked by
reading the code only. Written on 4.6.x and carried to main with the 4.6.3 merge.

Reported (iOS): a GnuPG 2.5 key with an RSA 4096 certify-only primary kept offline and RSA 4096 [E] and [S]
subkeys, exported with `gpg --export-secret-subkeys 'ENC!' 'SIGN!'`. The primary arrives as a GNU dummy stub:
a complete public part, then S2K usage 0xFF, cipher 0x00, S2K type 101, hash 0x00, "GNU", mode 0x01 (1001,
no secret material). Import works; encrypt with signing fails on iOS. The ask is support for offline
primaries, as GnuPG and OpenKeychain have.

Where Android stands: BouncyCastle parses the stub (S2K.GNU_DUMMY_S2K, isPrivateKeyEmpty), and
pickSigningSecretKey prefers a signing subkey, so plain signing likely works already. Only the 4.6.3 pairing
code knows what a stub is (PairKeyProtection). Everything that unlocks the primary does not: UserIdService,
KeyExpirationService, RevocationService, subkey add and revoke, certification of other keys, and the
signing-key picker, which lists an [SC] stub primary as a choice. On a stub, extractPrivateKey returns null
or throws, and today that surfaces as a generic error or a passphrase prompt that can never succeed.

Work:

- One check, `isOfflineStub(secretKey)`: GNU dummy (1001) or divert-to-card (1002) S2K, or
  isPrivateKeyEmpty. Use it everywhere a secret key is picked or unlocked.
- Signing: signingSecretKeys and pickSigningSecretKey skip stubs; the picker never offers one. When the only
  Sign-capable key is a stub, say "The primary key's secret is not on this device (offline primary). Sign
  with a signing subkey." instead of asking for a passphrase.
- Decrypt: the PKESK scan skips stubs as candidates, so a locked stub never sets sawLockedKey.
- Key Detail: show the primary as "Offline primary (secret not on this device)"; disable add or revoke user
  ID, add, revoke or extend a subkey, change expiry, certify another key and revoke the key, each with a line
  saying why.
- Import preview: "Key pair (offline primary)". The passphrase check unlocks a subkey, never the stub.
- Export, backup and passphrase change keep the stub byte for byte, so the key goes back into gpg as
  `sec#`. Pairing already skips stubs; keep that.
- A divert-to-card stub (1002) imports with a note, or pairs with a card when one is linked.
- New strings in all locales.

Test: gpg fixtures (RSA [C] stub primary with [E] and [S]; Ed25519 [C] stub primary with Cv25519 [E] and
Ed25519 [S]; an [SC] variant of each; a 1002 stub). Unit tests for isOfflineStub and signer selection. On
device: import each, sign, encrypt and sign to self and to others, decrypt, sign through the OpenPGP provider
from a mail app, export and re-import into gpg 2.5, `gpg --verify` every signature, and confirm each
disabled Key Detail action explains itself.


## 23. Encrypt and sign a large file with an ML-DSA key runs out of memory (#73 follow-up)

**Status:** Built for RC1. encryptStream takes a composite signer (CompositeDocumentSigner.InlineStream), used by single files above the inline limit and by package mode; detached file signing and verifying stream (signDetachedStream, CompositeSignerGate.verifyDetachedStream). The streaming decrypt no longer buffers a composite inline message: CompositeInlineStreamReader hashes the literal as it is written and CompositeSignerGate.verifyStreamed grades the signatures from their digests. The large-file encrypt path also passes the chosen recipient subkeys now. Unit tests: CompositeStreamingTest. On device: the 500 MB case, and the GpgFrontend check. RC1 (#73): a 2 GB file encrypted and signed, then decrypted and verified, both ways with GpgFrontend on an ML-DSA-65 key; ML-DSA-87 still open.

Priority: high (bug). Origin: #73, after 4.6.3 RC1: a 500 MB file encrypts fine but encrypt and sign with an
ML-DSA key fails with an out-of-memory error.

Cause: with a composite signer, encryptFile reads the whole file (`readBytes()`), and
CompositeDocumentSigner.signInline copies it again into the literal packet and again into the joined message,
before encryption makes one more copy. The comment that a composite signature "cannot stream" is wrong: it signs
a SHA-256 digest like any OpenPGP signature, so the data can be hashed as it streams.

Work: a streaming composite inline signer (one-pass packet, literal data streamed through the hash, signature
packet at the end) feeding the same streamed encryption encrypt-only uses; the same for package mode and for
detached signing of a file. Test: a signed 500 MB file on a low-memory device, and a byte-for-byte check that the
streamed output verifies in PGPony and in GpgFrontend.


## 24. Re-importing your own key edited in gpg changes nothing (#78)

**Status:** Built for RC1: CertificateMerge.mergeDetailed takes newer owner self-signatures (0x1F, 0x10 to 0x13, 0x18) on components already present; the secret ring gets the same public parts (PGPSecretKeyRing.replacePublicKeys, BC rings only, so a composite key pair updates its public copy only); the import says what was applied, or why nothing was. Unit tests in CertificateMergeTest. On device: the gpg setpref and SHA-512 case, then export and `gpg --import`. RC1 (#78): the reporter confirmed the gpg-edited key imports with its changes and the export reads back in gpg.

Priority: medium-high (bug, interop). Origin: #78: preferences changed and binding signatures remade with
SHA-512 in gpg, exported and imported back; PGPony keeps the old key and says it is already in the keyring.

Cause: CertificateMerge (4.6.0 items 17.1 and 12) treats the local copy of a key pair as authoritative and takes
only revocations and third-party certifications from an incoming copy, never self-signatures. The rule was meant
to stop a keyserver adding or stripping parts of your own key; a newer self-signature that verifies against the
primary can only come from the key's owner.

Work: for key pairs, accept newer self-signatures (direct-key, User ID binding, subkey binding) that verify
against the primary; newest wins per component, as OpenPGP reads them. Update the stored secret ring's copy too,
so a key pair export carries them. The import result says what was applied, or why nothing was. Keep the rule
for components the owner never bound (new User IDs and subkeys from a server). Test: the gpg setpref and SHA-512
case, a stale older self-signature replayed (ignored), a server copy with a stripped User ID (unchanged), and an
export afterwards that gpg reads with the new preferences.


## 25. Quick Actions decrypt of an ML-DSA-signed file loses its name and shows as text (#67)

**Status:** Built for RC1: CompositeDocumentVerifier.inlineFilename on both composite decrypt paths; PlaintextKind classifies the Quick Action result. Unit tests: PlaintextKindTest, CompositeDocumentSignaturesTest.

Priority: high (bug, visible). Origin: #67 (Oct 5): an image encrypted and signed with an ML-DSA key, decrypted
through the Quick Action, shows as text and offers to save as "message.txt". The same file through Decrypt Files
keeps its name and type. Promised on the thread for the next update; 4.6.4 did not carry it.

Cause: two gaps that add up. PGPCryptoService.parsePlain's composite-inline branch builds its DecryptResult without
the literal packet's filename, where the classical branch carries it. ShareTargetViewModel.publishDecryptResult
then decides text or binary by `String(data, UTF_8)`, which never throws, so with no filename to go on every
result reads as text.

Work: carry the literal filename through the composite branch. Classify the result by content, not by whether a
lenient decode succeeds: a strict UTF-8 decoder (CodingErrorAction.REPORT), NUL bytes, and the known image and
archive magic numbers the 4.6.3 share routing already recognizes. Save under the literal filename, falling back to
an extension from the sniffed type. Test: a JPG encrypted and signed with an ML-DSA key opens as a file with its
name through the Quick Action; the classical path is unchanged; a signed text message still shows as text.


## 26. An ML-DSA-65 v6 key imported in 4.5.x can't be encrypted to after upgrading (#67)

**Status (Oct 9 2026):** desk reproduction built (ImportedPqcKeyUpgradeTest, with sq 1.5.0 fixtures). Every stored shape an upgrade leaves behind loads as a recipient and decrypts, and sq's own encrypted and signed message decrypts and verifies, so the stored public key is not the cause. The run found a different bug that every sq key hits in every shape: composite signing always used the primary, and sq makes a certify-only primary with a separate ML-DSA signing subkey, so each signature PGPony made with such a key graded "Signer key is not allowed to sign" (NOT_SIGNING_KEY), in PGPony and in other verifiers. Fixed for RC1: CompositeKeyFacade picks the signing key (the primary when its self-signature allows signing, else the newest valid composite signing subkey) and every composite signing path uses it. Whether this is the reported red error still needs the message wording; the old key store path was checked on a phone on Oct 9: two sq 1.5.0 keys (one protected) imported armored on 4.5.2, upgraded through 4.5.3 and 4.6.3 to main, encrypting to, signing with and decrypting each at every step: no errors. Not reproduced outside the reporter's install (a Work Profile since about 4.1.0); waiting on the wording of the red message and the reporter's public key. 4.5.2 cannot import a binary ML-DSA key (its composite path reads armor only); fine on later versions.

Priority: high (bug, data). Origin: #67 (Oct 5): in a Work Profile install dating from about 4.1.0, a v6 key with
an ML-DSA-65 primary and only post-quantum subkeys, generated with sq and imported during 4.5.x, fails with a red
error when chosen as a recipient on 4.6.3. A copy of the same key restored from another profile's backup works.

Reading so far: since 4.6.1 a recipient that can't be loaded stops the operation instead of being left out, so a
stored copy the current loader can't read now surfaces as an error. That points at the form 4.5.x stored the key
in. It also means messages encrypted from that install before 4.6.1 may not have included the key (the 4.6.1
notes already warn about the silent drop).

Work: reproduce on a test phone: install 4.5.x, import an sq-generated all-PQ v6 ML-DSA-65 key, upgrade through
4.6.0 to current, and encrypt to it. Compare the stored blob with a fresh import. Fix in the loader, or normalize
old stored keys once at upgrade, whichever the comparison supports; never by dropping the key silently. Needs the
reporter's public key (asked on Oct 5) if a fresh sq key does not reproduce it.


## 27. User IDs bound with SHA-1 vanish on import or restore; the key shows "Unknown" (#67)

**Status:** Built for RC1 per the Oct 9 decision (see RC breakdown). SignaturePolicy.isWeakCertificationDigest; CertificateBindings keeps a weak-only User ID through analyze and sanitize; Key Details shows a Weak hash mark. Keys already restored without their names need one more restore or re-import. Unit tests: CertificateBindingsWeakUserIdTest.

Priority: medium-high (bug, visible). Origin: #67 (Oct 5): after restoring a backup, several older RSA 4096 public
keys came back named "Unknown", while the same keys in the live install still showed their names.

Cause (to confirm): since 4.6.0 an import keeps only components whose binding signature verifies under the current
algorithm rules. Older keys often bind their User IDs with SHA-1 self-signatures, so every User ID is dropped and the
key is left nameless. Restore re-imports every key, which is why it shows there and not in the live keyring.

Work: keep a User ID whose only binding uses SHA-1, and mark it in Key Details as bound with a weak hash, so the key
keeps its name. Decide what the weak binding means for trust (it must not make the key look verified) and for
recipient lookup by address. Test: an RSA key with a SHA-1 User ID binding imports with its name and the weak mark;
a backup holding it restores the same way; a key with both a SHA-1 and a SHA-256 binding uses the SHA-256 one.


## 28. Thunderbird on Android fails to decrypt with a USB security key (#36)

**Status:** RC4. ProviderCardOpActivity also watches for a wired OpenPGP reader (UsbCardConnectionManager, registered in onStart), asks for USB permission from the dialog when one is plugged in, and offers Use USB key once the PIN is in; the operation then runs through UsbCardOperations.run with the same performOperation a tap runs. One operation at a time across NFC and USB (an overlapping tap is refused quietly and the NFC reader re-armed). Without NFC the dialog no longer says NFC is unavailable when USB can be used. USB wording for a wrong PIN and an unplugged key. 4 new strings in all 10 locales.

Priority: medium (bug, needs information). Origin: #36 (Sep 24): a key that works in PGPony over USB, and in
Thunderbird with GnuPG on Linux, gives "error decrypting" in Thunderbird on Android. Not answered on the thread yet.

The path is the OpenPGP API provider handing the card operation to ProviderCardOpActivity over USB. Candidates: the
provider flow assuming NFC, the USB permission prompt when the request comes from the provider process, or a card
that chains its responses (fixed in 4.6.4 for the Nitrokey 3).

Work: ask on #36 for the key model, the PGPony version and the exact error; reproduce with Thunderbird and a USB
key once a working YubiKey is on hand; fix whichever it is.

Oct 13: confirmed on #43 with a Nitrokey 3C over USB on 4.6.4. ProviderCardOpActivity only enables NFC reader mode,
so a key plugged in over USB is never seen when a mail app asks for a card decrypt or sign; in the app the same key
works over USB. Work: the provider card prompt also watches for a USB OpenPGP card (the main app's USB path, with
the USB permission asked from that activity) and runs the operation on whichever arrives first. Joins RC4 with the
card work.


## 29. Nitrokey 3 follow-ups (#43)

**Status:** NFC SELECT message built for RC1 (err_nfc_openpgp_unavailable), for a SELECT that fails with 0x6A82 or 0x6985 and for one that gets no reply at all (a Nitrokey 3C on firmware 1.9.0 over NFC, reported on #43 as 0 bytes received). Command chaining checked in code: OpenPgpCardSession.sendCommand already sends any data field over 255 bytes with ISO 7816-4 command chaining (CLA 0x10), and no path builds an extended APDU, so the largest APDU over USB is a short one (261 bytes). CCID-level chaining would only matter for a reader whose dwMaxCCIDMessageLength is under 271, below what an APDU-level reader can work with; not needed. On-card keygen over USB on a Nitrokey 3C (firmware 1.9.0) confirmed working on #43 (4.6.4). The same report found three display bugs for a key generated on a card, now item 34.

Priority: medium. Origin: #43 and the 4.6.4 USB fix (PLANNING_4.6.4.md item 1).

- A SELECT that fails over NFC (0x6A82 or 0x6985) shows the raw status. Say instead that the key did not open its
  OpenPGP application over NFC and, if it has USB, to plug it in. Nitrokey 3 firmware turns OpenPGP off over NFC.
- On-card key generation over USB on a Nitrokey 3 is untested (asked on #43). Reading, decrypting and signing are
  confirmed on firmware 1.9.1.
- Command chaining is still not implemented: an APDU larger than the reader's dwMaxCCIDMessageLength gets an
  explicit error. Check the Nitrokey 3's limit against RSA-4096 PSO:DECIPHER (513 bytes of data); implement CCID
  command chaining if it falls short.


## 30. README: hardware keys and Verify a release (#43, #77)

**Status:** Done on main: the hardware line names NFC and USB with the Nitrokey 3 note, and Verify a release lists the four assets, immutable releases, the fingerprint check and the RC-only .sha256.

Priority: medium (docs, promised). Not gated on 4.7.0; can land on main at any time.

- The hardware line says NFC only, with YubiKey 5 NFC and Token2. USB has worked since 4.1.0, and the Nitrokey 3 works
  over USB since 4.6.4 (not over NFC). Promised on #43 in August.
- Verify a release: list the four assets every release carries since 4.6.3 (APK, detached signature, armored release
  key, signing-keys file), say releases are immutable, and say to check the OpenPGP fingerprint against pgpony.app,
  keys.openpgp.org or keys.pgpony.app before trusting the key in a release. Promised on #77. The ".sha256 beside
  every release APK" line describes the RC folder on pgpony.app, not the GitHub release; fix the wording.


## 31. Certify other people's keys, like gpg's --sign-key (#79)

RC4 (card): a key whose certifying primary sits in a card's signature slot (primaryOnCard, Certify, EdDSA or RSA, not revoked or weak) is offered in Certify with (marked On card); the sheet asks for the card PIN instead of a passphrase and says to hold or plug in the key. CertificationService.certifyOnCard and revokeOnCard sign on the card through CardPGPContentSigner (SHA-256), after checking the card's signature slot holds that primary (err_certify_card_mismatch otherwise, before any PIN is sent); KeyRepository.storeCardCertifications and storeCardCertificationRevocation keep them like software ones. Certifications made by a key on a card count as yours (CertificationRow.isMine uses isOwnKey), so they get Revoke; a local one is removed without signing. The certify_no_certifier text was replaced (certify_no_certifier_card) and the old string removed from every locale. 3 new strings in all 10 locales.

**Status:** RC2, software certifiers. Key Details of a public key has Certify… (CertifySheet): pick the User
IDs, the certifying key pair (software, classical, unrevoked, unexpired, not Don't use, primary secret here with
Certify; never an offline stub), the level (no claim 0x10 by default, persona, casual, positive), an optional
expiry, and Local only; Certify stays disabled until the full fingerprint is confirmed as compared. Exportable
certifications go into the stored certificate and its cached armor, so sharing the key carries them; the done
dialog offers Share and Mark as Verified and says keys.openpgp.org drops third-party certifications. Local-only
ones (Exportable Certification false, critical) are kept in their own sealed blob next to the key
(SecureKeyStore.storeLocalCertifications), which no export, share, upload, QR, backup or pairing path reads, and
which goes with the key on purge and Clear All Data. Each User ID lists who certified it (name when held, level,
local, revoked, expired, fails to verify); your own have Revoke: a 0x30 added to the certificate for an
exportable one, removal for a local one. CertificateMerge already keeps third-party certifications on merge.
Not in RC2: an ML-DSA certifier or target (a composite signature inside a classical certificate stops Bouncy
Castle from loading it; needs the raw-packet path) and certifying on a card (RC4). Tests: CertificationTest. On
device: `gpg --check-sigs` on an exported certified key at each level, v4 and v6 both ways; a local-only one is
absent from Share, Export, QR and an upload.
Oct 13 (#79, RC2): interop confirmed both ways by the requester: a PGPony certification read by other OpenPGP
tools, and a key certified in Kleopatra shows its certifications in PGPony. Request: whole-row taps (item 43).
Oct 13 (#79, RC2): two certifications from two keys with the same name looked identical; RC3 shows the
certifier's short fingerprint after the name (CertificationLine), as unknown certifiers already did.

Priority: medium-high (feature). Origin: #79: certify another person's User IDs with your own key to take part in
the Web of Trust from the phone, including when the certifying primary lives on an OpenPGP card.

Where Android stands: imports keep third-party certifications (CertificateBindings), but nothing creates one.
UserIdService already builds certification signatures over User IDs (self-signatures only), and the card path
signs through the Signature slot (CardPGPContentSigner), so both halves exist.

Work:

- Key Details of a public key gets Certify: pick the User IDs, pick the certifying key pair (only primaries with
  the certify capability; with item 22, never an offline stub), and compare the full fingerprint before signing.
- Level as gpg's --ask-cert-level: no claim (0x10, the default, as gpg), persona (0x11), casual (0x12), positive
  (0x13). Optional expiry.
- Local-only certification, the equivalent of --lsign-key: Exportable Certification subpacket set to false, never
  included in an export, share or backup sent elsewhere.
- Card: when the certifying primary is on the card's Signature slot, sign the certification on the card after the
  PIN, over NFC or USB.
- Afterwards: share the certified key back to its owner as a file or QR. keys.openpgp.org drops third-party
  certifications, so the sheet says to send it directly or through another keyserver.
- Revoke a certification you made (certification revocation, 0x30).
- Key Details lists who certified each User ID, marking certifiers already in the keyring, and whether each
  certification verifies.
- With item 10: certifying offers to set the key to Verified.
- Merge: an incoming copy of a key you certified keeps your certification (CertificateMerge already keeps
  third-party certifications); a later re-import of your own key pair (item 24) does not touch it.

Test: a certification made in PGPony verifies in gpg (`gpg --check-sigs`) at each level; a local-only one is
absent from every export; a card certification over NFC and USB; a revoked certification shows as revoked in gpg
and in PGPony; v4 and v6 keys, including an ML-DSA certifier.


## 32. Duress PIN: a second PIN that wipes PGPony (user email, Oct 8)

**Status:** RC3. Built: Settings > Security > Lock method (device unlock, unchanged, or a PGPony PIN of 6 to 16 digits), Change PIN, Duress PIN (setup text says what it does, that it cannot be undone, never to test it, and what is not touched; offers to turn fingerprint off afterwards), Unlock with fingerprint (biometric only, never the device credential), and Erase after wrong PINs (Off, 5, 10, 20; off by default). Core in lock/AppLockCore.kt (pure Kotlin): Argon2id through Bouncy Castle (Argon2PinHasher, version 1 = 64 MiB, 3 passes, 4 lanes, 32 bytes, the app's memoryConstrainedParameters cost), a 16-byte salt per PIN, a version tag, and every attempt hashing twice (real salt and duress or decoy salt) with constant-time compares; without the wipe option, a delay of 30 s, 1, 2 and then 5 minutes after the fourth wrong PIN. Stored in filesDir/app_lock (AppLockFileStore, read on every use like SessionPolicy). PinLockScreen replaces the device-unlock screen wherever LockScreen shows (MainActivity, ShareTargetActivity); no provider activity shows the lock today. The duress PIN or the wrong-PIN limit runs AppWipe silently: filesDir/wipe_pending first, then SecureKeyStore.cryptoErase (deletes the Keystore aliases pgpony_keystore_v2_hw and the legacy _androidx_security_master_key_, plus every .dek envelope, which also holds the passphrase recovery wraps), then data/AppReset.resetAll, the reset Clear All Data now calls too (it also clears the DataStore settings, session policy, app lock, scratch and held files, folder grants, reminders and notifications, and stops PassphraseHoldService), then kills :remote_api, removes the flag and restarts into onboarding. PGPonyApp.onCreate finishes a pending wipe. Tests: AppLockCoreTest (16, run on the JVM against Bouncy Castle 1.85). Left out: translations (English only for now); Argon2 timing and the restart after the wipe need checking on device. On device (Oct 13): all green, but unlock took 5 to 6 seconds at version 1 (64 MiB, 3 passes, two hashes in a
row). Version 2 is now the default: 32 MiB, 2 passes, and the two hashes run side by side on two threads, about six
times less work per hash on the desktop JVM (190 ms to 31 ms). A PIN set under version 1 keeps it until it is set
again. The PIN screen now sits above the keyboard (imePadding) and compacts while the keyboard is up, so
Unlock and the fingerprint button stay in view.

Priority: medium-high (feature, security). Origin: user email (Oct 8, on 4.6.4): a duress PIN that, entered at
the app lock, destroys every key and resets the app. Asked for on every platform: iOS is PGPony_8_4_0_Planning.md
item 1.4, desktop is PLANNING_DESKTOP_3_1_0.md.

Where Android stands: the app lock (biometric_lock) is the system prompt, BIOMETRIC_STRONG or DEVICE_CREDENTIAL
through BiometricGate. PGPony never sees what is typed there, so it cannot tell a duress PIN from the real one. A
duress PIN therefore needs PGPony's own PIN first.

Work:

- App lock gains a choice: device unlock (as today) or a PGPony PIN (6 to 16 digits). The PIN is stored as an
  Argon2id hash with its own salt, never the PIN itself.
- With a PGPony PIN set, an optional duress PIN (must differ from the PIN). Both are checked on every attempt the
  same way, so the time taken does not tell them apart. Setting one up explains what it does, that it cannot be
  undone, and that it is never tested by entering it.
- With a duress PIN set, offer to turn off fingerprint unlock, since a finger can be forced and the duress PIN only
  helps if the PIN is what is asked for. Recommend it, don't force it.
- Entering the duress PIN wipes without any prompt or progress that says so: crypto-erase first (delete the
  Android Keystore key that wraps SecureKeyStore, so the secret material is unreadable even if the rest of the
  wipe is interrupted), then the same reset as Clear All Data, including Recently Deleted (see item 33), every
  provider, SSH and pairing approval, held passphrases and the card PIN cache. Then the app opens as a fresh
  install, on onboarding.
- Every place the lock is asked: the app, the Quick Action (ShareTargetActivity), and any provider path that shows
  the lock. The duress PIN works the same in each.
- Optional, off by default: wipe after a set number of wrong PIN attempts, on the same wipe path.
- Not touched, and said so in the setup text: keys on a hardware key (the card keeps its own PIN counters), and
  backups the user saved outside the app. It also does not help against a copy of the phone's storage taken
  before the PIN is entered.

Test: unit tests for the PIN hashing and the duress check (both PINs, wrong PINs, the attempt counter); on device,
the duress PIN from the app and from the Quick Action leaves no keys (live or in Recently Deleted), no settings
and no provider approvals, and opens onboarding; the real PIN still unlocks normally; device-unlock mode is
unchanged.


## 33. Clear All Data leaves the keys in Recently Deleted behind

**Status:** Built for RC1 (4.7.0 only, no 4.6.x release). Clear All Data purges live and binned keys (KeyRepository.clearAllKeys), wipes the secure store with its hardware wrapping key (SecureKeyStore.wipeAll), and clears every database table, which also drops mail app and SSH approvals and Autocrypt peers that survived the reset before. Confirm on device.

Priority: high (bug, privacy). Found while planning item 32.

SettingsViewModel.clearAllData deletes every key from repo.getAllKeys(), and that query is `deletedAt IS NULL`, so
keys already in Recently Deleted are skipped. Their rows and their secret material in SecureKeyStore survive the
reset, and they show up in Recently Deleted on the fresh install. iOS (performFullReset) and desktop
(ClearAllData) both clear the bin; Android does not.

Work: purge the bin in clearAllData too (purgeKey on every soft-deleted key, or one DAO delete of all rows plus a
SecureKeyStore wipe). Test: delete a key pair, Clear All Data, check Recently Deleted is empty and the secret
material is gone from SecureKeyStore. Confirm on device first, and decide whether it waits for 4.7.0 or goes out
as a 4.6.x fix.


## 34. A key generated on a card shows like a public key (#43)

**Status:** RC4. PGPKeyEntity.isOwnKey (key pair or card-backed) drives how a key is shown: the Keyring row's avatar color and key icon, an ON CARD pill next to DEFAULT (the existing On card badge text), the Key Details type chip (Key pair on a security key), the avatar tap (decrypt with it) and the same-identity list. Key Details lists the subkeys of a key generated on a card under a line saying the primary key is on the security key's signature slot (PGPKeyEntity.primaryOnCard), since the signing key there is the primary, not a subkey. isKeyPair is unchanged for everything that needs the secret on the phone. 2 new strings in all 10 locales.

Priority: medium (bug, visible). Origin: #43, a Nitrokey 3C over USB on 4.6.4.

Reported: after on-card key generation the key is listed under Key Pairs but styled as a public key (avatar color, public key text, tap to encrypt to it). Key Details shows only the encryption subkey (with ON CARD), though the card holds a signing and an encryption subkey and the + > NFC menu shows both. Suggested: an ON CARD label (or the NFC symbol used in the recipient list) beside the name on the Keyring row, styled like DEFAULT.

Work: style card-backed key pairs as key pairs on the Keyring and its row action; list every card slot's subkey in Key Details with ON CARD; add the card label to the Keyring row. Test with a card-generated key on a YubiKey and a Nitrokey 3.


## 35. Exchange key selector: show the email with the name (iOS 8.4.0 item 1.5)

**Status:** RC2. PGPKeyEntity.pickerLabel ("Name <email>", the email or the name alone when the other is blank,
the User ID when both are, then a middle dot and the short fingerprint). Used by the Exchange selector rows,
both Settings dropdowns and the Default Signing Key button; the Exchange QR block adds the email line under the
name. SignAsSheet already shows name, email and short fingerprint on separate lines. No new strings.

Priority: medium (usability, cheap). Origin: user email (Oct 10, reported on iOS 8.3.0): four key pairs, one per
mail account, all with the same name. The iOS Exchange picker lists that name four times and nothing else, so
there is no way to pick the key for a given account. Asked: identify the name and the email together.

Where Android stands: ExchangeScreen's radio rows read "userName (shortFingerprint)", and the block under the QR
shows userName and the full fingerprint. Four same-name keys are distinguishable by fingerprint, but a user who
thinks in mail accounts still has to match fingerprints by hand. SettingsScreen's Default Signing Key and
Default Recipient dropdowns show `userName.ifBlank { userEmail }.ifBlank { userID }` and nothing else, so there
the four keys are indistinguishable, the same as the iOS report. SignAsSheet already shows the email on a second
line when both are set; ApiClientsScreen appends the short fingerprint.

Work:

- One label for the user's own keys on PGPKeyEntity (say `pickerLabel`): name and email when both are set
  ("Name <email>"), email alone when the name is blank, name alone when there is no email, then the short
  fingerprint always (two keys on one address are otherwise identical). Falls back to userID when both are
  blank.
- Exchange selector rows and the identity under the QR use it (the QR block keeps the full fingerprint and
  adds the email line).
- Settings Default Signing Key and Default Recipient dropdowns, and the button text that shows the current
  choice, switch to the same label. SignAsSheet keeps its two-line layout; check it also shows the short
  fingerprint when name and email both match another key.
- No new strings: the label is built from the key's own fields. If "<" ">" reads badly in a dropdown, use a
  middle dot separator; decide on device.

Test: four key pairs with one name and four emails (two on one address); every row in the Exchange selector and
both Settings dropdowns reads distinctly, and the QR block shows the picked key's email; a key with no name; a
key with no email.


## 36. "Until I clear it" passphrase is lost after a few minutes on Xiaomi (user email, Oct 11)

Priority: medium (bug, mail-app users on aggressive OEM builds). Origin: user email on 4.6.4, Xiaomi phone on
HyperOS, Android 16.

Reported: the duration is set to "Until I clear it", yet Thunderbird asks for the passphrase again after about
10 minutes. Battery for PGPony is set to unrestricted; no change.

Cause: ProviderPassphraseCache is memory only and lives in the :remote_api process. Under the until-cleared
sentinel an entry drops only on Clear, a wrong passphrase, invalidation or process death. Nothing keeps
:remote_api alive once the mail app unbinds, so HyperOS kills the idle process and the passphrase goes with it.
Stock Android does the same, only later. The duration file (4.6.3) is not involved.

Work:

- A foreground service in :remote_api that runs while ProviderPassphraseCache holds an entry, with an ongoing
  notification: "PGPony is holding a passphrase for mail apps", plus a Clear action that clears the provider
  cache (and the card PIN cache, if it lives there) and stops the service. OpenKeychain does the same.
- Start it from ProviderPassphraseActivity right after put(), while that activity is in the foreground, so the
  Android 12+ background-start limits do not apply. Stop it when the cache empties: timer expiry, Clear from
  Settings (ProviderCacheClearReceiver), wrong passphrase, invalidation. A timed entry needs one alarm or
  handler tick at its expiry so the service does not outlive it.
- Manifest: FOREGROUND_SERVICE and FOREGROUND_SERVICE_SPECIAL_USE, foregroundServiceType="specialUse" with the
  PROPERTY_SPECIAL_USE_FGS_SUBTYPE explaining the use. Play needs the special-use declaration in the Console
  before the build that adds it goes to Play.
- Own low-importance notification channel, no sound. Without POST_NOTIFICATIONS the service still runs; the
  notification just does not show.
- Decide on device whether timed durations of 5 minutes or less skip the service (process death within 5
  minutes is rare and the notification would be noise).
- Check CardPinCache and the "until the phone locks" hold for the same process-death gap.
- New strings (channel name, notification text, Clear action) in all 10 locales.

Test: on the reporter's class of device if one turns up, otherwise stock Android with `adb shell am kill` on
:remote_api in the background: with the service running the process survives and Thunderbird does not ask
again; Clear from the notification and from Settings both stop it and the next decrypt asks; a 15 minute
duration stops the service at expiry.

Status: RC2. PassphraseHoldService (in :remote_api, specialUse, not exported) starts from
ProviderPassphraseActivity right after put() when the duration is over 5 minutes, until cleared, or until the
phone locks; low-importance silent channel; Clear in the notification wipes the provider, card PIN and in-app
caches and stops it; it checks the cache every 30 seconds and stops when nothing is held; a clear from Settings
(ProviderCacheClearReceiver) stops it too. Not sticky. Before this build reaches Play, the special-use
declaration has to be filed in the Play Console. The reporter was asked about the notification; if they object,
a setting to turn it off follows. 4 strings, all 10 locales.


## 37. Saving a large decrypted file shows nothing and can be cut short (#73)

**Status:** RC3. Built: every Save now goes through the new ui/util/SafeSave.kt, which copies on PGPonyApp.applicationScope (the existing process scope, Dispatchers.IO) instead of the sheet's coroutine, in 64 KB chunks with bytes written reported to the sheet, a Cancel, and delete-on-failure-or-cancel (DocumentsContract.deleteDocument, then DocumentFile.delete). A document from the create-document picker is written in place, since its name is the user's choice and renaming is optional for providers; a save into a folder (the batch Save to a folder) writes ".<name>.part" and renames it to the final name only after the last byte and the close, falling back to the direct write when the provider cannot rename. The pure part is ui/util/SafeSaveCore.kt (partName, copyChunked, run, runCopy, ProgressOutputStream with a short-write check), so it runs on the JVM. The sheets show "Saving" with a determinate bar (indeterminate when the size is unknown, ui/util/SafeSaveUi.kt) and disable Save while it runs; the existing Saved banner or note shows on success, an error message on failure or cancel, and a Toast when the save ends after the sheet closed. Each source stream is opened before anything is written, so closing a sheet (which clears its scratch scope) does not cut the copy short. Wired into FileDecryptionResultScreen, FileEncryptionResultScreen (plain, zip and in-memory), BundleEncryptionResultScreen (.eml and .asc saves; saveBundleStream removed), the batch saveFileBatchToFolder (same never-overwrite names and per-file results, results dropped if the batch was closed), and the Quick Action Save (ShareTargetScreen.saveResult). Tests: SafeSaveCoreTest (temp names, progress, cancel stops early, failures and a failed commit run the cleanup, writer that closes its own stream, short write). Left out: a force-stop mid-save can still leave a partial file under the user's chosen name for the picker saves (no in-process code runs after a force-stop), and a Quick Action closed mid-save leaves the copy in a process with no visible activity, which Android may kill; a foreground worker would cover both. Shares are unchanged. English strings only so far. On device (Oct 13): large decrypt save with progress, leaving the screen mid-save, Cancel, a batch Save to a folder,
and package and Quick Action saves all green.

Priority: medium (bug, large files). Origin: #73, after RC1 confirmed a 2 GB encrypt-and-sign round trip with
GpgFrontend.

Reported: after decrypting a large file, PGPony takes a while to write it to device storage, with no progress
shown. If the app is closed during that write, the file can be left incomplete.

Work:

- Show a "Saving" state with bytes written (or indeterminate when the size is unknown) for the copy to the
  chosen location, in the app and in the Quick Action.
- Keep the write alive if the screen is left: run it outside the screen's scope (a short-lived worker or the
  process-level scope used for streaming decrypts) and write to a temporary name in the target folder, renaming
  only after the last byte and flush, so an interrupted save never leaves a file that looks complete.
- Same treatment for large encrypt outputs (item 23 streaming) and package mode.

Test: a 2 GB decrypt with the progress visible; leave the app mid-save and come back; force-stop mid-save and
confirm no partial file is left under the final name.


## 38. Quick Actions with several encrypted files encrypts them as one bundle (#72)

**Status:** RC3. Built: IntentHandler.handleSendMultiple reads only a 64 KB head of each shared file and classifies it with the new intent/SharedSelection.kt (armor first line, multipart/encrypted, PacketSniff.looksLikeEncryptedMessage and isDetachedSignature, isKnownNonOpenPgp, then the BouncyCastle recipient check). All encrypted routes to the new IntentAction.DecryptFiles, which opens the Decrypt tab and runs EncryptDecryptViewModel.startDecryptBatch: each file streams through streamDecryptToFile (factored out of decryptFileStreamingPath, so the envelope skip, progress, cancel and composite rings are the same), is named from its literal packet filename or its name without .asc/.gpg/.pgp, and gets its own signature banner in FileBatchResultScreen. There was no multi-file decrypt before; the in-app picker was single-file. Encrypted files mixed with other files (or with detached signatures) route to IntentAction.ChooseSharedFiles, a dialog in MainActivity: Decrypt the encrypted ones, Encrypt all as one package, or Cancel. Plain files keep ComposeBundle, now with item 15's each-file choice. Tests: SharedSelectionTest. Left out: detached signatures with their data files and no encrypted file still go to the package route, since verifying several pairs is not built; .zip and .eml wait for the reporter; a decrypted package in a batch is saved as one .eml file instead of being split into its attachments; card-encrypted files in a batch fail with "None of your keys can decrypt this file" (decrypt those one at a time).
On device (Oct 13): a batch from the Decrypt screen's picker loaded no secret keys and failed every file as "no
matching key"; the key pairs are now read from the repository, small files take the single-file in-memory decrypt
with the fallback cascade, and a name like "message.asc (8)" becomes "message (8).txt" (copy number kept, extension
from the content when the name has none). Sharing several files, the choice dialog and each-file encrypt, sign,
save and share all green.

Priority: medium-high (bug). Origin: #72 (RC1): selecting several .asc files in a file manager and sharing them
to PGPony gives one consolidated file, with no signature results; the in-app Decrypt File picker decrypts the
same files one by one and verifies them.

Cause (from the code): a share of two or more files arrives as SEND_MULTIPLE, which only MainActivity
registers, and IntentHandler.handleSendMultiple routes every multi-file share to ComposeBundle (encrypt
together) without looking at the files. So the "consolidated file" is the encrypted files wrapped into one new
encrypted bundle, not a decrypt at all.

Work:

- handleSendMultiple classifies each shared file the way handleFileUri does (sniff, not just the extension).
  When every file is an encrypted PGP message, route to the existing multi-file decrypt (the in-app picker's
  path) with those URIs; each file decrypts, verifies and saves on its own.
- All detached signatures with their data, or a mix of encrypted and plain files: offer a choice (decrypt the
  encrypted ones, or encrypt everything as a bundle) instead of guessing.
- Plain files keep the bundle route, and item 15 adds "encrypt each separately" next to it.
- Check .zip and .eml once the reporter reports on them.

Test: share 2, 5 and 20 .asc files (armored and binary, signed and unsigned) from a file manager; each
decrypts and verifies separately; a mixed selection offers the choice; plain files still bundle.


## 39. Signing picks an expired subkey (#83, #82)

**Status:** RC3. signingSecretKeys keeps stubs and weak keys out as before, orders signing subkeys newest first
then the primary, and keeps only keys whose CertificateBindings signerValidityAt is VALID now (bound by the newest
binding, back-signed, unrevoked, unexpired). When the primary itself has expired nothing is valid, and the keys that
are only expired are offered, since the Allow expired keys gate upstream already decided that case; a valid primary
whose signing subkeys all expired or were revoked refuses with SigningError.SigningKeysExpired (new
err_signing_keys_expired, 9 locales, no ko). pickSigningSecretKey and signingKeyOptions read that list, so a chosen
subkey that has expired falls back to the automatic pick. A certificate the analyser cannot read keeps the old
capability pick. Found while building it: ClassicalSubkeyGen (Add Subkey, Sign) called the three-argument
addSubKey, which writes no 0x19 back-signature, so every signing subkey added in PGPony since 4.2.0 is not
cross-certified (gpg warns, PGPony's own check grades it UNBOUND). It now passes the subkey's signer builder. Such
a subkey is no longer picked; signing falls back to the primary when the primary can sign (PGPony's own v4 keys),
and changing the subkey's expiry rebinds it with a back-signature (KeyExpirationService). Tests:
SigningKeyPickTest, fixtures in test/resources/signsub (GnuPG 2.2, faked times).

Priority: high (bug, visible to anyone with a renewed signing subkey). Origin: #83 (Oct 13): a signed-only mail
from FairEmail is always signed with the key's expired signing subkey, with Allow expired keys off and with Ask
which key to sign with on or off. #82 (Oct 13) reports the same on another key with two current signing subkeys.

Cause (from the code): PGPCryptoService.pickSigningSecretKey and signingSecretKeys skip only offline stubs (item
22) and weak keys, then take the first Sign-capable subkey in ring order. Nothing checks the binding, revocation
or expiry, so a key whose old signing subkey comes first signs with it. findEncryptionKey already picks from
CertificateBindings.verified and SignerEvaluator.isUsableEncryptionKey (4.6.0 item 17.1); signing never got the
same treatment.

Work:

- Build the signing candidates from the verified view: a subkey must be bound, unrevoked and unexpired at signing
  time (expiry read from the newest valid binding signature, so a renewed subkey counts as current). The primary
  likewise, by its newest self-signature.
- Among usable signing subkeys, prefer the newest by creation time (gpg's choice), then the primary if it can
  sign.
- Allow expired keys does not apply: it covers encrypting to an expired recipient, and nothing ever signs with an
  expired or revoked subkey.
- signingKeyOptions (the per-send and in-app picker) lists usable subkeys only, newest first, so a key with two
  current signing subkeys offers both.
- A user-chosen signing subkey (item 26 / 4.6 §4.5) that has since expired falls back to the automatic pick.
- No usable signing key left: the existing no-signing-key error, worded for an expired subkey when that is why.

Tests: a ring with an expired then a current signing subkey (both orders); a subkey renewed by a newer binding
signature; a revoked signing subkey; two current subkeys, the newer picked and both offered. On device: FairEmail
signed-only mail with the #83 key shape, and in-app Sign Text.


## 40. Subkeys missing after removing and re-importing a key (#82)

**Status:** RC3. New crypto/SubkeyAdmission.kt holds the decisions. A duplicate import of a key pair that carries
secret material proven by SecretKeyCheck (as the upgrade path; a protected secret without a passphrase passes on
its structure) adds every subkey the stored certificate lacks and the primary binds (a verified 0x18, and for a
signing-capable subkey a back-signature in its newest binding): newBoundSubkeys picks them, withSubkeys appends
them in sanitized form, and graftNewSecretSubkeys (now SubkeyAdmission.graftSecrets) brings the secret, or the
stub gpg exported for a subkey not held at all. A held secret is never replaced; a held stub still takes real
material. A public-only re-import adds nothing (item 24). ImportOutcome.subkeysAdded drives "Added N subkeys."
(plurals import_result_subkeys_added) after the merged or self-signature note. ImportPreview.leftOutSubkeys lists
each subkey the import drops or cannot use (algorithm, short key ID, reason: SHA-1 after the cutoff, no valid
binding, no back-signature, revoked, expired); the analyser reports a SHA-1 binding as unbound, so weakHashOnly
re-checks the raw binding and back-signature against SignaturePolicy. Key Details rows get a status line
(SubkeyDisplayInfo.secretLocation and issue, SubkeyRows.withStatus): secret on this device, offline (GNU 1001),
on a card (1002, or the card-backed key's card fingerprints), or not present, read from the stored secret
packets; public keys show only the reason. Tests: SubkeyAdmissionTest (fixtures in test/resources/subkeyadd, GnuPG
2.2.27, faked times) on the pure functions, since KeyRepository needs Room. Left out: the preview does not yet say
how many subkeys a re-import will add (only the result does), and a secret block in which only the new subkeys
carry material (primary and older subkeys all stubs) proves nothing about the stored key, so it adds none. English strings only so far; translations are still to do. On device (Oct 13): green.

Priority: high (bug, needs the key). Origin: #82 (Oct 13): after deleting a 2017 RSA-4096 key and importing it
again, Key Details shows fewer subkeys than gpg lists (E and A from 2017, two S from 2025). The screenshot and
the key come from the reporter's public copies.

Work: fetch the key (github.com/<user>.gpg and keys.openpgp.org), list every subkey with gpg's
show-unusable-subkeys, and import it with the same path PGPony uses. Candidates: a binding that
CertificateBindings drops (hash policy, a missing or bad back-signature on a signing subkey), the
CertificateMerge path on a re-import after delete (item 24), or the Key Details list filtering expired subkeys.
Fix whichever it is.

Oct 13 findings: the key has six subkeys (2017 E, S expired 2021, A; 2023 S expired 2025; 2025 S and 2025 S). The
reporter's Key Details lists only the three from 2017. The 2023 binding and its back-signature use SHA-1 made after
the Feb 2023 cutoff, so dropping that subkey is policy (as sq). The 2025 bindings are SHA-256 with valid
back-signatures, and the public key from keys.openpgp.org imports on RC2 with all five expected subkeys, so the
binding check is not it. The loss is on the secret key path: an older secret backup that predates the 2025
subkeys (item 24 never adds subkeys from a public re-import), or the 2025 secrets exported as stubs before item 22.
Asked on #82 for gpg -K, the PGPony version and where the secret key came from.

Oct 13 (reporter): the PGPony backup made from that key already lacks the 2025 subkeys. Cause found in the code: for
a key pair, CertificateMerge never adds a component the stored certificate lacks (item 24's rule for public
re-imports), and graftNewSecretSubkeys only grafts a secret whose public part the stored certificate already binds.
So re-importing your own secret export with subkeys added in gpg adds nothing, which also defeats item 22's "subkey
added where the offline primary is kept" case.

Work:

- A secret re-import of your own key pair (secret material present and proven, as the upgrade path already checks)
  adds every subkey the stored key lacks that the primary verifiably binds (CertificateBindings on the incoming
  ring): the public subkey with its verified bindings into the certificate, and its secret (or stub) into the secret
  ring. A public-only re-import keeps item 24's rule and still adds nothing.
- The import reports it: "Added N subkeys" next to the existing "updated self-signatures" note.
- Seeing it (requested on #82): Key Details gives each subkey a status line, where its secret is (on this device,
  offline as a gpg stub, on a card, or not present) and why it is not used when it is not (expired, revoked, binding
  with a SHA-1 hash after the cutoff, no back-signature). The import preview lists any subkey it leaves out and why.
- New strings in all 10 locales.

Tests: a key pair re-imported with one and two new subkeys (classical, and a stub), a public re-import still adding
none, a subkey with a SHA-1 binding after the cutoff left out and listed, and the Key Details status for each case.


## 41. Recipient review from mail apps when some addresses have no key (#25, reopened)

**Status:** RC3. A non-opportunistic encrypt from a mail app that names an address with no usable key (none held,
or only a key marked Don't use) now returns USER_INTERACTION_REQUIRED with a PendingIntent to
ProviderRecipientReviewActivity (:remote_api, not exported, same look as ProviderKeyPickerActivity) instead of
"No PGPony key found". The screen lists the addresses without a key and those marked Don't use, then a
searchable keyring with whole-row checkboxes (Don't use and revoked keys left out, expired keys only with "Allow
expired keys"), with the client's signing key, else the sender's own key, ticked. Confirm returns the request plus
EXTRA_KEY_IDS_SELECTED; encryptOp adds those keys to the recipients it resolved (deduped by fingerprint), refuses
any id that is not in the keyring, revoked, Don't use or disallowed expired (new provider error, with an ErrorText
rule), and no longer fails on the missing addresses for that send. Cancel returns RESULT_CANCELED, so the draft
stays. Opportunistic sends keep OPPORTUNISTIC_MISSING_KEYS, and a storage failure keeps its own error. A send
whose only problem is an address whose sole key is Don't use now opens the review; a Don't use key the client
names by key id keeps the item 10 refusal. GET_KEY_IDS offers the same review (its own request code and URI
scheme), since FairEmail decides "no key found" from that answer and never reaches encrypt, as OpenKeychain's
getKeyIdsImpl does: its re-run validates EXTRA_KEY_IDS_SELECTED with the same rules and refusal and returns the
resolved ids plus the picks, deduped. GET_KEY_IDS no longer hands over a Don't use key's id (the item 10
fallback); the review covers that address. Opportunistic callers get the silent partial answer, and the Autocrypt
status action is unchanged. Rules in RecipientReview (pure). 8 new strings, English only so far (other locales
fall back to English). Test: RecipientReviewTest, plus the new example in ErrorTextTest. On device: whether
FairEmail's encrypt after the review sends only the returned key ids (if it also sends the addresses, the encrypt
review opens a second time). On device (Oct 13): green.

Priority: medium (feature, provider). Origin: #25 (Oct 13, reopened): OpenKeychain answers an encrypt with
addresses it has no key for by showing "Please review the list of recipients": the addresses without keys,
then the keyring with the sender preselected, to pick keys for this send. Useful when a recipient's key lacks
one of their addresses, and for addy.io's encrypt-a-reply flow.

Where Android stands: encryptOp collects the missing addresses and returns GENERIC_ERROR "No PGPony key found
for: ...". The provider already returns USER_INTERACTION_REQUIRED for the per-send sign key picker
(ProviderKeyPickerActivity), and OpenPgpApi.EXTRA_KEY_IDS_SELECTED is in the bundled API.

Work:

- When any address has no usable key and the request is not opportunistic, return USER_INTERACTION_REQUIRED
  with a recipient review screen: the addresses without keys, then a searchable keyring list (public keys and
  own keys, Don't use keys left out), with the sender's own key preselected.
- On confirm, re-run the same operation with EXTRA_KEY_IDS_SELECTED plus the keys already resolved. Cancel
  returns the client's cancel result.
- Opportunistic encryption keeps OPPORTUNISTIC_MISSING_KEYS, so Autocrypt-style "encrypt if possible" stays
  silent.
- Item 10: a Don't use key for an address shows as such on the screen, not as missing.
- New strings in all 10 locales.

Test: FairEmail and Thunderbird with one missing recipient, with all missing, and opportunistic; the picked key
is used and the send succeeds; cancel leaves the draft.


## 42. Look up a GitHub user's OpenPGP keys (#81)

**Status:** RC3. A GitHub chip (Code icon) joins the Import method picker after Link, hidden while offline
like Server and Link. It takes a username, "@name" or a pasted github.com profile or .gpg link, checks it
(1 to 39 letters, digits or single hyphens, no hyphen at either end) and fetches https://github.com/<user>.gpg on
the shared HttpClientFactory client, so offline mode, Tor and a custom proxy apply with the key server timeouts.
The body is capped at 2 MB. network/GitHubKeyFetcher.kt classifies the answer: key blocks are validated by
KeyResponse into one public key block and go to the normal preview, which lists every key (4.6.0 item 17.9),
with the .gpg link as the source; GitHub's no-keys answer (an armored block holding only a "Note:" header) and a
plain note both say the user has no OpenPGP keys on GitHub; 404 says there is no such user; other failures use
the key server search messages. KeyringViewModel.fetchKeysFromGitHub, ImportKeyScreen GitHubSection. Tests:
GitHubKeyFetcherTest (normalization, validation, the link, one and two keys, no keys, 404, other statuses, HTML
and private key answers, offline and invalid input refused before any request). Classification was also run
against GitHub's real answers for a user with keys, one without, and an unknown name. No network security
config change was needed (only the first-party onion is listed there). New strings are English only for now. On device (Oct 13): green. RC4: after a review comment on e85b48b, the binary key check in GitHubKeyFetcher and KeyResponse now reads ((body[0].toInt() and 0x80) != 0). Kotlin's infix and already binds tighter than !=, so the behavior is unchanged; the parentheses and a comment make that plain, and the comment also says why the check comes after validate (validate accepts binary keys too).

Priority: low-medium (feature). Origin: #81 (Oct 13): when a commit is signed by someone whose key you don't
have, fetch that GitHub user's keys and import them.

Work:

- A GitHub source next to WKD and the keyserver in Import: a username fetches https://github.com/<user>.gpg
  through the same network settings (offline switch, Tor, proxy) as the other lookups.
- Each key found goes through the normal import preview; an empty answer says the user has no OpenPGP keys on
  GitHub.
- Out of scope: SSH keys, and generating allowed_signers files from a repository's contributors (git tooling,
  not key management). Said so on #81.
- New strings in all 10 locales.

Test: a user with one key, several keys, none, and a username that doesn't exist; offline refuses; Tor on.


## 43. Toggle and checkbox rows respond to a tap anywhere on the row (#79)

**Status:** RC3. 31 code sites in 17 files (two of them shared row helpers, 54 rows on screen in all) now carry Modifier.toggleable (Role.Switch or Role.Checkbox, same enabled state as before) with the control's onCheckedChange set to null and Modifier.minimumInteractiveComponentSize() on the control, so its 48dp footprint and the look stay the same. Two shared helpers cover most of Settings: SettingsToggle (22 rows) and the Keyservers ToggleRow (3 rows). Other files: ApiClientsScreen, SettingsScreen (the two clear-data acknowledgements), CardKeygenScreen, PublishSheet, KeyDetailSections (strict mode and the fallback rows; the up and down arrows keep their own taps), KeyringScreen (three generate switches), CertifySheet (User IDs, Local only, fingerprint confirmation), ExportPrivateKeyResultSheet, AddUserIdSheet, DeleteKeySheet, ChangePassphraseSheet, FileEncryptionResultScreen, BundleEncryptionResultScreen, Screens.kt (recipient picker, ASCII armor, detached signature), OnboardingPage (five switches) and PairScreen (outgoing and incoming items). Rows that used clickable plus a live checkbox now use toggleable instead. Skipped: the unused LegacyInlineRecipientList in Screens.kt (kept verbatim on purpose), ProviderRecipientReviewActivity (already correct from item 41), and the FileBatch screens (no toggles). Radio rows are out of scope. On device (Oct 13): green.

Priority: low (UI). Origin: #79 (Oct 13, RC2): Local only and the fingerprint confirmation in the Certify sheet
only respond to a tap on the control itself.

Work: every row in the app that pairs a label with a Switch or Checkbox becomes the toggleable element
(Modifier.toggleable with Role.Switch or Role.Checkbox on the Row, the control's own onCheckedChange set to
null), so the whole row toggles and TalkBack reads it as one control. Covers the Certify sheet, Settings, the
encrypt and sign options, the import preview and the remaining sheets. No new strings.

Test: tap the label and the empty part of each row; TalkBack announces one switch or checkbox with its label.


## 44. Signed-only mail with an attachment: GpgOL says the attachment is not signed (#84)

**Status:** RC4, micalg part built; the GpgOL warning waits for the raw messages asked for on #84. New provider/Micalg.kt reads the hash algorithm octet of the detached signature PGPony just made (v4, v5 or v6 signature packet, armored or binary, old or new packet header) and maps it to the RFC 3156 token (pgp-sha256, pgp-sha384, pgp-sha512, pgp-sha224, pgp-sha3-256, pgp-sha3-512, and the legacy ones), falling back to pgp-sha256 when it cannot read one. Used for RESULT_SIGNATURE_MICALG on the software and composite paths in PGPonyOpenPgpService.detachedSign and on the card path in ProviderCardOpActivity. Tests: MicalgTest (also run on the JVM against Bouncy Castle 1.85 with Ed25519 signatures over SHA-256, 384, 512 and SHA3-512). On device (Oct 14): green.

Priority: medium (bug, needs information). Origin: #84 (Oct 14, RC3): a signed-only message with an attached
image, sent from FairEmail through PGPony, makes GpgOL in Outlook warn that not all attachments were signed. The
same send through OpenKeychain on the same phone gets no warning.

FairEmail builds the multipart/signed structure and hands PGPony the bytes to sign; PGPony returns a binary
(0x00) SHA-256 detached signature in RESULT_DETACHED_SIGNATURE. The one thing PGPony controls beyond the
signature is RESULT_SIGNATURE_MICALG, hard-coded to "pgp-sha256" on the software and composite paths, where
OpenKeychain reports the hash it used. A warning about attachments rather than a bad signature points at the
structure GpgOL sees, so the cause is not known yet.

Work: ask on #84 for the raw source of both sent messages (FairEmail can export a raw message) and the key's
algorithm; compare the MIME trees, micalg and signed range. Either way, report the hash the signature actually
used in RESULT_SIGNATURE_MICALG (software, composite and card paths), from the signature itself.

## 45. Long certification lists push Key Details down (#85)

**Status:** RC4. KeyDetailSections: each User ID's certifications go through CertificationList, which orders them (your own first, then the ones that verify and are current, each group in stored order; orderCertifications) and shows the first three (CERTIFICATIONS_SHOWN), then a "Show all N certifications" row (plurals key_detail_cert_show_all) that expands in place and turns into Show fewer; the state survives rotation. Keys with three or fewer are unchanged. Tests: CertificationOrderTest. Strings in all 10 locales. On device (Oct 14): green.

Priority: low (UI). Origin: #85 (Oct 14, RC2): a widely certified public key (the F-Droid one) lists every
certification (item 31) before the rest of Key Details.

Work: show the first three certifications per User ID, then a "Show all N" row that expands in place (and
collapses again). Keys with three or fewer are unchanged. New strings in all 10 locales.

## 46. Choose which signing subkey a key pair signs with (#82)

**Status:** RC4. New crypto/SigningSubkeyPins.kt stores the choice in files/signing_pins (one primary and subkey fingerprint pair per line, written atomically, read on every pick, so the main process and :remote_api agree, the SessionPolicy reasoning). PGPCryptoService.signingSecretKeys moves the pinned subkey to the front while it is in item 39's valid list (automatic order otherwise, and always when only one key can sign); pickSigningSecretKey, signingKeyOptions and so every signer (app, Quick Actions, provider) follow it, and a key chosen for one send (Ask which key to sign with) still wins. Key Details shows Use for signing on a software key pair with two or more valid signing keys, or a pin that no longer applies: Automatic (now naming the key it picks) or each valid key (key ID, algorithm, created), and a note when the chosen subkey can no longer sign. Refreshed after the key loads and after Add Subkey, revoke, remove and expiry changes (KeyDetailViewModel.refreshSigningSubkeys). The pin goes with the key on purge (KeyRepository.purgeKey) and with Clear All Data (AppReset). Tests: SigningSubkeyPinsTest (two-current and expired-first fixtures). Strings in all 10 locales. On device (Oct 14): green.

Oct 14 (#82): the requester's old signature came from OpenKeychain (primary [C] only, two current [S] subkeys, no pin), which picked the older subkey; agreed with newest by default plus the pin, and asked that the difference from OpenKeychain be documented. Work: the 4.7.0 release notes and the README's coming-from-OpenKeychain notes say that PGPony signs with the newest valid signing subkey where OpenKeychain used the older one, and point to Use for signing on Key Details.

Priority: medium (feature). Origin: #82 (Oct 14, RC3): item 39 signs with the newest valid signing subkey; the
requester prefers keeping the older one until it expires, so signatures stay the same after a new subkey is added.
The newest valid subkey stays the default (GnuPG's rule as well, for a subkey whose secret it holds).

Work: Key Details on a key pair with more than one valid signing subkey gets "Use for signing" on each one
(Automatic, the default, or a pinned subkey), stored per key. Signing everywhere (app, Quick Actions, provider)
uses the pinned subkey while it is valid and falls back to the automatic pick, with a note on Key Details, once it
expires or is revoked. Ask which key to sign with still lists every valid one. New strings in all 10 locales.

## 47. A passphrase changed in gpg does not carry over on re-import (#78)

**Status:** RC4. SubkeyAdmission.replaceableSecrets compares the secret key packets of the stored key pair and the file per key (primary and subkeys, real material on both sides, same fingerprint, different bytes). gpg re-protects on every export, so this cannot tell a new passphrase from the same one under a new salt; the preview therefore offers it as an opt-in: ImportPreview.replaceableSecrets drives a Use the secret keys from this file checkbox (off by default, single-key imports only) with a passphrase field for the file. Confirming calls KeyRepository.importReplacingSecrets: before anything changes, SecretKeyCheck.checkSecretForPublic must return OK for the file with that passphrase (every secret in it unlocks and proves it is this key's), else KeyRepoError.SecretsNotReplaced (two new err_ strings and ErrorText rules) and nothing is imported. Then the normal duplicate path runs, and SubkeyAdmission.replaceSecrets puts the file's secrets in place under the stored certificate's public parts, the passphrase recovery wrap moves to the new passphrase (as Change Passphrase does) and the in-app passphrase cache for the key is cleared; the result says how many were replaced. Tests: SecretReplaceTest (keys made with Bouncy Castle, run on the JVM: every secret replaceable after a passphrase change, the replaced ring unlocks only with the new passphrase, only the keys asked for are replaced, another key's secrets never are). Checked in code, a key whose subkeys carry different passphrases: signing and decrypting work when the passphrase of the subkey in use is entered (only that key is unlocked); Change Passphrase uses one passphrase for every key and reports a wrong passphrase otherwise; Use the secret keys from this file needs one passphrase that unlocks every secret in the file. Strings in all 10 locales (Korean without the err_ strings). On device (Oct 14): green.

Priority: medium (bug). Origin: #78 (Oct 14): after changing passphrases in gpg (several subkeys had different
ones, consolidated to one), re-importing did not change the passphrase PGPony asks for until the key was deleted
and imported again. Item 40 never replaces a held secret, so a re-import with the same key material under new
protection is ignored.

Work: on a re-import of a key pair whose secret parts PGPony holds, compare the protection (S2K and encrypted
material) per subkey; when it differs, the import preview offers to replace the stored secrets with the imported
ones, saying the passphrase becomes the one set in the export, and the result says how many were replaced. Also
check what PGPony does today with a key whose subkeys carry different passphrases (unlock, change passphrase,
export) and fix or document it.

## 48. Decrypt results say which key signed and which key decrypted (#79)

**Status:** RC4. New crypto/KeyIdText.kt gives the 16-hex key ID of the key that signed or decrypted (version-aware) and its primary when that is another key. The verify banner adds "Signing key X" or "Signing subkey X of key Y" under the signer (from signingKeyFingerprint, else the signer key ID), also on a red banner whose signature verified but whose signer is revoked or expired. Decrypted with now names the key pair with its short fingerprint and, when a subkey decrypted, its key ID ("Decrypted with Alice · 1DB1A626, subkey F0F9AB15B82320BB"); DecryptStreamResult gained decryptingKeyIdRaw, so the large-file path shows it too. Quick Actions show both lines (ShareTargetViewModel.decryptedByOf, SignatureSummary.keyLine). Key IDs (16 hex) rather than short fingerprints, so they match gpg's "using RSA key ...". Left out: the multi-file decrypt shows the signing line per file but not the decrypting key. Tests: KeyIdTextTest (also run on the JVM). Strings in all 10 locales. On device (Oct 14): green.

Priority: medium (feature). Origin: #79 (Oct 14, RC3): the decrypt result names the signer but not the key that
made the signature, and "Decrypted with" names the key chosen, not the subkey that actually decrypted (a fallback
can differ).

Work: the signature banner shows the signing key's short fingerprint after the name (the subkey that signed, with
its primary when they differ); the result shows the key ID of the subkey that decrypted, taken from the PKESK that
succeeded. Same in Quick Actions and the in-app decrypt and verify screens. New strings in all 10 locales.

## 49. Trust level polish (#75)

**Status:** RC4. TrustMark draws Don't use itself: a red disc with a white bar on Material's 24-unit grid (the DoNotDisturbOn glyph's bar is a cut-out, which showed the background, black in the dark theme); the recipient review's Don't use row uses TrustMark too. Key pairs generated in PGPony start at Ultimate (generateKey, the composite and algo-35 paths, the granular path, and keys generated on a card, where only an Unknown or Unverified level is raised); imported key pairs and public keys keep Unknown. Existing keys are unchanged. No new strings. On device (Oct 14): green.

Priority: low (UI). Origin: #75 (Oct 14, closed by the requester after RC2): the bar in the red Don't use shield
is black and would read better white, like a traffic sign; key pairs generated in PGPony start at Unverified.

Work: draw the bar white. A key pair generated in PGPony (or on a card from PGPony) starts at Ultimate; imported
key pairs and public keys keep Unverified, so the owner decides. No change to keys already in the keyring.

## 50. The mail-app unlock prompt does not focus the passphrase field (#59, reopened)

**Status:** RC4. New provider/ProviderAutoFocus.kt (rememberProviderAutoFocus) focuses the field and asks the keyboard controller to open it, after a short delay so the dialog window is attached. Used by ProviderPassphraseActivity (Unlock decryption key, Unlock signing key) and the card PIN field in ProviderCardOpActivity. No new strings.

Priority: low (UI, regression of a promise). Origin: #59 (Oct 14, reopened on 4.6.4): the Unlock decryption key dialog a mail app opens has no focus and no keyboard. 4.5.0 item 20 fixed the in-app unlock dialogs (Screens.kt rememberAutoFocusRequester) and said the same went to the other prompts, but the provider prompts, which run in their own activity in :remote_api, were never changed.

## 51. Re-sign a key's self-signatures with a current hash (#86)

**Status:** RC5, on device green (Oct 16). Key Details > Refresh self-signatures (software key pairs whose
primary is on the phone): KeyExpirationService.refreshSelfSignatures re-signs every live User ID and every
subkey binding not revoked with SHA-256 (Target.Refresh), each keeping its own expiry, carrying the old
subpackets forward; a signing subkey whose secret is not here is passed over. First it puts back a subkey the
stored certificate lacks but the stored secret ring still carries, when its only problem is a weak-hash
binding or back-signature (SubkeyAdmission WEAK_HASH); a subkey whose secret is not held is never put back.
The import case is covered by the same action: the secret ring is stored as imported, so after importing your
own key pair, Refresh brings the subkeys back. The weak-hash mark on User IDs goes away after a refresh.
Tests: RefreshSelfSignaturesTest (three weak subkeys back, SHA-256 bindings and back-signature that verify,
expiry kept, the expired one still expired, no secret no restore), JVM, Bouncy Castle 1.85. Left out: the
SHA-512 choice for large RSA keys (SHA-256 everywhere, as the other self-signatures).

Priority: medium (feature, interop). Origin: #86 (Oct 14): gpg appears to have no way to remake a key's
cross-certifications with a newer hash, so a subkey bound or back-signed with SHA-1 after the Feb 2023 cutoff
stays unusable. PGPony could let the key's owner fix it instead of only warning that the subkey is left out.

What exists: KeyExpirationService.rebuildExpiration already remakes every user ID self-certification, every
subkey binding and, for a signing subkey, the embedded 0x19 back-signature (made by the subkey), all with SHA-256.
So changing a key pair's expiry already clears the weak-hash mark on its user IDs. It cannot reach a subkey whose
only binding is weak: CertificateBindings.sanitize drops that subkey before the certificate is stored
(SecureKeyStore.storePublicKey), and the import preview lists it as left out (item 40, SubkeyAdmission
Issue.WEAK_HASH).

Work:

- Key Details > Refresh self-signatures on a key pair: the same rebuild as an expiry change, keeping each
  component's current expiry, offered when a user ID carries the weak-hash mark or a subkey was left out for
  WEAK_HASH. Keep every hashed subpacket the old signature had (copySubkeySubpackets keeps only key flags and
  expiry today, so preferences and features on a subkey binding would be lost; fix that for expiry changes too).
- Import of your own key pair: a subkey left out only for WEAK_HASH gets Re-sign and keep, when the import holds
  real secret material for both the primary and that subkey. Before re-signing, check the weak signature
  otherwise verifies (only the hash is the problem) and that the subkey's secret matches its public part.
  Holding the subkey's secret is what makes this safe: the SHA-1 risk is a binding forged over a subkey someone
  else controls, and that subkey's secret would not be in the owner's export. A public-only import or a stub
  subkey gets no offer.
- A subkey whose secret was dropped earlier may still sit in the stored secret ring with its old binding;
  check whether the refresh can reach it from there.
- Card-backed keys: the card path skips signing subkeys today (it cannot make the back-signature). A signing
  subkey in the card's signature slot could make its own back-signature on the card; decide whether that is in
  scope or stays a stated limit.
- Hash: SHA-256 as everywhere else, or SHA-512 when the key is RSA 3072 or larger; decide once.

Test: a fixture key with a SHA-1 subkey binding and SHA-1 back-signature dated after the cutoff (made with Bouncy
Castle, since gpg will not make one now): before, the subkey is left out; after Re-sign and keep, it is admitted,
signs, and its new binding verifies in gpg and Sequoia. Same for a user ID self-certification. A public-only import
of the same key gets no offer.

## 52. Publishing refuses a key whose first User ID is revoked

**Status:** RC5, on device green (Oct 16). New UserIdService.shownUserId: the live User ID whose newest
self-certification carries the primary flag (the newest such one when several do), else the first live User
ID, else the first. Import takes it for the key's shown identity (PGPCryptoService, the four import paths)
instead of the first User ID in ring order. KeyRepository.reconcileShownUserId corrects a key imported before
when Key Details opens (like reconcilePrimaryExpiry), and persistUserIdChange moves the shown identity off a
User ID that was just revoked. Key Details' PRIMARY badge uses the same pick, so another flagged User ID keeps
Make primary. publishPayload no longer refuses when the one flagged User ID differs only from a shown one that
is revoked or gone (the Exchange upload passes the list's cached identity). No new strings. Tests:
ShownUserIdTest (revoked first User ID, no flag, a revoked flagged one, two flagged, a single one), run on the
JVM against Bouncy Castle 1.85.

Priority: medium-high (bug, blocks publishing). Origin: a tester by email (Oct 15): a key imported with a
revoked first User ID and the primary flag on another one listed the revoked name, and Publish refused with
the repair hint ("tap Make primary on the one you want"), which cannot be followed because Make primary is
hidden on the User ID that is already primary. Workaround on 4.6.4 and RC4: Make primary on another live
User ID, then on the wanted one again.

## 53. Changing the primary key's expiry brought expired subkeys back (#86)

**Status:** RC5, on device green (Oct 16). KeyExpirationService edits now have a Target: Primary (each
live User ID's self-certification; a revoked User ID is skipped, so its revocation stands) with an opt-in
"Also set it on subkeys that are still valid" (only subkeys bound, not revoked and not expired now, the v4
ML-KEM bindings included), or Subkey (that subkey's binding alone, with a new back-signature for a signing
subkey). Before, every subkey got the primary's date, expired ones included. Key Details: the subkey menu has
Edit expiration on software key pairs (a signing subkey only when its secret is on the phone); the entity's
expiry changes only with the primary. Self-signatures now carry every hashed subpacket of the old one forward
(the old copy kept a short list, which dropped the SEIPDv2 feature, AEAD and key server preferences from User
IDs and everything but key flags from subkey bindings). selfCertFor no longer picks a User ID revocation as
the certification to replace. 5 new strings (in English; locales in the RC5 translation pass), and the sheet
subtitle reworded. Tests: KeyExpirationTargetTest (primary leaves bindings byte for byte, current-subkeys
skips an expired subkey and re-signs the signing one with a back-signature that verifies, subkey target
touches nothing else, features and preferences kept, revoked User ID stays revoked), run on the JVM against
Bouncy Castle 1.85; KeyExpirationEditTest now asks for current subkeys.

Left out: per-subkey expiry on keys whose subkeys are listed from the certificate (composite ML-KEM), and on
card-backed keys. A confirm step before the change (asked on #86): the edit now only touches what the sheet
names, and it asks for the passphrase unless it is cached.

Priority: high (bug, changes a published key). Origin: #86 (Oct 15): Never to Never on the primary revived
the tester's expired subkeys; they removed the key before publishing. Also asked: expiry per subkey.

## 54. A security key scanned before its public key is imported never pairs (#71)

**Status:** RC5, on device green (Oct 16). A card scanned with no matching key makes a placeholder row
keyed by the Signature slot's fingerprint. Importing the public key afterwards paired onto it only when that
was the primary's fingerprint; with a subkey in the Signature slot (Move to security key's default when the
primary only certifies) the import made a separate public key row, and the placeholder stayed unusable
(signing and decrypting need the certificate). Import now pairs onto a placeholder whose slots hold any key
of the imported certificate (KeyRepository.cardPlaceholderFor) and gives the row the real primary
fingerprint. A scan that links a card to a key now deletes that card's leftover placeholders. Key Details on
a placeholder says what is missing (CardNeedsPublicKeyBanner: the card holds the private keys, not the User
IDs and signatures; import the public key and it pairs). 2 new strings (English; locales in the RC5 pass).

Priority: high (bug, hardware keys). Origin: #71 (Oct 15, YubiKey 5C NFC): after a move, the key removed and
the card scanned showed On card but could not sign or decrypt; a key generated in PGPony, moved, removed and
scanned back did the same.

## 55. Move only some keys to a security key and remove those from the phone (#71)

**Status:** RC5, on device green (Oct 16). Remove from this phone is now also offered when every subkey
moves and the primary stays (picked = keys with a secret here minus the primary). finishKeyToCard stubs the
moved subkeys and keeps the key a key pair linked to the card (isKeyPair and isCardBacked both set, the state a
card scan already made when it linked onto a key pair): signing and decrypting go to the card, in the app and
for mail apps, as they already did for that state. The edits signed by the primary now accept it: expiry (the
software path), User ID add/revoke/remove/primary, notations, subkey revoke/remove, certify (software list,
deduped against the card list; the sheet asks for the passphrase), Refresh self-signatures. Add Subkey stays
off for it: a new subkey would stay on the phone and receive mail the card cannot open (add subkeys first,
then move them). Use for signing and fallbacks stay off (the card signs). Expiry with "also current subkeys"
and Refresh pass over a signing subkey whose secret is on the card.

Previously planned scope, still out: routing each operation per subkey, so a key can have some working subkeys
on the phone and others on a card. Remove from this phone is offered only when every key with a secret
moves (RC4 review). gpg's usual layout is the primary kept (sec) and the subkeys on the card (ssb>), and a
key with a certify-only primary and three subkeys cannot move whole into three slots. Making the partial
case work means routing per subkey everywhere a software key pair is used: signing (item 39 and 46 picks)
and decrypting go to the card for a subkey with a divert-to-card stub and to the phone otherwise; expiry,
certify, Add Subkey and User ID edits keep using the primary on the phone; Key Details shows each subkey's
place (item 40's secret locations already do). Also the import of such a key from gpg.

Priority: medium-high (feature gap). Origin: #71 (Oct 15).

## 56. The recipient review opens two or three times for one send (#25)

**Status:** RC5, on device green (Oct 16). FairEmail asks for key ids on Encrypt, again on Send, and
again when it saves an encrypted draft, each time with the addresses and without the earlier picks, so the
review (item 41) opened each time and started from scratch. New RecipientReviewMemory (provider process, in
memory only): the picks from a review are kept for 30 minutes per calling app and per exact set of addresses
the review covered (case and display names ignored). GET_KEY_IDS and encrypt reuse them for the same set,
after the same checks as a fresh answer (a pick that is now revoked, Don't use or expired sends the user back
to the review). When the set changes, the review opens with the earlier picks ticked. Cleared with the
provider's cache (clear-all) and on device lock. No new strings. Tests: RecipientReviewMemoryTest.

Priority: medium (bug, provider). Origin: #25 (Oct 15, FairEmail): the review opened on Encrypt and again on
Send (three times when the draft was saved first), and the keys picked were not remembered.

## 57. Copy a subkey's key ID (#91)

**Status:** RC5, on device green (Oct 16). Each subkey's key ID row is tappable with a copy icon; a snackbar confirms. 2 new
strings. Origin: #91 (Oct 15).

## 58. The primary key's usage in Details (#89)

**Status:** RC5, on device green (Oct 16). Details shows Usage for the primary (Certify, Sign, Encrypt, Authenticate) from the
key flags on its newest self-signature made by the primary (KeyDetailViewModel.primaryUsageOf), in the same
wording as the subkey rows (SubkeyCapability.displayString, English like them). 1 new string. Origin: #89
(Oct 15, coming from OpenKeychain's usage icons).

## 59. Trust signatures on certifications (#79)

**Status:** RC5, on device green (Oct 16). A certification carrying a Trust Signature subpacket (gpg tsign) now says so after
its level: trusted introducer (amount 120 or more), partly trusted introducer (60 or more), or the amount, with
the depth, and "limited to some User IDs" when a Regular Expression subpacket is present. The level label
"No claim" is right for gpg's default tsign (0x10). 4 new strings. Origin: #79 (Oct 15).

## 60. Key server check result stays in Details (#90)

**Status:** RC5, on device green (Oct 16). Check Key Server now uses fetchByFingerprint, so a network failure is reported as an
error instead of "not found"; the answer is kept per key (KeyServerCheckStore: server, found, time) and Last
checked reads "<date>, found on keys.openpgp.org" or "not on". The message names the server. The record goes
with the key on purge. 4 new strings. Origin: #90 (Oct 15).

## 61. Look up a certifier's key (#88)

**Status:** RC5, on device green (Oct 16). A certification by a key not in the keyring gets Look up, which searches the
configured key servers by the issuer fingerprint (keys.pgpony.app and the others first, then keys.openpgp.org),
or by key ID when the certification has no fingerprint, and shows the key before importing it (the signer
lookup sheet in a certifier wording). After import the certifications are read again, so the certifier shows by
name and its signature is checked. Hidden in offline mode. 6 new strings. Origin: #88 (Oct 15).

## 62. Import and Exchange overlap (#92)

**Status:** Decided Oct 15, built in RC6 as item 64 (after a follow-up on #92: the Import sheet's slide-ups are the harder part to use). The requester proposes that Import keep Paste, File and Link and
point to Exchange for QR, Server and GitHub (GitHub joining Exchange), since Exchange has room to explain.
Recommendation: keep every method in Import (it is where people look to add a key, and the Keyring's + leads
there) and make Exchange the place for meeting in person and publishing: add GitHub to Exchange's key server
tab so the two lists agree, and give Import's QR, Server and GitHub rows a one-line explanation each. Origin:
#92 (Oct 15).

## 63. Export several public keys as one file (#93)

**Status:** RC5, on device green (Oct 16). Keyring > overflow > Select keys: a tap ticks a key (a checkbox on each card), the
bar shows how many are picked, Select all, and Export, which puts the picked keys' public keys in one armored
block (KeyRepository.exportPublicKeysArmored: the binary certificates one after another, as gpg --export
--armor writes them) and opens the public key sheet (Copy, Save as .asc, Share). Back or the close icon ends
selecting. A card placeholder without its certificate is left out. 5 strings and 2 plurals. Origin: #93 (Oct 15:
the requester reconstructed old keys and wants them in one .asc).

RC3 translation pass (Oct 13): every string missing from a locale went into all 10 (about 125 each; Korean 322,
including 184 strings and 10 plurals that had fallen behind since 4.6.3, still no err_ strings), and strings that
were English copies (key_count_summary, clipboard_will_clear_in and a few per locale) were translated. One
translator and one separate reviewer per locale; a script check confirms every key and plural is present once,
the files parse, placeholders match English and apostrophes are escaped. The Korean community revisions from the
translations repository (PR #6, 82 strings) were applied on top, the contributor's wording kept where both
translated a string, with five particle fixes. The English GitHub help now names the Import Key button.

## 64. Import's QR, Server and GitHub open the Exchange page (#92)

**Status:** RC6, code in. ImportKeyScreen's section, error banner and preview are now ImportMethodBody, shared
by the Import sheet (Paste, File, Link) and the Exchange page. The QR, Server and GitHub chips carry an open-in
icon and, when tapped, close the sheet and open Exchange on Scan Key or Key Server (MainActivity sets the
section and navigates like a tab tap). Exchange's Scan Key and Key Server tabs now run on the Keyring's view
model (preview with fingerprints, the multi-key list, Import or Encrypt to this key), and Key Server has Key
server and GitHub chips; the import outcome shows as a snackbar there. Exchange's own scan confirm dialog and
search card are gone. No new strings.

Priority: medium (UI). Origin: #92 (Oct 15). Import's method picker keeps every method, so people still find
them where they look to add a key, but QR, Server and GitHub open their tab on the Exchange page instead of a
slide-up; the requester found the slide-ups the harder part to use. GitHub joins Exchange's key server tab, so
both pages offer the same lookups. Paste, File and Link stay in the sheet. Offline mode hides the same rows as
before.

## 65. The same-identity key list does not scroll (#87)

**Status:** RC6, code in.

Origin: #87 (Oct 15). The count badge on a Keyring card ("8 keys") opens a dialog listing every key with that
address; the list had no scroll, so with eight keys everything after the seventh was cut off. The dialog's
text slot scrolls now. No new strings.

## 66. Confirm before an expiry change or a self-signature refresh (#86)

**Status:** RC6, code in. Update expiration in the sheet (date and passphrase or PIN, as before) opens
ConfirmExpiryChangeDialog: current and new date, the number of live User IDs re-signed (and of still-valid
subkeys when that option is ticked), or for a subkey that only its binding is re-signed, and that others see
it after publishing. Change expiration then goes through deleteWithOptionalBiometricGate (screen lock or
fingerprint when the device has one and Protect destructive actions is on), and only then signs. Refresh
self-signatures keeps its dialog as the confirmation and adds the same gate. 8 strings and 2 plurals.

Origin: #86 (Oct 15, after item 53): the requester wants a change that re-signs a published key to need a
deliberate confirmation. Edit expiration (primary or subkey) and Refresh self-signatures first show what will
change (old and new date, which User IDs and subkeys get re-signed, and that others see it after publishing),
then device authentication through BiometricGate when the device has a screen lock (as delete and private key
export do), then the passphrase as before.

## 67. The recipient review shows the keys already included (#25)

**Status:** RC6, code in.

Origin: #25 (Oct 15). FairEmail sends the From address with the recipients, so the sender's own key is added
from that address, but the review listed it unticked, which looked like it was left out. Keys the request
already resolves from its addresses show ticked and locked, with a line saying which address includes them.

Status detail (RC6, code in): GET_KEY_IDS and encrypt pass the fingerprints they resolved, with the address or
key ID behind each (EXTRA_INCLUDED_FPS and EXTRA_INCLUDED_FOR, RecipientReview.includedMap). The review shows
those rows ticked and disabled with "Already included for <address>", and returns them with the picks (the
service dedupes by fingerprint), so confirming with only those keys works as before. 1 string. Test:
RecipientReviewTest (two new cases).

## 68. The card scan screen stops answering after Change PIN and back (#79)

**Status:** RC7, code in. MainActivity keeps the owner of the current reader (cardReaderOwner);
startCardScan and startCardOperation take an optional owner, and stopCardScan(owner) stops only the reader
that owner started (with no owner it stops whatever runs, as before, for the operation callbacks). The six
card screens (scan, Change PIN, sign, decrypt, keygen, card management) pass their own owner to the start
calls and to the stop in onDispose. No new strings.

Origin: #79 (Oct 15, on RC4, YubiKey 5 NFC): scan a key on the card screen, open Change PIN, go back; the
screen says it is ready but no longer reacts to the card until it is left and opened again.

Cause (read from the code): MainActivity holds one cardReader. Going back, the card screen's
DisposableEffect arms a new reader (startCardScan), and the Change PIN screen's onDispose, which runs when its
exit transition ends, then calls stopCardScan() and stops the reader the card screen just armed. The same
ordering can hit any pair of card screens.

Work: startCardScan and startCardOperation return a handle, and stopCardScan(handle) stops the reader only
when it is still the one that handle started (the no-argument form stays for the error paths that must stop
whatever is running). Every card screen's onDispose passes its own handle. Test on device: scan, Change PIN,
back, scan again; the same through Card sign and Card decrypt.

## 69. Show Key with a key too large for a QR code (#100)

**Status:** RC7, code in.

Origin: #100 (Oct 17, on RC6). With a default key too large for a QR code, Exchange showed "This key is too
large for a QR code. Use Share or Copy instead." as a snackbar on every visit, including after item 64's links
from Import, and Show Key then showed nothing under the key list: the key's name, fingerprint and the Copy Key
and Upload buttons sat inside the QR block. Show Key has no Share button either. Now the view model sets
qrTooLarge instead of an error message; Show Key says so inline (new string, naming Copy Key and Upload) and
keeps the key and its buttons on screen. The Select Key rows are selectable as a whole (Role.RadioButton), so
tapping the name selects the key. 1 string.

## Feature freeze (Oct 17)

RC7 is the release candidate. It carries item 68, item 69, and two contributor fixes merged on GitHub: #97
(contact email lookup tolerates a provider that leaves out a column) and #99 (the French and Portuguese
"keys need regenerating" plural shows its count, so 0 no longer reads as one key), with #94 (test
infrastructure only) under them, then the 12a on-device checks. Only a regression or crash found in RC7
justifies an RC8, and only for that fix. Everything else goes to the next release:

- #101: a setting to turn off drag to reorder on the Keyring.
- #86 follow-up: choose the hash (SHA-512) when re-signing self-signatures.
- #93 follow-up: long press on a key starts select mode.
- #100 follow-up: slower or paused QR playback by default (part of #95).
- #95: QR exchange rework and the optional PGPONY2 format (review; iOS and desktop need to read it first; needs
  a rebase on RC6's Exchange changes, and its planning-doc edit taken out).
- #96: Korean err_ strings (decision pending on Korean error strings).
- #98: manifest content VIEW filters without the inert path patterns.
- #71: signing new subkeys with a primary held on a card.
- #102: ECDSA card signing (secp256k1, NIST): CardPGPContentSigner hands BC the card's raw r||s, which BC
  decodes as DER ("exception decoding signature"); DER-encode it and match the hash to the curve. Also the
  labels: subkeyAlgorithmLabel names every ECDH subkey X25519, and a card key on a curve PGPony does not model
  falls back to Ed25519+Cv25519 (importCardKeyInternal). Not new in 4.7.0.

## RC breakdown (set Oct 9 2026)

Release note (Oct 14): the new store listing (fastlane/metadata/android: localized descriptions in 11 locales, 7 screenshots per locale, feature graphics) is committed for 4.7.0. F-Droid reads the listing from the tagged commit it builds, so it appears with the v4.7.0 build; 4.6.4 was built from a tree with the old screenshots. The F-Droid changelog 470.txt is still to write before tagging.

One RC at a time: the next RC's work starts only after the current one is built and tested. versionCode 470 /
4.7.0 from RC1 on, unchanged across RCs. New strings go into all 10 locales (de, es, fr, ja, ko, pt-rBR, ru, tr,
uk, b+zh+Hans).

- RC1, bugs and promises already made: 33, 25, 27, 24, 23, 3, 29, plus 26 (signing subkey). Items 7 and 28 join
  a later RC if their reporters answer. Item 33 ships in 4.7.0 only (no 4.6.x point release).
- RC2, key management on soft keys: 22, then 10, then 31 (31 needs 22's stub check and 10's Verified level).
  Certifying on a card waits for RC4. Also 35 (label change, no new strings; RC1 was built before it was
  added) and 36 (provider foreground service).
- RC3: 39 first (signing picks an expired subkey), 40 once the #82 key is in hand, then 15 (each file
  separately), 38 and 37 (multi-file Quick Actions and large-file saves, same area as 15), 41 (recipient review),
  42 (GitHub key lookup), 43 (tappable rows),
  32 (duress PIN, builds on 33), 6, 21 remainder (protocol change shared with desktop and iOS PGPonyPair), 8.
  Oct 13: 21's remainder moves to the next release (it needs the desktop side too); 8 stays open until checked
  against gpg 2.5 and does not hold the RC3 build.
- RC4: 44 to 50 first (RC3 tester reports, no card needed), then the card work (Token2 on hand for testing): 13 (keytocard), card certification for 31, 34 (card-generated key display) and 28 (provider card
  prompt over USB), once a working card is on hand for testing.
- RC5 (Oct 15, green Oct 16): 51 to 63.
- RC6 (Oct 16): 64 to 67.
- RC7 (release candidate): 68, 69, #94, #97, #99, then the 12a on-device checks below.
- Last RC: the 12a on-device checks (Tor with Orbot, custom proxy, OpenKeychain restore, protected key over a
  contact, the provider with Thunderbird including a card).
- Release (Oct 20): 4.7.0 is RC7's code with the release notes, the 470 changelog and the README's OpenKeychain
  notes. No RC8: RC7 and the 12a on-device checks passed.
- Not RC-gated: 30 (README), 11 (SOP wrapper), 12 (external review follow-up).

Item 27 decision: a User ID whose only binding uses SHA-1 is kept with its name and a weak-hash mark, still
matches recipient lookup by address, and never counts toward Verified.


## Release process notes (learned in 4.6.0)

- F-Droid reads the changelog (fastlane/metadata/android/en-US/changelogs/<versionCode>.txt) from the tagged
  commit. Finalize that file before tagging; it cannot be changed for a version after F-Droid builds it.
- Commit release notes before tagging, and keep planning docs free of finding IDs and security detail.
- The reproducibility gate's clean clone needs local.properties and keystore.properties copied in before the
  signed build (docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md step 3).
- Stage by path, never git add -A: drafts/, _archive/ and _to_delete/ stay out of the repository.


## Delivery note

Android first per the new-feature procedure. iOS mirrors each item once the Android version is verified,
tracked separately. iOS 8.3.0 also still owes the 4.6.0 mirror.
