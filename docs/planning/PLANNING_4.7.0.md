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

**Status:** Built for RC1. encryptStream takes a composite signer (CompositeDocumentSigner.InlineStream), used by single files above the inline limit and by package mode; detached file signing and verifying stream (signDetachedStream, CompositeSignerGate.verifyDetachedStream). The streaming decrypt no longer buffers a composite inline message: CompositeInlineStreamReader hashes the literal as it is written and CompositeSignerGate.verifyStreamed grades the signatures from their digests. The large-file encrypt path also passes the chosen recipient subkeys now. Unit tests: CompositeStreamingTest. On device: the 500 MB case, and the GpgFrontend check.

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

**Status:** Built for RC1: CertificateMerge.mergeDetailed takes newer owner self-signatures (0x1F, 0x10 to 0x13, 0x18) on components already present; the secret ring gets the same public parts (PGPSecretKeyRing.replacePublicKeys, BC rings only, so a composite key pair updates its public copy only); the import says what was applied, or why nothing was. Unit tests in CertificateMergeTest. On device: the gpg setpref and SHA-512 case, then export and `gpg --import`.

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

Priority: medium (bug, needs information). Origin: #36 (Sep 24): a key that works in PGPony over USB, and in
Thunderbird with GnuPG on Linux, gives "error decrypting" in Thunderbird on Android. Not answered on the thread yet.

The path is the OpenPGP API provider handing the card operation to ProviderCardOpActivity over USB. Candidates: the
provider flow assuming NFC, the USB permission prompt when the request comes from the provider process, or a card
that chains its responses (fixed in 4.6.4 for the Nitrokey 3).

Work: ask on #36 for the key model, the PGPony version and the exact error; reproduce with Thunderbird and a USB
key once a working YubiKey is on hand; fix whichever it is.


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

Priority: medium (docs, promised). Not gated on 4.7.0; can land on main at any time.

- The hardware line says NFC only, with YubiKey 5 NFC and Token2. USB has worked since 4.1.0, and the Nitrokey 3 works
  over USB since 4.6.4 (not over NFC). Promised on #43 in August.
- Verify a release: list the four assets every release carries since 4.6.3 (APK, detached signature, armored release
  key, signing-keys file), say releases are immutable, and say to check the OpenPGP fingerprint against pgpony.app,
  keys.openpgp.org or keys.pgpony.app before trusting the key in a release. Promised on #77. The ".sha256 beside
  every release APK" line describes the RC folder on pgpony.app, not the GitHub release; fix the wording.


## 31. Certify other people's keys, like gpg's --sign-key (#79)

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

Priority: medium (bug, visible). Origin: #43, a Nitrokey 3C over USB on 4.6.4.

Reported: after on-card key generation the key is listed under Key Pairs but styled as a public key (avatar color, public key text, tap to encrypt to it). Key Details shows only the encryption subkey (with ON CARD), though the card holds a signing and an encryption subkey and the + > NFC menu shows both. Suggested: an ON CARD label (or the NFC symbol used in the recipient list) beside the name on the Keyring row, styled like DEFAULT.

Work: style card-backed key pairs as key pairs on the Keyring and its row action; list every card slot's subkey in Key Details with ON CARD; add the card label to the Keyring row. Test with a card-generated key on a YubiKey and a Nitrokey 3.


## RC breakdown (set Oct 9 2026)

One RC at a time: the next RC's work starts only after the current one is built and tested. versionCode 470 /
4.7.0 from RC1 on, unchanged across RCs. New strings go into all 10 locales (de, es, fr, ja, ko, pt-rBR, ru, tr,
uk, b+zh+Hans).

- RC1, bugs and promises already made: 33, 25, 27, 24, 23, 3, 29. Item 26 joins once it reproduces; items 7 and
  28 join if their reporters answer. Item 33 ships in 4.7.0 only (no 4.6.x point release).
- RC2, key management on soft keys: 22, then 10, then 31 (31 needs 22's stub check and 10's Verified level).
  Certifying on a card waits for RC4.
- RC3: 15 (each file separately), 32 (duress PIN, builds on 33), 6, 21 remainder (protocol change shared with
  desktop and iOS PGPonyPair), 8.
- RC4, card work: 13 (keytocard), card certification for 31, and 34 (card-generated key display), once a working card is on hand for testing.
- Last RC: the 12a on-device checks (Tor with Orbot, custom proxy, OpenKeychain restore, protected key over a
  contact, the provider with Thunderbird including a card).
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
