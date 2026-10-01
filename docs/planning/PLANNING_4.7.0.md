# PGPony Android 4.7.0: Planning

Status: open (Sep 25 2026). Carries what was deferred out of 4.6.0 and 4.6.1 once 4.6.0 was frozen for review,
plus reports that came in during the 4.6.x cycle. Android leads, then iOS mirrors each item once verified.
Items are detailed enough to build against; priorities and the RC breakdown are set once the list settles.

Context: 4.6.0 (versionCode 460) shipped Sep 24 2026 and is the tag submitted for external review. 4.6.1
(versionCode 461) is a small follow-up: share-menu recipients (#67), private key import from the share menu
(#67), and MTE async mode (#70). Anything below is a 4.7.0 change unless it says otherwise.


## 1. Mail apps ignore the passphrase cache duration (#15)

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

Priority: low-medium (behavior). Origin: CertainBot (#58), on 4.6.0 RC1.

Reported: for text with a PGP block inside it, "Encrypt the other text" has no real-world use; offer to encrypt
the whole thing (text plus block) and let the user trim it in the text field.

Work: replace "Encrypt the other text" with "Encrypt all of it", which opens the full shared text on the Encrypt
screen. Keep the block's own action (Import, Decrypt, Verify) as it is. Update the string in all 8 locales.


## 4. Days left on each key in Recently Deleted (#58)

Priority: low (polish). Origin: CertainBot (#58).

Work: each row in Recently Deleted shows how long until it is destroyed ("10 days left", "Less than a day
left"), computed from deletedAt and KeyRepository.RECYCLE_BIN_RETENTION_DAYS, refreshed when the screen opens.
Plurals in all 8 locales.


## 5. Other places that load recipients with the plain BouncyCastle loader

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

Priority: high for the bug, medium for the feature. Origin: #72.

Bug: package (bundle) mode loads the signing key through a path that cannot read ML-DSA keys and then reports
that the key could not be unlocked. Same gap 4.5.3 fixed for single files; route the package signer through the
composite signer and verify a signed package on decrypt. Overlaps item 5's loader sweep.

Feature: when several files are chosen, offer one package (as now) or each file on its own: encrypted, encrypted
and signed, or signed only with a detached .sig per file. Output to a picked folder or shared together; one
failed file does not stop the rest. Decrypt and Verify accept several .gpg or .sig files at once.


## 16. Keyring "tap the +" tip flashes on every launch (#74)

Priority: medium (bug, visible). Origin: #74.

Cause: KeyringScreen shows the keyring_fab ScreenTooltip when state.allKeys is empty, and KeyringUiState.isLoading
starts false, so the first frame (before the keys load) looks like an empty keyring. ScreenTooltip marks a tip
seen only on dismiss, so the flash never consumes it and it returns on every start. Surfaced after 4.6.0 made
Reset tips work.

Work: add a loaded-once flag to KeyringUiState (or start isLoading true) and gate both the tooltip and the
empty-keyring state (KeyringScreen around line 233) on it.


## 17. User ID row: Make Primary shifts Revoke and Remove (#76)

Priority: low (polish). Origin: #76.

Work: in KeyDetailSections' user ID row, order the actions Revoke, Remove, then Make Primary when shown, so the
first two line up on every row.


## 18. One PGPony entry in the share menu (#58)

Priority: low (polish). Origin: #58.

The EncryptTextShareAlias ("Encrypt in PGPony", added in 4.5.1) predates the 4.6.0 share sheet, whose Encrypt
option now covers it. Remove the alias so PGPony shows once in the share menu, and drop share_encrypt_text_label
from every locale.

## 19. Play Console: user-perceived ANR rate above the bad behavior threshold

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
