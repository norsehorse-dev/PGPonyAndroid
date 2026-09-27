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


## 10. Tabled: trust-level colors and shield symbols (4.6.0 item 7)

Status: tabled. Revisit only if either side of that thread raises it again.


## 11. Parallel effort (not release-gated): SOP interoperability wrapper (#64)

Carried from 4.6.0 item 8. A Stateless OpenPGP CLI over PGPony's crypto so it can join the sequoia-pgp interop
test suite; only the core roundtrip commands are needed. Does not gate 4.7.0.


## 12. External review follow-up

Placeholder. If the external review of the 4.6.0 tag goes ahead, its findings land here, under the same rules as
4.6.0 item 17: generic wording in anything committed or public, and the detail kept outside the repository.


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


## 14. Simplified Chinese (zh-Hans)

Priority: medium (localization). Origin: a user, by email, Sep 26 2026.

Requested: a Simplified Chinese interface.

Approach: NorseHorse does not read Chinese, so this is mostly machine translation. PGPony iOS already has a
zh-Hans translation done by a Chinese-speaking tester; reuse those strings wherever the Android string has the
same meaning (key terms first: encrypt, decrypt, sign, verify, key pair, subkey, fingerprint, keyring, trust
levels, passphrase), so the vocabulary matches iOS, and machine-translate the rest (about 1,570 strings and 6
plurals as of 4.6.1). Say plainly in the release notes and the reply that the translation is mostly machine-made,
and invite corrections.

Work:

- New resource folder values-b+zh+Hans (script qualifier, so it covers zh-CN, zh-SG and any other Simplified
  locale, not only mainland China). Keep format arguments (%1$s, %1$d), escapes (\', \n) and XML entities
  intact; run the string-resource lint and a format-argument check against values/.
- Add zh-Hans to res/xml/locales_config.xml and to the in-app picker (i18n/LanguageManager: "简体中文").
- Plurals: Chinese uses only the "other" form.
- Fastlane: fastlane/metadata/android/zh-CN/ (title, short and full description; changelogs can stay English
  until someone reviews them), and the Play listing translation.
- Check layouts for text overflow is not the issue it is for German; check instead that CJK fonts render in the
  QR/Exchange and monospace fingerprint views.
- Ask the iOS translator, and the user who asked, to review the most-used screens (Encrypt, Decrypt, Keyring,
  Key Detail, Settings, the share dialog) before the release.

Related: values-ko exists but is not in locales_config, and much of it is still English. Either finish Korean the
same way or remove the folder, so the picker and the resources agree.


## 15. ML-DSA keys cannot sign a package (#72)

Priority: high (bug, user-facing). Origin: #72.

Reported: Package (bundle) mode only signs with classical keys; an ML-DSA key cannot be used to sign a package.

Cause: encryptBundle loads the signer with KeyRepository.loadSecretKeyRing, the BouncyCastle loader, which cannot
read a composite ML-DSA key and returns null. The 4.1.0 guard then refuses with "the selected signing key could
not be unlocked", which is also the wrong reason. It is the same gap 4.5.3 closed for single-file signing (#65):
the file paths learned the composite signer, the bundle path did not.

Work:

- Sign a bundle through the composite signer when the signing key is a composite ML-DSA key, the way
  sign-while-encrypting a single file does since 4.5.3, for both the streamed and the in-memory bundle paths and
  the card path where it applies.
- Apply the 4.6.0 item 14 rule: a composite signature encrypted to a v4-only recipient asks Sign anyway / Send
  unsigned / Cancel, as on the Encrypt screen.
- Give the refusal an accurate message when a key truly cannot sign (no signing-capable key, key not on this
  device), instead of "could not be unlocked".
- Decrypting a signed bundle verifies the composite signature, as file decrypt does.

Test: unit test that a bundle signed with ML-DSA-65 and with ML-DSA-87 decrypts in PGPony with a verified
composite signature; the v4-recipient prompt; the error text when the key cannot sign.


## 16. Encrypt or sign each file separately when several files are chosen (#72)

Priority: medium (feature). Origin: #72.

Requested: when several files are chosen, Package mode is the only option and it produces one archive. Offer to
encrypt and/or sign each file on its own, as desktop PGP tools and AgePony do.

Work:

- Package mode gets an output choice: "One package" (today's behavior) or "Each file separately".
- Each file separately: every file is encrypted to the same recipients as its own .gpg (binary) or .asc
  (armored), streamed one at a time so memory stays flat, with the same progress and cancel handling as single
  file mode. Signing options per run: signed inside each file (sign-while-encrypting), a detached .sig next to
  each file, or sign only (a detached .sig per file with no encryption). Composite ML-DSA signers work in every
  option (item 15).
- Output: save all results into a folder the user picks (ACTION_OPEN_DOCUMENT_TREE, names through
  ScratchFiles.safeChild / LiteralFilename.sanitize), or share them together as multiple attachments. A failure
  on one file is reported by name and does not leave a half-written file behind; the others still complete.
- Decrypt and verify side: accept several .gpg / .sig files at once and process each, with a per-file result
  list, so the round trip works inside PGPony too.
- iOS mirrors it once Android is verified (8.3.0 track).

Test: encrypt, encrypt and sign, and sign only for 3 files of different sizes including one over the in-memory
limit; decrypt and verify each in PGPony and with gpg; one unreadable input file fails on its own.


## 17. Settings seam for PGPony Desktop (KeyValueSettings)

Priority: medium (internal, no user-visible change). Origin: PGPony Desktop 3.0.0 planning.

Four small stores reached SharedPreferences through PGPonyApp.instance, which forced Desktop to exclude
each one and keep a hand-written twin. They now go through data/settings/KeyValueSettings.kt, and
Android installs platform/SharedPreferencesSettings first thing in PGPonyApp.onCreate, in every process.

- Moved: KeyPublicationStore, RemovedUserIdStore, WkdLookup, FallbackPrefs. Same file (pgpony_prefs),
  same mode (MODE_PRIVATE), same keys. Public APIs unchanged, so no caller changed.
- Later, as each is touched: ProxyPrefs, OfflineMode and CardPinCache (these need the multiProcess
  flag, which maps to MODE_MULTI_PROCESS) and PassStorePrefs.
- Not covered: KeyRepository, KeyServerDirectory and ArmorCommentSettings (DataStore) and SecureKeyStore.

Test: SettingsStoresTest (defaults with nothing installed, round trip, the old keys). On device: toggle
WKD lookup, publish a key and reopen Key Detail, remove a User ID and refresh, set a fallback key to
strict; each survives an app restart, and existing values from 4.6.1 are still read after the update.

## 18. Three key-management fixes found by the Desktop 3.0.0 port

Priority: high for the first (it changes what a key says about itself), low for the others. Origin: PGPony
Desktop 3.0.0 stage 2, which ported this code and tested it on its own.

- **Add Subkey expiry.** AddSubkeySheet hands over the chosen expiry as a date (epoch seconds), and
  KeyDetailViewModel.addSubkey passed it straight to the generators, which write it as a key-expiration
  subpacket: seconds after the subkey's creation. "1 year" made a subkey good for about 58 years; any
  preset or custom date had the same problem. Fixed: addSubkeyLifetimeSeconds turns the date into a
  lifetime (a date already past becomes one second). Keygen, granular keygen and the SSH subkey at
  generation already passed a lifetime and are unchanged. Subkeys already added this way keep their long
  expiry; the user can set it again from Key Detail.
- **User ID revoked in the same second.** UserIdService.isRevoked needed the revocation strictly newer than
  the newest certification. Signature times have one-second resolution, so a User ID revoked in the same
  second it was last certified read as not revoked. A revocation now wins a tie.
- **Post-quantum signing default.** EncryptDecryptViewModel.resolveEffectiveSigner chose the post-quantum
  default only when every recipient isComposite (ML-KEM keys), so a composite ML-DSA recipient took the
  classical default. It now uses isPostQuantum, which matches the provider twin (resolveProviderSigner
  looks at the recipient ring, and a composite ML-DSA key's recipient ring is its ML-KEM subkey).

Test: AddSubkeyLifetimeTest, UserIdRevokeTieTest. On device: add a subkey with "1 year" and check its
expiry in Key Detail and in `gpg --list-keys`; add a User ID and revoke it at once; set a post-quantum
signing default and encrypt to a composite ML-DSA key.

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
