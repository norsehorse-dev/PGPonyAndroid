# PGPony Android 4.8.0: Planning

Status: open (Oct 20 2026; issues #105, #106 and #108 added Oct 26; items 4e to 4l added Oct 29 to Nov 4; Rev 1 with the RC breakdown, Nov 4). Seed: what the 4.7.0 feature freeze deferred, what 4.7.0 left open, and requests
that came in during the 4.7.0 cycle. Android leads, then iOS and desktop mirror each item once verified (iOS is
on 8.4.0, Android 4.6.1 to 4.7.0 parity; see HANDOFF-8.4.0.md in the iOS repo). The RC breakdown is in section
9.

Context: 4.7.0 (versionCode 470) shipped Oct 20 2026 from RC7's code: GitHub release, pgpony.app, Play (with the
special-use foreground service declaration for PassphraseHoldService), F-Droid from the tag. The 4.7.x patches since:
4.7.1, 4.7.2 (Oct 28) and 4.7.3 (Oct 30, GnuPG X448 subkeys and LibrePGP v5 signatures). Anything below is a 4.8.0
change unless it says otherwise.

Rules carried over: one RC at a time; new strings in all 10 locales (de, es, fr, ja, ko, pt-rBR, ru, tr, uk,
b+zh+Hans), translated multi-agent with a separate reviewer per locale; no names or handles of reporters or
testers here (credit by issue number or "a user"); no finding IDs or security detail; no em or en dashes.


## 1. SSH authentication with ML-DSA-44 + Ed25519 (user email, Oct 12)

Priority: low to medium (feature; experimental upstream). Origin: user email (Oct 12, reply drafted Oct 20).

Requested: post-quantum SSH public key authentication with the composite mldsa44-ed25519 key type that
OpenSSH added, in the same format OpenSSH uses.

Upstream (checked Oct 20): OpenSSH 10.4 (July 2026) adds `ssh-mldsa44-ed25519@openssh.com` and a certificate
variant `ssh-mldsa44-ed25519-cert-v01@openssh.com`. It is experimental and off by default: both sides opt in
through PubkeyAcceptedAlgorithms and HostKeyAlgorithms, and keys come from `ssh-keygen -t mldsa44-ed25519`. It
follows draft-miller-sshm-mldsa44-ed25519-composite-sigs-00, an individual submission the SSHM working group has
not adopted, so the wire format can still change. OpenSSH 10.0's post-quantum default is key exchange
(mlkem768x25519-sha256), which already protects the session from harvest-now-decrypt-later and needs nothing
from PGPony.

What PGPony has: the org.openintents.ssh.authentication API (provider/SshAuthenticationService.kt,
crypto/ssh/SshAuth.kt), reached through the OkcAgent fork and okc-agents in Termux. It signs with the OpenPGP
key's authentication subkey: ssh-ed25519, ssh-rsa / rsa-sha2-256 / rsa-sha2-512, ecdsa-sha2-*, and a card's
authentication slot. A composite ML-DSA primary uses a classical authentication subkey.

The gap: the OpenPGP post-quantum spec defines ML-DSA-65 + Ed25519 and ML-DSA-87 + Ed448, and no ML-DSA-44
composite, so no standard OpenPGP subkey can hold this key. No OpenPGP card can hold it either.

Options:

- (a) Track the draft and build once it is adopted and the format is stable. Nothing breaks for users meanwhile.
- (b) An SSH-only key in PGPony, outside the OpenPGP keyring: its own storage, picker entry, export of the
  OpenSSH public key, backup rules and Clear All Data coverage. The API's key id is the primary fingerprint
  today, so this needs its own id scheme. Bouncy Castle 1.85 has ML-DSA-44 and Ed25519 (confirm the
  parameter set and context string the draft uses); the composite signing input follows the draft.
- (c) A private-use OpenPGP algorithm id for an ML-DSA-44 + Ed25519 authentication subkey. No other OpenPGP tool
  could read the key. Not recommended.

Checks before any build: what the OkcAgent fork does with an unknown key type (GET_PUBLIC_KEY returns an X.509
SubjectPublicKeyInfo and an algorithm code, and there is no code for this type; GET_SSH_PUBLIC_KEY and SIGN may
pass through untouched); whether okc-agents needs a change; OpenSSH 10.4 accepting a signature built from the
draft against a key from `ssh-keygen -t mldsa44-ed25519`.

Decision (Oct 20): (b) in 4.8.0, marked experimental like OpenSSH's own option, phone only (no card). Work starts
after iOS 8.4.0 catches up with Android, about two weeks out; the user was told that and will hear if it starts
sooner. If the draft changes the format later, the key is generated again.


## 2. ECDSA card signing and card key labels (#102)

**Status:** moved to 4.7.1 (Oct 22), see PLANNING_4.7.1.md item 3.

Priority: medium (bug, cards). Origin: #102 (on RC7; not new in 4.7.0).

Reported: a Token2 with all three slots on secp256k1 (card-generated layout, primary in the Signature slot)
cannot sign, and Key Details labels the keys wrong.

Cause: CardPGPContentSigner hands Bouncy Castle the card's raw r||s, which it decodes as DER ("exception
decoding signature"). Labels: subkeyAlgorithmLabel names every ECDH subkey X25519, and importCardKeyInternal
falls back to ED25519_CV25519 for a curve PGPony does not model.

Work: DER-encode r and s for ECDSA card signatures and match the hash to the curve; model secp256k1 and the
NIST and brainpool curves in the card key import and the labels. Keytocard for NIST and brainpool keys
(4.7.0 item 13's left-out) builds on the same signer. Mirror on iOS (8.3.0 known limit "Card ECDSA signing on
NIST curves").


## 3. Signing new subkeys with a primary held on a card (#71)

Origin: #71 (follow-up to 4.7.0 items 13 and 55). Add Subkey, User ID edits and the other primary-signed edits
on a key whose primary sits in the card's Signature slot, signed on the card. 4.7.0 keeps Add Subkey off for a
partial move (a new subkey would stay on the phone).


## 3a. Private key export: ask for the key's passphrase, and gate Backup (user email, Oct 22)

A user asked, on iOS, for a confirmation of ownership before a private key leaves the phone, given how often
phones are lost or stolen: entering the key's passphrase first. iOS takes it in 8.4.0 (plan item 1.9); Android
mirrors it here. Decided by Kevin, Oct 22.

Today on Android: Export Private Key in Key Details shows the confirm dialog, then BiometricGate (biometric or
device credential, falling through to the dialog alone when nothing is enrolled). A passphrase-protected key
exports as stored, still protected, without its passphrase being asked; an unprotected key can take an optional
passphrase on the export copy (#16). Backup (Settings, Backup and data) opens with no device check.

Work:

- A passphrase-protected key asks for its passphrase before the export result sheet (Copy, Save as File,
  share), for every key type including the composite and v4 algorithm 35 paths, and the passphrase is checked
  by unlocking the key before any armor is produced. A cached passphrase (PassphraseCache, the hold service)
  does not count: it is typed each time. A key with no passphrase keeps today's flow, including the optional
  export passphrase.
- Backup asks for BiometricGate before it starts, like the private key export, with the same fall-through
  when nothing is enrolled.
- Not taken (same as iOS): refusing export on a device with no screen lock; requiring a passphrase on an
  unprotected export.

Strings: the passphrase prompt (reuse the existing passphrase dialog strings where they fit) and the backup
prompt title and subtitle, in all 10 locales.

Test: export a protected Ed25519, RSA, v6 and composite key: each asks for the passphrase, a wrong one is
refused and no armor is produced. An unprotected key still exports after the biometric check, with or without
an export passphrase. Backup asks for the biometric check first; cancelling it starts no backup.


## 4. Keyring and Exchange follow-ups

- #101: a setting to turn off drag to reorder on the Keyring. Done in RC2; the reorder mode follow-up is item 4m.
- #93 follow-up: a long press on a key starts select mode (4.7.0 item 63).
- #86 follow-up: choose the hash (SHA-512 for large RSA keys) when re-signing self-signatures (4.7.0 item 51).
- #100 follow-up: slower or paused QR playback by default.
- #95: QR exchange rework and the optional PGPONY2 format. Needs review, iOS and desktop must read it first, a
  rebase on 4.7.0's Exchange changes, and its planning-doc edit taken out.


## 4b. Requests after 4.7.0

- #103: encrypt or sign selected text from the text selection menu (ACTION_PROCESS_TEXT), replacing the
  selection in place when the field is editable and the result can be returned, as OpenKeychain does.
- #72 follow-up: sign a single shared file from Quick Actions (detached .sig, or encrypt and sign). Several
  files already have Sign only on the package screen.
- #67 follow-up: restore a PGPony backup shared to Quick Actions (recognize the backup file and open Restore).
- Keyboard on the other screens: 4.7.2 closes it on a tap away from a text field on Encrypt and Decrypt
  (PLANNING_4.7.2.md item 1). Extend dismissKeyboardOnTap and keepsKeyboard to Settings, the Key Details sheets,
  Import and Pair.
- #104: compress large files too. Today a message or file up to 16 MB is compressed with ZLIB
  (COMPRESSION_LIMIT) and a larger one is not; nothing is padded. Narrowed with the reporter (Oct 23, a CSV over
  50 MB): one opt-in switch in Settings, off by default, that lifts the 16 MB limit so every file is compressed
  with ZLIB. The Encrypt progress already covers the longer run. Other methods (ZIP, BZip2) and padding are not
  planned unless someone asks for them.
  - Oct 27, another user: asked for zstd or xz, and to avoid bzip2 on mobile. OpenPGP defines only ZIP, ZLIB and
    BZip2, so zstd and xz would not open elsewhere. Also asked about multiple cores: compression is single-threaded
    today. Possible follow-up: compress large files in parallel blocks joined into one standard ZLIB stream (the
    pigz approach), so the output is unchanged for other apps. Measure on a phone before committing to it.
  - Oct 28, same user: for files, pre-compress (zstd or xz) and then encrypt with OpenPGP compression off, with
    the user choosing whether decrypt saves the compressed or the unpacked file. Interoperable on the OpenPGP side
    (gpg or sq decrypt it to file.xz); the receiver needs xz or zstd to unpack, the caveat the reporter raised.
    Needs a compressor in both directions and a new dependency in the reproducible build. Not in 4.8.0; after
    the ZLIB switch.
- #105: the Enter key runs the default action on passphrase prompts. The provider prompt (SSH, and mail apps
  decrypting or signing) sets no IME action, so the keyboard's checkmark only closes the keyboard and Unlock has
  to be tapped. ImeAction.Done with keyboardActions running Unlock there, and the same on the Encrypt and Decrypt
  passphrase prompts. No new strings.
- #106: verify a detached signature with one trip to the picker. Asked: pick the signature and find the signed
  file by dropping .asc or .sig. The system picker grants access to the picked document only, never its folder,
  so the sibling cannot be checked directly. Planned instead: the Verify picker takes several files
  (OpenMultipleDocuments) and pairs each signature with its file by name; a lone signature still asks for the
  file. Same pairing serves the 4.7.0 item 38 left-out (several signatures with their files, section 6).
- #108: ADSK (additional decryption subkeys, GnuPG 2.4.1 and later).
  - Encrypt: findEncryptionKey picks one encryption subkey per recipient (the newest valid one, or the one chosen
    in the picker), so a recipient's ADSK is dropped. Encrypt to every valid encryption subkey of each recipient
    key, ADSKs included, as GnuPG does; the per-recipient subkey choice stays as an override.
  - Decrypt: a message from GnuPG to the reporter's key and its ADSK fails with the key-not-on-this-device error,
    though one of the subkeys should be held. Cause not known; asked the reporter (Oct 26) for the PGPony version,
    how the key is held (card link or imported secret, which token holds which subkey), the key listing and the
    message's PKESK key IDs. Suspects: card-recipient detection matching only the card's stored subkey, or the
    ADSK key flag making a subkey unusable in SignerEvaluator.
  - Oct 26: reporter is on 4.7.0 from Play and pointed to the public key on their GitHub profile (6C525E39...
    819140A, RSA 3072). Three ordinary encryption subkeys (2B771252..., BDC5DA42..., 03C78DF0..., the last the
    newest), two signing, two authentication; no standalone ADSK, but both authentication subkeys carry key flags
    20 04 (authentication plus the 0x0400 ADSK flag). GnuPG encrypts to the newest valid encryption subkey plus
    ADSKs, so if PGPony's linked token holds one of the two older encryption subkeys, nothing in the message is
    for it. Waiting on the PKESK key IDs and which token holds which subkey. Either way, decrypt should try every
    PKESK against every held secret, and the picker should say which subkey a card holds.
  - Oct 27: card status in. The message's PKESKs, in order: 2AE019246C5C0CB6 and B9E473DF106CBD8A (the two
    ADSK-flagged authentication subkeys, set that way on purpose), then 03C78DF0C62F7C14 (newest encryption
    subkey). Card 10240001 (OpenPGP 3.4) holds 03C78DF0... in its decryption slot and 2AE0... in authentication.
    Card 0006 18160546 holds BDC5DA4245EFAC3D in decryption and B9E4... in authentication. 2B77125258187770 is a
    stub only. Card 10240001 failed because pass 1 took the first PKESK in the ring (2AE0...) and sent it to the
    decryption slot; fixed in 4.7.2 RC7 (PLANNING_4.7.2 item 9; the RC6 tag did not compile). Card 0006 has no PKESK for its decryption slot,
    so it needs the 4.8.0 work: MSE so PSO:DECIPHER uses the authentication slot (OpenPGP card 3.3 and later)
    when the only matching PKESK names the key in that slot, plus encrypting to ADSKs. Check whether the iOS card
    path has the same first-match selection.


- In-app viewer for decrypted files (user email, Oct 23): a decrypted PDF or image always goes to the Android
  app chooser. Asked: show it inside PGPony instead (PdfRenderer for PDF, an image view for JPEG and PNG), with
  Open in another app and Save still offered. Not planned yet; scope and whether iOS has the same gap to check.


## 4c. Two keyring rows with one fingerprint (from 4.7.2 item 2)

4.7.2 guards the recipient and Sign as lists against a repeated fingerprint (the Play crash). Find how two
pgp_keys rows came to share a fingerprint (no unique index on the column), merge any that exist on upgrade, and
add the index.


## 4d. Left out of 4.7.2

- Show or hide on the other passphrase fields (4.7.2 item 7 covers the Encrypt and Decrypt prompts and the two
  Decrypt screen fields): Key Details sheets, Import, Settings, Pair, the provider prompt (pairs with #105).
  Card PIN fields keep none.
- Text around the armor (4.7.2 item 5 covers decrypt): check clear-signed verify and file decrypt for the same
  failure when text with a dash line surrounds the block.
- The passphrase field rule (4.7.2 item 6: a typed passphrase is used once, the cache is the only memory): check
  the other places a passphrase is typed for a field that outlives its attempt.


## 4e. Inline text signatures that GnuPG reports as BAD (found in the Desktop 3.0.3 interop run, Oct 29)

An inline signed message with a text signature (type 0x01) is reported as BAD by gpg 2.4.4 and 2.5.21, for v4
keys as well as v5 ones. That covers PGPCryptoService.sign(textMode = true) and, on desktop, the SOP wrapper's
`inline-sign --as=text` and `encrypt --as=text --sign-with`. Binary inline, detached text and cleartext signatures
are good in gpg. Desktop 3.0.2 already did this with a v4 key, so it predates 4.7.3.

Cause: PGPony writes the text into a 'u' literal data packet with the line endings it was given (LF) and hashes
it with CR LF, as a text signature should. GnuPG hashes text literal data as stored and expects it to be in
canonical CR LF form already (gpg --textmode writes CR LF into its 't' packets). PGPony verifies its own messages
because Bouncy Castle converts LF to CR LF on the reading side as well.

Work: write the literal data in canonical CR LF form whenever the signature is a text signature, in sign() and
wherever else an inline text signature is made; then check gpg reports Good, and that gpg's own text-mode messages
still verify here (they do today). Desktop's SOP wrapper builds its own literal packet (SopInline), so desktop
changes that file itself when it takes this from the sync.


## 4f. Polish (pl)

Origin: a Google Play review, Oct 30 2026 (five stars, waiting for Polish).

- Resource folder values-pl, the whole of values/strings.xml (about 2,400 strings and 26 plurals). Machine
  translation, multi-agent: split the file between translators, then a separate reviewer per part who did not
  translate it, then one pass for terminology across the whole file (encrypt, decrypt, sign, verify, key pair,
  subkey, fingerprint, keyring, trust levels, passphrase, security key) so each term has one Polish word.
- Plurals need all four forms Polish uses: one, few, many, other. Check every <plurals> entry by hand against the
  CLDR rules (few is 2 to 4, 22 to 24 and so on, never 12 to 14; many is 0, 5 to 21, 25 to 31 and so on); this is
  where machine translation most often goes wrong.
- Register it: res/xml/locales_config.xml (pl), i18n/LanguageManager (PL, picker name Polski).
- The format-argument check from 4.6.2 (every %1$s, %1$d, escape and entity matches values/) runs on values-pl.
- Store text: fastlane/metadata/android/pl-PL/ (title, short description, full description) and the same in the
  Play listing. The Play release notes for 4.8.0 and later add Polish as a twelfth language.
- From the release that ships it, "all 10 locales" in the rules above means all 11.
- Release notes and the reply on the review say plainly that the translation is mostly machine-made and ask for
  corrections. iOS and desktop add Polish when they mirror this item.


## 4g. Messages whose first partial chunk is under 512 octets (#110)

Origin: #110, Oct 30. A signed message for a v4 RSA key opens in OpenKeychain and GnuPG, and PGPony stops with
"Malformed message: first partial chunk shorter than 512 octets". The file is the reverse signature from the key's
Keybase sigchain (confirmed by the reporter), written by Go's OpenPGP code, which sends a small first chunk.

Cause: MessageGrammar.packets() (added Sep 29 for the SOP interop run) enforces RFC 9580 4.2.1.4, which says the
first partial length MUST be at least 512 octets. Bouncy Castle and GnuPG do not enforce it, so PGPony is the only
one of the three that refuses these messages.

Work: accept a short first partial chunk in MessageGrammar.packets() and in CompositeInlineStreamReader. Keep the
other checks, including partial lengths only on literal, compressed and encrypted data packets. MessageGrammarTest's
`a first partial chunk under 512 octets is rejected` becomes a test that it reads, plus a test with the file from
#110 once it is in test resources. Desktop takes the same change from the sync. Decided Oct 30: not worth a 4.7.4 on
its own; it ships in 4.8.0 unless another interop fix makes a 4.7.4 worth doing first.


## 4h. Email in exported key file names (a user, promised 28 October)

A user with several keys under one name (one per mail account) asked for the email in exported key file
names. Android already writes `{name}_{KEYID}_public.asc` (KeyShareIntents.buildExportFilename), so files
don't collide, but the email is what tells them apart at a glance. iOS 8.4.0 build 13 writes
`Name_email_KEYID_public.asc` (and `_private.asc`), the "@" as "-", for example
`Riley_Park_riley-example.com_9D04ADE0_public.asc`. Match it: add the email (lowercased, "@" to "-", other
unsafe characters to "_", 64 characters at most) between the name and the key ID, in every caller of
buildExportFilename (public, private, revocation). Unit test the shape.

## 4i. A v4 base for "Advanced: compose subkeys" (a user, Nov 2)

A user asked why a key built with the subkey composer always comes out as a v6 Ed25519 key, and whether it could
be a standard v4 key with subkeys. Nothing in OpenPGP requires v6 here. The composer is hard-wired to v6:
PGPCryptoService.assembleGranularV6Ring always starts from buildV6Ed25519X25519KeyRings, KeyRepository
.generateGranularKey stores the result as V6_ED25519, and KeyringScreen hides the algorithm picker in granular mode.
The likely reason is that the composer offers ML-KEM-1024 and ML-DSA signing subkeys, which are v6-only. Today the
workaround is to generate a plain Ed25519 key (v4) and use Add Subkey in Key Details, which already offers the v4
set.

Work: give granular mode a v4 / v6 choice for the base, v6 by default so the current shape is unchanged.
- v4 base: start from the v4 Ed25519 + Cv25519 ring the normal keygen builds, keep or strip its default encryption
  subkey per the existing toggle, and graft each spec with ClassicalSubkeyGen.addSubkey (all classical types,
  RSA included) or, for ML-KEM-768, the v4 algo-35 interop graft (CompositeKeyGen.addV4Algo35SubkeyRings, with the
  SEIPDv2 Features flag item 14 of 4.5.0 relies on). Each subkey keeps its own expiry, as on v6.
- The Add subkey menu in the composer filters with AddSubkeyChoice.classicalFor(isV6) and postQuantumFor(isV6), the
  same lists Key Details uses. Switching the base from v6 to v4 drops any v6-only subkeys already in the list and
  says so.
- generateGranularKey sets the stored algorithm from the base (Ed25519 for v4) instead of always V6_ED25519.
- Strings for the base choice and the dropped-subkeys note in all locales.
- Tests: a v4 granular key with RSA, Ed25519 and X25519 subkeys and one with ML-KEM-768 reads back as v4 in
  BouncyCastle and gpg (gpg --list-packets shows version 4 on every key packet), with per-subkey expiry intact.
- iOS and desktop mirror once verified.


## 4j. Signing with an ML-DSA signing subkey on a classical primary (a user, Nov 4)

Reported on 4.7.2 (Pixel 8, Android 17): a key with an ML-DSA-87 signing subkey cannot sign. With a passphrase the
sign fails as a wrong passphrase; without one it fails with an unknown public key algorithm. The user also saw an
Ed25519 primary and an X25519 subkey on a key meant to be post-quantum only, which is the subkey composer's v6
Ed25519 base with its default encryption subkey switch on (the switch defaults to on).

Cause, from the code (not yet reproduced): a classical v6 primary carrying an ML-DSA signing subkey, from the
composer or from Add Subkey in Key Details, is stored as a BouncyCastle ring with the algo-30/31 subkey as an
UnknownBCPGKey and the key labelled V6_ED25519. Every sign path checks `algorithm.isCompositeSign` on the key's
label, so this key goes through SigningService, and pickSigningSecretKey takes the newest valid signing subkey: the
ML-DSA one. BouncyCastle cannot extract or sign with it. The sign-only path in EncryptDecryptViewModel maps the
failure to the passphrase error when a passphrase was given. No test signs a document with a composite signing
subkey on a classical primary, and no test signs a document with ML-DSA-87+Ed448 at all (CompositeSignerTest and
CompositeDocumentSignaturesTest use ML-DSA-65+Ed25519 only).

Work:
- Reproduce first: a unit test that builds a composer key (default encryption subkey on, one ML-DSA-87 signing
  subkey), with and without a passphrase, and signs cleartext, detached and inline through the paths the app uses.
- Route a composite signing subkey on a classical primary through CompositeDocumentSigner (unlock the subkey's
  secret the way CompositeKeyFacade does for a composite primary, sign with the subkey's suite and fingerprint), at
  every sign site: sign-only, encrypt and sign, files, the provider. Until then, leave a composite subkey out of the
  BouncyCastle signing pick so the classical primary signs instead of failing.
- A wrong passphrase and an unsupported key stay two errors: the sign path stops mapping every failure to the
  passphrase message.
- Add ML-DSA-87+Ed448 to the document-signature tests (cleartext, detached, inline, verified back), and check the
  signatures in a second implementation before shipping.
- The composer's "Include default encryption subkey" switch: say on the switch that it adds a classical X25519
  subkey, and consider defaulting it to off when only post-quantum subkeys are in the list.
- Desktop shares this code and takes the same fix from the sync.


## 4k. Korean complete and in the picker

values-ko has shipped since 4.6.2 but stays out of locales_config and the in-app picker until the translation is
complete. Done on main Nov 2 (af491ba): the 389 err_ strings, so every string and plural in values/ now has a Korean
entry. The translations repository's Korean is at its PR #6 (Oct 8), which 4.7.0 RC3 already applied, so a sync
from it brings nothing new; check it again before the RC in case more has landed.

Left:
- Review: a reviewer who did not write them checks the 389 err_ strings against English, the same as the RC3 pass;
  the format-argument check runs on values-ko.
- Register it: res/xml/locales_config.xml (ko), i18n/LanguageManager (KO, picker name 한국어), and drop the
  "unlisted until complete" note in locales_config.xml.
- Store text: fastlane/metadata/android/ko-KR already exists; check it matches the current English listing.
- Sync the app's values-ko back to the translations repository so contributors work from the complete file.
- #96 carries its own translation of the same 389 strings; with af491ba on main it is superseded (see section 5).


## 4l. More curves for key generation (#109)

Origin: #109 (Oct 27). A hardware-key provisioning app can now import keys from PGPony and write them to YubiKey,
Nitrokey and Librem Key cards, and the request is for PGPony to generate ECDSA keys on brainpoolP256r1,
brainpoolP384r1, brainpoolP512r1 and secp256k1. PGPony already reads and uses these curves (KeyAlgorithm has
ECDSA_BRAINPOOL_P256/P384/P512 and ECDSA_SECP256K1); they are not in any generate list. Scope is K5.

If yes: add them to the generate picker's Advanced group (v4 only, ECDSA primary with an ECDH subkey on the same
curve), check what Bouncy Castle 1.85 generates against gpg 2.4 and 2.5 (import, sign, encrypt both ways), and say
in the captions that cards differ in which curves they hold. iOS and desktop mirror once verified.


## 4m. Reorder mode on the Keyring (#101 follow-up, Nov 4)

After trying RC2's setting, the #101 reporter asked for a way to turn dragging back on from the menu for a while,
working like select mode, with Cancel and Done for the order changes. Plan:
- A Reorder keys item in the Keyring menu enters reorder mode: the drag handles show, the top bar carries Cancel and
  Done the way select mode does, and nothing is saved until Done. Cancel and Back put the order back as it was.
- With the RC2 setting on, the handles stay always on and a drag saves at once, as now. With it off, the menu item
  is the way to reorder. K6 asks whether the setting stays once the mode exists.
- Select mode and reorder mode don't mix: entering one leaves the other.
- Strings for the menu item and the mode's title; Cancel and Done reuse the existing ones where they read right.
Desktop has no drag reorder, so nothing to mirror there; iOS checks its own Keyring when it takes 4.8.0.


## 5. Contributor PRs waiting on a decision

- #96: Korean err_ strings. Superseded by af491ba (Nov 2), which translated the same 389 strings on main. Close it
  with thanks, or compare its wording with af491ba first and take any better lines (item 4k's review is the place).
- #98: manifest content VIEW filters without the inert path patterns.


## 6. Carried from 4.7.0

- 4.7.0 item 7: key-server and WKD import failure (#41). No status since it was filed; needs the reporter's
  details or a reproduction.
- 4.7.0 item 8: interop check for LibrePGP ML-KEM-768 + brainpoolP256r1 keys against gpg 2.5.
- 4.7.0 item 21 remainder: an optional `"skipped": true` member on RESULT so a skip is not told from a failure by
  its reason text, and the matching rows in desktop's PairDialog.
- 4.7.0 item 31 left-out: an ML-DSA certifier or target (needs the raw-packet path).
- 4.7.0 item 37 left-out: a foreground worker so a save survives the sheet or Quick Action closing.
- 4.7.0 item 38 left-outs: verifying several detached signatures with their files; .zip and .eml in a batch; a
  decrypted package split into its attachments; card-encrypted files in a batch.
- 4.7.0 item 40 left-out: the import preview saying how many subkeys a re-import adds.
- 4.7.0 item 48 left-out: the multi-file decrypt naming the decrypting key per file.
- 4.7.0 item 11 (SOP wrapper, #64) and item 12 (external review follow-up): not release-gated.


## 7. Questions for Kevin

- K3. #96: Korean error strings, yes or no. Answered yes by af491ba (Nov 2); what is left is #96 itself (section 5).
- K4. #95: take the PGPONY2 format in 4.8.0, or only after iOS and desktop read it? Answered Nov 4: the whole PR in
  4.8.0, in RC6, rebased on 4.7.0's Exchange changes with its planning-doc edit taken out. #100's slower playback by
  default ships with it.
- K5. #109: generate brainpool and secp256k1 ECDSA keys in 4.8.0 (item 4l), or leave generation as it is? Answered
  Nov 4: yes, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 and secp256k1, v4 only, in RC4.
- K6. Item 4m: keep the drag setting next to reorder mode, or drop it so the handles only show in reorder mode?
  Recommendation: keep it, since it shipped in RC2 and some people want the handles always there. Open.


## 8. Status of this document

Rev 1, Nov 4: K4 and K5 answered, RC breakdown in section 9. Rev 0 was the seed, kept current to Nov 4.

Already on main (no RC yet):
- af491ba (Nov 2): Korean for the 389 err_ strings (item 4k); DecryptResult, DecryptStreamResult and
  CardDecryptResult carry the v5 literal fields (literalExtra), so the desktop SOP wrapper can verify a LibrePGP v5
  signature packet by packet (follow-up to 4.7.3).
- 3712407 (Nov 3): the app lock store replaces its file with an atomic move (Files.move, ATOMIC_MOVE). File.renameTo
  fails on Windows when the target exists, so PGPony Desktop saved the first PIN and then failed every later save.


## 9. RC breakdown (Rev 1, Nov 4)

Smallest and safest first. Each RC's work starts only once the one before it is built, tested on the device and
published.

RC1, interop fixes with no new strings:
- 4g (#110): a short first partial chunk reads. Desktop takes it from the sync.
- 4j, the signing path: the reproducing test first (ClassicalPrimaryCompositeSignTest), then a composite signing
  subkey on a classical primary signs through CompositeDocumentSigner, and a wrong passphrase and an unsupported key
  stay two errors. If the fix reaches past the signing path (keygen, bindings or the picker), 4j leads RC2 and RC1
  ships without it. Desktop takes it from the sync. The composer switch is RC2's, since it needs strings.
- 4e: the literal data is written in CR LF form for a text signature, on Android's SOP path. Desktop changes
  SopInline itself.
- #105: Enter runs Unlock on the passphrase prompts. Android UI only; desktop checks its own prompts when it mirrors
  the item.
- 4h: the email in exported key file names, matching iOS build 13. Desktop names its exports in KeyDetailDialog
  (short fingerprint) and changes that itself.

RC2, the subkey composer and small UX:
- 4i: a v4 base for the composer.
- 4j, the composer switch: its caption says it adds a classical X25519 subkey, and it defaults to off when the list
  holds only post-quantum subkeys (decided Nov 4).
- 4k: Korean reviewed, registered and synced back to the translations repository. The review compares #96's wording
  with af491ba and takes any better lines; #96 is closed after that.
- #101, the #93 long press, keyboard dismissal on the other screens (4b), the 4d items, #98.

RC3, data and security:
- 4c: duplicate fingerprint rows merged on upgrade and the unique index added. The migration gets its own device pass.
- 3a: the passphrase before a private key export, and BiometricGate before Backup.

RC4, card and key crypto:
- #108: encrypt to every valid encryption subkey including ADSKs, and decrypt through the authentication slot with MSE.
- 3 (#71): primary-signed edits on a key whose primary is on the card.
- #86: the hash choice when re-signing self-signatures.
- 4l (#109): brainpool and secp256k1 generation, v4 only.

RC5, new ways in:
- #103 (text selection menu), #72 (sign one shared file), #67 (restore a shared backup), #106 (the Verify picker pairs
  signatures with their files, which also covers the 4.7.0 item 38 left-out), #104 (the ZLIB switch), and 4m
  (reorder mode on the Keyring, added Nov 4).

RC6: #95 whole, with #100's slower playback.

RC7: item 1, SSH with ML-DSA-44 + Ed25519, after the OkcAgent, okc-agents and OpenSSH 10.4 checks in the item.

RC8: 4f, Polish. Last, so the translation covers the final values/ in one pass, item 1's strings included.

Not in an RC: the section 6 carry-overs unless one comes up on its own, and the in-app viewer for decrypted files
(4b), which is not planned yet.

What desktop takes from the sync and what it changes itself is noted per item above for RC1. Later RCs note it in
each item when their work starts.
