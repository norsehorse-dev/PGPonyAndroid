# PGPony Android 4.8.0: Planning

Status: open (Oct 20 2026; issues #105, #106 and #108 added Oct 26; items 4e to 4n added Oct 29 to Nov 4; Rev 1 with the RC breakdown, Nov 4; Rev 2 adds RC8 for 4n, Nov 4). Seed: what the 4.7.0 feature freeze deferred, what 4.7.0 left open, and requests
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

Core done in RC7: crypto/ssh/MlDsaEd25519Ssh (keys from the two seeds, SHA-512 composite input, ML-DSA-44 pure
with the label as context, Ed25519 plain), OpenSshKeyFile (openssh-key-v1 read and write, bcrypt_pbkdf with
aes256-ctr, 32 rounds as ssh-keygen 10.6 writes), data/ssh/SshKeyStore (ids "ssh:SHA256:...", seeds and metadata
sealed in SecureKeyStore, no Room change), backup as additive ssh-keys/ entries merged by fingerprint, and Clear
All Data. First checked against OpenSSH 10.4's test vectors, and ssh-keygen 10.4 read the exported file and
verified an SSHSIG made by PGPony. Provider wiring and Settings follow.

Rename in RC7 (Nov 6): OpenSSH 10.6 (Oct 2026) renamed the type to `ssh-mldsa44-ed25519` (IANA codepoint; cert
`ssh-mldsa44-ed25519-cert`), kept no alias for the @openssh.com name, turned it on by default, and raised the
default bcrypt rounds to 32. Blob, private section, signature and M' are unchanged. 10.4 and 10.5 know only the old
name, 10.6 only the new one. PGPony now writes only the new name (blob, .pub line, key file, signature, ids and
fingerprints), still imports a 10.4/10.5 key file, .pub line or blob under the old name and re-encodes it, and
refuses a signature under the old name as 10.6 does. Still experimental: draft-ietf-sshm-composite-sigs is at -00.
Keys stored by earlier RC7 builds are not migrated (never published); they drop out of the list. Unit tests now use
OpenSSH 10.6's test data, plus the 10.4 key file as a legacy import fixture. Device checks (Nov 6): ssh-keygen 10.6
reads a PGPony export after its passphrase, and Termux's OpenSSH 10.6p2 logs in to a 10.6 sshd with a PGPony key
through OkcAgent and okc-ssh-agent. Not run: ssh-keygen 10.6 verifying a PGPony SSHSIG.

Provider done in RC7: SshAuthenticationService routes "ssh:" ids to SshKeyStore before any OpenPGP lookup
(SELECT_KEY, GET_SSH_PUBLIC_KEY with no comment, SIGN with the hash ignored; GET_PUBLIC_KEY is INVALID_ALGORITHM),
the SSH key picker lists SSH-only keys marked experimental, and per-app approval covers them (ids kept case-exact).
Settings done in RC7: Settings > Keys & Servers > SSH keys (ui/settings/SshKeysScreen, a pushed "ssh_keys" route),
marked experimental: generate with a label, copy or share the authorized_keys line, export the private key as an
OpenSSH file under a passphrase asked twice (device check first, FLAG_SECURE dialogs), import an ssh-keygen file
(passphrase prompt when encrypted, other key types named), rename, delete. The restore report and the pairing
backup count include SSH keys.


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

Done in RC4: PrimarySigner (software, or external through CardPGPContentSigner) under the edits;
CardPrimarySigner checks the Signature slot holds the primary, and every signature verifies PW1 again before its
PSO:CDS (DO C4). When the stored primary is a divert-to-card stub, or a card-generated key has no secret ring,
Key Detail asks for the card PIN and the tap for: Add Subkey (0x18 on the card, 0x19 by the new subkey, which
stays on the phone; the key becomes a key pair linked to the card so Move to security key is offered for it),
add User ID, make primary, revoke User ID, expiry of the primary and of a non-signing subkey, Refresh
self-signatures, revoke a subkey. The stub ring takes the new public material. Add Subkey on a key pair linked to
a card (item 55) is no longer blocked; the sheet offers classical types only and says to move the new subkey. When no
secret of the key on the phone has a passphrase, Add Subkey asks for a new one, so the new subkey's secret is never
stored unprotected (decided Nov 5).
Left out: revoking the key, notations, removing a User ID or subkey on a key with every secret on the card, a
signing subkey's expiry (its back-signature needs the subkey), post-quantum subkeys. Tests:
CardPrimaryEditTest.


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
  Done in RC4: SHA-256 or SHA-512 in the Refresh and expiry confirmations, default SHA-512 for RSA 3072+.
  No choice where the key sets the hash: Ed448 and ECDSA on a 384 or 512-bit curve use SHA-512, a card signs with
  its own hash, and composite ML-DSA keys keep SHA-256.
- #100 follow-up: slower or paused QR playback by default.
- #95: QR exchange rework and the optional PGPONY2 format. Needs review, iOS and desktop must read it first, a
  rebase on 4.7.0's Exchange changes, and its planning-doc edit taken out.


## 4b. Requests after 4.7.0

- #103: encrypt or sign selected text from the text selection menu (ACTION_PROCESS_TEXT), replacing the
  selection in place when the field is editable and the result can be returned, as OpenKeychain does.
  Done in RC5: "Encrypt with PGPony" and "Sign with PGPony" in the selection menu (two aliases of
  ProcessTextActivity). Encrypt has the recipient list and "Also sign this message" with Sign as; Sign makes a
  cleartext signature with Sign as, the passphrase when the key has one, or PIN and tap for a card. An editable
  field gets the result back; a read-only one shows it with Copy, Save and Share. A selection holding a PGP
  block opens the Quick Action, which decrypts, verifies or imports it. App lock and the empty-keyring card as
  in the Quick Action.
- #72 follow-up: sign a single shared file from Quick Actions (detached .sig, or encrypt and sign). Several
  files already have Sign only on the package screen.
  Done in RC5: a single shared file gets Sign a file next to Encrypt: Sign as, .asc or .sig (named
  file.ext.asc or file.ext.sig, as the Sign a file sheet names it), streamed from the file, saved or shared from
  the result. Encrypt gains a Sign as row, None by default, with the Encrypt screen's ML-DSA to v4 prompt.
  Software keys only, as on the Sign a file sheet; the typed passphrase is used once and the in-app cache applies.
- #67 follow-up: restore a PGPony backup shared to Quick Actions (recognize the backup file and open Restore).
  Done in RC5: a backup is recognized by its armor headers (Comment: PGPony Backup, or OpenKeychain's
  Passphrase-Format; the .pgpony name only on an armored message) and gets Restore, which opens the main app's
  Restore with the file (IntentAction.RestoreBackup). A backup shared with other files keeps today's behaviour.
- Keyboard on the other screens: 4.7.2 closes it on a tap away from a text field on Encrypt and Decrypt
  (PLANNING_4.7.2.md item 1). Extend dismissKeyboardOnTap and keepsKeyboard to Settings, the Key Details sheets,
  Import and Pair.
- #104: compress large files too. Today a message or file up to 16 MB is compressed with ZLIB
  (COMPRESSION_LIMIT) and a larger one is not; nothing is padded. Narrowed with the reporter (Oct 23, a CSV over
  50 MB): one opt-in switch in Settings, off by default, that lifts the 16 MB limit so every file is compressed
  with ZLIB. The Encrypt progress already covers the longer run. Other methods (ZIP, BZip2) and padding are not
  planned unless someone asks for them. Done in RC5: Settings > Compress large files (off by default), decided
  in CompressionPolicy for the streamed file encrypt.
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
  file. Same pairing serves the 4.7.0 item 38 left-out (several signatures with their files, section 6). Done in RC5.
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
  - Done in RC4 (Nov 5). Encrypt: each recipient gets the chosen encryption subkey (automatic pick or the picker's
    override, unchanged) plus every usable ADSK (flag 0x0400 read from the second key flags octet; bound, unrevoked,
    unexpired, an encrypting algorithm, not weak). Other ordinary encryption subkeys are not added, which is what
    GnuPG does (newest encryption subkey plus ADSKs), not "every valid encryption subkey" as written above. An ADSK
    is never the main pick and a key with only an ADSK is still not a recipient. Software decrypt: a secret ADSK was
    refused by mayDecryptWith (first flags octet 0x20 only); it now counts. Card: pass 1 reads the slots whenever a
    packet names a ring key and prefers the decryption slot; when only the authentication slot's key has a packet and
    the card advertises MSE (C0 tenth octet, spec 3.3 and later), it sends MSE 00 22 41 B8 83 01 03, PSO:DECIPHER, then
    MSE back to 02 (also on failure). Without MSE the old "different key" error, now without a PSO:DECIPHER. Not
    covered: a hidden-recipient (wildcard) packet for an auth-slot ADSK.


- In-app viewer for decrypted files (user email, Oct 23): a decrypted PDF or image always goes to the Android
  app chooser. Asked: show it inside PGPony instead (PdfRenderer for PDF, an image view for JPEG and PNG), with
  Open in another app and Save still offered. Not planned yet; scope and whether iOS has the same gap to check.


## 4c. Two keyring rows with one fingerprint (from 4.7.2 item 2)

4.7.2 guards the recipient and Sign as lists against a repeated fingerprint (the Play crash). Find how two
pgp_keys rows came to share a fingerprint (no unique index on the column), merge any that exist on upgrade, and
add the index.

Found (Nov 4): every import path looked only for a live row. Delete a key (it moves to Recently Deleted), import
it again, and a second row is added next to the binned one; restore the binned row and the keyring holds the key
twice. Purging the binned row later (Empty bin, or the retention window) also wiped the store entry both rows
share, so the live copy lost its key material. Fix in RC3: an import of a binned key brings that row back and
lands on it; purge leaves the store alone while another row holds the fingerprint; MIGRATION_12_13 merges every
group of rows that share a fingerprint (DuplicateKeyRows: secret material first, then a card link, then a live
row, notes from both kept) and adds the unique index. Desktop has its own keyring store and checks its import
and bin paths for the same gap when it mirrors the item.


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

Done in RC9 (Nov 9): values-pl covers all 2,551 translatable strings and 32 plurals. A glossary came first, taken
from the Polish GnuPG, Kleopatra, Thunderbird and OpenKeychain strings (informal ty, "pęk kluczy" for keyring,
"odcisk klucza" for fingerprint, "hasło" for passphrase, trust levels Nieznany, Niezweryfikowany, Zweryfikowany,
Absolutny, Nie używać). Seven agents translated one part each, seven others reviewed a part they did not
translate, and one pass over the whole file settled the terms and made every quoted label match its string.
SupportedLanguage.PL (Polski) and locales_config.xml register it; SupportedLanguagePlTest checks that values-pl
has every string with the English format arguments and all four plural forms. PairSkip now also knows the Polish
skip reason and the Korean one Android actually sends ("상대 사용자가 건너뜀" was missing, so a skip from a Korean
phone counted as a failure); PairLedgerTest checks every shipped language. Store text in
fastlane/metadata/android/pl-PL.


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

Done in RC4: brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 and secp256k1 are in the Advanced group (v4 only),
each an ECDSA primary with an ECDH subkey on the same curve, KDF SHA-256/AES-128, SHA-384/AES-192 or SHA-512/AES-256
by curve size, self-signatures with the matching hash (EcdsaKeygen). New signatures by any ECDSA key (messages,
cleartext, detached, User ID, expiry and revocation signatures) now use a hash at least as long as the curve. Move to
Security Key takes ECDSA and ECDH keys on NIST, brainpool and secp256k1 curves. The gpg 2.4 / 2.5 checks are still to do.


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
Done in RC5, with the RC2 setting kept (K6).

## 4n. Recipient groups, and the picker's order (Nov 4)

PGPony Desktop 4.0.0 replaces its inline recipient list with this app's picker and waits for the 4.8.0 tag to take
groups from the sync (PLANNING_DESKTOP_4_0_0.md section 6), so groups are built here first. Decided Nov 4:
- Order: the picker lists your own keys first, then everyone else A to Z by name (email when there is no name).
  Today it follows the keyring query, newest first. The share target's picker takes the same order.
- Groups: a named set of keys, stored by primary fingerprint in a new table, with its Room migration. Groups show at
  the top of the picker sheet and search matches their names. Picking a group adds its usable keys as chips and
  names the ones it left out (revoked, expired, or a card row without its public certificate).
- Managing groups: "Save as group" in the picker sheet turns the current selection into one; a Groups section on
  the Keyring creates, renames, edits members and deletes; Key Details lists the groups the key is in, with add and
  remove.
- Deleted keys: a key in Recently Deleted stays a member but cannot be picked, and restoring it puts it back; a key
  deleted for good leaves every group.
- Moving: the full backup and the full-backup pairing transfer carry groups; public-key-only transfers do not. The
  backup format leaves room for iOS to read groups later. Check that 4.7.x still restores a backup that carries
  groups and skips them.
- Strings: new ones in all locales, before 4f so the Polish pass covers them.
Desktop takes data/groups/ and backup/RecipientGroupBackup.kt from the sync (corrected in RC10: its backup
service and its database migrations are its own code, BackupService.kt and RoomMigrations.kt being excluded there,
so it wires groups into those itself, calling RecipientGroupSchema.MIGRATION_13_14 for the SQL), builds its own
screens and the `pgpony encrypt -r @name` form. The format is in docs/PGPONY_BACKUP_FORMAT.md. iOS mirrors it when it takes
4.8.0.

Done in RC8: data/groups holds the data layer, with no Compose in it: RecipientGroupEntity (tables
recipient_groups and recipient_group_members, members by primary fingerprint in lowercase hex), its DAO,
RecipientGroupStore, and RecipientGroups for the rules (the picker's order, names trimmed, at most 64 characters
and unique ignoring case, what a pick adds and leaves out, the merge by name). Schema v14 with MIGRATION_13_14,
whose SQL sits in RecipientGroupSchema (exportSchema stays false, and the project has no Room migration test, so a
JVM test pins the SQL). The Encrypt picker and the share target's picker list your own keys first, then everyone
else A to Z. The picker sheet lists groups above the keys, search matches their names, and Save as group turns
the selection into one; picking a group adds its usable keys as chips and names the ones left out (revoked,
expired, a security key without its certificate, in Recently Deleted). Don't use keys are added, since the picker
offers them and encrypting asks first. Keyring > More > Groups (a pushed "groups" page, like Recently Deleted)
creates, renames, edits the keys of and deletes groups; Key Details has a Groups section with add, remove and a
new group holding the key. A key in Recently Deleted stays a member and is shown as such; a key deleted for good
(purge, the automatic purge, Empty, Clear All Data) leaves every group in KeyRepository. The full backup, and so
the full-backup pairing transfer, carries an additive recipient-groups.json entry (formatVersion 1, name,
createdAt, members), with only members whose key is in the backup; a restore merges by name after the keys are in,
keeps only members whose key is on the device, and reports groups added and groups with new keys. 4.7.x reads
only keys/*.asc and its two JSON files, so it skips the entry. Strings are in values/ only; the other locales
follow with 4f in RC9.


## 4o. Three follow-ups from #78, #88 and #90 (Nov 5)

A tester confirmed the 4.7.0 fixes for #82, #87, #89, #91 and #92 and asked three follow-ups. All in RC4.
- #78: a re-import from gpg after the primary's usage flags changed, on a key whose primary is offline (a GNU stub).
  Read from the code it works: CertificateMerge takes the newer self-signature (a User ID certification or a
  direct-key signature), updateSecretRingPublicParts replaces only public parts so the stub stays a stub, and the
  Usage row reads the newest flagged self-signature. No test covers it. Add one to CertificateMergeTest: a key flags
  change at a later time, as a User ID certification and as a direct-key signature, merged with isKeyPair = true;
  then the stub leg (primary turned into a GNU stub, the public parts replaced, the stub still a stub, the subkey
  secret still unlocks, the primary's flags C and S).
- #88: the certifier and signer lookup cards show the key's algorithm on the last line, and a key KeyAlgorithm does
  not model (DSA, ElGamal) reads Unknown. Show the algorithm and size from the public key instead (DSA 1024,
  ElGamal 4096), with Unknown only when even that cannot be read. KeyAlgorithm.UNKNOWN stays the truthful fallback
  elsewhere.
- #90: Check on Key Details asks keys.openpgp.org only (KeyServerRepository.CHECK_SERVER_NAME). Ask the servers
  marked for lookup, in the user's order, stop at the first that has the key, and record that server's name in
  KeyServerCheckStore so Details shows it. Not found names the servers asked. A network failure on one server moves
  to the next and is reported only when every server failed.
Desktop takes #88 and #90 from the sync when it mirrors RC4; #78's test is Android only.

Done in RC4.
- Nov 6, #88 follow-up: RC4 labelled the lookup cards only, so the same key read Unknown once imported (Keyring,
  Key Details, its Subkeys list, the import preview and the encryption key picker), since those show the stored
  KeyAlgorithm. KeyAlgorithmLabel now labels a stored key from its armored public key when KeyAlgorithm is UNKNOWN
  (badge: the primary, "DSA 1024"; Details: "DSA 1024 + ElGamal 4096"). In RC5.


## 4p. Move to security key on a YubiKey NEO (a tester, Nov 5)

Found: a tester moved a PGPony-made RSA 2048 key (subkeys S, E and A into the three slots, Replace on) to a freshly
reset YubiKey NEO. iOS failed at the write with the "cannot hold" message and PGPony Desktop with status 6A83. The
same key, exported and moved with gpg's keytocard, lands on the NEO fine, so the bug is ours. The NEO (Yubico's
ykneo-openpgp applet) is an OpenPGP card 2.0 with fixed RSA 2048 attributes (01 0800 0011 03: e 17 bits, import
format 03, CRT with modulus), a C0 whose first octet is F8 (bit 0x04, "algorithm attributes changeable", clear), and
no PUT DATA for C1 to C3 at all: anything it does not know is 6A83. gpg (rsa_writekey and change_keyattr in
scd/app-openpgp.c) only changes an RSA slot's attributes when the key's modulus size differs and C0 says they can
change; otherwise it imports with the slot's own e length and format. PGPony wrote C1 to C3 whenever the bytes
differed from what it built (KeyToCard.sameAttributes), which on a NEO is 6A83. Android has the same code.

The change, matching PGPony iOS 8.4.1 build 1 (KeyToCard.attributePlan, plan section 3a):
- KeyToCard.attributePlan decides Keep, Write or Refuse. RSA: Keep when the slot is RSA of the key's modulus size
  with an e field at least as wide as the key's, built from the slot's own e length and format (00 when the slot
  reports five octets); otherwise Write with the key's size, the widest of the slot's e, the key's e and 17, and the
  slot's format (or 00). Ed25519, Cv25519, ECDSA and ECDH: Keep when sameAttributes, else Write. Anything that needs
  a write is Refuse when C0 says the attributes cannot change; no C0 keeps the old behaviour (try the write).
- ApplicationRelatedData reads the C0 flag (attributesChangeable). The move reads the Application Related Data
  before any PIN, every time (it used to only when Replace was off), and plans every slot there, so a key the card
  cannot take is refused before any PIN is sent and before any slot is written.
- KeyToCardService.write builds the RSA parts from the plan's attributes (their e length and format) and sends PUT
  DATA C1 to C3 only for Write.
- Errors: OpenPgpCardException.CardRefused carries the card's answer in protocol terms ("slot B6: key import, status
  6A80", "slot B8: PUT DATA 00C2, status 6A83", or "slot B6: attributes 010800001103, the card cannot change them").
  The move screen shows the localized "cannot hold" message with that detail after it, untranslated. No new strings.
- Tests: KeyToCardAttributePlanTest (the plan on the NEO's attributes, five-octet attributes, 4096 on the NEO with C0
  false, true and absent, Ed25519, Cv25519 and ECDSA into an RSA-only slot, the C0 flag, the format 03 import parts
  of RSA 2048 and 4096 against Bouncy Castle's CRT values, and a write against a fake NEO: a kept slot gets no PUT
  DATA C1 to C3, a refused attribute write and a refused import name the slot, the command and the status).

Device test: a NEO is not at hand, so the tester's NEO is the real check. On another card: with a slot already at
RSA 2048 (a YubiKey 5 after an RSA 2048 move or `key-attr`), move an RSA 2048 key; the plan is Keep, so no PUT DATA
C1 to C3 is sent (the fake-NEO test covers the commands) and the move must pass its check as before. Then the Write
path: the same card with its slots at Ed25519/Cv25519, move the RSA key (the attributes are written first).

Done in RC5. Desktop (corrected in RC10): not done there yet. KeyToCard's attribute plan comes with the v4.8.0
sync; desktop's own Read card change (6A83 handled like 6A88 on the optional reads) is desktop 4.0.0 work.


## 4r. Done after a backup goes back to the choice (#113)

Origin: #113 (Nov 7). After a backup is saved, the Backup screen's Done button closed the screen and went to Settings,
while the X in its app bar went back to the choice between Back up and Restore. Restore had the same mismatch: Done on
the restore report closed the screen, the X went back to the choice.

The work: Done on both the backup-saved and the restore-report screens resets to the choice (BackupViewModel.reset),
the same as the X. A restore's pending settings question is dropped by Done as it already was by the X. No new strings.

Done in RC8.


## 4s. The passphrase keyboard in Key Details (#86 follow-up)

Origin: #86 (Nov 7). After RC4's hash choice, the tester found that the passphrase field in Refresh self-signatures
did not take focus, so the keyboard (which shows its privacy mode on password fields) never came up, and that the
keyboard's action key did not run Refresh. The expiry change asks for the passphrase in its sheet, before the
confirmation with the hash choice, and had the same gap.

The work: each passphrase or PIN field below takes focus and opens the keyboard when its dialog or sheet appears
(rememberProviderAutoFocus, the #59 helper, called inside the dialog or sheet so it reaches that window's keyboard),
and the keyboard's Done key runs the confirm action once something is typed and nothing is in flight:
- Refresh self-signatures (the passphrase field and the card PIN field).
- Edit expiration sheet (passphrase and card PIN). Done there opens the confirmation dialog, as Save does; nothing is
  signed before it and the screen lock step.
- User ID action sheet (revoke a User ID, make it primary; Remove has no field).
- Withdraw a certification (passphrase or card PIN).
- Restore key access, after the device reset the key's secure storage.
- The passphrase before a private key export (Done already worked there; focus added).
Left as they are: Add User ID, Add subkey, Edit notations, Change passphrase, Certify, Revoke key, Move to security
key and Delete key, where the passphrase is one field in a longer form (focusing it would skip the fields above it,
and Done on Revoke key would revoke without a look at the reason). No new strings.

Done in RC8.


## 4t. Missing QR parts, the parts a large key needs, and Long QR codes (#100 follow-up)

Origin: #100 (Nov 7). The tester scanned a 32-part code after RC6, but sat at 31 of 32 with no way to tell which part
was missing. He asked how many parts a key too large for a QR code would need, and for a much longer slideshow as an
option, switching between the normal limit and 512.

The work:
- Scanner: while a PGPONY1 code is collected, a strip of one cell per part (solid when received, faint while
  missing) shows under the progress line, 32 per row for a normal code and 64 per row for a long one, so 512 parts
  make an 8-row block. Once eight or fewer parts are left their numbers are listed ("Still missing parts 3, 17.").
  PGPONY2 completes from any of its parts, so it shows only its count, as before (QrMissingParts, Collector.missing).
- Too large: Show Key and Key Details say how many parts the key would need at the current limit, and point to Long
  QR codes when turning it on would fit the key (QrPartLimit.tooLarge, QrChunking.partsNeeded).
- Settings, Sharing: Long QR codes, off by default, raises the sender's limit from 32 to 512 parts. A key that fits in
  32 parts is split exactly as before with it on, so iOS and Desktop, which stop at 32, still read every normal code.
  The receiver always accepts up to 512 parts (QrChunking.parse), and its retained-text bound grows with the declared
  part count (max of 32,000 and 1,000 per part). seq and total are plain decimals with no fixed width; the frame
  store holds 512 frames. PGPONY2 keeps its own 160-shard ceiling and is not sent by the app.
- Tests: 512-part round trips (plain and through PublicKeyQrCollector), the 512 cap and the 32 default, codes that fit
  in 32 unchanged by the setting for every profile, 513 refused on parse, the retained bound, missing parts, the strip
  layout and the too-large numbers (QrChunkingTest, QrPartLimitTest, QrFrameStoreTest).

Done in RC8. iOS and Desktop can take the receiver side (accept up to 512) when they next touch QR.


## 4u. NIST curves for key generation (#109 follow-up)

Origin: #109 (Nov 7). The tester confirmed RC4's brainpool and secp256k1 keys work in the provisioning app, and noticed
that a P-384 key imported fine but NIST curves could not be generated.

The work: NIST P-256, P-384 and P-521 join the Advanced group the same way as 4l: v4, an ECDSA primary with an ECDH
subkey on the same curve, KDF SHA-256/AES-128, SHA-384/AES-192 and SHA-512/AES-256, self-signatures with the
matching hash (EcdsaKeygen, KeyAlgorithm.generatableEcdsa, PGPCryptoService). They come first in the ECDSA chips. The
existing ECDSA_NIST_* entries, labels and card handling are reused. EcdsaCurveKeygenTest covers the seven curves
(shape, labels, encrypt and decrypt, encrypt and sign, cleartext and detached signatures, export, the hash floor and a
later User ID). No new strings: the 4l caption applies.

Done in RC8. The gpg 2.4 / 2.5 checks from 4l cover these curves too.


## 4v. The commit hash on About (#114)

Origin: #114 (Nov 7). A tester asked for a way to tell which RC is installed, with a hash that stays static and does
not break the reproducible build checks.

The work: app/build.gradle.kts reads HEAD with `git rev-parse --verify HEAD` (providers.exec, configuration-cache
safe) into BuildConfig.GIT_COMMIT, empty without git, with no dirty marker. Settings > About shows the version with
the short hash ("4.8.0 (1a2b3c4)"), and the feedback email carries the same. Two clean clones of a tag and F-Droid's
checkout resolve the same HEAD, so the APK stays reproducible; the playbook says so in 4.2. BuildCommitTest covers
the short form and the fallback.

Done in RC8.


## 4w. Keys certified by your own Ultimate key show as Verified (#115)

Origin: #115 (Nov 7). A tester imported his public keys from GitHub. His old key carries a certification by his own
key pair, which is on the phone at Ultimate, and it still showed as Unverified. gpg shows such a key as fully valid.

Found: no code turned a certification into trust. The stored level is set by the user, by key generation (Ultimate)
and by import (Unknown, key pairs included). Certifications were only listed in Key Details, and certifying a key in
PGPony offers a manual Mark as Verified. The 4.7.0 item 27 note that a weak User ID never counts toward Verified had
no computation behind it.

The work: an effective trust, derived and never stored, kept per User ID. A key that is not yours, stored at
Unknown, shows Verified while the User ID it is shown under (bound now by a verified, unrevoked, not weak-only
self-signature) carries a certification (0x10 to 0x13) by the primary of one of your keys that is at Ultimate,
unrevoked and unexpired. The certification must verify, have a creation time that is not in the future or before the
certifier, be unexpired, use SHA-2 or SHA-3, carry no unknown critical subpacket, and not be withdrawn by a later 0x30
from the same certifier. A User ID the certification does not cover is not raised, so a User ID added later by the
key's owner does not borrow it; the provider's confirmed answers (Autocrypt status, the signature result) need a
certified User ID with the address asked about. Unverified, Don't use, a Verified or Ultimate the user set, and your
own keys are never changed. An imported key pair stays at Unknown until the user sets it to Ultimate, as in gpg.
crypto/TrustFromCertification holds the rule; data/CertifiedTrust caches the answers per key, keyed on the key's
stored files (seen by both the app and the provider process) and the set of Ultimate keys, and each answer runs until
the earliest expiry of its certification, certifier or key. The Keyring list refreshes in the background; Key
Details, the decrypt banner and the provider check the keys they show first, and card lookups skip the check. The
Keyring, Contacts, the provider's recipient review, the provider's signature result and the decrypt banner use the
effective level; Key Details shows it with a line naming the certifying key, and the User IDs it covers when not all
are. Mark as Verified after certifying is hidden when the certification already makes the key Verified. Backup,
deduplication and the trust picker keep the stored level. TrustFromCertificationTest covers the rule, including a
User ID added after the certification.

Done in RC8.

RC10 (Nov 10, the tester's follow-up on #115): trusted introducers and key pairs. The tester's own Ultimate key A
certified his old key O with a trust signature, and O certified his current key pair C; C stayed Unknown. Now a
certification by a root (your key at Ultimate) that is a trust signature of level L >= 1 and amount >= 120 makes
its target a trusted introducer of depth L (capped at 8): its certifications validate User IDs like a root's, and
its own trust signatures of level m make further introducers of depth min(m, L-1), as gpg does. A plain
certification by a key that is not a root never vouches; a marginal amount, a Regular Expression subpacket (scoping
not implemented), a revoked, expired, Don't use or Unverified key never make an introducer. Of one certifier's
certifications on a User ID only the newest that verifies is in force; if it has expired or fails a check, nothing
from that certifier counts there, so an older trust signature does not come back. Your own key pairs at Unknown can
now be raised too; Unverified, Don't use and a level the user set still never change. The answers are computed over
the whole keyring, one computation at a time, with each certification's result cached until either key changes or
it expires; a published path is checked against the newest keyring read, and a failed computation raises nothing.
Key Details names the introducer and your key at the top of the chain. TrustIntroducerTest and
CertifiedTrustChainTest cover it.


## 4x. The Generate Key sheet, and subkey types that match (#109, after RC8)

Origin: #109 (Nov 9 and 10), two testers on RC8. One slid the Generate Key sheet away "half a dozen times" while
scrolling to the NIST curves under Advanced, and could not compose a subkey on those curves. The other, provisioning
a security key from a brainpoolP384r1 key, had signing and encryption on the card but an empty AUT slot: Add subkey
offered no ECDSA or ECDH type, and its list and the composer's differed both ways (Add subkey had RSA and lacked
ML-KEM-1024 and ML-DSA on their key; the composer, on its default v6 base, had those and lacked RSA).

The work:
- A swipe no longer closes a sheet that holds a form (ui/components/FormSheet.kt): Generate Key (with a Close button
  in its title row), the first-key sheet in onboarding, and in Key Details Add subkey, Add User ID, Edit notations,
  Change passphrase, Revoke key and Certify. A drag springs back and the content still scrolls; back and the sheet's
  Close or Cancel close it. A tap on the scrim no longer does: Material 3 1.3 asks the same question for a scrim tap
  as for a drag, and sheetGesturesEnabled only arrived in 1.4.
- ECDSA (Sign, Authenticate) and ECDH (Encrypt) subkeys on every curve PGPony generates (NIST P-256/384/521,
  brainpoolP256r1/384r1/512r1, secp256k1), v4 only, made like a generated key on that curve (EcdsaKeygen, gpg's KDF,
  a back-signature as long as the curve). An Authenticate subkey on brainpool or secp256k1 is for a card's AUT slot;
  SSH has no type for those curves, which the sheet says, and SshAuth passes it over. A NIST key's SSH subkey from
  Generate Key is now ECDSA on its curve.
- One list for both (AddSubkeyChoice.optionsFor), grouped Signing, Authentication, Encryption, in the same order with
  the same labels, and a curve field for the ECDSA and ECDH entries (an ECDSA key starts on its own curve). It differs
  only by the key's version, said in AddSubkeyChoice.allowedOn: ECDSA and ECDH are v4 only; RSA is v4 or a composite
  ML-DSA primary; ML-DSA and ML-KEM-1024 are v6 only (an ML-DSA subkey on a classical v6 primary signs since 4j). The
  composer takes one ML-KEM-768 subkey on a v4 base, as before, and switching it to v6 now removes RSA, ECDSA and ECDH
  subkeys (with a note) instead of failing at Generate.
- Tests: EcdsaSubkeyTest (every curve and use added with the right shape, a brainpool signing subkey signs, ECDH
  subkeys decrypt, NIST Authenticate subkeys for SSH and a brainpool one kept for a card, a composed key with brainpool
  subkeys encrypts and decrypts), SubkeyOptionsTest, and the composer and choice tests updated.

Done in RC10.

RC11 (Nov 11), after the RC10 comments. Compose subkeys ignored the primary: it hid the algorithm picker and built
an Ed25519 key (v6 unless the v4 chip was picked), and its curve field for ECDSA and ECDH subkeys sat where the primary
had been, so a NIST P-256 pick looked lost and then restored by the v4 chip. Only Ed25519 Authenticate subkeys were
on the default v6 base, and the simple SSH switch gave a brainpool or secp256k1 key an Ed25519 AUT subkey.
- The picker stays at the top in compose mode and the composer builds on the primary picked there: Ed25519 v6 (the v6
  composer), Ed25519, RSA 2048 or 4096, or ECDSA on any generated curve (a v4 key made as plain Generate makes it,
  then the subkeys added through ClassicalSubkeyGen, all in memory so a failure stores nothing). The v4/v6 base chips
  are gone. While composing, the picker's own caption is hidden and the composer's caption names the primary by its
  chip name and says the version follows it; an ECDSA primary keeps the card note. A post-quantum primary turns
  compose off and clears it, and the switch says why (pick Ed25519 v6, or Ed25519 for an ML-KEM-768 subkey).
  Turning compose on or off never changes the primary. Composed keys get the revocation pre-cache and the expiry
  read from the key, as plain Generate does.
- One subkey picker for both (SubkeyPicker, rules in SubkeyPick): three short rows of chips, "Used for" (Signing,
  Authentication, Encryption), "Key type" (Ed25519 or X25519, ECDSA or ECDH, RSA, ML-DSA or ML-KEM; shown when the use
  has more than one) and "Curve", "Key size" or "Security level" (shown when the type has more than one), with the
  subkey's full name under them. It starts on the first use the key lacks (encryption before authentication), the
  primary's family and the primary's curve or size; changing the use or type keeps the rest where it can. In Key
  Details it replaces the type field; in the composer, Add subkey opens it in place with Cancel and Add. An earlier
  RC11 build had one dropdown menu of every kind, with a curve row inside it that renamed four entries; it ran past
  the screen, so it was replaced before the tag. The SSH note shows for an ECDSA Authenticate subkey on a curve SSH has
  no type for, in both. A v6 key's Ed25519 signing subkey is a fixed chip, with a lock instead of the disabled look,
  and not offered again. "Include default encryption subkey" names what it adds (ECDH on the curve, RSA of the size,
  X25519 (Encrypt), Add subkey's name for it). A new primary drops the subkeys it can't hold and names them. The
  picker group "Advanced / compatibility", which sat next to "Interop / compatibility", is "RSA, ECDSA and LibrePGP".
- "Primary certifies only" (v4 composer, off by default) gives the primary the Certify flag alone for a security key
  that holds S, E and A; with no signing subkey composed, one of the primary's type is added and shown as a fixed chip.
  Plain Generate is unchanged.
- Add subkey offers ML-KEM-768 on a v4 key only when its primary is Ed25519 (an allow-list); its v4 binding is an
  EdDSA signature, so it failed on RSA and ECDSA keys. The repository's v4 path checks the primary too.
- The simple switch is "Authentication subkey" and matches the primary (ECDSA on its curve, RSA of its size, Ed25519
  otherwise). On brainpool and secp256k1, with the switch on, it offers "Same curve (for a security key)", the default,
  or "Ed25519 (for SSH)"; the caption says what each is for and only asks to pick while the choice is shown.
- UX pass: a collapsed algorithm group names the primary picked in it; the picker's spacing is on the 4dp grid; the
  onboarding sheet always makes a plain key with the default expiry (it shares state with the Keyring sheet); the
  composer's remove icon has a label for TalkBack.
- Tests: GenerateFormTest (compose never changes the primary, the curve follows the primary, a post-quantum primary
  clears compose, dropped subkeys are named, onboarding resets), GranularComposerTest (options per primary, where the
  picker starts, fixed subkeys), SubkeyPickTest (every curve once, start on a brainpool key is its AUT subkey, use and
  type changes keep the rest), SubkeyOptionsTest (allow-listed base, primary family first), EcdsaSubkeyTest (a composed NIST P-256 key
  with ECDSA auth and ECDH encrypt subkeys; a composed RSA key; ML-KEM-768 refused on ECDSA; the brainpool AUT subkey
  and its Ed25519 choice; a certify-only brainpool key that signs with its added subkey, takes a new subkey and moves
  S, E and A to their card slots; plain Generate still signs and certifies).

Done in RC11.


## 4y. The keyboard's private mode on every field (#86, after RC8)

Origin: #86 (Nov 9). A tester asked for the keyboard's private (incognito) mode. Passphrase fields already were, as
password fields; message, name and comment fields were not.

The work: every text field asks the keyboard not to learn from it (EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING),
through Compose's InterceptPlatformTextInput in ui/components/PrivateKeyboard.kt. It wraps PGPonyTheme's content,
the root of every activity with text input (the app, the OpenPGP API dialogs, the share target and process text),
and dialogs and sheets inherit it. Always on, no setting. A keyboard may ignore the flag. No new strings.

Done in RC10.


## 5. Contributor PRs waiting on a decision

- #96: Korean err_ strings. Superseded by af491ba (Nov 2), which translated the same 389 strings on main. Close it
  with thanks, or compare its wording with af491ba first and take any better lines (item 4k's review is the place).
- #98: manifest content VIEW filters without the inert path patterns.


## 6. Carried from 4.7.0

- 4.7.0 item 7: key-server and WKD import failure (#41). No status since it was filed; needs the reporter's
  details or a reproduction.
- 4.7.0 item 8: interop check for LibrePGP ML-KEM-768 + brainpoolP256r1 keys against gpg 2.5.
- 4.7.0 item 21 remainder: an optional `"skipped": true` member on RESULT so a skip is not told from a failure by
  its reason text, and the matching rows in desktop's PairDialog. Android side done in RC10; desktop's rows are desktop 4.0.0
  work.
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
  Recommendation: keep it, since it shipped in RC2 and some people want the handles always there. Answered
  Nov 5: keep the setting.


## 8. Status of this document

Rev 2, Nov 4: item 4n (recipient groups and the picker's order) added as RC8; Polish moves to RC9.
Rev 1, Nov 4: K4 and K5 answered, RC breakdown in section 9. Rev 0 was the seed, kept current to Nov 4.

Already on main (no RC yet):
- af491ba (Nov 2): Korean for the 389 err_ strings (item 4k); DecryptResult, DecryptStreamResult and
  CardDecryptResult carry the v5 literal fields (literalExtra), so the desktop SOP wrapper can verify a LibrePGP v5
  signature packet by packet (follow-up to 4.7.3).
- 3712407 (Nov 3): the app lock store replaces its file with an atomic move (Files.move, ATOMIC_MOVE). File.renameTo
  fails on Windows when the target exists, so PGPony Desktop saved the first PIN and then failed every later save.


## 9. RC breakdown (Rev 2, Nov 4)

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
- 4o (#78, #88, #90, added Nov 5): the usage-change re-import test, the algorithm on the lookup cards, Check across
  the lookup servers in order.

RC5, new ways in:
- #103 (text selection menu), #72 (sign one shared file), #67 (restore a shared backup), #106 (the Verify picker pairs
  signatures with their files, which also covers the 4.7.0 item 38 left-out), #104 (the ZLIB switch), and 4m
  (reorder mode on the Keyring, added Nov 4).
- 4p (added Nov 5): Move to security key on a YubiKey NEO.
- #88 follow-up (added Nov 6): the algorithm label on stored keys, not only the lookup cards.
- 4p follow-up (added Nov 6, found in RC5 device testing on a Token2): moving an RSA key into a slot that held
  Ed25519/Cv25519 writes the slot as RSA format 00 (e, p, q), the same as RC4, and the Token2 refused the import
  with 6984 because it cannot work out n. A written RSA slot whose import is refused with 6984 or 6A80 is written
  again as format 03 (CRT values and the modulus) and imported once more. Kept slots are never retried.
- File decrypt (added Nov 6, found in RC5 device testing): a file decrypted on the buffered path (4 MB or less) also
  filled the message box with its content read as text, so a binary file showed garbage behind and after the result
  sheet. The message box stays empty for a file, as on the streamed path; the result sheet carries Save and Share.
- 4q (added Nov 6, a user by email, 4.7.3): Thunderbird could not open mail encrypted to a passphrase-protected
  composite (ML-KEM) key. The provider decrypts through decryptStream, which had no mapping for a locked composite
  key, so the mail app showed "Decryption failed: composite secret key is passphrase-protected" instead of PGPony's
  passphrase prompt. Sending (signing) and drafts did prompt. decryptStream and decrypt now map a locked composite
  key in all four composite formats to PassphraseRequired (InvalidPassphrase when a passphrase was given), so the
  provider returns its passphrase intent. The buffered decrypt had this for one format only since #26.
  A wrong passphrase on such a key fails inside the ML-KEM unlock rather than as InvalidPassphrase, so the provider
  now checks the matched key with SecretKeyCheck when a decrypt with a passphrase fails, and asks again when the
  passphrase does not unlock it (found in RC5 device testing).

RC6: #95 whole, with #100's slower playback.
- Five tabs (added Nov 6, owner decision): Contacts leaves the bottom bar, which is now Keyring, Encrypt, Decrypt,
  Exchange and Settings. Contacts opens from a Contacts icon in the Keyring's top bar (normal bar only, not in select
  or reorder mode) as a pushed page with a Back arrow, under the Keyring like Recently Deleted: the bar stays, no tab
  is lit, and Keyring or Back returns to the list. The "contacts" route keeps its name. Android only. Done in RC6.

RC7: item 1, SSH with ML-DSA-44 + Ed25519, after the OkcAgent, okc-agents and OpenSSH 10.4 checks in the item.

RC8: 4n, recipient groups and the picker's order (added Nov 4).
- 4r (#113, added Nov 7): Done after a backup or restore goes back to the choice.
- 4s (#86, added Nov 7): the passphrase fields in Key Details take focus, and Done confirms.
- 4t (#100, added Nov 7): missing QR parts on the scanner, the parts a large key needs, and Long QR codes.
- 4u (#109, added Nov 7): NIST P-256, P-384 and P-521 key generation.
- 4v (#114, added Nov 7): the commit hash on About.
- 4w (#115, added Nov 7): keys certified by your own Ultimate key show as Verified.
- Also (Nov 9, owner request): TapPony and HashPony in Settings, More from NorseHorse, with the subtitles PGPony Desktop already ships.

RC9: 4f, Polish. Last, so the translation covers the final values/ in one pass, item 1's and 4n's strings included.
  Done in RC9, with the Korean pairing skip fix found on the way.

RC10 (added Nov 9): what PGPony Desktop 4.0.0 needs from the v4.8.0 tag, from docs/planning/BEFORE_DESKTOP_4_0_0.md.
PairSkip moves to pair/PairSkip.kt and buildExportFilename to crypto/ExportFilename.kt (move only, both shared trees
desktop vendors, with their tests); a skip RESULT carries an optional "skipped": true member (the 4.7.0 item 21
remainder from section 6), counted before the reason text; docs/PGPONY_BACKUP_FORMAT.md writes the backup format down,
with the 4.8.0 ssh-keys/ and recipient-groups.json entries; PAIRING_PROTOCOL.md gets the member and what a backup
item carries; and the 4n and 4p notes on desktop are corrected. No new strings. Done in RC10.
- 4x (#109, added Nov 10): a swipe no longer closes Generate Key or the Key Details forms; ECDSA and ECDH subkeys on
  every generated curve, Authenticate included; one subkey list for Add subkey and the composer.
- 4y (#86, added Nov 10): every text field asks the keyboard for its private mode.

After RC10 (Nov 10), for PGPony Desktop 4.0.0: the backup format constants (the armor comment, the format version and
the file extension) move from BackupService's companion to backup/BackupFormat.kt, values unchanged, and
BackupFileSniff and its test read them there. BackupFileSniff named BackupService, which desktop does not vendor, so
it could not compile there (BEFORE_DESKTOP_4_0_0.md section 1.3). A compiled source changes, so the APK differs from
RC10's: this needs a build before the v4.8.0 tag.

RC11 (added Nov 11): 4x after the RC10 comments (#109): compose subkeys on the primary picked in Generate Key, the
Authentication subkey on the primary's own algorithm and curve, no ML-KEM-768 on an RSA or ECDSA key, and the UX
pass in 4x. RC11 also carries the BackupFormat.kt move above, so it is the build that move needed.

Not in an RC: the section 6 carry-overs unless one comes up on its own, and the in-app viewer for decrypted files
(4b), which is not planned yet.

What desktop takes from the sync and what it changes itself is noted per item above for RC1. Later RCs note it in
each item when their work starts.
