# PGPony Android 4.8.0: Planning

Status: open (Oct 20 2026). Seed: what the 4.7.0 feature freeze deferred, what 4.7.0 left open, and requests
that came in during the 4.7.0 cycle. Android leads, then iOS and desktop mirror each item once verified (iOS is
on 8.4.0, Android 4.6.1 to 4.7.0 parity; see HANDOFF-8.4.0.md in the iOS repo). Priorities and the RC breakdown
are set once the list settles.

Context: 4.7.0 (versionCode 470) shipped Oct 20 2026 from RC7's code: GitHub release, pgpony.app, Play (with the
special-use foreground service declaration for PassphraseHoldService), F-Droid from the tag. Anything below is a
4.8.0 change unless it says otherwise.

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

- #101: a setting to turn off drag to reorder on the Keyring.
- #93 follow-up: a long press on a key starts select mode (4.7.0 item 63).
- #86 follow-up: choose the hash (SHA-512 for large RSA keys) when re-signing self-signatures (4.7.0 item 51).
- #100 follow-up: slower or paused QR playback by default.
- #95: QR exchange rework and the optional PGPONY2 format. Needs review, iOS and desktop must read it first, a
  rebase on 4.7.0's Exchange changes, and its planning-doc edit taken out.


## 5. Contributor PRs waiting on a decision

- #96: Korean err_ strings. Korean has had no err_ strings so far; decide whether that stands.
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

- K3. #96: Korean error strings, yes or no.
- K4. #95: take the PGPONY2 format in 4.8.0, or only after iOS and desktop read it?


## 8. Status of this document

Rev 0 seed. Rev 1 once K3 and K4 are answered and the RC breakdown is set.
