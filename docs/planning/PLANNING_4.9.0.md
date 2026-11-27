# PGPony Android 4.9.0

The next minor after 4.8.x. Opened Nov 16 2026 with one item; more get added as they come in. Items moved to 4.8.2 (Nov 26): certifying
your own key pair, the Ed25519 subkey fix on ML-DSA keys, and the LibrePGP switch. Version
numbers are set when the release is cut. PGPony iOS and PGPony Desktop pick this up for parity in their
own next releases.

## 1. Encrypt a whole folder

Request (Nov 2026, a tester on GrapheneOS): encrypt an entire directory. Sharing a folder into PGPony from a
file manager fails today with an "is a directory" error, because every entry point expects a single file.

OpenPGP encrypts one stream, so a folder is packed into an archive first and the archive is encrypted as one
file. GnuPG does the same with gpgtar, so the format should be one GnuPG users can open.

What it does:

- Encrypt tab: a "Folder" option next to the file picker (ACTION_OPEN_DOCUMENT_TREE). A folder shared in
  from another app goes to the same flow instead of the current error.
- The folder is packed as a tar archive and encrypted as `<folder>.tar.gpg` (or `.asc` when armored), with
  the literal data filename `<folder>.tar`. Recipients, signing, armor and the passphrase prompt work the
  same as for a single file.
- Streamed end to end: the tar writer feeds the existing streaming encrypt path directly, with no
  intermediate archive file, so memory stays flat for large folders (same rule as the batch and single-file
  paths).
- Decrypt: when the decrypted payload is a tar (literal filename ends in `.tar`, or the ustar magic at
  offset 257), offer "Extract to folder" (pick a destination with the tree picker) next to the usual
  "Save file", which keeps the .tar as is.
- Interop target: `gpg -d folder.tar.gpg | tar -x` and `gpgtar --decrypt folder.tar.gpg` both work on
  PGPony's output, and PGPony extracts a `gpgtar --encrypt` archive.

Security on extraction (treat every archive as hostile, including our own):

- Reject absolute paths, `..` segments, and anything that resolves outside the destination folder.
- Regular files and directories only. Skip symlinks, hard links, device and FIFO entries, with a count of
  what was skipped.
- Run names through LiteralFilename.sanitize. Never overwrite an existing file silently; number it like the
  batch does ("photo (1).jpg").
- Cap entry count and total extracted size against SecurityLimits, checked while streaming, not after.

Implementation notes:

- backup/UstarArchive.kt is the starting point but not enough as is: it builds the whole archive in memory,
  has no directory entries, and only takes names up to 100 bytes. Folder encryption needs a streaming
  writer and reader with directory entries and pax headers (or GNU long names) for long and non-ASCII
  paths. Keep it hand-rolled and dependency-free, as UstarArchive is, for the reproducible F-Droid build.
- Walking a SAF tree is slow on big folders. Collect the file list and total size first so the sheet can
  show progress, then stream.
- Check first whether the existing multi-file Bundle package format could carry a directory tree. Plain tar
  is still preferred because GnuPG can open it.

Testing:

- Round trip on nested folders with empty directories, long names, non-ASCII names and a multi-GB file.
- Interop both ways with gpg and gpgtar on desktop.
- Hostile archives: traversal, absolute paths, symlinks, oversized and over-count entries.

Strings: new UI text into every shipped language, planned as several agents split by language plus a
separate pass for missing keys.

## 2. Choosing the SSH authentication subkey (#124)

Request (Nov 17 2026, a tester who uses SSH through OkcAgent): choose which authentication subkey SSH uses.
SshAuth.authSubkey takes the newest authentication-only subkey that is bound, not revoked and not expired, so
today the only way to steer it is to let the others expire, which is what the tester does.

What it does: a per-key choice in Key Details, shown when the key has more than one usable authentication
subkey ("Use for SSH"), stored on the key's row and read by SshAuthenticationService. When the chosen subkey
stops being usable (revoked, expired, removed) it falls back to today's rule. Full backup and pairing carry the
choice. New strings in every shipped language.

## 3. Themes and the bottom bar (#127)

Request (Nov 18 2026): import or customize app themes, and hide bottom bar tabs a user doesn't use (Contacts, for
example). Hiding tabs: a Settings list of the tabs with a switch each, Keyring always on, and the order kept.
Themes: start from the existing light, dark and system choice; decide between a few built-in accent palettes and
an importable theme file (a small JSON of color tokens, validated, no code) before building. New strings in every
shipped language.

## 4. A gpg-agent bridge for Termux (#118)

Request (Nov 2026): let GnuPG in Termux (git commit -S, gpg --sign, --decrypt, pass) use PGPony's keys,
including keys on a card, through a gpg-agent compatible Assuan socket. Like SSH through OkcAgent, it is a small
Termux-side program that answers on the agent socket and forwards the private-key operations (PKSIGN, PKDECRYPT,
the key list) to PGPony over the OpenPGP API, which shows its own consent, passphrase and card prompts. gpg itself
keeps doing the OpenPGP packet work. Porting gpg-agent's own source doesn't fit, because gpg-agent expects to hold
the secret keys itself. Scope to settle first: which Assuan commands gpg 2.4 and 2.5 send for sign and decrypt,
how keygrips map to PGPony keys, and whether it lives in the OkcAgent fork or a new helper.

## 5. Choosing the signature hash

Request (Nov 19 2026, by email): an Ed25519 key's clear-signed text shows "Hash: SHA256", and the user would rather
sign with SHA-512.

Today SigningService signs with SHA-256 (DEFAULT_HASH_ALGORITHM) for clear-signed, detached and inline signatures,
and EcCurveOid.signatureHash raises it only where needed: SHA-384 or SHA-512 for ECDSA on the longer curves, SHA-512
for Ed448. Signatures inside encrypted messages take RecipientPreferences.hashFor, which already picks SHA-512 when
every recipient lists it. Keys made in PGPony list SHA-256 first in their hash preferences, so following the signer's
own preferences would not change anything for them. SHA-256 with Ed25519 is sound (RFC 9580 asks for at least 256
bits); this is a preference, not a fix.

What it does:

- Settings: "Signature hash", SHA-256 (default) or SHA-512, worded like the Refresh self-signatures picker.
- The choice goes in as the requested hash to EcCurveOid.signatureHash, so ECDSA and Ed448 are still raised when
  their curve needs more.
- Covers clear-signed, detached and inline signatures in the app, Quick Action, and signing through the OpenPGP API
  for mail apps (including the PGP/MIME micalg value, provider/Micalg.kt).
- Sign and encrypt: SHA-512 when every recipient's preferences accept it, otherwise RecipientPreferences.hashFor as
  now.
- Security keys: CardSigningService passes SHA-256 today. Check that Ed25519, ECDSA and RSA cards accept a SHA-512
  digest before applying the setting there; keep SHA-256 for a card that refuses it.

Testing: signatures with each key type and both settings verify in gpg and in PGPony; the Hash header and micalg
match the signature; card signing with the Token2 key. New strings in every shipped language. PGPony iOS and
PGPony Desktop get the same setting for parity.

## 6. Certifying with and certifying ML-DSA keys

Request (Nov 19 2026, by email). Both directions are off: KeyRepository.canBeCertified leaves out ML-DSA targets,
and certifierChoices leaves ML-DSA key pairs out of "Certify with" (the sheet says "ML-DSA keys can't certify yet"),
because Certify goes through Bouncy Castle, which can't load an ML-DSA primary.

- With an ML-DSA key: a certification (0x10 to 0x13) over the target's key and User ID, signed by PGPony's own
  ML-DSA signer, as signing and the 4.8.1 self-signature edits already do.
- Of an ML-DSA key: the hash covers the target's v6 key packet, built from the key's packets as the 4.8.1 edits
  do; a classical certifier signs it through Bouncy Castle, an ML-DSA certifier through PGPony's signer.
- Key Details lists and verifies these certifications, and trusted introducers (#115) count an ML-DSA certifier.
- Interop: GnuPG 2.5 verifies both directions. 4.8.2 item 5 loosened the same two gates for key pairs.

## 7. Exporting a key pair with only its subkeys' secrets

Request (Nov 22 2026, by email): the offline-primary export gpg makes with --export-secret-subkeys. PGPony already
imports such a file ("Key Pair (offline primary)") but can't make one. An Export option leaves the primary's secret
out (a GNU dummy S2K stub, mode 1001, as gpg writes it) and keeps every subkey's secret. v4 and v6 keys; for ML-DSA
keys the stub is written on the raw packets. Check that gpg and PGPony both import the result as an offline primary.

## 8. Adding an existing key as a subkey of another primary

Request (Nov 22 2026, by email): gpg's addkey with "Existing key". Pick a key pair, or one of its subkeys, in the
keyring and bind it under the current primary: a new 0x18 binding by the target primary, with a 0x19 back-signature
from the borrowed key when it signs. Its Key Flags come from the use chosen (sign, encrypt, authenticate). The
source key stays as it is. v4 borrows into v4 and v6 into v6; a v4 key can't become a v6 subkey.
