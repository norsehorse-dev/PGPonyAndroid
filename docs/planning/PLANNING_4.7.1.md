# PGPony Android 4.7.1: Planning

Status: open (Oct 22 2026). A quick point release on main after 4.7.0 (versionCode 471): two problems Play
reported on 4.6.4, and ECDSA card signing (#102), moved here from PLANNING_4.8.0.md item 2. One RC, then release.


## 1. ANR: opening the full text of a long message

**Status:** code in (Oct 22).

Origin: Play Console, Crashes and ANRs, two ANRs on 4.6.4 (two devices, one a slow Unisoc phone). Both main
threads were in a single text measure pass inside a dialog: AlertDialog, a scrolling Box, SelectionContainer,
one Text with the whole string (ReadOnlyTextOutput.kt, FullTextDialog). The inline output already stops at 4,000
characters; Open full text laid out everything at once.

Work: FullTextDialog is a plain Dialog with a LazyColumn of blocks (TextBlocks.split: up to 2,000 characters,
ending at a line break where one falls in range, a longer line cut every 2,000). Only the blocks on screen are
laid out. Each block is selectable on its own; a selection cannot cross blocks, and Copy still takes the
complete text. No new strings. Test: TextBlocksTest (blocks join back to the exact text, line-break ends, an
unbroken line, a megabyte splits in well under a second).

On device: decrypt a message of several hundred kilobytes, Open full text, scroll to the end, select inside a
block, Copy and paste the whole text elsewhere.


## 2. Crash: IllegalArgumentException in LayoutNodeSubcompositionsState

**Status:** waiting for the stack trace from Play.

Origin: Play Console, two crash clusters on 4.6.4 (one user, 3 and 5 events). The exception comes from Compose's
subcomposition (lazy lists, SubcomposeLayout); the usual cause is two items in one lazy list with the same key.
The trace names the screen.


## 3. ECDSA card signing and card key labels (#102)

**Status:** code in (Oct 22).

Origin: #102 (on RC7; not new in 4.7.0). A card with all three slots on secp256k1 (card-generated layout,
primary in the Signature slot) could not sign ("exception decoding signature"), and its keys showed as X25519
and Ed25519 + Cv25519.

Cause: CardPGPContentSigner handed Bouncy Castle the card's raw r and s, and BC reads an ECDSA signature as DER.
KeyDetailViewModel.subkeyAlgorithmLabel named every ECDH subkey X25519, and CardAlgorithmAttributes mapped no
curve other than 25519, so a card scanned before its key was imported fell back to Ed25519 + Cv25519.

Work:

- CardSigningFormat: rawEcdsaToDer (SEQUENCE of two positive INTEGERs, long-form length for P-521),
  ecdsaHashFor (SHA-256 for 256-bit curves, SHA-384 for P-384 and brainpoolP384r1, SHA-512 for P-521 and
  brainpoolP512r1), digestName.
- CardPGPContentSigner: an ECDSA key hashes with the curve's hash, reports it to BC, and converts the card's
  output to DER. RSA and EdDSA unchanged (SHA-256). Every card signing path goes through it (messages, files,
  mail apps, certifications, expiry edits).
- Labels: subkeyAlgorithmLabel reads the curve (ECDH secp256k1, ECDSA NIST P-256, and so on; the 25519 family
  unchanged). CardAlgorithmAttributes maps NIST, secp256k1 and brainpool curves to their ECDSA entries.
- A row already stored with the wrong algorithm is put right by scanning the card again: the card link path
  (KeyRepository.importCardKeyInternal) now re-reads the algorithm from the stored certificate, or from the
  card's slots when there is no certificate yet.
- No new strings.

Tests: CardSigningFormatTest (r and s survive the conversion, leading-zero and high-bit handling, P-521 length,
a secp256k1 signature converted from raw verifies, hash per curve, raw digest as the card input).

On device (Token2, secp256k1 in all slots): sign a message and a file and verify with gpg; certify a key;
check the subkey labels in Key Details and the card scan screen. Decrypting with the secp256k1 ECDH slot was
not part of the report; check it once while the card is set up.

Left out: moving NIST or brainpool keys onto a card (4.7.0 item 13 left-out) stays in 4.8.0.


## Release

versionCode 471, versionName 4.7.1. Changelog 471.txt and RELEASE_NOTES_4.7.1.md once item 2 is in. Same
release path as 4.7.0: signed commit and tag, reproducibility gate, GitHub release with four assets,
pgpony.app, Play (notes in all 11 listing languages), F-Droid from the tag.
