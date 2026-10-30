# PGPony Android 4.7.3

A patch release for one problem: PGPony could not encrypt to, or decrypt with, the X448 encryption subkey of a
GnuPG or Kleopatra Ed448 key. Reported by email, Oct 28 2026, with a LibrePGP v5 key (Ed448 primary, X448
encryption subkey, v4 Ed25519 authentication subkey). versionCode 473, versionName 4.7.3. PGPony Desktop gets the
same fix as 3.0.3. iOS can't import these keys at all; that is separate work in the iOS 8.4.0 plan.

## 1. Encrypting to a GnuPG X448 subkey

What the user saw on 4.7.1: encrypting to their key alone, or to them and someone else, failed; encrypting
without their key worked. Desktop shows the same: "Encryption failed: exception encrypting session info:
exception constructing public key".

Cause: GnuPG stores the X448 public value of an ECDH (algorithm 18, OID 1.3.101.111) key as the bare 56-octet
u-coordinate (gnupg common/kem.c: X448 point length 56, no prefix). Bouncy Castle 1.85's BcPGPKeyConverter only
accepts the 0x40-prefixed 57-octet form for legacy X448 and throws "Invalid X448 public key", which BC wraps as
"exception constructing public key". Signing with the Ed448 primary works because BC accepts the Ed448 point with
or without the prefix.

Work: GnuPgX448 (crypto/GnuPgX448.kt) does the X448 ECDH, the RFC 6637 KDF and the AES key wrap itself for a key
in GnuPG's bare form, and writes a v3 PKESK the way GnuPG does: the ephemeral value bare, 56 octets, MPI bit
count 448 (GnuPG has no prefix handling for X448 and would reject a prefixed one). The KDF takes the leftmost 20
octets of a v5 fingerprint, as GnuPG and BC both do. A 0x40-prefixed X448 key still goes through BC. Used at both
encrypt sites in PGPCryptoService and in SecretKeyCheck.

## 2. Decrypting with a GnuPG X448 subkey

Same mismatch from the other side, found by reading BC and GnuPG: BC's decryptor requires a 57-octet prefixed
ephemeral value, while GnuPG writes it bare, and BC reverses the X448 secret scalar (as for Curve25519) while
GnuPG stores it in native order (scalar_reverse 0 for X448 in kem.c).

Work: GnuPgX448.DecryptorFactory wraps BcPublicKeyDataDecryptorFactory. For ECDH on Curve448 it reads the
ephemeral value in either form, and picks the scalar order that gives back the key's own public value, so keys
from GnuPG and from BC-based tools both open. Everything else goes to BC unchanged. Used in PGPCryptoService's
PKESK resolution and in SecretKeyCheck.

To check: whether BC reads GnuPG's v5 secret key packets for these keys (LibrePGPV5Interop.toBcFormat only
normalizes the algorithm-8 composite subkey today). The gpg vectors below answer it.

## 3. Verifying signatures from a v5 key

Desktop did not verify a signature from the reported key; no v5 document signature verified anywhere in PGPony.

Cause, confirmed against GnuPG vectors: for a v5 signature over a document (type 0x00 or 0x01), GnuPG hashes an
extra block between the hashed subpackets and the 0x05 0xFF trailer (gnupg g10/sign.c, hash_sigversion_to_magic):
the literal data packet's format octet, its file name with a one-octet length and its four-octet date. A detached
signature hashes six zero octets in their place; a cleartext signature hashes 't' and five zero octets
(clearsign_file). Bouncy Castle 1.85 leaves the block out. Key signatures have no such block and verify fine,
which is why the key imports.

Work: LibrePgpV5Sig. VerifyService's cleartext, detached and streamed detached checks go through it, and
ContentWalker feeds a v5 verifier next to the one-pass signature when the signer key is v5, finishing with the
literal data fields it read. Other signatures still go to Bouncy Castle.

## 4. Signing with a v5 key

Bouncy Castle 1.85 writes v5 signatures with a 4-octet trailer length (v5 needs 8) and without the document
block, so GnuPG reported every signature PGPony made with a v5 key as BAD, and BC could not verify its own. BC
also refuses to make a v4 signature with a v5 key. The reporter's "signing works" on 4.7.1 was a signature nobody
else could verify. Decided Oct 28: fix it in 4.7.3.

Work: PonySigGen replaces PGPSignatureGenerator at every signing site (messages, files, cleartext, detached,
one-pass, card signing, certifications, user ID and expiry changes, bindings, revocations). For a v4 or v6 key it
is BC's generator unchanged; for a v5 key it writes the v5 signature itself: the 8-octet trailer, the document
block (the literal fields from setLiteralData, 't' and zeros after setCleartext, six zeros for detached), keys
hashed by their own version (0x99 or 0x9A, as GnuPG does), and a version 3 one-pass packet. The three inline
signing sites in PGPCryptoService hand it the literal fields they write; SigningService and CardSigningService
mark cleartext. SecretKeyCheck signs and verifies the raw challenge for a v5 key; KeyToCardService's test
signature verifies through LibrePgpV5Sig.

Checked against GnuPG 2.4.4 with the test key: detached, text detached, inline (one-pass) and cleartext
signatures from PonySigGen are good signatures in gpg, and a user ID self-certification it made imports into
gpg as a good self-signature.

## Tests

- GnuPgX448InteropTest, against gpg vectors in test resources gnupg448/ (a throwaway v5 Ed448 + X448 key with a
  neutral user ID, no passphrase): decrypt a gpg message, decrypt and verify a gpg signed and encrypted message,
  verify gpg detached (buffered and streamed) and cleartext signatures, reject a tampered one, and prove the v5
  secret against its public key. PGPony-encrypted output was opened by gpg 2.4.4 against the same key.
- GnuPgX448Test: round trips on synthetic GnuPG-style keys (v5 and v4, native and reversed scalar), a BC-written
  message to a prefixed key, the PKESK layout (key ID, algorithm, 448-bit ephemeral), the v5 KDF fingerprint, PKCS#5
  padding, wrong key, and BC alone failing on the bare form.
- GnuPG interop on the Mac, with a throwaway GNUPGHOME and a test key with neutral user IDs (never the reporter's
  key, which carries real names): gpg encrypts and signs to fixtures; PGPony decrypts and verifies them; PGPony
  encrypts and `gpg --decrypt` opens it; PGPony signs and `gpg --verify` accepts it.

## Release

RC1 was tagged on the wrong commit (the 4.7.2 release commit 454bf8e, not the RC1 commit aff8306); the gate built
4.7.2's content hash and nothing was published. The tag stays as it is, RC_HISTORY records it, and the RC1
changes ship as RC2 on aff8306. RC_BUILD_SIGN_DEPLOY step 1 now checks the tag's commit against HEAD.

versionCode 473, versionName 4.7.3, from RC2's code (checked on device, and by the reporter with the real key
against Kleopatra, Oct 29). Changelog 473.txt and RELEASE_NOTES_4.7.3.md. Same release path as 4.7.2: signed commit
and tag, reproducibility gate, GitHub release with four assets, pgpony.app, Play (notes in all 11 listing
languages), F-Droid from the tag. The release commit only adds docs and the changelog, so the release APK should
have RC2's content hash. Desktop 3.0.3 shipped Oct 29 with the same GnuPgX448 code.
