# PGPony 4.7.3

A patch for keys made with Curve 448 in GnuPG or Kleopatra. 4.7.3 carries versionCode 473 and installs in place
over 4.7.2. It went through a release candidate published as a GitHub pre-release with its own signed tag;
docs/RC_HISTORY.md lists it. The tag v4.7.3-rc1 went onto the 4.7.2 release commit by mistake, the gate caught it,
and nothing was built or published from it, so RC2 is the only build. The release APK is the RC2 file itself, with
the same whole-file SHA-256.

## Ed448 keys from GnuPG and Kleopatra

GnuPG 2.3 and later make Curve 448 keys as LibrePGP v5 keys, with an Ed448 primary key for signing and an X448
subkey for encryption. PGPony imported them but could not exchange messages or signatures with anyone else using
one. Reported by email, and checked on RC2 with the reporter's own key against Kleopatra in both directions.

Encrypting to such a key works. It used to fail with "exception constructing public key", because GnuPG stores the
X448 public value without the prefix byte Bouncy Castle expects. Messages encrypted to the X448 subkey decrypt.
GnuPG writes the sender's ephemeral X448 value without that prefix and keeps the secret scalar in its own byte
order, and PGPony now reads both.

## Signatures from v5 keys

Signatures from a v5 key verify, whether inline, detached or cleartext. For a v5 signature over a document, GnuPG
hashes a few extra octets: the literal data's format, file name and date for an inline signature, and a fixed block
for detached and cleartext signatures. PGPony left them out, so no v5 document signature verified before.

Signatures PGPony makes with a v5 key verify in GnuPG. Bouncy Castle wrote them with a 4-octet trailer length where
v5 needs 8, and without the extra document octets, so gpg reported every one as BAD and PGPony could not verify its
own either. This covers signed messages and files, cleartext signing, signed and encrypted messages, and the
self-signatures written when you add a user ID, change the expiry or revoke.

Signing and verifying with v4 and v6 keys goes through the same Bouncy Castle code as in 4.7.2. PGPony Desktop
3.0.3 carries the same changes.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
82617be87e493fbb165864483c7834cd13a854d023b790fa124806cf034d3b84
```

Content hash (for rebuilders; excludes signature, see docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
4637e545efcf06a240cafb0c72872f1e3b2e9f0d527f340384468928345bd890
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release, along with the armored release key (NorseHorse-release-key.asc) and
PGPony-4.7.3-signing-keys.txt with the OpenPGP fingerprint and the APK signing certificate's SHA-256. Check the
fingerprint against pgpony.app, keys.openpgp.org or keys.pgpony.app rather than trusting the copy in the release
alone.
