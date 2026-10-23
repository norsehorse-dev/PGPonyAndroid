# PGPony 4.7.1

Two fixes on top of 4.7.0. 4.7.1 carries versionCode 471 and installs in place over 4.7.0.

## Opening the full text of a long message

The inline result of a decrypt shows the first 4,000 characters, and Open full text shows the rest. That view laid
out the whole message at once, which could take long enough on a slower phone for Android to report PGPony as not
responding. It now loads the text in blocks and lays out only the ones on screen. You can select text within a
block; Copy still copies the complete message.

## Signing with ECDSA keys on a security key (#102)

A security key holding ECDSA keys (secp256k1, the NIST curves or brainpool) could not sign: the card returns its
signature as two raw numbers, PGPony passed them on unchanged, and the OpenPGP library expects them in a different
encoding, so signing failed with "exception decoding signature" after the PIN and the tap. PGPony now converts the
signature, and hashes with SHA-256 on 256-bit curves, SHA-384 on 384-bit curves and SHA-512 on P-521 and
brainpoolP512r1. This covers every card signature: messages, files, mail apps, certifications and expiry changes.

The labels were wrong for those keys too. Key Details named every ECDH subkey X25519, and a card on one of these
curves was stored as Ed25519 + Cv25519. Both now show the real curve. An entry stored with the wrong label is
corrected the next time you scan the card.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
WHOLE_FILE_SHA256
```

Content hash (for rebuilders; excludes signature, see docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
CONTENT_HASH
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release, along with the armored release key (NorseHorse-release-key.asc) and
PGPony-4.7.1-signing-keys.txt with the OpenPGP fingerprint and the APK signing certificate's SHA-256. Check the
fingerprint against pgpony.app, keys.openpgp.org or keys.pgpony.app rather than trusting the copy in the release
alone.
