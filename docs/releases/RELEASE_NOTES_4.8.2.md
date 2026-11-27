# PGPony 4.8.2

A patch release: X25519 key agreement through the OpenPGP provider, which StegPony uses to reveal with a key kept
in PGPony, and four fixes: Ed25519 subkeys on protected ML-DSA keys, text selection in decrypted text (#130),
LibrePGP keys without the classical X25519 subkey, and certifying one of your own keys with another (#126). 4.8.2
carries versionCode 482 and installs in place over 4.8.1. No release candidate came before it; it was tested on a
device before the tag.

## Key agreement for StegPony

Apps can ask PGPony for raw X25519 key agreement with one of your Curve25519 encryption subkeys, on the phone or on
a security key. StegPony uses it to reveal a message with a key you keep in PGPony, instead of a key it holds
itself. Every request asks first: PGPony names the app, the key and the number of agreements, then asks for the
passphrase when it isn't remembered, or for the card PIN and a tap. Only apps you allowed under Connected apps can
ask, and only X25519 and Curve25519 ECDH encryption subkeys take part. The actions are documented in
docs/PROVIDER_PGPONY_ACTIONS.md.

## ML-DSA keys

An Ed25519 subkey added to a passphrase-protected ML-DSA key keeps its secret. Saving the subkey protected the wrong
key, so its secret was lost and the next edit (Add User ID, Add subkey, Change passphrase) failed. Reported by
email. A key that already lost it can be edited again with its passphrase, and the broken subkey removed.

## Decrypting

Long-pressing a word in decrypted text selects it, and the selection stays when you lift your finger (#130). The
lift counted as a tap outside the text, which closed the keyboard and cleared the selection with it.

## Generating keys

The LibrePGP ML-KEM options have the "Include default encryption subkey" switch. Turned off, the key gets only the
Kyber subkey, which already combines ML-KEM with X25519, as GnuPG's own keys do, so GnuPG and Kleopatra encrypt to
it and not to a classical X25519 subkey. It stays on by default. Requested by email.

## Certifying

You can certify one of your own keys with another, a key pair or a key on a security key (#126). The certification
stays on the key through later edits. Mark as Verified isn't offered for your own keys, which are already trusted.
ML-DSA keys still can't be certified.

## Languages

The two new confirmation dialogs are in all 11 languages.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
a1bba2d65f51e41a11b79f1f48e4bdb84e5678fbf5ce70f82ea26980115a502e
```

Content hash (for rebuilders; excludes signature, see docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
4c56a2fafdadb5f2193b3c0bf459002df8f6e711571846954c9cdc194d942510
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release, along with the armored release key (NorseHorse-release-key.asc) and
PGPony-4.8.2-signing-keys.txt with the OpenPGP fingerprint and the APK signing certificate's SHA-256. Check the
fingerprint against pgpony.app, keys.openpgp.org or keys.pgpony.app rather than trusting the copy in the release
alone.
