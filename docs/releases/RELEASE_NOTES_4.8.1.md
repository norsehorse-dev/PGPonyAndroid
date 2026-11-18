# PGPony 4.8.1

A patch release: key edits on ML-DSA keys, signing with keys made by Proton, imports that no longer drop subkeys,
fixes for security keys, mail apps and expiry reminders, and a public key picker for apps that ask PGPony for keys,
which CarrierPony 4.0 uses. 4.8.1 carries versionCode 481 and installs in place over 4.8.0 and the 4.8.1 release
candidates. It went through two release candidates published as GitHub pre-releases, each with its own signed tag;
docs/RC_HISTORY.md lists them. The release adds one fix after RC2, pass entries on a card with an offline primary
below, so its APK is a new build and not an RC file.

## ML-DSA keys

Key edits work on ML-DSA-65 and ML-DSA-87 keys. Changing the expiry failed, with or without a passphrase, because
the edit went through Bouncy Castle, which can't load these keys. A subkey's expiry, Refresh self-signatures,
notations, revoking the key, revoking a User ID and making a User ID primary failed the same way. They all work on
the key's own packets now, and a protected key stays protected under its passphrase. Reported by email.

An ML-DSA key made in PGPony with an expiry date counts as expired after that date in PGPony's own checks. The date
was only in one of the key's signatures and the checks read another, so the key looked like it never expired. New
keys carry it in both, and Refresh self-signatures fixes an older key.

Changing a subkey's expiry on a v6 key found the right subkey only on v4 keys. It works on v6 Ed25519 keys and
ML-DSA keys too.

## Keys made by Proton

Keys made by Proton (OpenPGP.js) sign again after a User ID edit. These keys certify their User ID with a generic
certification, and PGPony only looked for a positive one, so adding a User ID, making one primary or editing notations
wrote a new certification without the key's flags and preferences. With no flags left, PGPony read an Ed25519
primary as certify-only and found no key to sign with. Edits keep the flags now, and a key with no flags signs with
its primary, as RFC 9580 allows, so a key that already lost them signs again. Reported by email.

## Imports and the keyring

Importing a key you already have no longer drops its subkeys. For ML-DSA keys, and v4 keys with an ML-KEM subkey,
importing a copy that lacked a subkey (an older export, or a copy from another device made before the subkey was
added) wrote that copy over the stored key. Restoring an older backup and pairing did the same. The import now merges
the copy into the stored key, and importing the full key again brings back a subkey that was lost. Reported in a Play
review and confirmed by a tester.

A key pair can't lose its subkeys any more (#119). A tester's Ed25519 key lost all its subkeys three times on 4.7.2
without any edit, leaving only the certify primary, so SSH through OkcAgent found no key. The cause isn't found yet,
so PGPony now keeps every subkey a key has bound whenever it saves the key, except through Remove subkey, and logs
where a save that would have dropped one came from.

A subkey's expiry date in Key Details comes from the same signature as its Expired label (#120). A subkey with more
than one binding signature could show Expired next to a date still to come.

## Security keys

Certifying a key with an ECDSA key on a YubiKey works (#117). Quick Action decrypts with a key pair whose keys are
only on a security key: Decrypt stayed greyed out with "No private keys available" when no key pair had its keys on
the phone.

A pass entry decrypts with a security key that holds only subkeys, with the primary kept offline (#128). It failed
with "pair this card's public key first", while the same message decrypted in the Decrypt tab, because the pass
entry screen looked the card's key up as a primary. It now finds it the way the Decrypt tab does.

## Apps that use PGPony

An app can ask PGPony for public keys without naming an address, and PGPony shows a picker with the keys in your
keyring. CarrierPony 4.0's "Pick from a key app" makes that request, and PGPony answered with no keys. Requests that
name an address, from mail apps and others, work as before.

Signing through the OpenPGP API (K-9 Mail and other apps) carries the Comment header set in Settings (#121). Only
encryption picked it up before.

## Decrypting and reminders

A PGP/MIME message decrypted from a file shows its decoded text, as pasting it does (#123). The preview showed the
raw MIME, with quoted-printable escapes and non-ASCII text as =XX codes. Save and Share keep the file as it decrypted.

Expiry reminders are only for your own keys (#125). A contact's public key with an expiry date got "Your PGP key
expires" reminders. Reminders already scheduled for other people's keys are cleared, and post nothing if one fires
first.

## Languages

The key picker's four new strings are in all 11 languages.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
94e63dde00c3e91f40bba57959402627e436d6f075d9acd573153a15b49dbd70
```

Content hash (for rebuilders; excludes signature, see docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
705bb688ee4ac5cdb66663d00a12330afeb225ec13d26052d5a6c0aecf9df62e
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release, along with the armored release key (NorseHorse-release-key.asc) and
PGPony-4.8.1-signing-keys.txt with the OpenPGP fingerprint and the APK signing certificate's SHA-256. Check the
fingerprint against pgpony.app, keys.openpgp.org or keys.pgpony.app rather than trusting the copy in the release
alone.
