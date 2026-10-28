# PGPony 4.7.2

Fixes for typing on Encrypt and Decrypt, passphrase entry, pasted messages and hardware key decryption. 4.7.2
carries versionCode 472 and installs in place over 4.7.1. It went through release candidates published as GitHub
pre-releases, each with its own signed tag; docs/RC_HISTORY.md lists them. RC6 was tagged but did not build, so it
has no download.

## The keyboard on Encrypt and Decrypt

A tap outside a text field on Encrypt, Decrypt or the recipient picker closes the keyboard. Scrolling and moving
between fields keep it open. Both screens also scroll while the keyboard is open, so the options and the Encrypt
or Decrypt button under it can be reached without closing it.

## Passphrases

The passphrase prompts on Encrypt and Decrypt show the key's email under its name, so keys with the same name can
be told apart. The prompts and the passphrase fields on Decrypt have a show or hide button, and open masked.

The passphrase field on Decrypt is used for one attempt and emptied after it, when a new message is pasted, and
when the prompt is closed. It used to keep the last passphrase behind the dots. A pasted passphrase was added after
it and read as wrong, and the leftover passphrase kept a key usable after the passphrase cache time set in Settings
had run out.

## Text pasted around a message

Decrypt reads only the PGP MESSAGE block. Text pasted with it, such as an email signature below the message that
starts with a line of dashes, made the message fail as malformed.

## Hardware keys (#108)

When a message is encrypted to more than one subkey of your key, PGPony decrypts with the one in the card's
encryption slot. It used to take the first subkey it recognised, so a message that listed another subkey first
failed with "encrypted to a different key" although the card could open it. gpg writes messages like this for a
key whose authentication subkeys carry the ADSK flag.

On a card with Curve25519 keys, a message for a key the card doesn't hold now says it was encrypted to a different
key. It used to fail with "checksum failed". A message that hides its recipient (gpg -R) opens on a card when your
key has more than one encryption subkey; before, PGPony could stop after the first subkey that didn't fit. Opened as
a file, such a message now offers your hardware key once none of your software keys opens it, as a pasted one
already did.

Decrypting with the card's authentication slot, for a message whose only matching subkey sits in that slot, is
planned for 4.8.0.

## A crash in the key lists

The recipient list and the Sign as list show each key once. A key that appeared twice could crash PGPony while the
list scrolled, reported through Google Play.

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
PGPony-4.7.2-signing-keys.txt with the OpenPGP fingerprint and the APK signing certificate's SHA-256. Check the
fingerprint against pgpony.app, keys.openpgp.org or keys.pgpony.app rather than trusting the copy in the release
alone.
