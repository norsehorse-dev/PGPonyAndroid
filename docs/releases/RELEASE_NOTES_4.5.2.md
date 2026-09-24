# PGPony 4.5.2

A bug-fix release for the post-quantum key work from 4.4.0 and 4.5.0. The
composite ML-DSA keys looked done but three things did not actually work end to
end: signing an encrypted message, adding subkeys, and using these keys from
other mail apps. All three are fixed here.

4.5.2 carries versionCode 447 and installs in place over 4.5.1.

## Signing an encrypted message

Encrypt-and-sign with an ML-DSA-65 key produced a message with no signature in
it, so the recipient saw an unverified origin even though the sender had signed.
Signing on its own always worked, which is what made this easy to miss. The
combined encrypt-and-sign path now attaches the signature the same way the
sign-only path does, and decrypt verifies it, so a signed-and-encrypted message
from a modern key shows a verified signature.

## Subkeys on ML-DSA keys

Adding a subkey to an ML-DSA key failed before it started, on every subkey type,
because the key could not be loaded into the form the add-subkey code expected.
You can add subkeys to an ML-DSA key now: ML-KEM encryption subkeys, ML-DSA
signing subkeys, and classical Ed25519 or X25519 subkeys. Added subkeys show in
the key's Subkeys list with the right capability, and a passphrase re-protects
them along with the rest of the key.

## Other apps (the OpenPGP provider)

Mail apps that talk to PGPony through the OpenPGP API, such as FairEmail, K-9
Mail, and Thunderbird for Android, could not use a modern ML-DSA key at all: the
key would not export to the app, and signing and sign-and-encrypt failed. Those
paths went through a code path that cannot read these keys. Exporting the key,
encrypting to it, signing, and sign-and-encrypt now all work with an ML-DSA key
from an external mail app.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
0dd192d4a8768da2cd84df8b61a408f9e3a090252bdcf60b781f40b39235b019
```

Content hash (for rebuilders; excludes signature, see REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
346ecab9c7c05a0831b2c4e240767d3fa57c0f1827dcbfbde3c1fa831a705b0a
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release.
