# PGPony 4.6.1

Fixes for the share menu and for the passphrase cache in mail apps, and memory tagging on phones that support it. 4.6.1 carries versionCode 461 and installs in place over 4.6.0.

## Post-quantum recipients in the share menu (#67)

Encrypting a shared file or text to a composite ML-DSA key, or to a v4 key with an ML-KEM subkey, did not work
from the share menu. With that key as the only recipient it failed with "No recipient keys in your keyring",
even though the same key worked from the Encrypt screen. With other recipients selected as well, it was worse:
the key was left out without a warning and the file was encrypted to everyone else, so that person could not
open it.

The share menu loaded recipients with a loader that cannot read these keys, while the Encrypt screen uses one
that reaches their ML-KEM encryption subkey. The share menu now loads recipients the same way, and if any
selected recipient still cannot be used it stops and names the key instead of encrypting without it.

If you encrypted a file from the share menu to several people, one of them with an ML-DSA key or a v4
key with an ML-KEM subkey, that person may not be able to open it. Encrypt it again with 4.6.1.

## Importing a private key from the share menu (#67)

Sharing a private key file or text to PGPony only offered to encrypt or sign it as text; only public keys were
recognized as keys. A private key block now gets Import key, which opens it in the usual import preview, where
the key pair and its fingerprint are shown before anything is added.

## Mail apps follow the passphrase cache duration (#15)

Settings lets you keep a passphrase unlocked for 1 minute to 1 hour, until you clear it, or until the phone
locks. A passphrase entered while decrypting in a mail app stayed for 5 minutes whatever was chosen. The part of
PGPony that answers mail apps runs in its own background process, and that process read the setting once and
kept the old value. It now reads the current setting every time, so mail apps, security key PINs and the app
itself all follow the same duration.

## Memory tagging (#70)

PGPony now asks for Arm Memory Tagging Extension (MTE) in asynchronous mode. Where MTE is available (GrapheneOS
on supported Pixels, or Pixel 8 and later with MTE turned on in developer options), the system tags the app's
native memory and stops the app on a
use-after-free or out-of-bounds access instead of letting it run on corrupted memory. Other phones ignore the
setting. Origin: Sami32 (#70).

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
681d13767d4ece6a79a5f2da095c2a3a1f5495ea0d8feb91737c6d89693ecbda
```

Content hash (for rebuilders; excludes signature, see docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
75fcea38ca8435f9348c1a1305cb023de3408f3f897fac9c1bb3423b0c5cd716
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release.
