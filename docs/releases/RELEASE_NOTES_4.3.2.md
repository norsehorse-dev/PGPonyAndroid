# PGPony 4.3.2

## Passphrase encryption now opens in GnuPG on Linux by default

Password-protected files and messages are now encrypted with a key-derivation function (iterated-salted SHA-256, S2K type 3) that every version of GnuPG can read. Earlier builds defaulted to Argon2id, which needs GnuPG 2.4 or newer built against a recent libgcrypt. On Linux machines without that, gpg reported "unknown S2K mode 4" and could not open the file even though nothing was wrong with it. Thanks to darkvegas for the report and the exact gpg output.

Argon2id is still available as a Settings toggle, "Stronger passphrase protection". It is off by default; turn it on if your recipients are all on GnuPG 2.4 or newer and you want the memory-hard key derivation. Files you already encrypted with Argon2 still decrypt normally.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
ffe915922a64dddd000ba6e5373fb0bed07a6acb19cca2bc16527c3618f9d2d8
```

Content hash (for rebuilders; excludes signature, see
REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
75eb5635082757b54a31e2a5c6b5e7b6da0e11d505390fac9269d4a2795237b2
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is
attached to this release.
