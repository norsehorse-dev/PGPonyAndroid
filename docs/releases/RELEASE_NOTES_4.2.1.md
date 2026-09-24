# PGPony 4.2.1

A point release fixing one bug in the multiple-identities feature that
shipped in 4.2.0.

## Fixed

Encrypting to a key by one of its additional identities now works. 4.2.0
added multiple identities per key, but a mail client resolves a recipient
address through the OpenPGP provider, and that lookup matched only a key's
primary identity. A message addressed to a secondary identity found no key,
so the client would not offer to encrypt it. The provider now matches any
identity on the key, across all three places it resolves an address:
offering encryption, performing it, and reporting Autocrypt status.

Reported by bluemle with v6 ML-KEM-1024 keys. In-app encryption was not
affected, since the recipient picker selects a key directly rather than by
typing an address.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
a6db202812b5fc30ea78cad29ff5eedda81bc4cebc7edb1dbc1979852aa6764f
```

Content hash (for rebuilders; excludes signature, see
REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
afb0fd16cb1beef6c98a059d26013e98d060695c40d6fcb25126cf2495f1d390
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is
attached to this release.
