# PGPony 4.4.1

A fixes-only release addressing four reports against 4.4.0's post-quantum
support, raised on #36 (Umotas) and #55 (elnardosa).

4.4.1 carries versionCode 434 and installs in place over 4.4.0.

## Fixed

Encrypted files were much larger than they should be. A v6 (post-quantum)
encrypted file used a 64-byte AEAD chunk, so the OCB integrity layer added
a 16-byte authentication tag for every 64 bytes of data, about a 25% size
increase on top of the file. The chunk size is now 64 KiB, which drops that
overhead to a fraction of a percent, so an encrypted file lands close to its
compressed size. The file was already being compressed; the tags were the
whole difference. Existing files still decrypt unchanged. Reported with
packet dumps by Umotas (#36).

Encrypting to a composite ML-DSA key failed. A v6 ML-DSA signing key carries
an ML-KEM encryption subkey, so it can receive encrypted messages, but
selecting it as the only recipient failed with a misleading "no recipients"
error. The key could not be read through the normal path because the library
does not parse its composite primary, so it was dropped before its encryption
subkey was reached. That subkey is now lifted out and used, so a composite
ML-DSA key works as an encryption recipient, and the message shown when a key
genuinely has no encryption subkey is clearer. Reported by Umotas (#36).

ML-KEM-1024 keys were shown as ML-KEM-768. In LibrePGP the two share one
algorithm number and differ only by curve, so the label defaulted to 768. The
key material was correct all along; only the label was wrong. Key detection now
reads the curve and reports the right level. Reported by elnardosa (#55).

An imported RSA 8192 key was shown as RSA 4096. Key-size detection keyed off the
algorithm number, which does not carry the modulus size, and capped the label at
4096. It now reads the actual modulus size, so RSA 3072, 4096, and 8192 are each
labeled correctly. Reported by elnardosa (#55).

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
<FILL_WHOLE_FILE_SHA256>
```

Content hash (for rebuilders; excludes signature, see
REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
<FILL_CONTENT_HASH>
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is
attached to this release.
