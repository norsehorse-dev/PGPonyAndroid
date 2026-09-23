# PGPony 4.5.0

The post-quantum release. 4.5.0 makes ML-DSA and ML-KEM keys usable end to
end, adds real key management on keys you already have, hardens the app, and
clears a batch of tester reports from #36, #55, #58, and #62.

4.5.0 carries versionCode 444 and installs in place over 4.4.x.

## Post-quantum

You can now generate a post-quantum-only key (composite ML-DSA), not just a
classical key with a PQC subkey. Key generation can also produce a v4
ML-KEM-768+X25519 encryption key (algorithm 35) for interop with other
implementations, and you can add post-quantum subkeys to a key you already own
instead of starting over.

A composite ML-DSA key can now carry more than one User ID, and it works as an
encryption recipient through its ML-KEM subkey. When you encrypt to a mix of
post-quantum and classical recipients, PGPony warns you that the message drops
to classical security for everyone rather than doing it silently.

## Key management

Key creation is more granular, so you choose what goes on the key instead of
taking a fixed template. You can delete or revoke a subkey, and the delete
dialog for a key pair now offers "revoke instead", since a revocation
certificate cannot be made after the key is gone. Keys can be generated without
an email address. You can point the app at your own key server repositories and
use Web Key Directory, and a public key shared into PGPony can be used to
encrypt straight away, not only imported.

## Security

Settings has an offline-mode toggle that keeps the app from reaching the
network. Destructive actions (deleting a key, removing a subkey, clearing all
data) sit behind one switch that requires device authentication, on by default.
The cipher paths had a hardening pass.

## Smartcard

Decryption with a nistp521 secret key on a SmartPGP JavaCard now works. The
Cipher DO for the card was written with short-form TLV lengths, which a
133-byte P-521 point overflows, and the KDF used a fixed curve OID. Both are
fixed, and the other NIST curves are covered too. Confirmed on hardware by
wreps8Owt (#62).

## Fixed

Decrypting a file to an imported composite ML-KEM key failed on the file path
while the same message pasted as text worked. The streaming decrypt never
handed the imported composite key to the part that opens the ML-KEM subkey. It
does now, with a regression test built from the reporter's own key and file.
Reported by Umotas (#36).

A message encrypted to several recipients including your own composite ML-KEM
key failed to decrypt. That path is fixed.

Adding a second email to a key set the new address as primary once the key was
uploaded, even when it was not marked primary. A fresh key's first User ID is
only implicitly primary, so the newer self-signature won on the server. Adding
a non-primary User ID now pins the original as primary explicitly. Reported by
limbodiver.

A truncated or incomplete PGP message showed a raw range error instead of a
clear "incomplete message". A post-quantum-only key could not produce a QR
code, even a multipart one. A key's primary expiry could show a stale "Never"
next to a live subkey date. Several Google Play stability reports from the
September vitals review are addressed.

## Improved

The encrypt and decrypt key pickers show the email under the name, so two keys
with the same name are easy to tell apart. Encrypt and decrypt gained a subkey
selector when a key offers more than one target. Key algorithm and curve labels
are detected correctly, so ML-KEM-1024, the NIST and brainpool curves, and RSA
sizes read right. The key-generation publish prompt is clearer, with an offline
case and a pgpony.app opt-out, and there is an onboarding toggle to drop the
PGPony armor comment. The unlock-signing-key dialog opens the keyboard on its
own. The v5 LibrePGP post-quantum interop is deemphasized in the UI in favor of
the standard scheme. Importing or sharing a key tolerates extra surrounding
text.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
9842e68809d115bf15c7f1c9af67a0cdc941399c15ebc646175535fedbb3766e
```

Content hash (for rebuilders; excludes signature, see
REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
08f02c6be12da1e11f971ad64ec20400cb1cdf497a0114e69790068ba2f6600a
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached
to this release.
