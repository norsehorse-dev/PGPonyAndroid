# PGPony 4.5.3

A bug-fix release for a device-specific key-storage failure. On some phones,
PGPony would suddenly report that it could not export or use a key it clearly
still listed, and mail apps talking to it through the OpenPGP provider failed
the same way. This release moves key storage onto a more resilient foundation
and, where the damage has already happened, says so plainly instead of showing
a misleading error.

4.5.3 carries versionCode 448 and installs in place over 4.5.2.

## Key storage that stops reading on some devices

A few users hit a state where PGPony still showed their keys in the key list
and the signing picker, but every operation that needed the actual key material
failed: exporting the key, encrypting to yourself, signing, and the same
operations from FairEmail, K-9 Mail, or Thunderbird through the OpenPGP
provider. It affected every key at once regardless of type, and on one report a
freshly generated key worked for a couple of days and then went unusable. It
could not be reproduced on most hardware.

The cause was the storage layer. Key metadata lives in a plain database, but the
key material was kept in an encrypted store built on a deprecated Android
security library. That library wraps its encryption key in the device's hardware
keystore, keeps a separate keyset that can be regenerated, and was opened from
two app processes at once. On certain builds, some realme and ColorOS devices
and Android 16 among the reports, the keystore key or that keyset gets
invalidated. When it does, the metadata survives but the key bytes can no longer
be decrypted, so the key looks present while nothing that needs it works.

Key material now lives in app-private files. Each key's bytes are encrypted with
a per-key data key, and that data key is wrapped two ways: once under a stable
hardware-keystore key, and, when the key has a passphrase, once under a key
derived from that passphrase. Reads use the hardware wrap. If the OS invalidates
the hardware key, a key that has a passphrase is recovered by unlocking it once,
which re-establishes a working hardware wrap, so it survives the wipe instead of
being lost. This also removes the regenerable-keyset and two-process problems
that caused most reports. Existing keys migrate over automatically the first time
they are read, and the old store is left in place untouched.

A passphrase-less key has no second factor, so if the hardware key is wiped it
cannot be recovered and PGPony will tell you to re-import it. Setting a passphrase
on a key is what lets it survive this class of failure, so it's worth doing for
any key you rely on.

## Signing files with an ML-DSA key

An ML-DSA key could sign text but not files. A detached file signature failed with "No signing-capable key
found in key ring," and signing a file while encrypting it produced no error but left the file unsigned, so it
decrypted as merely encrypted. Text signing with the same key worked. The text paths were taught about these
composite keys in 4.5.2 and the file paths were not, so file signing still went through the classical signer,
which cannot see an ML-DSA signing key. Both file paths now sign through the composite signer, so a detached file
signature and a signed-and-encrypted file from an ML-DSA key both work and verify.

## Verifying ML-DSA signatures on files and in mail apps

The companion to the fix above. An ML-DSA (composite) signature verified fine on
a text message opened in PGPony, but the same signature on a decrypted file, or
on any message a mail app decrypted through the OpenPGP provider, showed as
unsigned. The streaming decrypt path that files and the provider use only ran the
classical BouncyCastle verifier, which cannot parse a composite signature packet,
so it never saw the signature at all. The in-app text path had its own composite
handling and the streaming path did not.

The streaming path now detects a composite inline signature and verifies it
against the stored composite public key, the same way text decryption already
did. A signed-and-encrypted file from an ML-DSA key, and a message a mail app
decrypts through PGPony, now report the signature and signer instead of coming up
unsigned. Classical messages take the unchanged streaming path exactly as before.

Note this is about PGPony reading composite signatures. A third-party tool that
does not implement the composite ML-DSA algorithms still cannot verify them, and
that is a limitation of that tool, not of the message.

## Signatures not verified in the Quick Action

A signed, encrypted message opened through the share-target Quick Action came up
unverified, while the same message verified fine when opened in the decrypt
screen or as a file. The share-decrypt and file paths handed the decryptor the
stored public keys to check the signature against; the Quick Action passed none,
so it decrypted the message but had nothing to verify the signature with and
reported it unsigned. All three Quick Action decrypt paths now pass the stored
public keys, so a signed message verifies there the same as everywhere else.

This was separate from the display issue in some mail apps, where an encrypted
message that is signed inside shows no signature indicator. That reproduces with
other OpenPGP providers too, so it is the mail app's own handling of
inline-signed-and-encrypted mail, not PGPony withholding the signature.

## Comment header ignored the setting in mail apps

The customizable "Comment:" line in armored
output followed the setting only for in-app encryption. Anything encrypted
through the OpenPGP provider (FairEmail, K-9, Thunderbird) always carried the
default comment, whether the setting was turned off or set to custom text. The
provider runs in a separate process that skips the startup step which loads that
setting, so its copy stayed on the default. The provider now reads the setting
before it builds armored output, so the comment matches what you chose there too.

The blank line between the armor headers and the encoded body is not the comment
and is not removable; it is required by the OpenPGP armor format.

## Signature banner now shows whether the signer key is confirmed

When PGPony verified a signature it showed a plain
green "Verified, Signed by ..." no matter whether the signer's key was one you
had verified or an unconfirmed key sitting in your keyring. Since anyone can
publish a key for any address, a valid signature from an unconfirmed key is a
weaker statement than one from a key you have verified, and the banner did not
say which it was. The status was already sent to mail apps (FairEmail shows
"valid but not confirmed"), it just was not shown inside PGPony.

The decrypt and file verification banner now reflects the signer key's trust
level: a verified or ultimate key keeps the green "Verified", while an unknown or
unverified signer key shows an amber "Signed, key not verified" instead. The
signature is still cryptographically valid in both cases; the difference is
whether you have confirmed the key belongs to who it claims.

## Expired keys are blocked from signing and encrypting

An expired key could still be used to sign or to
encrypt with no warning; only decrypting or verifying afterward flagged it. PGPony
now refuses to sign with, or encrypt to, an expired key. The Encrypt screen shows
which key has expired, and the operation stops with a message pointing to the new
setting rather than silently producing output that the other side will reject. This applies both in the app and to sends made through the OpenPGP provider from a mail app, so an expired key is refused there too.

For the occasional deliberate case, Settings has a new "Allow expired keys"
toggle, off by default. With it on, expired keys work as before, and the screen
still shows the expiry so it is never silent.

The check is on the key's overall (primary) expiry. A finer per-subkey expiry
warning is noted for later.

## Verify this build

Whole-file SHA-256 (is this download the published file): the value that matches the published APK is shown on this version's GitHub release page.

Content hash (for rebuilders; excludes signature, see REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
3bccc3ccc10e28615cd9de9343ee176b26d9f5da2c9c023b3062d7c33e381a6b
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release.
