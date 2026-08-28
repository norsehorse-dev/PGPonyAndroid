# PGPony 4.4.0

The post-quantum signatures release. 4.4.0 adds the signature half of
RFC 9980 to match the encryption half PGPony has shipped since the 4.0
line, reworks how a signing key is chosen when an address carries more
than one, adds Tor stream isolation, and clears a batch of key-management
and interface reports from the candidate cycle.

4.4.0 carries versionCode 433 and installs in place over the 4.3.x line;
this is the final.

## Added

Composite ML-DSA signatures (RFC 9980). PGPony now generates, signs with,
verifies, imports, and labels composite ML-DSA-65+Ed25519 signing keys
(RFC 9980 signature ID 30, the MUST), the post-quantum counterpart to the
composite ML-KEM encryption keys already supported. Signatures are produced
and verified over both messages and certifications, and round-trip against
GnuPG 2.5.x in both directions. Requested on the core repo (PGPonyCore #1).

Choose the signing key per send. When a mail app hands PGPony an outgoing
message to sign or encrypt, the first key picked for that account was
remembered and never offered again, so a second key on the same address
was unreachable. PGPony now remembers the choice per address, offers a
"Sign with a different key" control on the passphrase prompt, and has an
"ask which key to sign with" setting for people who switch every send.
Reported by RandomNam3, tested against FairEmail with two keys on one
address (#51).

Tor stream isolation. The proxy section gains an optional SOCKS5 username
and password for Orbot and Custom, so distinct credential pairs land on
distinct Tor circuits. Every outbound path routes through the one shared
client, the connection fails closed when the proxy is unreachable rather
than falling back to a direct request, and the target hostname resolves at
the proxy, not on device. Off by default, so no existing setup changes on
update.

Offline switch. A setting that turns off every online key lookup, for
people who want the app to make no network requests at all. The signer
lookup on a decrypted message drops its online affordance while it is on.

A text-encrypt armor toggle, contact identities, and composite-key
passphrase protection carried through decrypt and export.

## Changed

The decrypted-message view names the key that actually decrypted, so a
passphraseless key that silently matches can no longer be mistaken for the
one shown in the picker.

The Decrypt tab icon fills with a solid open padlock when selected, like
every other tab, and the Keyring tab returns to its list from the Key
Detail, NFC, and Recently Deleted screens instead of stranding you there.
The doubled inset band above the tab bar is gone. All reported by
CertainBot (#45).

The message search box keeps its placeholder to a single line so the field
no longer looks oversized.

## Fixed

Key generation no longer produces a duplicate entry or freezes partway
(#48).

A password (symmetric) encrypted message showed a recipient count and a
"can decrypt" list that do not apply to passphrase encryption, and the same
"Password protected" state could bleed onto a following signed message. The
result now reads the true per-operation state: password messages show a
password note and no recipients, and a signed message is never mislabeled.
Reported by CertainBot (#53).

Decrypting a password message no longer shows the "no signature, origin
unverified" banner, which says nothing useful about a message sealed to a
passphrase rather than sent from a key. A password message that is also
signed still shows its verification result. From CertainBot (#53).

The recipient picker sheet scrolls its own list instead of dragging the
whole sheet down. Reported by CertainBot (#53).

The per-address signing key now reaches the signer across the provider's
separate process, so the chosen key is the one that actually signs (#51).

A provider hang on certain operations is resolved.

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
