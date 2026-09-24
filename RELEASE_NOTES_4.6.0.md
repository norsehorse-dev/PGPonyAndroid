# PGPony 4.6.0

SSH logins with your PGPony keys, one share dialog that works out what you shared, a round of key-server
fixes, and security hardening ahead of an external audit.

4.6.0 carries versionCode 460 and installs in place over 4.5.3.

## SSH with your PGPony keys (#68)

PGPony now answers OpenKeychain's SSH authentication API, so an ssh-agent bridge can log you in with a key
held in PGPony. The private key never leaves PGPony or your security key.

- Key generation can add an authentication subkey (Ed25519, or RSA to match an RSA key), and you can add one
  to a key you already have. Key Detail has Copy SSH Public Key for a server's authorized_keys.
- Ed25519, RSA (rsa-sha2-256 and rsa-sha2-512) and ECDSA P-256/384/521 authentication subkeys all work,
  including a classical one on a composite ML-DSA key. Smart cards sign through the card's authentication slot.
- Only a dedicated authentication subkey is used. A subkey that can also sign or certify is not.
- For Termux, PGPony links to a maintained OkcAgent fork that works with the stock okc-agents package. Settings
  and Key Detail both have "Set Up SSH in Termux" with the steps.

## Sharing to PGPony (#58)

Sharing text to PGPony opens one dialog, and its options depend on what the text holds: Import or Import and
encrypt for a key, Decrypt for an encrypted message, Verify for a signed-only message, and Encrypt, Sign or
Encrypt and sign for plain text. When a PGP block sits inside other text, only the block is decrypted.

## Keys

- A key's note shows as a label on its keyring row and under the Key Detail header.
- Import a public key from a link. The key shows in the import preview with its fingerprint and the full
  source link before anything is added.
- ML-DSA-87 with ML-KEM-1024 is a new post-quantum key type, and ML-KEM-768 with brainpoolP256r1 (the LibrePGP
  form GnuPG 2.5 uses) is in the Advanced group. Post-quantum options now say "Limited app support".
- RSA subkeys can be added to composite ML-DSA keys. GnuPG and Thunderbird cannot read v6 certificates yet, so
  for them a separate v4 key is still the way.
- ML-KEM subkeys on a classical key now show in Key Detail, and editing such a key (adding a subkey, changing
  a User ID, expiry or passphrase, revoking) no longer drops them.
- A keyring row whose address is shared by other keys shows how many, and lists them.
- When a post-quantum key signs a message encrypted to a classical-only recipient, PGPony asks whether to
  include the signature, since only PGPony can read it there.

## Key servers

- Upload stays on the menu after the first upload, and shows when each server last got the key and whether
  each address is confirmed.
- A key edited since it was published is marked as out of date, with an Update action.
- Refreshing from a key server merges what the server has into your copy instead of replacing it, and your
  own key pairs keep your local User IDs and primary choice.
- A lookup answer that is not a key (an error page, say) is now "no key found", not an import offer.
- Offline mode hides the key-server menu items.

## Key Detail and Keyring

- The avatar shortcut on a key pair sets that key for decrypting, and on a public key it adds the key to your
  current recipients. Each has its own one-time hint, and Reset tips brings both back (#63).
- The Default Key picker is back to the right of its title with the star.
- Deleting a public key says it moves to Recently Deleted for 14 days, as it already did (#58).
- The import methods wrap onto a second line instead of squeezing their labels.

## Other apps (the OpenPGP provider)

- Settings > Connected apps shows what each app can do, OpenPGP or SSH, and removes each separately. An app
  allowed for one gets nothing from the other, and an SSH app can use only the key you picked for it. Apps you
  had already connected keep OpenPGP access only, so an app that also uses SSH asks once more.
- Composite ML-DSA signatures verify through the share Quick Action.

## Security hardening

This release includes hardening from an internal security review done ahead of an external audit: stricter
checks on keys and key-server answers, tighter limits on untrusted input (message size and nesting, file
names, archives), and tighter handling of other apps' access.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
<APK_SHA256>
```

Content hash (for rebuilders; excludes signature, see REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
<CONTENT_HASH>
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release.
