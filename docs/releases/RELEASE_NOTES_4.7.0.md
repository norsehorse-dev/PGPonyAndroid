# PGPony 4.7.0

Moving existing keys onto a security key, certifying other people's keys, an app PIN with a duress PIN, and a long
list of changes from tester reports. 4.7.0 carries versionCode 470 and installs in place over 4.6.4.

## Move a key onto a security key (#71)

Key Details > Move to a security key does what gpg's keytocard does. Each slot (Signature, Decryption,
Authentication) gets one key that fits it, the newest subkey for that use by default, or is left as it is.
PGPony offers to save a backup first, checks the user PIN before writing anything, then uses each slot once
(a signature, a test decryption, an authentication) and reads the card's fingerprints back. Only after every
check passes does anything on the phone change. By default the moved keys are removed from the phone and kept as
pointers to the card, as gpg does.

It works over NFC and USB with v4 RSA 2048, 3072 and 4096, Ed25519 and Cv25519 keys. v6 keys and NIST or
brainpool curves cannot be moved yet; the sheet lists each key that cannot move and why.

You can also move only the subkeys and keep the primary on the phone. Signing and decrypting then use the card,
and the edits that need the primary (User IDs, expiry, certifying other keys, Refresh self-signatures) keep
working with the key's passphrase.

## Security keys

- Thunderbird and other mail apps can decrypt and sign with a USB security key, not only over NFC (#36).
- A key generated on a card now shows as your own key: avatar, an ON CARD pill, "Key pair on a security key",
  and a line in Key Details saying the primary key sits in the Signature slot (#43).
- A card scanned before its public key was imported now pairs when you import the key, also when the
  Signature slot holds a subkey. Until then Key Details says what is missing (#71).
- A key that does not open OpenPGP over NFC (the Nitrokey 3 among them) says so and points to USB, instead of
  failing with a bare error (#43).
- The card scan screen stopped answering after Change PIN and back. Fixed (#79).

## Certify other people's keys (#79)

Key Details of a public key has Certify…: pick the User IDs, your certifying key (on the phone or on a security
key), the level (no claim, persona, casual or positive), an optional expiry, and Local only. Certify stays off
until you confirm you compared the full fingerprint. Exportable certifications travel with the key when you share
it. Local-only ones never leave the phone: no share, export, QR code, upload, backup or pairing carries them.

Each User ID lists who certified it, with the certifier's short fingerprint, and you can revoke your own. Long
lists show three, then Show all (#85). A trust signature (gpg's tsign) shows its amount and depth (#79). A
certification from a key you do not hold has Look up, which finds the certifier's key on your key servers and
checks the certification after import (#88).

## Trust levels (#75)

New shields for each level, and a new Don't use level. PGPony asks before encrypting to or signing with a Don't
use key, never picks one for a mail app, and turns the verify banner red for a signature from one. Key pairs you
generate in PGPony now start at Ultimate; imported keys keep Unknown.

## Expiry and self-signatures (#86)

- Changing the primary key's expiry set the same date on every subkey, expired ones included, which brought
  them back. Now it changes the User IDs only, with an option to also set it on subkeys that are still valid,
  and each subkey has its own Edit expiration.
- Before anything is signed, a confirmation shows the current and new date and what gets re-signed, then asks
  for your screen lock when Protect destructive actions is on.
- Expiry changes dropped part of the old self-signature: User IDs lost their feature flags, AEAD and key server
  preferences, and subkey bindings kept only their key flags. The new self-signature now carries everything
  forward.
- Refresh self-signatures re-signs every User ID and subkey binding with SHA-256, keeping each expiry. It also
  brings back subkeys that were dropped for a SHA-1 binding.

## Signing subkeys (#82, #83)

- Signing could pick an expired subkey. PGPony now signs only with a subkey that is valid now (bound, cross
  certified, not revoked, not expired), newest first, then the primary.
- Add Subkey has written signing subkeys without a back-signature since 4.2.0, so gpg warned about them and
  PGPony's own check did not accept them. New subkeys get one. For an existing one, change its expiry and it is
  bound again with a back-signature; until then PGPony signs with the primary when the primary can sign.
- Use for signing: on a key pair with two or more valid signing subkeys, Key Details lets you pick one or leave
  it on Automatic, which names the key it picks.

Coming from OpenKeychain: PGPony signs with the newest valid signing subkey, where OpenKeychain used the older
one. If others expect your signatures from a particular subkey, pick it under Use for signing.

## Import and re-import

- Re-importing your own key edited in gpg applies the changes: newer self-signatures (#78), subkeys added in gpg
  (#82), and, as an opt-in, the secret keys from the file after a passphrase change in gpg (#78). The result says
  what was applied, or why nothing was.
- The import preview lists each subkey it leaves out and why, and Key Details shows where each subkey's secret
  is: on this phone, offline, on a card, or not present (#82).
- Offline primary keys (secret subkeys only, as gpg exports with --export-secret-subkeys) import, sign and
  decrypt. The edits that need the primary are hidden behind one banner that says why.
- User IDs bound only with SHA-1 vanished on import or restore and the key showed as Unknown. They are kept now,
  with a Weak hash mark (#67). A key restored without its names needs one more restore or re-import.
- A key's shown name follows its primary User ID, so a revoked first User ID no longer stops publishing.
- GitHub lookup: enter a username, @name or profile link and PGPony fetches that user's OpenPGP keys, through Tor
  or your proxy when those are on (#81).
- Import's QR, Server and GitHub now open the Exchange page, and Exchange's Key Server tab has GitHub (#92).

## Key Details and Keyring

- Copy a subkey's key ID (#91), the primary key's Usage (#89), and the last key server check with server and
  date (#90). A network failure during that check is reported as an error, not as "not found".
- Keyring > Select keys exports several public keys as one .asc file (#93).
- The list behind a key count badge scrolls (#87).
- Key selectors show "Name <email>" with the short fingerprint.
- Toggle and checkbox rows respond to a tap anywhere on the row (#79).

## App lock and duress PIN

Settings > Security > Lock method: device unlock as before, or a PGPony PIN of 6 to 16 digits, with Unlock with
fingerprint as an option. A Duress PIN erases PGPony's keys and data when entered, and Erase after wrong PINs (5,
10 or 20, off by default) does the same. Without it, repeated wrong PINs add a delay. PINs are stored as Argon2id
hashes.

Clear All Data now also removes the keys in Recently Deleted, mail app and SSH approvals, and every setting.

## Mail apps

- When an address has no usable key, PGPony asks which keys to use instead of failing with "No PGPony key found"
  (#25). Keys the request already includes show ticked, with the address that includes them. FairEmail asks
  several times for one send; your picks are reused for 30 minutes for the same addresses.
- A long passphrase duration ("Until I clear it" and others) was lost after a few minutes on Xiaomi phones,
  because the system stopped PGPony's mail app process. While a passphrase is held for mail apps, a notification
  now keeps it alive, with Clear to forget it.
- Signed mail now names the hash its signature used (micalg) (#84).
- The passphrase and card PIN prompts open with the field focused and the keyboard up (#59).

## Files and Quick Actions

- With several files, the package screen offers Each file on its own: encrypt, encrypt and sign, or sign only
  with a .sig per file, then Save to a folder or Share all (#72).
- Several encrypted files shared to PGPony decrypt one by one, each with its own signature result, instead of
  being encrypted again as a package (#72).
- Saving a large file shows progress and can be cancelled, and a save that fails or is cancelled removes its
  partial file (#73).
- Encrypting and signing a large file with an ML-DSA key ran out of memory. It streams now; a 2 GB file was
  checked both ways with GpgFrontend (#73).
- ML-DSA keys made by sq signed with their certify-only primary, so every verifier rejected the signature. They
  sign with their signing subkey now (#67).
- Decrypt results name the key and subkey that signed and the one that decrypted, as gpg's key IDs (#79).
- A Quick Actions decrypt of an ML-DSA-signed file keeps its file name (#67).
- Shared text holding a PGP block can be encrypted whole with Encrypt all of it (#58).

## Network

- With Tor or a custom proxy on, host names are looked up through the proxy too.
- The keys.pgpony.app onion mirror is off by default. A choice you already made is kept.
- Further message and key import hardening from an internal review.

## Contributed fixes

- The contact email lookup handles a contacts provider that leaves out a column (#97).
- The French and Portuguese "keys need regenerating" message shows its count, so 0 no longer reads as one key
  (#99).
- Test infrastructure (#94).

## Signed source

Release tags and the commits on main are now signed with the norsehorse-dev SSH signing key. The README's Verify
a release section has the key and the git commands to check a tag.

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
PGPony-4.7.0-signing-keys.txt with the OpenPGP fingerprint and the APK signing certificate's SHA-256. Check the
fingerprint against pgpony.app, keys.openpgp.org or keys.pgpony.app rather than trusting the copy in the release
alone.
