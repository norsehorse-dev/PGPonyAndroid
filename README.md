# PGPony for Android

OpenPGP for Android. Encrypt, decrypt, sign, and verify messages and files,
manage your keyring, and use a hardware security key over NFC or USB, all on
device.

PGPony has no accounts, no ads, no analytics, and no tracking. The `foss`
build contains no Google services and runs fully on de-Googled devices.

## Features

- Encrypt, decrypt, sign, and verify text and files
- Modern key generation, including RFC 9580 (OpenPGP v6) Ed25519 and X25519,
  with Argon2id passphrase protection
- Hardware security keys over NFC and USB (YubiKey 5 NFC, Token2): on-card
  key generation, moving an existing key onto the card (since 4.7.0),
  decrypt, sign, PIN management, and factory reset. USB has
  worked since 4.1.0. The Nitrokey 3 works over USB since 4.6.4 for decrypt
  and sign; its firmware turns OpenPGP off over NFC, so it does not work there
- Read-only password-store (pass) support, including hardware-key entries
- Key discovery via WKD and the keys.openpgp.org verifying keyserver
- Optional contacts integration, QR import and scanning
- Biometric lock and secure-screen protection

## Coming from OpenKeychain

- Keys: export them in OpenKeychain and import the file in PGPony; every key
  in it imports at once. For an encrypted OpenKeychain backup (a .sec.pgp
  file), use Settings, Backup, Restore and enter the 36-digit backup code.
- Mail apps: in the mail app's OpenPGP settings, choose PGPony as the
  OpenPGP app. Apps you allow are listed under Connected apps.
- SSH: OkcAgent works with PGPony through a fork that lists PGPony as a
  provider. Settings has the link and the Termux steps.
- Signing subkeys: PGPony signs with the newest valid signing subkey, where
  OpenKeychain used the older one. If others expect your signatures from a
  particular subkey, pick it under Key Details, Use for signing (since
  4.7.0). Automatic names the key it picks.

## Build

The app ships two product flavors:

- `play`: Google Play build. Includes the Play In-App Review dependency.
- `foss`: F-Droid / IzzyOnDroid / direct APK. No Google Play dependencies.

```
./gradlew assembleFossRelease
./gradlew assemblePlayRelease
```

Debug variants are `assembleFossDebug` and `assemblePlayDebug`.

## Verify a release

Every release is built reproducibly, so you can rebuild the APK from the
tagged source and confirm it matches the published binary bit for bit,
and you can confirm the published APK is signed with the project's own
key. You do not have to trust the download.

Verify the signature and certificate. The release APK is signed with the
PGPony release key; its certificate SHA-256 fingerprint is:

```
446bf9e621222a40c66cd2476e1a97105ccb2a9b16a01a91c1c7eb90765b50dc
```

Check a downloaded APK against it with the Android build tools:

```
apksigner verify --print-certs PGPony-<version>-foss.apk
```

The printed "certificate SHA-256 digest" must equal the fingerprint
above.

Since 4.6.3 every GitHub release carries four assets, and releases are
immutable, so the assets cannot be swapped after publishing:

- `PGPony-<version>-foss.apk`, the APK
- `PGPony-<version>-foss.apk.asc`, its detached OpenPGP signature
- `NorseHorse-release-key.asc`, the armored OpenPGP release key
- `PGPony-<version>-signing-keys.txt`, the OpenPGP release key
  fingerprint and the APK signing certificate SHA-256

```
gpg --import NorseHorse-release-key.asc
gpg --verify PGPony-<version>-foss.apk.asc PGPony-<version>-foss.apk
```

Before trusting the key that ships with a release, check its OpenPGP
fingerprint against a source GitHub does not control: the verify page
on pgpony.app, keys.openpgp.org, or keys.pgpony.app. The release notes
carry the whole-file SHA-256 for downloaders and a content hash for
rebuilders, each labeled with what it means. Release candidates on
pgpony.app have a `.sha256` file beside each APK; GitHub releases do
not.

Verify the source. From 4.7.0 on, release tags and the commits on main
are signed with the norsehorse-dev SSH signing key:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPhzdDdquHgaZq8dgEQzcncPBnSZvIVlusBg0TvOA8To
```

To check a tag or commit locally, list the key in an allowed signers file
and point git at it from inside a clone:

```
echo "norsehorse-dev@users.noreply.github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPhzdDdquHgaZq8dgEQzcncPBnSZvIVlusBg0TvOA8To" > allowed_signers
git config gpg.ssh.allowedSignersFile "$PWD/allowed_signers"
git verify-tag v<version>
git log --show-signature -1
```

The same key is registered as a signing key on the norsehorse-dev GitHub
account, so GitHub marks these commits and tags Verified; the copy here
lets you check them without relying on that badge.

Rebuild from source and compare. The release gate script clones a tag
twice into clean, isolated build roots, proves the two builds are
byte-identical, and compares them against a candidate APK:

```
tools/verify_repro.sh rebuild v<version> PGPony-<version>-foss.apk
```

It requires an Android SDK and network access for the clone and
dependency downloads, and prints per-dex SHA-256s and the canonical
content hash. The full procedure, and how this maps to F-Droid's own
verification, is in `docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md` and
`docs/REPRODUCIBLE_BUILDS.md`.

## License

Apache License 2.0. See `LICENSE`.



## Links

- Website: https://pgpony.app
- Source: https://github.com/norsehorse-dev/PGPonyAndroid
- Desktop: https://github.com/norsehorse-dev/PGPonyDesktop

## A note on how this is built

This app is developed solo and with heavy use of AI assistance, which I don't hide. What matters for a tool like this is the crypto, and PGPony builds on the open OpenPGP standard, with its output verified against the reference tools. The full source is here to audit, and bug reports and code review are welcome.
