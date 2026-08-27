# PGPony for Android

OpenPGP for Android. Encrypt, decrypt, sign, and verify messages and files,
manage your keyring, and use a hardware security key over NFC, all on device.

PGPony has no accounts, no ads, no analytics, and no tracking. The `foss`
build contains no Google services and runs fully on de-Googled devices.

## Features

- Encrypt, decrypt, sign, and verify text and files
- Modern key generation, including RFC 9580 (OpenPGP v6) Ed25519 and X25519,
  with Argon2id passphrase protection
- Hardware security keys over NFC (YubiKey 5 NFC, Token2): on-card key
  generation, decrypt, sign, PIN management, and factory reset
- Read-only password-store (pass) support, including hardware-key entries
- Key discovery via WKD and the keys.openpgp.org verifying keyserver
- Optional contacts integration, QR import and scanning
- Biometric lock and secure-screen protection

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
above. A detached OpenPGP signature (`.asc`) and a `.sha256` are
published beside every release APK; the release notes carry the
whole-file SHA-256 for downloaders and a content hash for rebuilders,
each labeled with what it means.

Rebuild from source and compare. The release gate script clones a tag
twice into clean, isolated build roots, proves the two builds are
byte-identical, and compares them against a candidate APK:

```
tools/verify_repro.sh rebuild v<version> PGPony-<version>-foss.apk
```

It requires an Android SDK and network access for the clone and
dependency downloads, and prints per-dex SHA-256s and the canonical
content hash. The full procedure, and how this maps to F-Droid's own
verification, is in `REPRODUCIBLE_BUILDS_PLAYBOOK.md` and
`docs/REPRODUCIBLE_BUILDS.md`.

## License

Apache License 2.0. See `LICENSE`.

The cryptographic core is maintained separately as open source:
[PGPonyCore-Kotlin](https://github.com/norsehorse-dev/PGPonyCore-Kotlin).

## Links

- Website: https://pgpony.app
- Source: https://github.com/norsehorse-dev/PGPonyAndroid
- Desktop: https://github.com/norsehorse-dev/PGPonyDesktop

## A note on how this is built

This app is developed solo and with heavy use of AI assistance, which I don't hide. What matters for a tool like this is the crypto, and PGPony builds on the open OpenPGP standard, with its output verified against the reference tools. The full source is here to audit, and bug reports and code review are welcome.
