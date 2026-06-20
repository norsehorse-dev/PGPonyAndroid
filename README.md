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

- `play` — Google Play build. Includes the Play In-App Review dependency.
- `foss` — F-Droid / IzzyOnDroid / direct APK. No Google Play dependencies.

```
./gradlew assembleFossRelease
./gradlew assemblePlayRelease
```

Debug variants are `assembleFossDebug` and `assemblePlayDebug`.

## License

Apache License 2.0. See `LICENSE`.

The cryptographic core is maintained separately as open source:
[PGPonyCore-Kotlin](https://github.com/norsehorse-dev/PGPonyCore-Kotlin).

## Links

- Website: https://pgpony.app
- Source: https://github.com/norsehorse-dev/PGPonyAndroid
