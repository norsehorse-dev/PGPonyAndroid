# PGPony 4.6.3

Pairing with PGPony Desktop, and the bug fixes that were waiting for 4.7.0. 4.6.3 carries versionCode 463 and installs in place over 4.6.2.

## Pair with another device

Settings and the Keyring menu have a new Pair with another device. It moves public keys, key pairs or a full
backup between this phone and PGPony Desktop 3.0 or another phone on the same network.

One device waits and shows a QR code and its address; the other scans the code or types the address. The
joining device shows a six-digit code, and its user confirms the waiting device shows the same one, while the
waiting device's user types the code from the joining screen. After that, either side can send. The receiving
side picks what it wants and sees each key, read from the key itself, before anything is added. A key pair
always travels under a passphrase: one that has none is protected with a transfer passphrase you choose for the
trip. A backup restores with the recovery code the sending screen shows, and takes no trust levels or settings
from the other device.

The phone only pairs over Wi-Fi, Ethernet, tethering or USB, never over mobile data, and only with a device on
the local network. Offline mode blocks pairing. Sending a key pair or a backup asks for your fingerprint or
screen lock first, as exporting a private key does. Nothing is kept: leaving the screen ends the session and
wipes its keys.

## Mail apps keep your passphrase for the time you chose (#15)

A passphrase entered while decrypting in Thunderbird or another mail app stayed for exactly 5 minutes, whatever
you set in Settings. The part of PGPony that answers mail apps runs in its own process and never saw your
setting; the 4.6.1 fix for this did not reach it. The setting now lives where both parts of the app read it on
every check. The passphrase prompt also says what it is for (sign, decrypt or SSH login) and how long PGPony
keeps it, where it used to say "sign" and "5 minutes" every time. Settings no longer claims nothing is remembered
when a mail app holds a passphrase, and Clear now reaches it.

## SSH agents with several keys (#68)

PGPony remembered only one SSH key per app, so with two or more keys loaded in OkcAgent every approval undid the
last one and git operations raised a stream of approval prompts. Each key is now approved once and stays
approved. Settings > Connected apps lists every approved key with its own Remove.

## Post-quantum fixes

- A message encrypted by an rPGP-based app (GpgFrontend, for one) to a PGPony ML-DSA-65 v6 key could not be
  decrypted. PGPony read the key ID from the wrong end of a v6 fingerprint. (#73)
- Adding a User ID to, or revoking a subkey on, a passphrase-protected ML-DSA key always failed, even with the
  right passphrase.
- Package mode can sign with an ML-DSA key; it used to say the key could not be unlocked. (#72)
- Encrypting to a recipient PGPony cannot load now stops with a message naming that recipient. Before, some paths
  (package mode, the hardware key encrypt-and-sign, the mail app send through a hardware key) left that
  recipient out of the message without saying so.

## Other fixes

- An image shared into PGPony (PNG, and some JPEG) landed in the signature field of Verify. A file now counts as
  a signature only when it is one. An encrypted .gpg or .pgp file whose recipients PGPony could not list opens
  to Decrypt instead of Encrypt. (#67)
- The "tap the +" tip no longer flashes on the Keyring at every start. (#74)
- Several freezes on slow storage and long key edits: adding a subkey, other Key Details edits and changing a
  passphrase run in the background; picking a file from a cloud provider, and saving or sharing a large
  encrypted or decrypted file, no longer block the screen.
- Fixed a crash when PGPony was opened from a share before its screens were ready, a crash on picking a very
  large file to import as a key (now "too large to be a key"), and a crash on verifying a signature whose block
  was damaged (now reported as damaged).
- Message handling hardening.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
(added at release)
```

Content hash (for rebuilders; excludes signature, see docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
(added at release)
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release.
