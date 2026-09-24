# PGPony 4.5.1

A follow-up to the post-quantum release. 4.5.1 rounds out key management, fixes
a QR regression from 4.5.0, adds a share action and a couple of settings, quiets
a contacts hang, and brings the six active translations up to full coverage.

4.5.1 carries versionCode 445 and installs in place over 4.5.0.

## Key management

You can delete a User ID from a key now, not just add or revoke one. Key servers
keep what they are given, so the app also remembers a deleted User ID as removed,
and a later key-server refresh will not pull it back. When the goal is to retire
a User ID for other people rather than only locally, the copy points you at
revoke instead.

The subkey remove dialog offers "revoke this subkey instead", matching the same
option on the key delete dialog, since a removed subkey cannot be revoked after
the fact either.

Settings > Keys & Servers > Default Key is a picker. Tap it to choose any of your
key pairs, rather than it only showing the current one.

From a key's detail screen, the header avatar is a shortcut: on a public key it
opens Encrypt with that key set as the recipient, on a key pair it opens Decrypt.
A one-time hint points it out the first time you open a key.

## Sharing and QR

Sharing text to PGPony offers "Encrypt in PGPony" as its own target now, separate
from import. It takes the shared text as-is and opens the Encrypt screen with it
loaded, so you can encrypt a selection without importing anything or treating it
as a key.

The multi-part QR codes are readable again. 4.5.0 packed more data into each
frame, which pushed the symbols to a higher density with smaller modules that a
second phone struggled to scan. The split is rebalanced toward more frames of
roomier codes, and each frame renders at its natural resolution scaled up
cleanly, so the codes fill the frame instead of sitting in a wide white border.
Generating them is much faster too: the Exchange screen no longer takes several
seconds to draw a key's frames.

## Security

Settings > Security has a new "Hide destructive actions" switch, off by default.
Turn it on and delete key, remove subkey, remove User ID, and clear all data
disappear from the app entirely. Revoke stays. It is also offered on the
onboarding privacy screen. This is separate from "Protect destructive actions",
which stays on by default and gates those same actions behind device
authentication for anyone who keeps them visible.

## Fixed

Opening the Contacts tab could hang the interface while it read the system
contacts on the main thread. That work moved off the main thread, so the tab
stays responsive.

The privacy policy link pointed at a domain that no longer resolves. It points at
pgpony.app/privacy now.

## Under the hood

The R8 keep rules were narrowed so more of the app is shrunk and optimized. The
redundant whole-library keeps are gone, while the load-bearing ones stay: the
BouncyCastle provider lookups, the OpenPGP provider Binder contract, the
stored-key managers, and Room. No behavior change, a smaller and tighter release
build.

## Localization

The six active translations (German, Spanish, French, Japanese, Brazilian
Portuguese, and Russian) are brought up to full coverage for every string 4.5.0
and 4.5.1 added.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
166df6e0cc5840b98cbdcea2b55343241a357ea86a47ca7a3159b4b42ecfb3e4
```

Content hash (for rebuilders; excludes signature, see REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
6f0d2c808dc45ab14cf4b3eb06e9f657e2ceef9f239d12f047ae192938a3b8ec
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release.
