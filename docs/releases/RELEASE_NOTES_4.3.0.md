# PGPony 4.3.0

The key-security release. 4.3.0 fills in the key-management and session
work deferred from 4.2.0, adds full GnuPG composite-key interoperability,
and ships a seventh language. It is the largest release since the 4.0
line.

Every build in the 4.3.0 candidate cycle carried versionCode 430 and
installed in place; this is the final.

## Added

Key recycle bin. Deleting a key now soft-deletes it. Deleted keys move to
Keys, then Recently Deleted, where you can restore them or purge them for
good, and they auto-purge after 14 days. The delete sheet also shows
whether the key is in a backup before you confirm, so a delete is no longer
a one-way door. Requested by AraafRoyall (#36).

Session policy. A new "until the phone locks" option ends a passphrase
session on device lock rather than on a timer, and the provider passphrase
cache, the card PIN cache, and the in-app prompts now answer to one policy
instead of three that could disagree. Changing a key's passphrase clears
its cached entry at once.

GnuPG composite-key interoperability. PGPony imports, labels, and decrypts
composite ML-KEM keys produced by GnuPG 2.5.x and GPG4WIN, including the
brainpoolP384r1 variant, and can export a composite secret key in GnuPG's
native format so it imports cleanly into GPG4WIN. A "GnuPG-compatible
format" toggle on the private-key export sheet drives it. Reported by
homehsu (#2).

Animated QR for large keys. A post-quantum key does not fit in one QR
symbol, so it is split across frames that now rotate on their own, with
play/pause and manual step controls, on both the Key Detail and Exchange
screens. Requested and scanner-tested by CertainBot (#37).

Verify a signed-only file. A file that was signed but not encrypted (the
form Thunderbird saves for a signed plain-text message) is now verified in
place instead of failing with "not encrypted". Raised by CertainBot.

Zip output. File and bundle encryption can wrap the ciphertext in a .zip
for transport over channels that mangle .gpg or .asc attachments, and
decryption accepts a zip containing a PGP message. Requested by AraafRoyall
(#31).

Editable key notations, a signing-key picker for keys with more than one
signing subkey, a default sharing method, a per-key last-backed-up
indicator, an opt-in update check for sideloaded builds that only notifies
and links (it downloads and installs nothing, and is off on F-Droid), and a
link to ScrubPony under More from NorseHorse.

Russian. PGPony is now available in Russian, its seventh language.

## Changed

Change a key's passphrase, set one on a key that had none, or remove it,
from Key Detail. Requested by AraafRoyall (#26).

The trust marks were unified into one shield ladder across the app, and the
Key Detail actions were reorganized into clearer menus. Both from
AraafRoyall (#24, #36).

Switching languages is now seamless. The change lands in place without the
black flash and without dropping you back to the top of Settings.

The encrypted-bundle result sheet is split into a Send as email block and a
Send as file block, so the Wrap in .zip toggle plainly governs the file and
not the email. From AraafRoyall's retest of #31.

The Bouncy Castle version shown on the About, FAQ, and security-info
screens now reads 1.85, matching the library the app has actually used
since 4.0.0. Reported and fixed by White-Sun-08 (#42).

## Fixed

WKD key import re-armors correctly, so a key served as ASCII armor is no
longer double-wrapped. Reported by ThePharaohArt (#41).

A key deleted or a trust level changed from Key Detail now updates the
Keyring immediately instead of after an app restart. Found by CertainBot.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
6b534dc4f96fd014d8475e3a05543f30aca07c14358537494a2fc07dd73dd61f
```

Content hash (for rebuilders; excludes signature, see
REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
cbb23ff8021f47604ebced73969b888a49979fbf5bb7461e0f0faac88f943504
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is
attached to this release.
