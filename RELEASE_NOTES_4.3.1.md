# PGPony 4.3.1

A small follow-up to 4.3.0, fixing two issues CertainBot found in the 4.3.0
release and cleaning up the English interface copy.

## Fixed

The Trust Level sheet opens fully expanded. It was stopping at its
half-height position, so all four levels only showed after you dragged it
up. Now every level is visible as soon as it opens.

Recently Deleted is reachable from the Keyring. Deleted keys go to a
recycle bin that 4.3.0 only exposed in Settings, which is not where you look
after deleting a key. The Keyring's overflow menu (the three-dot menu, top
right) now opens it directly. It is still in Settings too.

Both reported by CertainBot (#44).

## Changed

Reworked the English interface copy to drop the em dashes, so error
messages, help text, and labels read consistently. No wording meaning
changed. Other languages are unaffected.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
f09e1577d5c20b0514980063d445d8d184ce26980dd59a3e60bf0647453175e5
```

Content hash (for rebuilders; excludes signature, see
REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
d6006d76f6779c4350f21e5e166eb2cdc5b1e11021f9b964b6b2d12d40eb8715
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is
attached to this release.
