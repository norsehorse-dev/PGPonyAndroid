# PGPony Android 4.6.4: Planning

Status: RC1 verified (Oct 6 2026): items 2 to 5 checked on device, item 1 confirmed working over USB by the reporter. A small fixes release: Nitrokey 3 security keys over USB, plus four small items pulled
forward from PLANNING_4.7.0.md (4, 9, 17, 18).

versionCode 464. Branch: `4.6.x` (at v4.6.3), not main. Every change is cherry-picked onto main after release, so
4.7.0 keeps it. Database: no schema change.

4.7.0 items moved here: 4, 9, 17, 18. Mark them "moved to 4.6.4" in PLANNING_4.7.0.md on main.


## 1. Nitrokey 3 over USB: chained CCID responses

Priority: high (bug). Origin: email report.

Reported: plugging a Nitrokey 3 (firmware 1.9.1) into a Pixel 8 fails with status 0x0A3F, which is not a valid
status word. OpenKeychain works with the same key over USB.

Cause: the Nitrokey 3's CCID interface (Trussed usbd-ccid) splits any response longer than one 64-byte USB packet
into chained RDR_to_PC_DataBlock messages (bChainParameter 0x01 begins, 0x03 continues, 0x02 ends) and sends each
block after the first only when the host asks with an empty PC_to_RDR_XfrBlock carrying wLevelParameter 0x10.
CcidExchange parsed bChainParameter but ignored it, so PGPony took the first 54 bytes as the whole response and its
last two bytes as the status word. SELECT fits in one block, so the failure shows on the first longer read.

Work:

- CcidResponse.moreBlocksFollow, true on a DataBlock whose chain parameter is 0x01 or 0x03.
- CcidExchange.transceiveApdu requests each further block (empty XfrBlock, level 0x10, next sequence number) and
  concatenates the data before the status word is read. Capped at 2048 blocks so a reader that never ends the
  chain fails instead of looping.
- Command chaining (an APDU larger than dwMaxCCIDMessageLength) stays out of scope and keeps its explicit error.
- Tests: a three-block response is reassembled and each request is checked byte for byte; an unchained response
  sends nothing extra; an endless chain fails.

Not a bug: NFC returns 0x6A82 (application not found) on the same key. Nitrokey disabled OpenPGP over NFC in
firmware 1.5.0 and has not re-enabled it through 1.9.x, and OpenKeychain fails the same way over NFC.

Verified: the reporter confirmed RC1 works over USB with a Nitrokey 3 on firmware 1.9.1. Regression check on a
YubiKey over USB and NFC once one is available.


## 2. Days left on each key in Recently Deleted (#58, 4.7.0 item 4)

Each row shows how long until the key is destroyed: "N days left", or "Less than a day left" in the last day and
while a key past retention waits for the next launch's purge. RecycleBinCountdown.daysLeft rounds to the nearest
day from deletedAt and KeyRepository.RECYCLE_BIN_RETENTION_MS, so a key deleted a minute ago shows the full 14 days
the delete sheet promised. Computed when the screen composes. Plurals and the under-a-day string in all 11
locales; unit tests for the rounding.


## 3. Subkey "Revoke this subkey instead" alignment (#36, 4.7.0 item 9)

The subkey remove dialog's revoke-instead option was a left-aligned text button; the key delete sheet uses a
full-width outlined button with the Block icon. The subkey dialog now uses the same full-width outlined button and
icon.


## 4. User ID row: Make Primary shifts Revoke and Remove (#76, 4.7.0 item 17)

KeyDetailSections' user ID row orders its actions Revoke, Remove, then Make Primary when shown, so the first two
line up on every row.


## 5. One PGPony entry in the share menu (#58, 4.7.0 item 18)

The EncryptTextShareAlias activity-alias ("Encrypt in PGPony", 4.5.1) is removed along with its forwarding in
ShareTargetActivity and share_encrypt_text_label in every locale. The Quick Action's Encrypt option covers the same
path through IntentHandler.ACTION_ENCRYPT_TEXT, which stays.

Verify on device: share text from a notes app; PGPony appears once, and Encrypt in the Quick Action opens the
Encrypt screen with the text.


## Release

- RC1 on device: items 2 to 5 here; item 1 through the reporter.
- Reproducibility gate, then the GitHub draft release with four assets, per docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md.
- Cherry-pick onto main and mark the 4.7.0 items.
