# PGPony Android 3.0.0 — Phase B3: card status (inline, revised)

> 3.0.0 Phase B3 · revised. The first cut used a separate "Card status" screen
> reached by a button — but that screen had to re-scan, and the NFC reader's
> one-shot/re-arm behavior makes a second tap on a fresh screen fail with "no
> supported application" (a constraint we'd already hit before). The scan page
> already holds the full CardInfo from the first tap, so the fix is to show the
> complete status inline on the scan page and drop the separate screen.

## What this ships

The Hardware Key (card scan) screen already displayed almost everything: card
identity (manufacturer, serial, AID), PW1/PW3 tries, and per-slot rows
(Signature / Decryption / Authentication) with algorithm, "Empty", and
fingerprint. The only field the separate status screen added was the per-slot
key generation date — so that's the entire net change here: a "Generated
<date>" line under each populated slot. One tap, full status, no second scan.

## Changes (vs the first B3 cut)

- Deleted ui/card/CardStatusScreen.kt.
- Reverted MainActivity: removed the card_status route, its import, and the
  onCardStatus wiring on the card_scan route.
- Reverted CardScanScreen: removed the onCardStatus param (outer + inner action
  composable + call site) and the "View card status" button.
- Added to CardScanScreen.SlotRow: a "Generated <date>" line when the slot
  reports a generationTime, plus a formatCardDate helper and
  java.text.SimpleDateFormat / java.util.Date / java.util.Locale imports.
- Strings: removed the 23 now-dead card_status_* keys; added one
  card_scan_slot_generated ("Generated %1$s"). English-only, matching the
  existing card subsystem convention.

## Files touched

| File | Change |
|------|--------|
| ui/card/CardScanScreen.kt | per-slot "Generated" date + helper/imports; onCardStatus removed |
| MainActivity.kt | card_status route + import + wiring removed (back to original) |
| res/values/strings.xml | card_status_* removed; card_scan_slot_generated added |
| (deleted) ui/card/CardStatusScreen.kt | deleted |

## Deploy note - must remove the orphaned file

cp -R copies the bundle over your tree but does NOT delete files that exist
locally and not in the bundle. CardStatusScreen.kt is still on your machine from
the first B3 and now references deleted strings, so it WILL break the build
unless removed. The deploy block below does that.

### Deploy

```bash
cd ~/Downloads
unzip -o PGPonyAndroid_3.0.0-B3.zip
rm -f ~/Apps/PGPonyAndroid/app/src/main/java/com/pgpony/android/ui/card/CardStatusScreen.kt
cp -R ~/Downloads/PGPonyAndroid_3.0.0-B3/. ~/Apps/PGPonyAndroid/
cd ~/Apps/PGPonyAndroid
./gradlew installDebug
```

### Test

1. Keyring -> scan the Token2 (Hardware Key screen). Status shows on the same
   page from the single tap - no second scan, no "View card status" button.
2. Under each populated slot you should now see a "Generated <date>" line.
   Confirm it's a sane date (not Jan 1 1970 / epoch-0). Note: this reads the
   card's generation-date DO (0xCE), which can differ from the date in an
   exported public-key packet - that's display-only and expected.
3. Everything else already verified on-device against gpg --card-status:
   AID D2760001240103040011896369900000, Token2 / 89636990, Signature Ed25519
   0512...9C79, Decryption Cv25519 49EE...A3DA, Authentication Empty, PW1 3 /
   PW3 3.

## Build / verify status

Inspection-verified, not compiled here (the first B3 cut compiled clean on
device; this is a smaller delta). Verified: brace+paren balance on both changed
files; zero dangling CardStatusScreen / card_status / onCardStatus references;
card_scan_slot_generated present once and referenced; date imports present.
Needs local ./gradlew installDebug.

## Next in Phase B

B2 - admin-PIN management, unblock, factory reset (user-PIN change exists).
Then B1 - on-card key generation. (B1 is where Android writes the generation DO
itself, so the date-vs-fingerprint timestamp caution from the iOS debugging
session applies.)
