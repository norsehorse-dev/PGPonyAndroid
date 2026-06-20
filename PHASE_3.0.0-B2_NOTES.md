# PGPony Android 3.0.0 — Phase B2: admin-PIN lifecycle

> 3.0.0 Phase B2 · NET-NEW. The first card WRITE phase. Adds the rest of the
> PIN lifecycle on top of the existing user-PIN change: change the admin PIN,
> unblock a blocked user PIN, and factory-reset the card. Test on a SPARE card.

## What this ships

A "Manage card (admin)" entry on the Hardware Key scan screen opens a new
Card Management screen with three operations:

- **Change admin PIN (PW3)** — current + new (min 8 digits) + confirm, then tap.
- **Unblock user PIN (PW1)** — enter the admin PIN + a new user PIN (min 6),
  then tap. Restores PW1 and its retry counter. For when PW1 is blocked.
- **Factory reset** — wipes ALL keys/data and restores default PINs. Gated
  behind a two-step confirmation. Needs no PIN (recovers a locked card).

## Engine (OpenPgpCardSession)

- `changeAdminPin(old, new)` — SELECT + `changeReferenceData(CRD_PW3, …)`. Same
  CHANGE REFERENCE DATA (INS 0x24) path as the user PIN, just the PW3 reference.
- `unblockUserPin(adminPin, newUserPin)` — SELECT + VERIFY PW3 + RESET RETRY
  COUNTER (INS 0x2C, P1 0x02 admin-authenticated, P2 CRD_PW1), data = new PW1.
- `factoryReset()` — SELECT, then exhaust PW1 and PW3 retry counters with wrong
  values (`blockPin`), then TERMINATE DF (INS 0xE6) + ACTIVATE FILE (INS 0x44),
  then re-SELECT. This is GnuPG's `factory-reset` approach: no PIN required, so
  it recovers a card you're locked out of. `blockPin` is capped at 15 wrong
  attempts (spec max retry) so it can't loop; if a PIN never blocks, the
  following TERMINATE DF fails safely and the card is left unchanged.

New constants in `OpenPgpCard.kt`: `INS_RESET_RETRY_COUNTER` 0x2C,
`INS_TERMINATE_DF` 0xE6, `INS_ACTIVATE_FILE` 0x44. (PW3/CRD references already
existed.)

## Safety design

- **Factory reset is two-step:** "Factory reset this card" -> "Yes, wipe the
  card", with a red warning that it's irreversible. It can't fire from a single
  tap/click.
- PINs live only in Compose state for the screen's lifetime; never logged or
  persisted. Fields are digit-only with PasswordVisualTransformation.
- One operation per card tap (the NFC reader's one-shot model), same as the
  user-PIN change flow.

## Files touched

| File | Change |
|------|--------|
| crypto/card/OpenPgpCard.kt | INS_RESET_RETRY_COUNTER / INS_TERMINATE_DF / INS_ACTIVATE_FILE |
| crypto/card/OpenPgpCardSession.kt | changeAdminPin, unblockUserPin, factoryReset, blockPin, MAX_BLOCK_ATTEMPTS |
| ui/card/CardManagementScreen.kt | new — menu + three operation forms |
| ui/card/CardScanScreen.kt | "Manage card (admin)" entry (onManageCard) |
| MainActivity.kt | card_management route + import + wiring |
| res/values/strings.xml | 29 card_mgmt_* strings (English-only, card convention) |

## Acceptance criteria (from the plan)

- Change admin PIN; block then unblock user PIN; factory-reset a spare card to
  defaults — each verified against `gpg --card-status`.
- Destructive actions require explicit confirmation and cannot fire by accident.

## Build / verify status

Inspection-verified, not compiled here. Verified: brace+paren balance on all 5
changed/new Kotlin files; every icon swapped to a codebase-proven one
(AdminPanelSettings->Shield, LockReset->LockOpen, DeleteForever->Delete); new INS
constants defined; all 29 strings present once and referenced;
startCardOperation generic signature matches the arm() usage; session methods
reference only defined constants. Needs local ./gradlew installDebug.

### Deploy

```bash
cd ~/Downloads
unzip -o PGPonyAndroid_3.0.0-B2.zip
cp -R ~/Downloads/PGPonyAndroid_3.0.0-B2/. ~/Apps/PGPonyAndroid/
cd ~/Apps/PGPonyAndroid
./gradlew installDebug
```

### Test — USE A SPARE CARD

Order matters; check `gpg --card-status` after each:

1. **Change admin PIN.** Manage card -> Change admin PIN. Current 12345678
   (default) -> a new 8+ digit PIN. Tap. Verify you can use the new admin PIN
   afterward (and that the old one fails).
2. **Block then unblock user PIN.** Deliberately enter the wrong user PIN 3x
   somewhere that uses it (sign/decrypt) until PW1 retries hit 0 (confirm on the
   scan page: User PIN tries left = 0). Then Manage card -> Unblock user PIN,
   enter the admin PIN + a new user PIN, tap. Confirm tries are back to 3 and the
   new user PIN works.
3. **Factory reset.** Manage card -> Factory reset -> through both confirms ->
   tap. `gpg --card-status` should show no keys and default PINs (user 123456,
   admin 12345678). The card status / scan page should show all slots Empty.

If `installDebug` throws, paste it — this is inspection-only and it's the first
write phase, so a compile slip is the main risk.

## Next in Phase B

**B1** — on-card key generation (GENERATE ASYMMETRIC KEY PAIR, INS 0x47, which
already has a head start). That's the last Phase B slice, and where the
generation-date DO (0xCD) finally gets written on-device — so the B3 "Generated"
row will show a real date for cards keygen'd in-app.
