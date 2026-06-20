# PGPony Android 3.0.0 — Phase C2: hardware-key decrypt for pass

> 3.0.0 Phase C2 · builds on C1. A pass entry encrypted to a card-backed key now
> decrypts over NFC (PIN + tap), reusing the existing CardDecryptService. Routing
> between software and hardware is decided by recipient matching.

## What this ships

When you open an entry and tap Decrypt, PGPony now inspects the message's
recipients and routes:
- a **software keypair** holds a recipient key -> decrypt on device (C1, unchanged);
- only a **card-backed** key matches -> a "Decrypt with hardware key" screen:
  enter the card PIN (PW1), hold the card to the phone, and it decrypts via
  PSO:DECIPHER on the card;
- nothing matches -> "no matching key."

The pass-store biometric gate still runs first, before either path.

## How routing works (PassDecryptCoordinator)

- `messageRecipientKeyIds(bytes)` parses the PKESK key ids from the message
  (0 = hidden/wildcard recipient).
- `route(repo, bytes)`: a ring matches when it contains a key whose id is one of
  the recipients (the same `pubRing.getPublicKey(id) != null` check
  CardDecryptService uses) or when the message has a wildcard recipient. Software
  keypairs are preferred (no tap); otherwise the first matching card key ->
  PassRoute.Card; else NoMatch. Used `getPublicKey(id)` rather than
  `isEncryptionKey` because the codebase notes the latter is algorithm-level and
  unreliable.

## Card decrypt (reuses the proven flow)

PassEntryScreen's card path mirrors CardDecryptScreen exactly: startCardOperation
-> SELECT -> read the tapped card's fingerprint -> load its paired public ring ->
`CardDecryptService.shared.decryptBytes(session, pubRing, pin, leafBytes)` (PW1
0x82 verified inside) -> parse -> display. Binary or armored leaf bytes both work
(decryptBytes handles both). NFC-off is caught before arming.

## Files touched

crypto/pass/PassDecryptCoordinator.kt (PassRoute + messageRecipientKeyIds +
route); ui/pass/PassEntryScreen.kt (full rewrite: route -> software/card; card
PIN + tap states; FLAG_SECURE, passphrase, display unchanged from C1);
res/values/strings.xml (6 strings).

## Build / verify status

Inspection-verified; not compiled here. Verified: brace/paren balance on both
files; Nfc icon proven; 6 new strings present once + referenced; route /
messageRecipientKeyIds / PassRoute / CardDecryptService.decryptBytes resolve; no
unescaped apostrophes. The card decrypt itself reuses code already device-tested
in the hardware-key phases. Needs local ./gradlew installDebug.

### Deploy

```bash
cd ~/Downloads
unzip -o PGPonyAndroid_3.0.0-C2.zip
cp -R ~/Downloads/PGPonyAndroid_3.0.0-C2/. ~/Apps/PGPonyAndroid/
cd ~/Apps/PGPonyAndroid
./gradlew installDebug
```

### Test — needs an entry encrypted to a CARD key

The C1 test store is encrypted to a software key, so those entries still take the
software path (good — confirm they're unaffected). To exercise C2 you need an
entry encrypted to a card-backed key that's in the phone's keyring:

1. On the Mac, make a small store encrypted to a current card key's fingerprint
   (one you still have — e.g. generate a fresh key on a spare card with the new
   on-card keygen, pair its public key into the phone, then
   `pass init <THAT_FP>` a throwaway entry), and sync it over.
   Make sure that card's PUBLIC key is paired into the phone's keyring (scan the
   card or import the public block) so the tapped card resolves.
2. Open the entry -> Decrypt. It should skip the passphrase path and show the
   "Decrypt with hardware key" screen.
3. Enter the card PIN, hold the card to the phone. It should decrypt and show the
   password + fields, matching the desktop.
4. Confirm the software entries from C1 still decrypt without a tap (routing
   prefers software).
5. Turn NFC off and open a card entry -> it should say NFC is off rather than
   hang.

If a card entry routes to the passphrase prompt instead of the card screen, the
card's public key isn't paired in the keyring (so recipient matching can't see
it) — pair it and retry.

## Phase C status

C0 (foundations) + C1 (browse + software decrypt) + C2 (hardware decrypt) done.
Remaining: **C3 (fast-follow) — write/edit** (re-encrypt edited entries to the
nearest .gpg-id recipients, atomic write-back), which the plan scopes as optional
for 3.0. Read-only pass support is now complete.
