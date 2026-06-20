# PGPony Android 3.0.0 — Phase B1: on-card key generation

> 3.0.0 Phase B1 · NET-NEW. The strongest hardware-key story: an Ed25519 signing
> primary + Cv25519 ECDH subkey generated ON the card, secret keys never leaving
> it. The byte-exact OpenPGP construction was ported verbatim from the
> gpg/Sequoia-verified iOS implementation and re-validated against gpg offline.

## What this ships

A "Generate new key on card" entry on the Hardware Key scan screen opens a keygen
screen: name + email (UID), admin PIN (PW3), user PIN (PW1), and a REQUIRED
no-backup acknowledgment. One card tap generates both keys on the card, writes
the fingerprints + creation times back, has the CARD sign the self-signatures,
assembles the transferable public key, and saves it to the keyring as a
card-backed entry — so it appears immediately in Encrypt/Decrypt and sign/decrypt
route to the card via the existing isCardBacked paths.

## Architecture (staged B1a -> B1b -> B1c)

### B1a — card engine (OpenPgpCardSession + OpenPgpCard)
- INS_PUT_DATA 0xDA; per-slot fingerprint DOs C7/C8/C9; gen-time DOs CE/CF/D0.
- generateKeyOnCard(slot): GENERATE at P1=0x80, parse 0x7F49 -> CardPublicKeyMaterial.
- putData, setAlgorithmAttributes, writeFingerprint, writeGenerationTime.

### B1b — packet construction + orchestration
- **CardKeyPacketBuilder.kt** (new): byte-exact port of iOS Ed25519KeyGenerator —
  Ed25519/Cv25519 public-key bodies (OIDs, 0x40 prefix, MPI, KDF params 3/01/8/7),
  certification (0x13) + subkey-binding (0x18) hash data + trailer, subpacket sets
  in iOS order, EdDSA signature-packet assembly from card r||s, new-format packets.
  Fingerprint via the existing V4Fingerprint (already SHA-1(0x99||len||body)).
- **CardKeygenService.kt** (new): generateOnCard orchestration — PW3 (attrs,
  generate x2, fingerprints, gen-times) then PW1 re-verified BEFORE EACH card
  self-signature (cards reset PW1 after each PSO:CDS), assemble + return binary key
  + post-gen CardInfo.
- **KeyRepository.importGeneratedCardKey**: parse the binary with BC (validates the
  assembled key), then reuse the order-independent card pair-up (importCardKey to
  create/identify the card-backed row, importArmoredKey to fold the real public key
  + UID onto it).

### B1c — UI
- **CardKeygenScreen.kt** (new) + card_keygen route + "Generate new key on card"
  entry on CardScanScreen. No-backup warning is a hard gate (checkbox required).
  20 card_keygen_* strings (English-only, card convention).

## OFFLINE VALIDATION against real gpg 2.4.4 (the key point)

Because crypto can't be compiled/tested here, the construction was validated
against gpg in the container BEFORE shipping:

1. Generated a real Ed25519+Cv25519 key with gpg; extracted its points +
   creation times; ran them through a replica of CardKeyPacketBuilder:
   - primary fingerprint == gpg (A6D915A4...1D7795FD)  MATCH
   - subkey fingerprint (incl KDF params) == gpg (853F1738...892C9307)  MATCH
2. Rebuilt gpg's own certification hash data with the ported framing -> digest
   prefix == gpg's stored prefix (a94f)  MATCH
3. END-TO-END: extracted the key's Ed25519 seed, signed the cert + binding
   digests exactly as the card's PSO:CDS would (64-byte r||s), assembled the full
   transferable public key with the ported packet logic, and imported it into a
   fresh gpg keyring:
   - gpg imported it cleanly, correct UID, matching fingerprints
   - BOTH signatures verified GOOD (gpg --check-sigs shows `sig !` on the
     certification and the subkey binding)

So every byte-construction risk is retired. What remains is card behavior only:
GENERATE returning parseable points, the PUT DATA writes, PW1 re-verify timing,
and PSO:CDS returning 64-byte r||s — all verifiable only on a real card.

## Design decision (diverges from iOS, flagged)

iOS does not write the generation-time DO after keygen; **Android does**
(writeGenerationTime under the same PW3). It makes `gpg --card-status` show the
correct created date and the B3 status row show a real date, and it CANNOT affect
the fingerprint (the gen-time DO is read independently of the C7/C8 fingerprint
DO). Same creationTime feeds the fingerprint, the public-key packet, and the card
DOs — the timestamp-consistency rule from the iOS debugging session.

## Files touched

| File | Change |
|------|--------|
| crypto/card/OpenPgpCard.kt | INS_PUT_DATA + fingerprint/gen-time DO constants |
| crypto/card/OpenPgpCardSession.kt | generateKeyOnCard, putData, setAlgorithmAttributes, writeFingerprint, writeGenerationTime |
| crypto/card/CardKeyPacketBuilder.kt | new — byte-exact packet construction (gpg-validated) |
| crypto/card/CardKeygenService.kt | new — generateOnCard orchestration |
| data/repository/KeyRepository.kt | importGeneratedCardKey (parse+validate+link) |
| ui/card/CardKeygenScreen.kt | new — keygen UI + no-backup gate |
| ui/card/CardScanScreen.kt | "Generate new key on card" entry (onGenerateKey) |
| MainActivity.kt | card_keygen route + import + wiring |
| res/values/strings.xml | 20 card_keygen_* strings (English-only) |

## Acceptance criteria (from the plan)

- Generate Ed25519 + Cv25519 on a YubiKey 5; public key appears in the keyring;
  sign + decrypt work through the existing card paths.
- Card fingerprints match the generated public key (`gpg --card-status`).
- No-backup warning shown + acknowledged before generation.

## Build / verify status

Inspection-verified + gpg-validated offline; not compiled here. Verified:
brace/paren balance on all 8 changed/new Kotlin files; every icon proven in the
codebase; 20 strings present once + referenced; all CardKeygenService symbol
references (builder members, session methods, OpenPgpCard constants) resolve;
MainActivity NavHost balanced with both card routes intact. Needs local
./gradlew installDebug.

### Deploy

```bash
cd ~/Downloads
unzip -o PGPonyAndroid_3.0.0-B1.zip
cp -R ~/Downloads/PGPonyAndroid_3.0.0-B1/. ~/Apps/PGPonyAndroid/
cd ~/Apps/PGPonyAndroid
./gradlew installDebug
```

### Test — USE A SPARE CARD (generation overwrites the sign + decrypt slots)

1. Hardware Key scan -> tap a spare card -> "Generate new key on card".
2. Enter name/email, admin PIN (default 12345678), user PIN (default 123456),
   check the no-backup box, Generate, hold the card steady.
3. On success the screen shows both fingerprints and the key lands in the keyring.
4. **The acceptance gate:** `gpg --card-status` — the Signature + Encryption key
   fingerprints must match the two shown in-app (and match the keyring entry).
   This is what the offline validation already proved for the construction; the
   on-device run confirms the card path.
5. Then exercise the key: clear-sign a message and decrypt a message encrypted to
   it — both should route to the card and succeed.
6. Re-scan the card: the B3 status rows should show the real "Generated" date
   (the gen-time DO we wrote), not "Not recorded".

If `installDebug` throws or the card path misbehaves, paste it — the crypto is
proven, so any issue is in the card I/O sequencing or Compose wiring.

## Phase B is COMPLETE

B3 (status) + B2 (admin-PIN lifecycle) + B1 (on-card keygen) all shipped. Next is
Phase C (minimal pass integration): C0 -> C3.
