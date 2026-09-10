# PGPony — open items after desktop 2.1.3

Snapshot as of 2026-08-23, right after desktop 2.1.3 shipped to every channel
(GitHub release, download page, direct downloads, AUR). These are the threads
still open. Nothing here blocks 2.1.3; it's all follow-up.

---

## 1. Android 4.3.2 release loose ends

4.3.2 (the Argon2 S2K interop fix — default flipped to iterated-salted type 3,
plus a Settings toggle for Argon2) is built, reproducibility-verified, signed,
and published on GitHub. The remaining work is the surrounding distribution
plumbing.

- [ ] **fdroiddata build entry.** Add the 4.3.2 build block to the app's
  metadata in an fdroiddata merge request: versionName `4.3.2`, versionCode
  `432`, the binary URL, and bump `CurrentVersion` / `CurrentVersionCode`.
- [ ] **Re-run the reproducible-check CI on the `v4.3.2` tag** so the published
  APK's reproducibility is proven by the pipeline, not only locally. Local
  content hash for reference: `75eb5635082757b54a31e2a5c6b5e7b6da0e11d505390fac9269d4a2795237b2`;
  whole-file SHA-256: `ffe915922a64dddd000ba6e5373fb0bed07a6acb19cca2bc16527c3618f9d2d8`.
- [ ] **Update the site's APK listing** (`apk.php` / `downloads/`) to 4.3.2 so
  direct download and the version string match the release.
- [ ] **Commit `RELEASE_NOTES_4.3.2.md` to `main`** (currently only local).

Reminder for whoever does the fdroiddata MR: the F-Droid build must come from a
clean tag checkout and match the signed APK — the reproducible pipeline is what
proves that, so run it before or alongside the MR.

---

## 2. homehsu — issue #2 reply (blocked on a design decision)

Two separate things in homehsu's comment, and the reply should cover both.

**(a) The import bug — subkeys not loading.**
homehsu reports subkeys not showing up on import. `deriveSubkeys` currently
swallows any subkey it can't parse inside a try/catch, so a single
unparseable subkey silently disappears instead of surfacing an error. To
diagnose the specific case we need **homehsu's public key** (the one that
imports with missing subkeys) — ask for it in the reply. Until we can
reproduce it against their actual key, we can't say whether it's the
silent-catch masking a parse gap or a genuinely malformed subkey.

**(b) The two-encryption-subkey design question.**
homehsu asked about supporting a second encryption subkey. This needs a
direction decision before the reply can commit to anything:

- **Option A — PQC-only (recommended).** One composite ML-KEM encryption
  subkey, no classical second encryption subkey. Simpler key shape, matches
  where the spec is heading, avoids the "which subkey did gpg pick" ambiguity.
- **Option B — optional classical second encryption subkey** alongside the
  composite one, for interop with recipients that can't do PQC yet. More
  flexible, more surface area, and raises encryption-subkey-selection questions.

**Decision needed from Kevin: A or B.** Recommendation stands at A (PQC-only).
Once decided, the reply can go out: ask for the public key on (a), state the
chosen direction on (b).

---

## 3. PGPonyCore #1 — ML-DSA composite signatures (reply drafted, ready to post)

The reply is already drafted and ready to post. It acknowledges that ML-DSA-65
+ Ed25519 (RFC 9980 ID 30) is a MUST and confirms it's planned, points to the
4.4.0 planning brief, and sets expectations (not urgent per the reporter,
delivery follows the new-feature order: Android → iOS → desktop).

- [ ] **Post the drafted reply to PGPonyCore #1.**

Planning context already written up (for the 4.4.0 session, not part of the
reply): scope is ID 30 committed / ID 31 (ML-DSA-87+Ed448, SHOULD) as a
stretch, SLH-DSA MAYs out of scope; open questions are BouncyCastle ML-DSA
composite-ID support, the RFC 9980 composite signature encoding, and signature
size impact on message/QR surfaces.

---

## Also queued (not for tonight)

- **iOS issue #4** — v6 key expiration must land on every subkey (signing
  subkey + PQ composite subkey), both generation and edit paths, with the
  embedded 0x19 back-signature on the signing subkey's binding. Fixed on
  Android + desktop; iOS still needs the Swift equivalent. Handoff doc written.

---

## 4. New tester issues, 2026-08-24

Two issues opened 2026-08-24. #50 shipped in RC3; #51 is committed to the 4.4.0
plan (see PLANNING_4.4.0.md) and still needs building.

- [ ] **#51 E-Mail key selection (RandomNam3, FairEmail).** On the first email,
  PGPony let them choose between their keys; after that the choice sticks and
  they can never switch to a different key for that email account. They want
  either a way to switch the key or to be offered the choice every time. Likely
  the compose/send path caches the first key picked per account and never
  re-prompts or exposes a change control. Fix direction: a key selector on the
  email send path with a persistent-or-ask option, or at minimum a "change key"
  control instead of a one-time lock-in. Committed to the 4.4.0 plan
  (PLANNING_4.4.0.md, "E-mail key selection on the send path").

- [x] **#50 Fingerprint-protect the security toggles (CertainBot). Shipped in
  RC3.** Biometric lock and require-fingerprint-to-sign are now gated behind a
  biometric confirm in both directions (SettingsScreen.guardSecurityChange),
  falling through only where no biometric is enrolled so nobody is locked out of
  their own switch.

---

## 5. Composite ML-DSA completeness (4.4.0 RC4) — DONE

Passphrase protection (sign + decrypt gated), decryption to composite-primary
keys (ML-KEM subkey read packet-level, threaded through crypto.decrypt), and
composite private-key export/backup carrying the protected form. Composite
ML-DSA is now a full key type: sign, decrypt, passphrase, export. Passphrase
tested on device; decrypt/export tested via unit tests, on-device interop pending.

Scheduled for RC4. RC3 hides the Change passphrase row for composite ML-DSA
signing keys (algo 30/31) because they are stored as raw OpenPGP bytes,
unprotected by an OpenPGP passphrase, and the BouncyCastle re-protection path
cannot touch them. RC4 makes a passphrase actually work on these keys.

Why it is not a small change: the composite secret is stored as raw fixed-length
material with the s2k-usage octet at 0 (CompositeKeyFacade reads exactly that
form). Protecting it means encrypting that material and teaching every reader to
decrypt it with the passphrase, across storage, the facade, and the sign path.

Plan:

- Protection format. Encrypt the composite secret material (primary ML-DSA+EdDSA
  and the ML-KEM subkey secret in the same ring) with OpenPGP v6 secret-key
  protection: s2k-usage 253 (AEAD, e.g. OCB) with the app's existing S2K default
  (iterated-salted type 3, Argon2 opt-in, matching 4.3.2), writing usage octet +
  s2k specifier + AEAD params + nonce + ciphertext + tag in place of the usage=0
  plaintext. Public key, fingerprint, and signatures are unchanged, so interop
  and the v6 fingerprint are untouched.
- New CompositeSecretProtection helper: protect(rawSecret, passphrase, s2k) and
  unlock(protectedBytes, passphrase). Unit-test the round-trip on a byte vector.
- CompositeKeyFacade.secretMaterial: when usage != 0, decrypt via the helper
  using a passed passphrase instead of returning null. Thread an optional
  passphrase through parse()/loadCompositeKeyInfo.
- Sign path: CompositeDocumentSigner and the composite sign branch in
  EncryptDecryptViewModel need the passphrase to unlock before signing, with the
  same passphrase prompt / in-app cache the decrypt path already uses.
- changePassphrase: branch on isCompositeSign in KeyRepository to a composite
  path that reads the raw bytes, unlocks with the old passphrase (or reads
  unprotected), re-protects with the new one (blank = strip), and stores. Then
  re-enable the Change passphrase row and its overflow item for composite keys
  (revert the RC3 gate in KeyDetailSections and KeyDetailScreen).
- Backup/export: exportArmoredPrivate for composite keys should carry the
  protected form so a backup keeps its passphrase, same as other key types.

Test matrix: set a passphrase, sign and verify under it, change it, sign again,
remove it; confirm a protected key survives export and re-import; confirm the
public key and A.3 vectors still verify unchanged.
