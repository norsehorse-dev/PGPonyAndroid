# PGPony 4.5.0 planning

Status: planning. Feature and fix list for the 4.5.0 cycle. Android leads, then iOS,
then desktop, per the new-feature procedure (a genuinely new capability is built on
Android first, then ported). Most items came out of the 4.4.x tester cycle, chiefly
Umotas (#36) and elnardosa's multi-item report (#55).

versionCode: the next free value in the 4xx band above whatever ships last on the 4.4
line (4.4.1 is 434; a 4.4.2 detection release, if taken, is 435).

Two items below (5, ML-KEM/RSA label detection) are small, self-contained fixes that
can be pulled forward into a 4.4.2 instead of waiting for this cycle. Flagged inline.

---

## 1. Post-quantum-only key option

Priority: high. Origin: Umotas (#36).

Interop-tier note (added from #56): the two variants below are both v6 keys. RFC 9980 also allows a
third, more interoperable shape, specified in item 14: a v4 Ed25519 primary with a v4 ML-KEM-768+X25519
(algorithm 35) encryption subkey. Fold all three into one keygen choice organized by key-version /
interop tier, with the v4 interop shape as the recommended default. See item 14.

Today's ML-KEM keygen grafts a composite ML-KEM+ECDH encryption subkey onto an Ed25519
base that already carries a classical X25519 encryption subkey, so a generated key ends
up with TWO encryption subkeys: the composite (post-quantum) and a standalone plain
X25519 (classical). The composite subkey is itself hybrid (ML-KEM combined with an ECDH
curve, secure if either half holds), so it already provides the classical safety net on
its own. The extra standalone X25519 subkey adds nothing to security and is a downgrade
path: a sender that encrypts to every encryption subkey (sq does this by default, as
seen in the #36 dumps) wraps the session key under the breakable X25519, so the message
is not post-quantum confidential even though the PQ subkey is present.

Work:

- Add a keygen choice: "post-quantum only" vs "compatibility". PQ-only omits the
  standalone classical encryption subkey, leaving only the composite ML-KEM subkey.
- The current base builders (buildV6Ed25519X25519KeyRings, buildEd25519KeyRingGenerator)
  add an X25519 encryption subkey before CompositeKeyGen.addCompositeSubkey grafts the
  composite. PQ-only needs a base with a signing/certification primary and NO classical
  encryption subkey, or a step that strips it before the ring is finalized.
- Label both variants at generation with the plain interop tradeoff: PQ-only is
  encryptable only by PQ-capable tools; compatibility can be received by classical-only
  tools at the cost of a downgrade path.

Decided: a PQ-only key is a FULL post-quantum certificate: a composite ML-DSA signing
primary (already available since 4.4.0) plus a composite ML-KEM encryption subkey, and
no classical signing or encryption key at all. Not just PQ encryption on a classical
signing primary. Compatibility stays the default at generation; PQ-only is the deliberate
choice, since most correspondents are still classical.

Research and unknowns:

- The ML-DSA keygen already produces a composite signing primary with an ML-KEM
  encryption subkey. Confirm whether it ALSO adds a standalone classical X25519
  encryption subkey (like the ML-KEM keygen does); if so, PQ-only must omit it there too.
- Confirm PGPony's own send path already prefers the composite subkey over a classical
  one when a key has both (findEncryptionKey checks the composite first, so this looks
  correct, but verify).

Delivery: an sq inspect of a PQ-only key shows only the composite ML-KEM encryption
subkey and no standalone X25519; confirm no classical encryption target exists to
downgrade to. Round-trip encrypt/decrypt against gpg 2.5.x and sq.

Status (Sep 9 2026): the PQ-only crypto shape already EXISTS. Investigation confirmed the two
shapes are two already-offered algorithms: MLDSA65_ED25519_V6 (generatablePostQuantum) is the v6
PQ-only shape (CompositePrimaryKeyGen.assemble emits a composite ML-DSA signing primary and exactly
ONE composite ML-KEM-768+X25519 encryption subkey, algo 35, the X25519 fused into the composite, and
NO standalone classical encryption subkey), while MLKEM768_X25519_V6 / MLKEM1024_X448_V6 are the v6
compatibility shape (Ed25519 classical signing primary + a standalone X25519 encryption subkey +
the composite ML-KEM subkey = two encryption subkeys, the classical one being the downgrade path).
Done this slice: a PQ-only invariant test (CompositePrimaryKeyGenTest: assembled ring has exactly one
tag-7 subkey and it is algo 35, so a later classical-subkey graft here is caught), and the two keygen
captions now state the interop tradeoff plainly (pqc_sign = no classical fallback, nothing to
downgrade, PQ-tools only; pqc_ietf = keeps a classical fallback subkey so classical-capable tools can
still encrypt, at the cost of a downgrade path). REMAINING for item 1: fold the shapes into one
interop-tier keygen choice with item 14's v4 shape as the recommended default (blocked on item 14
wiring); on-device sq/gpg round-trip of a PQ-only (MLDSA65) key.

On-device VERIFIED Sep 14 2026 (RC4 foss debug, moto g play): both shapes generate the correct key material, confirmed in Key Details. PQ-only (MLDSA65_ED25519_V6): composite ML-DSA signing primary plus exactly one ML-KEM-768 (algo 35) encryption subkey, NO standalone classical X25519 encrypt. Compatibility (MLKEM768_X25519_V6): Ed25519 v6 signing plus TWO encryption subkeys, a standalone X25519 v6 (classical downgrade path) and the composite ML-KEM-768 v6. The standalone-X25519 presence/absence is the clean UI-visible differentiator; external sq/gpg inspection stays best-effort only because this Mac's sq is non-PQC and gpg 2.5.21 has no algo-35 parser.


## 2. Mixed-recipient post-quantum warning

Priority: medium-high. Origin: Umotas (#36).

Status (done, RC3): PGPCryptoService.isPostQuantumRecipient(ring) classifies a recipient by the encryption key encrypt() would actually pick (findEncryptionKey) — composite ML-KEM (IETF algo 35/36) or LibrePGP composite (algo 8) is PQ, everything else classical — so the label matches what goes on the wire. EncryptDecryptViewModel.recomputePqWarning reclassifies the selected set off the main thread on every recipient change and sets EncryptUiState.pqMixedWarning (naming the classical recipients) only when the set mixes PQ and classical; RecipientPickerCard renders a non-blocking errorContainer banner (shared by the text, file, and bundle flows), informational, never a hard block. MixedRecipientPqTest covers PQ vs classical classification and the mixed / uniform / single rules. Placement chosen: inline under the recipient chips (pre-send), not a result sheet.

OpenPGP wraps one session key per recipient, so a multi-recipient message is only
post-quantum confidential if every recipient has a PQ(/T) encryption key. One classical
recipient makes the whole message recoverable by a future quantum attacker through that
recipient.

Work:

- At encrypt time, classify the encryption key chosen for each selected recipient as
  PQ(/T) or classical.
- When a single message mixes PQ and classical recipients, show a non-blocking warning
  that names the classical recipient(s), so the weak link is visible before sending.
- Keep it informational, not a hard block; the user may still have a legitimate reason.

Research and unknowns:

- Copy and placement of the warning (result sheet vs pre-send).
- Interaction with the PQ-only key work (item 1): a PQ-only sender adding a classical
  recipient is the same situation.

Delivery: the warning fires on a mixed recipient set and stays silent on an all-PQ set.


## 3. Email-less key generation

Priority: medium. Origin: user request (relayed in the 4.4.x cycle).

An OpenPGP User ID is a free-form string; the "Name <email>" shape is a convention, not
a requirement, and RFC 9580 v6 even allows a key with no User ID at all. PGPony hardcodes
the User ID as "$name <$email>" in PGPCryptoService, CardKeygenService, and KeyRepository,
so a key without an email cannot be generated today.

Work:

- Make the email field optional in the keygen UI.
- UID assembly: emit just the name when the email is blank (no angle brackets), or
  "<email>" when only an email is given.
- Handle the no-email case downstream: recipient matching by email, key display, contact
  identities, the OpenPGP API provider's sendIdentityEmail derivation, keyserver-by-email
  lookup, and WKD publish (WKD needs an email, so a name-only key cannot publish there;
  disable and explain rather than fail).

Decided: support BOTH a name-only User ID and a fully UID-less v6 key (identified by
fingerprint alone). Name-only is the interoperable default; UID-less is offered for
people who want no identity string at all, and relies on RFC 9580 v6 allowing a
certificate with no User ID (metadata carried by a direct-key self-signature).

Research and unknowns:

- The UID-less v6 path needs a direct-key self-signature to carry key flags and expiry
  in place of a User ID binding signature. Confirm BouncyCastle can build a v6 key with
  no User ID, or hand-assemble the direct-key signature.
- gpg historically dislikes UID-less keys; verify interop, and keep name-only as the
  recommended option in the UI.

Delivery: generate a name-only key; confirm it imports and round-trips in sq and gpg;
encrypt, sign, and decrypt by fingerprint; confirm mail-client integration degrades
gracefully (no address to match on, manual key pick).

Status (Sep 9 2026): name-only path DONE (the interoperable default); UID-less v6 deferred.
PGPKeyEntity gained composeUserID(name, email) — the inverse of parseUserID: "Name <email>"
when both present, just the name when email is blank, "<email>" when only an email, "" when
neither. Every keygen UID-assembly site now routes through it (PGPCryptoService.generateKeyPair,
CardKeygenService, KeyRepository classical + composite-signing), so a blank email no longer emits
empty angle brackets. parseUserID also now handles the "<email>" shape. Keygen validation
(KeyringViewModel.generateKey) makes email optional: blank is allowed, a non-blank address must
still contain "@" (new string keyring_error_email_invalid). The Email field label is now
"Email (optional)" in both the Keyring generate sheet and onboarding. Downstream verified safe on
empty email: list/detail display and sign-as fall back to the fingerprint via ifBlank, the OpenPGP
provider matches by email so a name-only key simply doesn't match an address lookup (no crash),
keyserver upload is by key material, and WkdService is lookup-only (no publish path to disable).
Follow-up (Sep 9): a name-only (email-less) key no longer triggers the post-keygen key-server publish
prompt (KeyringViewModel gates pendingPublishFingerprint on generated.userEmail being non-blank), since
key servers discover by email and there is nothing to publish.

DEFERRED: the fully UID-less v6 certificate (direct-key self-signature carrying flags/expiry) still
needs BC build confirmation and gpg interop; name-only stays the recommended shape regardless.
On-device: generate a name-only key, confirm it appears (fingerprint as the identity), and that
encrypt/sign/decrypt and keyserver upload all work; import into sq/gpg to confirm round-trip.


## 4. Composite ML-DSA multi-User-ID support

Priority: medium. Origin: elnardosa (#55, report item 3).

Composite ML-DSA keys are hand-managed by CompositeKeyFacade because BouncyCastle cannot
hold algo-30/31 keys. The parser already reads every User ID, but the stored and
displayed record keeps only the first, and adding a User ID needs a composite ML-DSA
self-certification that BC cannot produce.

Work:

- Display: store and show all User IDs for a composite key (parse already returns the
  full list).
- Add User ID: build a User ID packet plus a positive-certification self-signature made
  with the composite ML-DSA primary, reusing the composite signature assembly from
  CompositePrimaryKeyGen's binding signatures / CompositeDocumentSigner.
- Primary-UID selection and UID revocation as follow-ons if needed.

Research and unknowns:

- The exact hashed-subpacket layout for a composite self-certification over a UID, and
  the signing target/hash. Mirror the binding-signature construction already in use.

Delivery: import a multi-UID composite key and see every UID; add a UID and confirm sq
and gpg accept the certification.

Status (Sep 8 2026): crypto core done and green. CompositePrimaryKeyGen.addUserId builds the UID
packet plus a composite 0x13 positive certification and splices it before the subkey;
CompositeAddUserIdTest verifies the added cert with CompositeSigVerifier and that both UIDs parse.
The same compositeSignaturePacket primitive is what items 16 (0x28 revocation) and 7 (0x18 binding)
reuse. Display gap also fixed: deriveUserIds now reads a composite key's User IDs from
CompositeKeyFacade (it is not a BC ring), so all of them show. Wiring done and green: repo.addUserId
now routes a composite key to CompositePrimaryKeyGen.addUserId, re-protects if it had a passphrase,
and re-stores the raw bytes plus the re-derived public ring, so the add-UID button works on composite
keys. Follow-ons only: makePrimary (primary-UID selection) and composite UID revocation.


## 5. Key-algorithm label detection (ML-KEM-1024, RSA size) (moved to 4.4.1)

Shipped in 4.4.1: single-arg detectAlgorithm now reads the LibrePGP composite curve to
label ML-KEM-1024 vs 768, and reads the RSA modulus size (RSA_3072/RSA_8192 added) instead
of defaulting to 4096. Kept here for the record; no 4.5.0 work.

Original note (elnardosa, #55, items 1 and 2):

KeyAlgorithm.from() and detectAlgorithm classify by the OpenPGP algorithm number, which
does not carry the ML-KEM level (LibrePGP v5 768 and 1024 both use algo 8) or the RSA key
size (all RSA share algo 1/2/3). So a v5 ML-KEM-1024 key is labeled 768 and an RSA 8192
key is labeled 4096. The key material is correct in both cases; only the label is wrong.

Work:

- ML-KEM v5: in detectAlgorithm (which has the key material), distinguish 768 from 1024
  by the composite subkey's curve OID (X25519 vs X448, plus brainpoolP384) and Kyber
  length, instead of delegating to from(8, v5), which defaults to 768.
- RSA: read the modulus bit length; add RSA_8192 (and RSA_3072) to KeyAlgorithm; map by
  bitLength rather than algorithm number.

Delivery: import known v5 ML-KEM-1024 and RSA-8192 keys and confirm the labels; confirm
no regression on 768 and 4096.


## 6. Custom key server repositories

Priority: high. Origin: requested by more than one user (#55 feature 1, plus a separate
request). Parity with the desktop version. Bumped from medium given the repeat demand.

Status (implemented, RC2): the directory backend already stored an ordered, user-editable list (KeyServerDirectory in DataStore) and both lookup (KeyServerRepository.directoryLookupServers) and publish (MultiKeyServerService against an arbitrary KeyServer.baseUrl, via the proxy-aware client) already iterated it, so custom servers ride the offline/Tor switch for free. Added the missing pieces: KeyServerDirectory.addCustom / remove / isSeed and a pure, testable normalizeBaseUrl (defaults https, keeps scheme://host[:port], rejects non-http(s)/junk, dotless host only with an explicit port); KeyserversScreen now has an Add-key-server dialog (label + URL, inline validation) and a delete action on custom (non-seed) servers; the two seeds stay protected (toggle, not remove). KeyServerUrlValidationTest covers the normalizer.

On-device VERIFIED Sep 14 2026 (RC4 foss debug, moto g play): custom-server add/lookup/publish all work. Added keyserver.ubuntu.com as a custom (non-seed) entry; it takes a delete action while the two seeds keep toggle-only. A fresh fake-email key published to ubuntu cleanly; the real long-lived key A0CB..DE62 published to both seeds (openpgp.org VKS + pgpony.app VKS) and, on RETRY, to ubuntu too. First ubuntu attempt on the real key threw okhttp "unexpected end of stream" (transient, retry succeeded). ROBUSTNESS GAP found (not a blocker, feature works): publish() tries VKS then HKP, but a connection-level throw during the VKS probe (full key body POSTed to a non-VKS Hockeypuck server that resets rather than draining a large body) hits the outer catch and aborts, so the HKP fallback never runs; and the catch returns PublishOutcome.Failed(e.message) which leaks the raw okhttp Address hashcode to the UI. Also found: normalizeBaseUrl accepted only https/http and REJECTED hkps:// (and hkp://), even though its own doc claimed HKPS/HKP support and hkps:// is the canonical form keyserver docs hand out; KeyServerUrlValidationTest had even baked in the wrong spec (asserted hkps:// rejected). FIXED for RC5: normalizeBaseUrl now maps hkps->https and hkp->http (hkp defaults to port 11371), rejecting only truly unknown schemes; test updated with hkps/hkp mapping cases. Publish hardening also landed for RC5: publish() now runCatching-wraps the VKS probe so a thrown connection error falls through to HKP (was aborting the whole publish), HKP add retries once on a dropped connection, and failures return a sanitized friendlyPublishError (host + "check your connection") instead of leaking the raw okhttp Address string. Re-verify on RC5: hkps:// entry accepted, and a large real key publishes to a custom HKP-only server without a manual retry.

KeyServerRepository uses a fixed set of lookup sources (WKD, keys.openpgp.org,
keys.pgpony.app, the directory). Desktop lets the user add their own key servers.

Work:

- Settings UI to add, remove, and reorder custom key server entries.
- Persist the list and fold it into the KeyServerRepository lookup and upload paths.
- Route custom servers through the same shared client so the offline switch and proxy
  settings apply.

Research and unknowns:

- Which protocols to accept (HKPS, VKS/Hagrid, WKD). URL validation for user input.

Delivery: add a custom HKPS server, then look up and upload a key through it.


## 7. Granular key creation and post-quantum subkeys on existing keys

Priority: medium. Origin: elnardosa (#55, feature 2).

Add-subkey exposes classical algorithms only (ClassicalSubkeyGen), even though
CompositeKeyGen.addCompositeSubkey already grafts a post-quantum composite subkey at
generation time. Two asks: attach PQ subkeys to an existing certificate, and a granular
mode that lets the user pick the exact subkey set.

Status (DONE): all five slices green. Composite ML-KEM encryption subkey on an existing v6 key
(addCompositeEncryptionSubkey), on a v4 key (converts to the RFC 9980 interop shape, with a
loadSecretKeyRing base-ring fallback so signing/classical-decrypt survive), composite ML-DSA signing
subkey (CompositeSignSubkeyGen, 0x18 + embedded 0x19 back-sig), a unified AddSubkeyChoice threading
classical + PQ types through the Add Subkey sheet, and advanced granular keygen (pick primary, strip or
keep the default encryption subkey, compose the exact subkey set) with an Advanced toggle. Tests:
CompositeAddSubkeyV6/V4Test, AddSubkeyChoiceTest, GranularKeygenTest.

Work:

- Expose PQ subkey grafting in the add-subkey UI (ML-KEM-768/1024 composite encryption,
  and possibly ML-DSA signing) via the existing addCompositeSubkey path.
- Advanced granular keygen behind an Advanced toggle: choose the primary and each subkey
  (algorithm, capability flags, expiry) explicitly.

Research and unknowns:

- Adding a subkey to a composite ML-DSA primary needs a composite self-signature to bind
  it (same machinery as item 4), since the primary is hand-managed.
- Scope of the granular UI: how much to expose without overwhelming the default flow.

Delivery: add an ML-KEM subkey to an existing Ed25519 key, encrypt to it, and verify in
sq; generate a key with a hand-picked subkey set.


## 8. Key generation publish prompt: offline suppression, clearer skip, and pgpony.app opt-out

Priority: medium-high (privacy). Origin: 4.4.x feedback.

The publish-to-key-server prompt is part of the KEY GENERATION flow, not onboarding
itself. It shows after a key is generated, in both the onboarding generate sheet and the
regular Keyring key generation, so these fixes apply to the keygen flow wherever it runs.
Three related fixes:

- Offline mode must suppress the publish prompt. While offline mode is on, keygen still
  offers to publish the new key to key servers. That contradicts the offline guarantee
  and must not appear. Gate the prompt on OfflineMode.isEnabled().
- Clearer skip when online. When not in offline mode, the publish step needs an obvious,
  unambiguous skip or "Not now" control so someone who does not want to publish can move
  on without hunting for it.
- Let users disable the pgpony.app publish suggestion. The prompt points people at the
  pgpony.app key server (keys.pgpony.app) as a place to publish. Add a way to turn that
  suggestion off, so keygen does not push anyone toward publishing to a server, in
  keeping with the app's no-server default posture.

Work:

- Locate the post-keygen publish/keyserver prompt in the generation flow (shared by the
  onboarding generate sheet and the Keyring keygen) and gate its visibility on OfflineMode.
- Add a prominent Skip or "Not now" control for the online case.
- Add a setting that disables the pgpony.app publish suggestion, and persist it.

Delivery: with offline mode on, no publish prompt appears after keygen anywhere; with
offline mode off, the publish step has a clear skip; the pgpony.app suggestion can be
turned off and stays off.

Status (Sep 9 2026): done, all three fixes. The post-keygen prompt is set in
KeyringViewModel.generateKey (pendingPublishFingerprint), shared by the onboarding sheet and the
Keyring keygen. A new shouldOfferPublish() gate now controls it: it returns false when
OfflineMode.isEnabled() (offline suppression) and false when the "offer_publish_after_keygen" pref
is off (the opt-out), so with offline on no prompt appears anywhere. PublishSheet gained an explicit
"Not now" TextButton below Publish (string publish_not_now) so the online prompt has an unambiguous
skip rather than tap-away dismiss; the sheet is shared with Key Detail where the button reads as a
plain dismiss. The opt-out is a persisted SettingsToggle ("Offer to publish new keys") in the Key
Management section, backed by SettingsViewModel.offerPublishAfterKeygen /
setOfferPublishAfterKeygen on the "offer_publish_after_keygen" pref (default true = prior behavior),
read by KeyringViewModel from the shared pgpony_prefs. On-device: with offline on, generate a key
and confirm no publish sheet; with offline off, confirm the "Not now" skip; toggle the setting off,
generate, and confirm the sheet stays suppressed across app restarts.


## 9. Korean localization (DEFERRED to a later build)

Status (Sep 12 2026): DEFERRED out of 4.5.0. The contributed translation is still short of the app's
current string set, so Korean stays dormant exactly as it shipped: res/values-ko/strings.xml is present
but "ko" is NOT in locales_config.xml and KO is NOT in SupportedLanguage, so it does not appear in either
language picker. No code change was needed to defer, and no release-notes "eighth language" line. Revisit
once the translation is topped up (the enable steps below still apply then).

Origin: community translation (PGPony-Translations PR #1, nuraqueer). The contributed
file is only ~22% translated (302 of 1389 strings; the rest English, 33 keys absent), so
Korean is NOT in the language picker or locales_config. The res/values-ko/strings.xml
ships dormant in 4.4.1, ready to enable later.

Work for 4.5.0:

- Get the translation to a shippable level (ask nuraqueer / the community to complete it,
  and top up the ~33 missing keys from the 4.4.x additions).
- Re-add KO to SupportedLanguage and "ko" to locales_config.xml to surface it in both
  pickers, and restore the release-notes "eighth language" line.
- Push the &nbsp; -> \u00A0 fix upstream to PGPony-Translations.

Korean is PGPony's eighth language. The translation was contributed and merged into
PGPony-Translations, then pulled into the app: android/values-ko/strings.xml copied to
res/values-ko/, KO added to SupportedLanguage, and "ko" added to locales_config.xml.

Coverage: 1390 strings, which is 100% of the translation base but about 91% of the app's
current 1422 strings; the roughly 32 newer strings (4.4.x additions) fall back to English
until the next translation sync.

Work:

- Build and let Android lint validate the Korean resources (format-arg parity, escaping).
- Top up the missing ~32 strings on the next PGPony-Translations sync.
- On-device check of the Korean UI, especially long strings and the language picker.

Delivery: Korean selectable in the in-app language picker and the system per-app language
list; UI renders in Korean with English fallback only for the not-yet-translated strings.


## 10. Offline mode toggle at the top of Settings > Security

Priority: low (UX). Origin: user request.

The offline mode switch is in the Security section of Settings but not at its top. Move it
to the first row of that section so the privacy-hardening switch is the first thing a user
sees there, matching how central the feature is to the app's posture.

Work:

- Reorder the Security section in SettingsScreen so the offline toggle
  (settings_offline_toggle_*) is the top item, above the other security rows.

Delivery: the offline mode toggle appears first under Settings > Security.

Status (Sep 9 2026): done. The offline SettingsToggle now renders immediately after the
Security SectionHeader, above the biometric-lock row; the rest of the section is unchanged.


## 11. Security hardening (Cipher review)

Priority: HIGH. Origin: private security review by Cipher, under embargo. Full detail,
exact sites, code, and test plans live in PGPony_Security_Hardening_Plan.md; this item just
tracks it as part of the 4.5.0 cycle. Three findings reproduce in the live app.

- Finding A [High] Unbounded Argon2 memory on decrypt. A crafted password-encrypted
  message can set an Argon2 memory exponent that forces a multi-GiB to TiB allocation
  before the passphrase is even checked, OOM-killing the app. Pre-authentication DoS. Fix:
  an enforceArgon2Policy guard (hard memory/passes/parallelism ceilings plus a
  device-relative heap-fraction check) before every SKESK getDataStream and every
  secret-key unlock.
- Finding B [High] Decompression bomb. The decrypt path recurses into compressed packets
  with no depth cap and reads the literal stream with no size cap, and the integrity check
  runs only after the full plaintext is read, so a small zlib bomb inflates to gigabytes
  (OOM) and deep nesting overflows the stack. Pre-authentication DoS. Fix: a depth cap and
  a total-bytes cap threaded through processDecryptedContent, streamDecryptedContent, and
  the card readLiteralAndVerify.
- Finding C [Medium] Verify ignores revocation, expiry, and key flags. A signature from a
  revoked, expired, or non-signing key still shows Verified. Fix: an evaluateSigner checker
  returning a SignerStatus (VERIFIED / REVOKED_KEY / EXPIRED_KEY / NOT_SIGNING_KEY /
  UNKNOWN_SIGNER / INVALID), wired into both the decrypt-verify path and VerifyService's
  clear-signed path, staged behind the existing signatureVerified boolean plus new UI
  badges.
- Finding D [Low] Distinguishable SEIPDv1 (MDC) decrypt errors. A session-key quick-check
  failure surfaces as a different error type than an MDC failure, a weak many-query CFB
  oracle (not a practical break, MDC stripping is already defeated). Fix: collapse every
  SEIPDv1 decrypt failure into one error type, as the symmetric path already does. From the
  family disclosure (item 1.4); not among the hardening plan's three, so add it there too.

Info, not blocking: no zeroization of passphrases and private keys (Java string immutability
makes this a real hardening direction, not a one-line fix); the card ECDH length parse trusts
message lengths but only throws a caught IndexOutOfBoundsException, so it is benign, though a
defensive bound would be tidy.

Already cleared on Android (per the disclosure, reassuring context): the SEIPDv2 integrity
gate is unconditional, so the Swift core's truncation-authentication bypass does NOT
reproduce here; RNG failures cannot slip through (fresh SecureRandom throughout); the
truncated-deflate infinite loop is handled by the JVM's EOFException; BC's MDC compare is
constant-time; and every sig.verify() return is consumed. So the Android surface is the four
findings above (2 High, 1 Medium, 1 Low), smaller than the Swift core's seven.

Shared scaffolding (lands with Finding A, reused): a SecurityLimits object holding every
ceiling in one place, and a new PGPCryptoError.ResourceLimitExceeded typed error. Guiding
constraint: no legitimate message may start being rejected, so every bound sits above real
GnuPG / Sequoia / PGPony values; fail closed with a typed error, never a crash.

Sequencing: A, then B, then C (worst first).

Progress (Sep 8 2026): Finding A implemented in RC1 and green (compile + crypto unit suite).
SecurityLimits object and PGPCryptoError.ResourceLimitExceeded added; enforceArgon2Policy reads the
S2K memory exponent / passes / parallelism via BC 1.85 getters (verified against BC source) with a
device-heap floor at our own 64 MiB so no legitimate message is rejected; enforceSkeskArgon2Policy
pre-scans the SKESK before getDataStream runs the KDF; wired into decrypt() and all five secret-key
unlock sites (two signing paths, sign(), the PKESK trial, changePassphrase); Argon2PolicyTest added.
The SecurityLimits ceilings (m=22 hard, m=16 self-floor, passes/parallelism 64, heap fraction 0.5)
are the open decision below and are set conservatively. Finding A is now complete: the streaming decryptStream() path guards the SKESK from its bounded
64 KiB message head (enforceSkeskArgon2Policy(head)) before the KDF runs.

Finding B implemented in RC1 and green. MAX_DECOMPRESSION_DEPTH (8), MAX_MESSAGE_PLAINTEXT_BYTES
(128 MiB, in-memory), and MAX_STREAM_PLAINTEXT_BYTES (8 GiB, streaming) added to SecurityLimits; a
depth counter and a per-loop byte cap are threaded through processDecryptedContent,
streamDecryptedContent, and the card readLiteralAndVerify, each throwing ResourceLimitExceeded past
the cap. No dedicated bomb unit test yet; the existing ZLIB round-trips cover the happy path. RC1
code is complete (items 12, 18, 11A, 11B); pending an on-device build and test (chiefly WundreLust's
two-key decrypt for item 18, now covered by a 768 + 1024 unit test). The decryptStream() SKESK guard
for Finding A is closed.

Finding C implemented (RC2). SignerStatus enum + SignerEvaluator (evaluate/isExpiredAt/hasSignFlag) added; grades a crypto-valid signature against revocation (PGPPublicKey.hasRevocation on primary and signing key), expiry (validSeconds vs the signature creation time, so a signature made while the key was valid stays trusted), and the CAN_SIGN key flag (a key with no flags subpacket is treated as sign-capable, so no legitimate message is rejected). Wired into processDecryptedContent and streamDecryptedContent (signerStatus added to DecryptResult/DecryptStreamResult; signatureVerified is now signerStatus == VERIFIED, the staged shim) and into all three VerifyService verify paths (revoked/expired/non-signing downgrade to Invalid with a reason). SignerStatusTest covers VERIFIED / UNKNOWN_SIGNER / NOT_SIGNING_KEY / REVOKED_KEY / EXPIRED_KEY. Remaining for a later UI pass: distinct revoked/expired/not-signing badges (decrypt path already carries the precise SignerStatus; clear-signed path currently shows Invalid+reason).

Finding D implemented (RC2). In BC 1.85 the SEIPDv1 quick-check does not throw at getDataStream; a corrupted CFB block surfaces later as a parse-level DecryptionFailed while an MDC failure surfaces as IntegrityCheckFailed at the gate, so the two were a distinguishable pair. Fix: on the public-key path, when the container is integrity-protected (SEIPD, not usedSymmetric), the processDecryptedContent / streamDecryptedContent call is wrapped so ANY parse failure collapses into the SAME IntegrityCheckFailed (same message) the MDC gate throws. The symmetric path keeps its wrong-passphrase remapping; the ResourceLimitExceeded DoS cap stays a distinct size-only signal. Seipdv1TamperTest: clean round-trip; a tail (MDC) tamper -> IntegrityCheckFailed; and a first-block (quick-check region, located by a packet walk) tamper -> the same IntegrityCheckFailed, so early and late corruption are indistinguishable. All four hardening findings (A/B/C/D) now implemented; RC2 hardening pending device build + unit run.

Open decisions (hardening plan section 6): the exact Argon2 ceilings, the streamed-file
cap approach, whether SignerStatus is a new enum or folds into VerificationResult, and
whether VerifyService is in scope this pass. Several BC 1.85 accessors are tagged [confirm
at build].

Embargo: keep public release notes generic ("input-bounding and verification hardening")
until Cipher opens the window; credit and link only then. Keep all fixes on NorseHorse's
own commits per the repo authorship rules.

Note: these are the two highest-severity items in 4.5.0 (pre-auth DoS). If the 4.5.0 cycle
runs long, A and B are worth pulling into a dedicated hardening release sooner.


## 12. Decrypt to imported composite ML-KEM keys

On-device VERIFIED Sep 14 2026 (RC4 foss debug, moto g play): the committed sq fixtures, armored and pushed to the phone, imported and decrypted end to end through the UI. Unprotected (sq-sec/sq-msg) and passphrase-protected (sq-sec-protected/sq-msg-protected, passphrase pgpony-test) both returned plaintext, no "no held composite secret key". Single-recipient imported-composite decrypt is good on device; multi-recipient stays on the separate #57 / item 18 track.

Priority: HIGH. Origin: issue #36 (Umotas), surfaced in the 4.4.1 RC1 verification.

Report: keys generated in sequoia-sq (ML-KEM 768 and 1024, i.e. an ML-DSA composite primary
plus an ML-KEM encryption subkey), imported into PGPony, cannot decrypt files SQ encrypted to
them. The error is "no held composite secret key for recipient <subkey-fp>", thrown from
CompositeDecryptor.recover once both the BouncyCastle-ring lookup and the raw-composite lookup
miss. The message parses fine as a composite PKESK; PGPony just finds no held key whose ML-KEM
subkey fingerprint matches the recipient. It fails identically for 768 and 1024.

Not a 4.4.1 regression. The 4.4.1 work was encrypt-side (loading a composite key as a
recipient) and the AEAD chunk size. The decrypt path for imported composite keys was untouched
and behaved this way before 4.4.1. Confirmed working in the same RC1 test: the AEAD size fix
(PGPony now writes 65536-byte chunks, output smaller than SQ's) and encrypt-to-composite (a
PGPony-generated ML-DSA-65 key encrypts a file SQ opens cleanly).

Root cause is one of two, not yet pinned (needs an actual SQ key, or a generated equivalent,
plus a unit test):

- a. The imported key is not reaching the raw-composite list CompositeDecryptor searches.
  compositeRings in EncryptDecryptViewModel is built from orderedKeys filtered by
  isCompositeSign, then loadCompositePrivateRing. If the stored algorithm, that filter, or
  loadCompositePrivateRing drops the key, the list is empty and this exact error follows.
- b. The subkey v6 fingerprint PGPony computes from SQ's packet layout does not byte-match the
  fingerprint carried in SQ's PKESK, so findRawComposite's contentEquals never hits.

Both explain the identical 768/1024 failure (a loading or matching bug, not a suite-specific
one). The suite-mismatch and missing-secret throws in openRaw sit further down the path and are
not what fired.

Fix plan: first reproduce in-tree. Generate ML-KEM 768 and 1024 composite keys with sq-pqc,
import them, and add a decrypt round-trip test (SQ encrypt, PGPony decrypt). Then confirm
whether compositeRings arrives empty (a loading bug) or populated-but-non-matching (a
fingerprint bug), and fix the identified stage. Keep the anonymous (gpg -R) raw-composite trial
path working.

Status (Sep 8 2026): reproduction test CompositeImportedDecryptTest added and green. With the committed
SQ fixtures (sq-sec.pgp / sq-msg.pgp, a real mldsa65 / ML-KEM-768 key), an imported composite key
DECRYPTS correctly via the raw path when its raw ring is handed to decrypt() with compositePrimaryRings.
That rules out candidate b (fingerprint mismatch) for the 768 fixture: the composite core is not the
problem. So item 12 does NOT reproduce on this fixture in the current tree, meaning either the raw path
already handles it or Umotas's specific key differs (a newer sq-pqc version, ML-KEM-1024, or a protected
key). A self-generated composite-primary control and the protected SQ variant are covered too. To close
it for Umotas: confirm against his actual failing key/message (his RC1 dumps) or fresh sq-pqc 768/1024
fixtures; if those pass, item 12 is resolved and only needs a tester re-verify.

Status (Sep 9 2026): the PROTECTED sq variant (sq-sec-protected.pgp / sq-msg-protected.pgp) did
reproduce a real failure, and it is now fixed. Root cause: CompositeSecretProtection hardcoded the
OpenPGP packet tag bound into the OCB AEAD associated data as 7, because PGPony historically protects
even the composite PRIMARY as a subkey (tag 7). Sequoia protects the primary with the real primary tag
(5), so unlocking an imported sq protected composite primary authenticated against tag 7 and failed OCB.
Fix: decryptProtected now tries AAD tags [7, 5] in order; a wrong tag fails OCB's authenticated tag and
never yields wrong plaintext, so the fallback is safe. CompositeImportedDecryptTest sq-protected now
exercises this. This upgrades item 12 from "does not reproduce" to "protected variant reproduced + fixed".


## 13. Subkey selector for encrypt and decrypt

Priority: MEDIUM. Origin: issue #36 (AraafRoyall).

Status (encrypt side done, RC3): PGPCryptoService.encryptionKeys / encryptionKeyOptions enumerate a recipient's encryption-capable keys in findEncryptionKey's own preference order (composite ML-KEM first, then LibrePGP composite, then classical subkeys, then an encryption-capable primary), so the first option is the automatic pick. findEncryptionKey gained a preferredKeyId override (mirrors pickSigningSecretKey's §4.5 pattern), and both encrypt() and encryptStream() take a recipientSubkeyChoices map (recipient fingerprint hex -> chosen key id). EncryptDecryptViewModel loads per-recipient options on selection change, exposes setRecipientSubkey, and threads the choices into the text, in-memory-file, and bundle encrypt calls; RecipientPickerCard shows a per-recipient dropdown only when a key offers 2+ encryption targets, labeled post-quantum / classical with the automatic pick marked. EncryptionSubkeySelectorTest proves enumeration and that a forced classical choice makes that subkey (not the composite) unwrap the message (via decryptingKeyIdRaw). Follow-on: the card-bundle and password-file encrypt paths are not threaded yet (edge cases), and the decrypt-side selector is deferred (decrypt is fixed by the message's PKESK key id, so a chooser only matters when a sender encrypted to several of your subkeys).

Request: "an option to select which subkey is going to encrypt or decrypt." A key with more
than one encryption-capable subkey gives the user no control today over which one is used.
Scope: a per-key subkey picker on the encrypt-recipient and decrypt surfaces, defaulting to the
current automatic choice so single-subkey keys are unchanged. Interacts with item 7 (adding PQ
subkeys to existing certs), which makes multi-encryption-subkey keys common, and with item 12,
where the composite subkey is the one at issue in the import bug. Sequence after item 12.


## 14. v4 ML-KEM-768+X25519 interop keygen (algorithm 35)

Priority: high. Origin: hko-s (#56). Adds a third, more interoperable key shape to the
key-shape choice in item 1.

Status (DONE): shipped end to end. v3-PKESK/SEIPDv1 + v6-PKESK/SEIPDv2 decrypt (both RFC 9980 A.2
vectors conform), at-rest protection (S2K usage 254 CFB) + private export, encrypt-to-v4 across
text/file/bundle, import detection, and the three-shape interop keygen tier, all green and committed.
Original notes: Status (in progress, RC3): crypto-core keygen done. CompositeKeyGen.addV4Algo35Subkey grafts a v4 algo-35 (X25519 32 || ML-KEM-768 1184) encryption subkey onto a v4 Ed25519 base ring and hand-rolls the v4 subkey-binding signature (0x99 / 2-octet framing on both keys, Ed25519 over SHA-256, key flags EC|ES, optional key-expiration subpacket). v4 has no material-length field so BC cannot parse the subkey; like the algo-30/31 composite primary the result is returned as RAW transferable-secret octets, not a PGPSecretKeyRing. New v4Algo35Bodies (v4 pub with no length prefix; secret = usage0 + material + 2-octet sum checksum) and buildV4Algo35SubkeyBindingSig, alongside the existing v5 LibrePGP hand-rolled path. CompositeV4Algo35Test verifies the binding offline (recomputes the v4-framed hash, Ed25519-verifies under the primary) and checks the subkey's SHA-1 (v4) fingerprint framing (green).

Status (Sep 9 2026, slice): the public-ring plumbing is done. CompositeKeyGen.addV4Algo35Subkey is
refactored into addV4Algo35SubkeyRings, which returns a V4Algo35Rings(secretRaw, publicRaw,
primaryFingerprintHex): the secret raw ring (base + TAG_SECSUBKEY algo-35 + binding) as before, the
matching public raw ring (base public + TAG_PUBSUBKEY algo-35 + the identical binding), and the v4
primary SHA-1 fingerprint hex. The original addV4Algo35Subkey stays as a thin back-compat wrapper
returning .secretRaw, so CompositeV4Algo35Test is unaffected; a new test pins that the public ring
carries the algo-35 subkey as tag 14 (never tag 7), that public and secret subkey share identical
public material, and that the reported fingerprint equals BC's own fingerprint for the base primary.
This is the storage/export prerequisite (a v4 interop key stores both raw rings by the primary's
BC-derived SHA-1 fingerprint) and is independent of the raw-vs-parsed storage question. NEXT slice:
add a MLKEM768_X25519_V4 KeyAlgorithm + a KeyRepository generate path that builds a v4 Ed25519 base
(optional Cv25519), grafts via addV4Algo35SubkeyRings, and stores both raw rings + the entity.

Status (Sep 9 2026, slice 2): generation + storage + public export + detection landed (NOT yet in the
picker). New KeyAlgorithm.MLKEM768_X25519_V4 (label "ML-KEM-768+X25519 (v4)"/"ML-KEM-768 v4",
isV6=false, added to isComposite; SubkeyCapability.heuristic gained its branch). New
CompositeKeyFacade.hasV4Algo35Subkey(raw) detects a v4 (version-4) algo-35 subkey by walking packets
(tag 7/14, body[0]==4, body[5]==35) — the load/export marker for these keys, whose Ed25519 primary is
NOT a composite primary so isCompositePrimary stays false. KeyRepository.generateV4Algo35Key builds a
v4 Ed25519 + Cv25519 base (crypto.generateKeyPair), grafts via addV4Algo35SubkeyRings, stores both raw
rings under the primary SHA-1 fingerprint, and inserts the entity; generateKey dispatches to it.
exportArmoredPublicKey / ForSharing now route through v4Algo35ArmoredPublicKey (armors the raw stored
public ring) so a BC re-serialization never drops the algo-35 subkey. Tests: CompositeKeyFacadeTest
pins hasV4Algo35Subkey (fires on the v4 interop rings, not on a plain base or a composite ML-DSA key).
DEFERRED to the next slice (the on-device interop milestone): offer MLKEM768_X25519_V4 in the picker
with a caption; protect the algo-35 secret subkey at rest and wire private-key export; encrypt/decrypt
TO the key (facade v4 encryptionSubkeyRing lift); then RFC 9980 A.2 vectors + gpg 2.5.x / sq
round-trips. Not in the picker yet precisely because private export and decrypt-to are not done, so a
user cannot generate a half-usable key.

Status (Sep 9 2026, slice 3): the encrypt/decrypt PKESK framing is RESOLVED and the v4 material
primitives are in. Per RFC 9580 5.1 / RFC 9980 a v6 PKESK addresses a v4 subkey with the key-version
octet set to 4 and the 20-octet v4 SHA-1 fingerprint, and PKESK version follows the SEIPD version, so
PGPony's AEAD (SEIPDv2) PQ path uses a v6 PKESK carrying the v4 subkey's real SHA-1 fingerprint (NOT a
v6-normalized one). The composite KEM (CompositeKem encapsulate/decapsulate/combine/wrap) is fully
version-agnostic and reused unchanged; the ONLY v4 difference is the missing 4-octet material-length
field. New CompositeKeyFacade primitives handle exactly that: v4Algo35SubkeyBody(ring),
v4Algo35PublicMaterial(body) -> 1216, v4Algo35SecretMaterial(body) -> 96 (unprotected s2k-usage 0),
and v4Algo35SubkeyFingerprint(body) -> the 20-octet SHA-1 the v6 PKESK carries. CompositeKeyFacadeTest
pins all four. NEXT slice (the encrypt/decrypt wiring): a v4 encrypt path that extracts the public
material, runs CompositeKem.encapsulate, and hand-builds a v6 PKESK (key-version 4, 20-octet
fingerprint, algo 35, algo-fields ephemeral||ct||len||wrapped); a v4 decrypt path that matches an
incoming v6/key-version-4 PKESK to our subkey by that fingerprint, extracts the secret material, and
decapsulates; a PGPony self round-trip test; then subkey-at-rest protection + private export + the
picker entry, and finally the RFC 9980 A.2 vectors and gpg 2.5.x / sq round-trips on device.

Status (Sep 9 2026, slice 4): the v4 KEM + PKESK round-trip is proven end-to-end offline.
CompositePkesk.encodeBody now takes a 20-octet (v4) or 32-octet (v6) fingerprint and writes the target
key-version octet accordingly (4 or 6); parseBody was already length-driven so it reads either back.
New test CompositeV4Algo35KemTest: from a generated v4 interop key it extracts the subkey public (1216)
+ secret (96) material and the 20-octet fingerprint, CompositeKem.encapsulate to the public material,
frames the v4-targeted v6 PKESK (asserts the key-version octet is 4 and the recipient fingerprint is the
20-octet SHA-1), parseBody, then CompositeKem.decapsulate with the secret material and confirms the
session key survives. This validates the full crypto core for v4 (the KEM is version-agnostic; only the
material extraction and the PKESK target framing differ from v6). REMAINING: wire this into
PGPCryptoService.encrypt/decrypt at the message level (a v4 encrypt method generator that hand-builds
the PKESK, and decrypt matching of a v4 20-octet fingerprint to the held v4 subkey secret), giving a
real PGPony self message round-trip; then protect the algo-35 subkey at rest + private export; then the
picker entry + caption; then RFC 9980 A.2 vectors and gpg 2.5.x / sq interop on device.

Status (Sep 9 2026, slice 5): the v4 encrypt method generator is built and tested. Confirmed from BC
source that PublicKeyEncSessionPacket.createV6PKESKPacket's FIRST arg is the target key-version octet,
written verbatim (not inferred from fingerprint length), so V4Algo35EncryptionMethodGenerator passes 4
+ the 20-octet fingerprint and BC frames the exact v4-targeted v6 PKESK. The generator is constructed
from raw subkey public material + the v4 fingerprint (no PGPPublicKey, since BC can't parse the
subkey). CompositeV4Algo35EncryptTest drives it through BC's own framing and confirms PKESK version 6,
target key-version octet 4, the right fingerprint, and that the wrapped session key decapsulates back.
OPEN DECISION for the message-level wiring (needs RFC 9980 A.2 / gpg-sq evidence, do NOT guess): the
SEIPD version. PGPCryptoService.encrypt currently forces SEIPDv1 the moment any recipient is v4, but
our algo-35 PKESK is v6 (SEIPDv2 pairing), and PGPony's generated v4 key does NOT yet advertise SEIPDv2
support via a Features subpacket. Resolve which of: (a) make the v4 algo-35 key advertise SEIPDv2
(Features on the primary self-sig / direct-key sig) so senders use SEIPDv2 + v6 PKESK, matching the
generator; or (b) pair the algo-35 v4 recipient with SEIPDv1 + a different PKESK. RFC 9980 A.2 shows
the canonical framing. Also still to plumb: routing v4 recipients into encrypt() (they are not BC
rings, so a separate recipient channel like the composite path), decrypt matching of the 20-octet
fingerprint to the held subkey, subkey-at-rest protection + private export, and the picker entry.

Status (Sep 9 2026, slice 6): the full v4 message round-trip works. Confirmed via RFC 9580 5.1 that a
v6 PKESK MUST pair with SEIPDv2 (and must not precede v1), so algo-35 v4 recipients use SEIPDv2 (option
a). Decrypt is wired: KeyRepository.loadCompositePrivateRing now also returns a v4 interop raw ring
(hasV4Algo35Subkey), so it flows into the decrypt compositePrimaryRings channel; CompositeDecryptor
gained a v4 branch (openV4Algo35 extracts the subkey public/secret material via the facade helpers and
decapsulates; findRawComposite matches a 20-octet v4 fingerprint by v4Algo35SubkeyFingerprint; openRaw
dispatches to it when hasV4Algo35Subkey). New CompositeV4Algo35MessageTest assembles a real SEIPDv2
(AEAD/OCB) message to a generated v4 key's subkey with V4Algo35EncryptionMethodGenerator (the same BC
PGPEncryptedDataGenerator path encrypt uses) and decrypts it back to plaintext through
CompositeDecryptor. So the crypto + PKESK/SEIPD framing + fingerprint match + decapsulation all work
end to end. REMAINING: (1) route v4 recipients into PGPCryptoService.encrypt so the UI can encrypt to
one (they are not BC rings, so a separate recipient channel like loadEncryptionRecipientRing plus
forcing SEIPDv2); (2) protect the algo-35 subkey at rest + enable private-key export; (3) advertise
SEIPDv2 in the v4 key's Features subpacket so gpg/sq choose it; (4) picker entry + caption; (5) RFC
9980 A.2 vectors + gpg 2.5.x / sq interop on device.

Status (Sep 9 2026, slice 7): the encrypt SEND path is wired through the real entry point.
PGPCryptoService.encrypt gained a v4Algo35Recipients: List<V4Algo35Recipient> channel (a v4 key is not
a BC ring); a v4 recipient forces allRecipientsV6 = true (SEIPDv2), and after the BC-recipient loop a
V4Algo35EncryptionMethodGenerator is added per v4 recipient. KeyRepository.loadV4Algo35Recipient reads
the stored public ring and returns the 1216-octet material + 20-octet fingerprint. New
CompositeV4Algo35EncryptServiceTest encrypts a message to a v4 recipient through svc.encrypt (empty BC
recipient list, v4Algo35Recipients only) and decrypts it back through CompositeDecryptor. Only encrypt()
(text) is wired this slice; encryptStream (file) and the ViewModel threading are deferred until there is
a selectable v4 recipient (picker or import). REMAINING: (2) protect the algo-35 subkey at rest + enable
private-key export (v4-framing-aware, blocks safe picker exposure); (3) advertise SEIPDv2 in the v4 key
Features subpacket; (4) picker entry + caption + ViewModel v4-recipient resolution + encryptStream; (5)
import detection of a v4 algo-35 key (shares item 12); (6) RFC 9980 A.2 vectors + gpg/sq interop.

Status (Sep 9 2026, slice 8): the v4 interop shape is now GENERATABLE in the picker, gated safely.
MLKEM768_X25519_V4 is added to generatablePostQuantum (first, as the reach default) with its own picker
caption (keyring_generate_algorithm_caption_pqc_v4) explaining the interop value and that private-key
backup is not available for it yet. Private-key EXPORT of a v4 interop key is gated (all three
exportArmoredPrivateKey* return null via isV4Algo35InteropKey) so an unprotected PQ secret never leaves
the app and a BC re-serialization cannot silently drop the subkey; at-rest is already covered by
SecureKeyStore. So a generated v4 key can be created, PUBLIC-exported (raw-bytes path, subkey
preserved), and DECRYPT received messages; it cannot yet be a UI encrypt recipient (needs the ViewModel
v4-recipient threading) or be private-exported (needs protection). This unblocks the receive-direction
interop: generate a v4 key, export the public key, import into sq/gpg, encrypt to it there, decrypt in
PGPony. REMAINING: (a) v4-framing-aware subkey protection to enable private export/backup; (b) ViewModel
v4-recipient threading + encryptStream so the UI can encrypt TO a v4 key; (c) SEIPDv2 Features
subpacket on the v4 key; (d) import detection of a v4 algo-35 key (shares item 12); (e) RFC 9980 A.2
vectors + gpg/sq interop on device; (f) fold the three shapes into item 1's interop-tier keygen choice.

Status (Sep 9 2026, slice 9): on-device generation confirmed and a real interop gap found + fixed.
NorseHorse generated a v4 ML-KEM-768+X25519 key on device and exported the public key; a packet walk
confirmed the exact RFC 9980 shape: v4 Ed25519 primary (fp 1BDB..1056), name-only UID, v4 Cv25519
encryption subkey (flags 0x0C), and the v4 algo-35 subkey (1216-octet material, flags 0x0C, valid v4
binding). BUT the primary self-sig carried NO Features subpacket, so it did not advertise SEIPDv2 — and
because the algo-35 KEM only has a v6-PKESK encoding (which requires SEIPDv2), a sender without that
advertisement would downgrade to the classical Cv25519 subkey and the message would not be
post-quantum. Fix: buildEd25519KeyRingGenerator gained an optional features octet, set ONLY for the v4
interop key (classical and LibrePGP keys must not advertise SEIPDv2 — their subkeys pair with v3 PKESK
+ SEIPDv1); a new buildV4InteropBaseSecretRing advertises SEIPDv1 (MDC) + SEIPDv2 (0x09), and
generateV4Algo35Key now builds on it. After a rebuild, a freshly generated v4 key advertises SEIPDv2,
so sq/gpg should encrypt to the algo-35 subkey with a v6 PKESK. VERIFIED on device (Sep 9): a freshly
generated v4 key's exported public key now carries FEATURES = 0x09 (MDC + SEIPDv2) on the primary
self-sig; structure otherwise identical and correct. REMAINING: (a) v4 subkey protection +
private export; (b) ViewModel v4-recipient threading + encryptStream (encrypt TO a v4 key in the UI);
(c) import detection of a v4 algo-35 key (shares item 12); (d) RFC 9980 A.2 vectors + the actual gpg/sq
round-trip on device; (e) fold the three shapes into item 1's interop-tier keygen choice.

Status (Sep 9 2026, slice 10): RFC 9980 conformance test added; the tooling ecosystem does NOT yet
implement algo-35. On-device interop with NorseHorse's key established: IANA confirms algo 35 =
ML-KEM-768+X25519 (RFC 9980), so PGPony's codepoint is correct; gpg 2.5.21 follows LibrePGP (reads 35
as a Dilithium variant, "dil30") and mainline Sequoia (sq 1.3.1 / sequoia-openpgp 2.0.0) calls 35
"Unknown" — neither can do RFC 9980 algo-35, though both parsed the rest of the key and sq honored the
new Features/SEIPDv2 flag (it chose SEIPDv2 but downgraded to the classical subkey it could use). So the
authoritative check is the RFC's own A.2 vectors, now committed as fixtures
(rfc9980-a2-v4-ed25519-mlkem768-{sec,pub,msg-v1,msg-v2}.asc, extracted from repo rfc9980.txt).
CompositeRfc9980A2Test decrypts A.2.4 (v6 PKESK / SEIPDv2, PGPony's exact form) with the RFC sample
secret key and asserts the plaintext "Testing\n". The sample key's algo-27 primary and algo-35 subkey
are both unprotected, so the raw v4 path opens them. NEW GAP FOUND: A.2.3 is a v3-PKESK / SEIPDv1
algo-35 message — a second valid encoding the RFC defines — which PGPony's composite decrypt does NOT
parse (CompositePkesk.parseBody only accepts v6 PKESKs); a conformant sender using that form (or gpg's
downgrade) would not decrypt. Add v3-PKESK algo-35 decrypt support as the next slice.

Open for follow-on slices: (1) [confirm at build] whether bcpg 1.85 can round-trip a v4 algo-35 subkey at all (decides raw-bytes-via-facade vs PGPSecretKeyRing storage) — the raw-bytes path is used now to be safe; (2) storage + CompositeKeyFacade v4 support (v4 SHA-1 fingerprint, encryptionSubkeyRing lifting a v4 algo-35 subkey) shared with item 12's v4 fingerprint matching; (3) encrypt/decrypt round-trip wiring; (4) RFC 9980 Appendix A.2 vector validation + gpg 2.5.x / sq interop (on-device delivery check); (5) fold into item 1's key-shape choice as the recommended default, with the optional-classical-ECDH-subkey toggle.

RFC 9980 (Post-Quantum Cryptography in OpenPGP, Standards Track, June 2026) restricts the
PQ(/T) algorithms to v6 keys with one exception: ML-KEM-768+X25519 (algorithm ID 35) is also
allowed in v4 encryption-capable subkeys. Section 3.5 states it directly; section 4.3.2 makes
it normative (algo 35 MUST be used only with v4 or v6 keys; algo 36 / ML-KEM-1024+X448 stays
v6-only). The RFC ships a full sample v4 Ed25519 + algo-35 key with test vectors in Appendix A.2.

Why it matters: v6 support across end-user software is thin and will stay that way for a while
(the tenth OpenPGP summit has Thunderbird at experimental v4-only PQC in stable, and GnuPG-derived
stacks cannot do v6 while upstream GnuPG does not). A v4 Ed25519 primary carrying a v4 algo-35
ML-KEM-768+X25519 encryption subkey is the standardized common denominator: the primary is an
ordinary v4 key every tool already handles, and only the encryption subkey needs algo-35 awareness.
The RFC authors designed the v4 allowance for exactly this, letting someone add a PQ encryption
subkey without forcing correspondents onto v6.

Threat framing that justifies making this the recommended default: harvest-now-decrypt-later is a
confidentiality threat, so post-quantum ENCRYPTION is what matters today. A forged signature needs
a quantum computer in the present, not retroactively, so a classical Ed25519 signing primary is a
sound near-term choice. The v4 Ed25519 + algo-35 shape delivers the security property users are
reaching for at the lowest interop cost.

Where it sits among the key shapes (this is the key-version / interop tier that item 1 did not name):

- v4 interop (this item): Ed25519 v4 primary, algo-35 ML-KEM-768+X25519 v4 encryption subkey,
  optional classical ECDH subkey for pre-PQC recipients. Maximum reach. 768-only. Classical signing.
  Recommended default for users who want PQC encryption that works with real correspondents.
- v6 compatibility (item 1, current default): v6 base, composite ML-KEM subkey plus a standalone
  classical encryption subkey.
- v6 PQ-only (item 1): full v6 PQ certificate, composite ML-DSA primary, no classical key. The
  deliberate hardline choice.

Hard constraint: only algo 35 (ML-KEM-768+X25519) gets the v4 allowance. ML-KEM-1024 (algo 36) is
v6-only, so anyone wanting 1024 is on the v6 path.

Work:

- Keygen: build a v4 Ed25519 primary and graft an algo-35 ML-KEM-768+X25519 composite encryption
  subkey with a v4 subkey binding signature. Offer to include or omit a classical ECDH subkey.
- Reuse the existing composite machinery (CompositeKeyGen.addCompositeSubkey, CompositeKeyFacade).
  The binding signature is an ordinary v4 signature; the new surface is assembling the algo-35 subkey
  packet under a v4 primary.
- Fold the key-version / interop tier into the item-1 keygen choice so the three shapes above are one
  coherent decision, with v4 interop as the recommended default.

Research and unknowns:

- Confirm bcpg 1.85 will assemble an algo-35 subkey packet under a v4 primary (or hand-assemble it as
  the composite path already does for algo 30/31). [confirm at build]
- Fingerprints: v4 is SHA-1 (20 octets), v6 is SHA-256 (32). The composite-subkey fingerprint match at
  the center of item 12 must handle the v4 form too, so item 12 and this item share that code. Pin
  item 12's investigation first.

Delivery: generate a v4 Ed25519 + algo-35 key; validate it against the RFC 9980 Appendix A.2 sample
and vectors; round-trip encrypt/decrypt against gpg 2.5.x and sq; confirm a v6-only tool still reads
the v4 primary (and its classical subkey, if present) and degrades gracefully on the algo-35 subkey.


## 15. Deemphasize v5 (LibrePGP) PQC interop in the UX

Priority: low (UX/copy). Origin: hko-s (#56 aside).

Status (done, RC3): the LibrePGP composite options were already structurally deemphasized (generatableAdvanced, under the 'Advanced / compatibility' group in KeygenAlgorithmPicker, separate from the promoted 'Post-Quantum' IETF group). Reframed the two captions: the LibrePGP caption now leads with 'For GnuPG / LibrePGP interop only' and states it is effectively GnuPG-only and not broadly interoperable, pointing to the RFC 9980 option for wider reach; the IETF caption now leads with 'Recommended for post-quantum interoperability' and frames RFC 9980 as where cross-tool support is heading. OnboardingGenerateSheet reuses the same picker, so both keygen surfaces inherit the copy; key-detail already labels these '(LibrePGP)' honestly. Pure copy change, no unit test.

The LibrePGP "v5" PQC formats (algo 8 composite, v5 keys) are effectively GnuPG-only and are not going
to become broadly interoperable. Presenting them in the UX as an interoperable option oversells their
reach. RFC 9980 (v4/v6, algo 35/36) is the IETF Standards Track consensus and is where cross-tool
interop actually lives.

Work:

- Keep supporting v5 for GnuPG / LibrePGP interop, but relabel it as such in keygen and key display
  ("for GnuPG / LibrePGP interop") rather than as a general interoperable format.
- Promote the IETF v4/v6 algo-35/36 path as the recommended interoperable option. Rides item 1 and
  item 14's label-the-tradeoff-at-generation work.

Delivery: keygen and key-detail copy no longer imply broad interoperability for v5; the IETF path is
the promoted default.

## 16. Delete or revoke subkeys

Priority: medium. Origin: user request (4.4.0, Pixel 8, Android 17). The add/remove counterpart
to item 7.

Status (in progress): composite subkey-revocation crypto core done. CompositePrimaryKeyGen.revokeSubkey builds a v6 composite 0x28 subkey-revocation self-signature over primary + subkey with a Reason-for-Revocation subpacket (type 29), spliced in after the subkey's binding sigs; CompositeRevokeSubkeyTest verifies it offline with CompositeSigVerifier (green). Classical 0x28 done too: RevocationService.generateSubkeyRevocation / applySubkeyRevocation (BC SUBKEY_REVOCATION, signed by the primary), ClassicalSubkeyRevokeTest green. Local remove done: ClassicalSubkeyGen.removeSubkey (BC removeSecretKey, v4+v6) and CompositePrimaryKeyGen.removeSubkey (byte-splice), SubkeyRemoveTest green. Repo + UI done: KeyRepository.revokeSubkey/removeSubkey (composite and classical dispatch, KeyRepoError.LastEncryptionSubkey guard), KeyDetailViewModel subkey revoke/remove flows, SubkeysSection per-subkey overflow menu, reused RevokeKeySheet for the revoke, remove-confirm + last-encryption-subkey warning dialogs, and CompositeKeyFacade now reports composite subkey revocation state (SubkeyInfo.isRevoked). item 16 COMPLETE pending device build + on-device check that gpg/sq see the revocation. Follow-up (Sep 13 2026, #36 Araaf, on RC2): subkey REMOVE
confirmed but gave no success feedback and no biometric gate (unlike primary-key delete). Fixed for rc3:
the remove-confirm dialog's Remove now runs behind deleteWithOptionalBiometricGate (generalized to take a
title/subtitle; new key_detail_subkey_remove_biometric_* strings), gated on device biometric capability and
falling through when unavailable; doRemoveSubkey now sets successMessage (kd_vm_status_subkey_removed ->
"Subkey removed" snackbar). UI-only, verified on device.

On-device VERIFIED Sep 14 2026 (RC4 foss debug, moto g play): local remove and classical revoke both confirmed externally. REMOVE: removed the standalone X25519 encrypt subkey from a v6 compatibility key; exported cert dropped from three subkeys to two (small classical + 1226-byte ML-KEM composite), the removed subkey is gone. gpg parse is structural-only on v6 (unknown version 6), so the authoritative shape check is on-phone Key Details, which matched. REVOKE (classical path, v4 key, gpg-verified end to end): the target rsa4096 encrypt subkey 0AAE4A86353837FC carries a proper 0x28 subkey-revocation self-sig (sigclass 0x28, revocation-reason subpacket type 29 code 0x00, issued by the primary B39860A99A9B345D); sibling encrypt subkeys stay live, gpg hides the revoked subkey from --list-keys and keeps valid encryption targets, i.e. it stops selecting the revoked one. COMPOSITE revoke path (0x28 over a composite ML-DSA primary) not gpg-checkable here (algo-30/35 tooling gap); stays covered by CompositeRevokeSubkeyTest (green) plus the phone isRevoked flag.

Add-subkey exists (ClassicalSubkeyGen, extended to PQ by item 7), but there is no way to remove a
subkey once it is on a cert. The request is a delete function. Two distinct operations sit behind
"delete", and the UI must make the difference obvious:

- Remove from keyring (local). Strip the subkey packet from the stored key. Local only: it tells no
  correspondent, and anyone who already holds the public key keeps the subkey and can still encrypt
  to it. Simple and immediate.
- Revoke subkey (proper retire). Generate a subkey revocation signature (type 0x28) so correspondents
  see the subkey as revoked and stop encrypting to / trusting it, then re-export and optionally
  re-publish. This is the correct way to retire a subkey that has already been shared.

Default the primary action to revoke for a key that has been published, since a bare local delete
leaves a shared subkey live for everyone else. Keep local remove for a subkey that was generated but
never published.

Work:

- Keyring UI: a per-subkey action to remove (local) and to revoke (with a reason subpacket: no reason
  / key superseded / key compromised / key retired).
- Local remove: rebuild the stored ring without the selected subkey packet.
- Revoke: build the 0x28 subkey revocation signature over primary + subkey with the chosen reason,
  add it to the ring, re-export.
- Guard rails: warn or block when the action would remove/revoke the last encryption subkey or the
  primary, i.e. leave the cert unable to encrypt.

Research and unknowns:

- Composite ML-DSA primary: a revocation signature over a subkey needs a composite self-signature,
  which BC cannot produce. Reuse the composite signature assembly from item 4 / CompositePrimaryKeyGen
  binding sigs / CompositeDocumentSigner. For a classical primary, BC's subkey-revocation path is
  straightforward.
- Whether to specifically support revoking the composite ML-KEM subkey, which items 7 and 14 make
  common once multi-PQ-subkey keys exist.

Delivery: remove a subkey locally and confirm it is gone from the stored key; revoke a subkey and
confirm gpg 2.5.x and sq see the revocation and stop selecting it for encryption.

Interactions: item 7 (add subkeys) and this item are the add/remove pair; item 13 (subkey selector)
and item 14 (multi-subkey v4 interop keys) both make pruning more useful; the composite path reuses
item 4's self-signature machinery.

## 17. ECC curve label detection (NIST P-256 / brainpool shown as RSA 4096)

Priority: medium (cosmetic, but public-facing). Origin: Google Play review, Sep 5 2026 (2 stars):
NIST P-256 and brainpool keys are labeled "RSA 4096"; encryption and decryption work, only the label
is wrong. Same family as item 5, which covered ML-KEM level and RSA modulus size but not ECC curves.

Status (done, RC3 batch): the review's core fix — detectAlgorithm's `?: RSA_4096` catch-all is now `?: KeyAlgorithm.UNKNOWN`, so a key PGPony cannot model shows 'Unknown', never a confident wrong 'RSA 4096'. New EcCurveOid resolves the curve from BouncyCastle's parsed curve OID (ECPublicBCPGKey.curveOID) against a dotted-OID table mirroring the card path. detectAlgorithm now maps an ECDSA primary (algo 19) to a curve-specific label (ECDSA_NIST_P256/384/521, brainpoolP256/384/512, secp256k1) with real keyBits, and refuses to mislabel a non-25519 ECDH subkey (algo 18) as Ed25519 (returns Unknown instead of the wrong 25519 label). SubkeyCapability.heuristic (exhaustive, no else) was extended to cover the new entries. EcCurveLabelTest generates real NIST P-256, P-384, and brainpoolP256r1 ECDSA keys with BC and asserts each shows its curve (not RSA 4096), plus RSA and Ed25519 regression. Follow-on: curve-aware labels for ECDH subkeys and EdDSA/Ed448 (per-curve entries) if desired; the iOS KeyAlgorithm mirror needs the same fix.

Root cause (KeyAlgorithm.kt, PGPCryptoService.kt):

- detectAlgorithm(publicKey) ends with `KeyAlgorithm.from(algoId, version) ?: KeyAlgorithm.RSA_4096`.
  Any algorithm from() does not map is silently labeled RSA 4096. That bare catch-all is the reported
  symptom.
- KeyAlgorithm.from() classifies ECC by algorithm number only and carries no curve: v4 ECDH (18) maps
  to ED25519_CV25519 (assumes Cv25519, wrong for a NIST/brainpool ECDH subkey), ECDSA (19) maps to a
  curve-less "ECDSA" with keyBits 0, EdDSA-legacy (22) maps to ED25519_CV25519. The 4.3.x ECDSA entry
  stopped an ECDSA primary from hitting the RSA-4096 catch-all, but the reporter is on 4.4.0 (versionCode
  433, current code), so a plain ECDSA-primary P-256 key should already label as ECDSA. That it still
  shows RSA 4096 means the label comes from a path that hits the catch-all or a wrong mapping, so step
  one is to reproduce with a real NIST P-256 and brainpool P-256 key (ECDSA primary + ECDH subkey) and
  identify which key and which display path yields RSA 4096. Either way, current code never reads the
  curve, so ECC labels are wrong or missing even where they are not RSA 4096.

Two defects, then: an unmapped key defaults to a confident wrong "RSA 4096", and recognized ECC keys
carry no curve (P-256 vs P-384 vs brainpool are indistinguishable, and a non-25519 ECDH subkey is
mislabeled Ed25519).

Work:

- Read the curve OID from ECDSA (19), ECDH (18), and EdDSA-legacy (22) key material and label the
  actual curve: NIST P-256 / P-384 / P-521, brainpoolP256r1 / P384r1 / P512r1, secp256k1, and the
  25519/448 curves. The card path already carries this OID table (CardAlgorithmAttributes.kt:
  OID_NIST_P256/384/521, OID_SECP256K1, OID_BRAINPOOL_P256/384/512); factor it into a shared curve-OID
  resolver used by both.
- Carry the curve in the label. Either add import-only KeyAlgorithm entries for the common NIST and
  brainpool ECDSA/ECDH curves, or give the ECC entries a curve/displayName the detector fills in. Set
  keyBits to the curve's real size so the label is not "0".
- Replace the `?: RSA_4096` catch-all with a truthful fallback (an "Unknown / unrecognized" label), so
  a key PGPony cannot model is never presented as RSA 4096. This is the actual fix for the review.
- Cover both the ring-aware detectAlgorithm(masterKey, ring) and single-key detectAlgorithm(publicKey),
  plus the encryption-algorithm display for ECDH subkeys.

Delivery: import NIST P-256, P-384, and brainpoolP256r1/P384r1/P512r1 keys (ECDSA primary + ECDH
subkey) and confirm each shows its real curve, not RSA 4096 or Ed25519; confirm a genuinely unknown
key shows "Unknown", not RSA 4096; confirm no regression on RSA, Ed25519/Cv25519, v6, and the ML-KEM
composites.

Note: display-only, the crypto is unaffected (the reviewer confirmed encrypt/decrypt work). The iOS
KeyAlgorithm enum mirrors this classifier and needs the same curve-aware fix on the port.

## 18. Multi-recipient composite ML-KEM decrypt failure (own generated key)

Priority: HIGH. Origin: WundreLust (#57). Same "no held composite secret key" error and composite
recovery path as item 12, but a distinct trigger: PGPony-generated keys, not imported, and only when
the message has more than one recipient.

Status (Sep 8 2026): root cause CONFIRMED by code read and fix APPLIED in
CompositeDecryptor.kt (pending build and on-device test against a two-key repro).
CompositeDecryptor only handled the first composite PKESK: split() captured a single
PKESK (guarded by parsed == null) and recover() tried only that recipient, so a
multi-recipient message failed whenever the held key's PKESK was not first. Fix: split()
now collects every composite PKESK into a list; a new recoverAmong() tries each against
the held keys (addressed via findSecretKey / findRawComposite, anonymous via trial),
propagating a matched-but-locked ProtectedKeyException and throwing NoMatchingKey only
after all PKESKs miss; the streaming path uses allCompositePkesks() in place of
firstCompositePkesk().

Report: two ML-KEM-1024 v6 keypairs, both generated in PGPony (the reporter's own and a friend's). A
message encrypted to both recipients, unsigned, decrypts fine for the friend but fails for the reporter
with "Decryption failed: no held composite secret key for recipient <subkey-fp>" (the error prints
twice, suggesting a second recovery attempt also missed). Encrypting to the reporter's own key alone
decrypts correctly.

The break is specific to a multi-recipient message: with more than one composite PKESK present, PGPony
fails to match its own held composite subkey and recover the session key, even though the same key
decrypts a single-recipient message. The single-recipient success rules out a plain loading failure of
the held key (item 12's candidate a); this points at the PKESK iteration / recipient-matching stage,
i.e. PGPony stops at or mis-selects the wrong composite PKESK when several are present, or the subkey
fingerprint match only lands on the first recipient slot.

Work:

- Reproduce in-tree: generate two ML-KEM-1024 v6 keys in PGPony, encrypt one file to both, decrypt with
  each. Confirm the multi-recipient failure and that single-recipient works.
- In the composite decrypt path (CompositeDecryptor.recover / findRawComposite and the PKESK loop in
  EncryptDecryptViewModel), confirm every composite PKESK is tried against the held key rather than only
  the first, and that the subkey fingerprint match is evaluated per PKESK. Fix the stage that stops
  early or matches the wrong slot.
- Determine whether this shares item 12's root cause (the v6 fingerprint match) surfacing only when the
  held key is not the first recipient; if so, fix once and cover both.

Research and unknowns:

- Whether the friend decrypts with PGPony or another tool (asked in the reply). If another tool
  succeeds on the same message, PGPony's own recipient matching is the sole suspect.
- The doubled error suggests both the BC-ring lookup and the raw-composite trial run and both miss;
  confirm the order and which one should have matched.

Delivery: a PGPony-generated ML-KEM-1024 key decrypts a message encrypted to it plus at least one other
recipient; no regression on single-recipient decrypt or on the item 12 import case.


## 19. Strip extraneous text when importing or sharing a key

Priority: medium. Origin: CertainBot (#58).

Status (done, RC4 batch): new ArmorExtractor pulls every '-----BEGIN PGP <TYPE>-----...-----END PGP <TYPE>-----' block out of noisy input (END matched to BEGIN via backreference), prefers PGP KEY blocks (public/private) and ignores surrounding page text and non-key blocks like a detached signature; falls back to all blocks when none is a key, and to null when there is no armored block (caller then reports 'no key data'). Wired into KeyringViewModel.previewArmoredKey, the choke point for paste, file-with-BEGIN, and shared text (previewKeyBytes routes armored bytes through it), so one change covers all text import paths; a clean .asc is a single block and passes through unchanged, keeping the strict path effectively intact. ArmorExtractorTest covers clean block, surrounding text, two keys, key+signature, no-block, and lone-signature fallback. Follow-on: none required; browser text that mangles the block internally (HTML tags inside the armor) is out of scope, as the plan notes only surrounding noise.

Sharing on-screen text into PGPony (open a key file in a browser, select all, share) carries
browser-added metadata around the armored key, and PGPony errors unless the user trims it by hand.
Copy-paste and shared .asc files are fine; only the select-all-and-share path adds noise.

Work:

- On import from shared text (and paste), extract the ASCII-armored block(s) between the BEGIN/END PGP
  armor lines and ignore anything outside them, instead of requiring the input to be exactly the key.
- Handle more than one armored block in a single payload (a public key, or a key plus a signature) and
  surrounding whitespace or HTML text.
- Keep the strict path for actual .asc files unchanged.

Delivery: sharing a browser text selection that contains an armored key (with surrounding page text)
imports cleanly with no manual editing; a payload with no armored block still reports a clear error.


## 20. Auto-focus and open the keyboard on the unlock-signing-key dialog

Priority: low (UX). Origin: ltguillaume (#59). Adjacent to item 8's passphrase-prompt work and the #8
autofill thread.

Status (done, RC4 batch): a shared rememberAutoFocusRequester() composable (FocusRequester + a LaunchedEffect that requests focus after a 50 ms attach delay, wrapped in try/catch) is applied to all four passphrase dialogs in Screens.kt — SignPassphraseDialog, DecryptPassphraseDialog, and the two legacy variants — with .focusRequester(fr) on each password OutlinedTextField. Requesting focus on an editable field raises the IME, so the field is focused and the keyboard is up with no extra tap. UI-only, no unit test (Compose focus is verified on-device). Follow-on: if the OpenPGP API provider-path unlock uses a distinct dialog, apply the same helper there; the four encrypt/decrypt dialogs are the primary surfaces.

The "Unlock signing key" dialog opens without focusing the passphrase field or raising the software
keyboard, so the user has to tap the field first. OpenKeychain focuses the field and shows the keyboard
automatically.

Work:

- On the unlock-signing-key dialog (the Compose AlertDialog with the passphrase OutlinedTextField),
  request focus on the field and show the IME when it appears (FocusRequester plus the keyboard
  controller / autofocus), so the user can type immediately.
- Apply the same to the sibling unlock dialogs (decrypt-key unlock, provider-path unlock) for
  consistency.

Delivery: opening the unlock-signing-key dialog focuses the passphrase field and raises the keyboard
with no extra tap; the same holds for the other unlock prompts.

## RC build breakdown

Four RC builds for the 4.5.0 cycle, ordered so the composite-decrypt spine and the pre-auth security
fixes land first and de-risk the feature work. Final versionName 4.5.0. Security release notes stay
generic ("input-bounding and verification hardening") until Cipher opens the embargo window (item 11
A to D).

RC1 - interop and pre-auth security (testers waiting, highest severity):

- Item 12: decrypt to imported composite ML-KEM keys (Umotas #36).
- Item 18: multi-recipient composite ML-KEM decrypt on own generated keys (WundreLust #57).
- Item 11A: Argon2 unbounded decrypt memory. Item 11B: decompression bomb.

Reproduce 12 and 18 together first: they share the composite recovery and subkey-fingerprint code, and
fixing that spine here de-risks RC3. A and B are contained pre-auth DoS fixes and ship behind generic
notes. This is the set that could stand alone as a 4.4.2 if the rest of the cycle runs long.

RC2 - security completion and key-management foundations:

- Item 11C: verify honors revocation / expiry / key flags. Item 11D: collapse SEIPDv1 decrypt errors.
- Item 4: composite ML-DSA multi-User-ID. Builds the composite self-signature assembly.
- Item 16: delete / revoke subkeys. Reuses item 4's composite self-signature.
- Item 6: custom key server repositories (HIGH, independent).

Item 4 lands before item 16 and before RC3's item 7, since all three need the same composite
self-signature machinery.

RC3 - PQC keygen cluster (flagship):

- Item 1: post-quantum-only key option. Item 14: v4 ML-KEM-768+X25519 interop keygen. Item 2:
  mixed-recipient PQ warning.
- Item 7: granular keygen and PQ subkeys on existing certs. Item 13: subkey selector.
- Item 15: deemphasize v5 in the UX (rides the item 1 / 14 labeling).

Sequenced after RC1 (item 14's v4 fingerprints and item 13 both depend on the composite spine) and
after RC2 (item 7 needs the composite self-signature).

RC4 - UX, privacy, labels, localization:

- Item 8: keygen publish prompt (offline suppression, clear skip, pgpony.app opt-out).
- Item 17: ECC curve label detection. Item 19: strip extraneous text on key import.
- Item 10: offline toggle at top of Settings > Security. Item 20: auto-focus and keyboard on the
  unlock-signing-key dialog.
- Item 9: enable Korean, if the fuller translation is ready by now; otherwise it ships whenever it
  lands and can slip past RC4.

Start the nuraqueer / community Korean translation top-up now so it is ready by this RC.

Three-RC option: fold 11C and 11D into RC1, and merge RC2's key-management foundations into RC3. That
leaves RC1 security-plus-interop, RC2 the full keygen and key-management cluster, and RC3 the
UX/privacy/localization batch.

## 21. Surface Web Key Directory in the Settings key-server section

Priority: low (UX / consistency). Origin: Peter (4.4.0). Related to item 6 but distinct: not about
adding servers, about showing a lookup source that already exists.

WKD is the FIRST source in the lookup chain (WKD -> configured servers -> keys.openpgp.org), and the
Import Key dialog's Key Server tab says so (import_keyserver_help). But Settings > Keys & Servers >
Key Servers (KeyserversScreen) lists only keys.pgpony.app and keys.openpgp.org with lookup/publish
toggles and never mentions WKD, so a user reading that screen cannot tell WKD is part of lookups at
all. Peter expected WKD represented there too, the same way it is in the import dialog.

Work:

- Add a non-removable WKD entry at the top of the Settings key-server list, matching the real lookup
  order, with copy consistent with import_keyserver_help ("Web Key Directory: tried first for email
  lookups, from the recipient's own domain. No publishing."). WKD has no publish target, so show a
  lookup state only, not a publish toggle.
- Optionally give WKD a lookup on/off toggle wired into the KeyServerRepository lookup path so a user
  can turn WKD lookups off; if that is more than wanted, at minimum an informational row so the
  screen matches the import dialog and the actual behaviour.

Delivery: the Settings key-server section shows WKD as the first lookup source, consistent with the
Import dialog; if a toggle is added, disabling it drops WKD from the lookup chain.

Status (Sep 9 2026): done, with the functional toggle. A new WkdLookup object (network, pref
wkd_lookup_enabled, default true, OfflineMode-style process-safe access) gates the WKD step in
KeyServerRepository.findByEmail: off drops WKD from the chain while the configured servers and Hagrid
still run (searchByEmail routes through findByEmail, so the single gate covers both). KeyserversScreen
now renders a non-removable WkdCard at the TOP of the list, above the configured servers, with a
lookup-only Switch (no publish toggle, no reorder) bound to WkdLookup, and copy matching
import_keyserver_help (label "Web Key Directory", desc "Tried first for email lookups, from the
recipient's own domain. No publishing."). On-device: open Settings > Key Servers, confirm WKD sits
first as a lookup-only row; toggle it off and confirm an email lookup for a WKD-only key no longer
resolves while server lookups still work; confirm the setting persists across restart.

Cross-reference: item 6 adds custom servers to this same screen; this item makes the screen's existing
sources complete.

## 22. Google Play Android vitals (Sep 8 2026 review)

Priority: HIGH (ANR), medium (optimization). Origin: NorseHorse reviewing Play Console on 4.4.0
(versionCode 433). Two Play-flagged issues plus one recommendation.

- ANR rate 1.78% user-perceived (threshold 0.47%) [HIGH]. The obvious main-thread-crypto causes are
  already fixed: encrypt/decrypt run on Dispatchers.Default/IO, file decrypt was moved off-main in
  4.0.4, and Application.onCreate defers heavy work to applicationScope. So the remaining ANRs are NOT
  the crypto path and cannot be pinpointed from the code alone. NEXT STEP (blocked on NorseHorse): pull
  the top ANR cluster's stack trace from Play Console > Android vitals > Crashes and ANRs > the ANR >
  the main-thread stack, so the exact blocking frame is known before changing anything. Guessing risks
  regressions in a security app. Candidate areas to check against the trace: BouncyCastle provider
  insert + SecureKeyStore/Android Keystore init at cold start, ScratchFiles.clearAll (synchronous file
  IO on the main thread at startup, kept sync for plaintext-debris security), and any Keystore/StrongBox
  access on a UI action. A baseline profile (androidx.profileinstaller + a macrobenchmark run on device)
  would cut cold-start jank and also lift the Play "Optimization" metric; it must be generated on a
  device, so it is a NorseHorse task.

  UPDATE (Sep 8, root cause from the Crashes-and-ANRs list): every ANR/crash is on 430 (4.3.0). The top
  ANR clusters are PGPCryptoService.build* (software keygen, 48%+) and pqc.CompositeKeyGen (PQC keygen),
  both "Input dispatching timed out" -> keygen ran on the MAIN THREAD in 4.3.0. Current code (4.4.0+)
  already fixes it: KeyRepository.generateKey wraps everything in withContext(Dispatchers.Default), and
  both UI entry points (KeyringViewModel.generateKey; onboarding reuses it) go through it. So the
  headline ANR is already resolved; the 1.78% (rolling window dominated by un-updated 4.3.0 installs)
  will fall as users move up. No keygen-threading change needed in 4.5.0; watch the rate on the next
  release. Two current-code crashes from the same list were hardened in 4.5.0: ClipboardService.copyText
  now try/catches setPrimaryClip (OEM ROMs + oversized-clip TransactionTooLargeException throw there;
  ~12% of crashes) so a failed copy is a no-op not a crash; DocumentBytes.readDetailed now catches
  Throwable on its four in-memory reads (OutOfMemoryError on a huge picked file) -> graceful null the
  caller already handles. Remaining rows (MainActivity IllegalStateException x1, MessageQueue.native ANR
  x1) are single-user 4.3.0-only, low priority.

- App optimization below 25% (Optimization / Obfuscation / Shrinking all 13%) [medium]. R8 minification
  is already on; the low percentage is a side effect of the deliberate broad keep rules that protect
  BouncyCastle and the OpenPGP Binder contract (documented: 4.0.x shipped without the contract keeps
  and R8 renamed OpenPgpSignatureResult, crashing Thunderbird/K-9 with BadParcelableException). Do NOT
  narrow those crypto/contract keeps to chase the metric. Done in 4.5.0: enabled isShrinkResources in
  the release buildType (safe, minifyEnabled already on) — lifts the Shrinking metric; verify on a
  release build that no dynamically-named resource is stripped. Further, safe obfuscation gains would
  come from a baseline profile (above), not from touching the keeps.

- Recommendation: bitmap downsampling for memory (QR bitmaps are the likely source). Low priority;
  fold into the QR generation path if it decodes/holds full-size bitmaps.

Delivery: isShrinkResources verified on a release build with a full crypto/keygen/import/decrypt
smoke test (R8 + resource shrinking failures are runtime, not compile). ANR fix follows the pulled
stack trace.

## 23. Truncated PGP message throws a raw range error instead of a clear "incomplete message"

Priority: medium (error-handling / UX). Not a decrypt correctness bug. Origin: Grigori Perelman
(4.4.1 feedback), then self-resolved.

RESOLVED as user error, with a real follow-up. The reporter first saw "Decryption failed: toIndex
(3370) is greater than size (2784)" on a post-quantum message and thought it was a length limit. He then
found the actual cause himself: copying the armored message out of Telegram, he did not select the whole
block, so PGPony was handed a truncated message. A cut-off armored message decodes to fewer bytes than
its own packet headers declare (a header says 3370 bytes follow, the buffer ends at 2784), and the read
runs off the end. That is exactly the observed error.

So there is no crypto bug here. The remaining, legitimate item is error handling: PGPony should detect a
truncated or malformed OpenPGP message and surface a clear message ("this message looks incomplete, make
sure you copied the whole block") instead of a raw range-check exception that reads like a crash. This is
common: chat apps that scroll make partial selection easy, and the next person will hit the same thing.

Work:
- Wrap the decrypt entry so an IndexOutOfBounds / range error (and a dearmor that ends without a proper
  END line, or a packet whose declared length exceeds the remaining bytes) maps to a friendly
  "incomplete or corrupted message" error string, not the exception text. Cheap, no crypto change.
- Optional: a lightweight pre-check that the armored block has a matching BEGIN/END and a CRC that lines
  up, to catch truncation before decrypt even starts.

Compression (his second question) is answered and needs nothing: PGPony already ZLIB-compresses every
payload on encrypt; a post-quantum message is large because of the ML-KEM encapsulation in the header,
which does not compress. See the reply sent for 4.4.1.

## 24. Primary "Never" shows stale beside a live subkey date - reconcile primary expiry live (FIXED in RC)

Priority: low. Origin: lukascomer (4.4.x feedback), imported RSA 3072 v4 key.

Reported: the primary read "Never" while the encryption subkey read "Sep 13, 2050" on the same key. The
first hypothesis (PGPony missing a primary expiry stored on the UID self-cert rather than a direct-key sig)
was wrong, and its speculative primaryKeyValiditySeconds helper was reverted.

Root cause (confirmed, not a parsing bug): the primary expiry is captured on the entity at import and stored,
while the subkey expiry is recomputed live from the ring every time Key Details opens. gpg AND BouncyCastle
both read this key's primary as expiring 2050-09-13 (fixture keys/uid-selfsig-expiry-rsa.asc;
PrimaryKeyExpirationTest asserts master.validSeconds = 851472000 = 2050-09-13). The stale entity.expiresAt
came from an older import or older build, so the stored primary showed "Never" while the live subkey read the
real date.

Fix (shipping in RC): KeyRepository.reconcilePrimaryExpiry(entity) reads the primary's Key Expiration Time
straight off the ring, using the same creationTime + validSeconds formula deriveSubkeys uses for subkeys, and
persists the corrected value via dao.update when it has drifted. KeyDetailViewModel.load() calls it right
after getByFingerprint, so opening Key Details self-corrects a stale primary without a manual re-import, and
because the corrected value is persisted the key list and every reload path inherit it. Composite-sign
primaries do not load as a PGPPublicKeyRing, so they are left unchanged. PrimaryKeyExpirationTest stays as the
regression guard that BC keeps reading the primary expiry reconcile depends on.


Reopened (Sep 13 2026, lukascomer on RC2): the reconcile was correct but he still saw "Never", because the
REAL cause was upstream. KeyDeduplicationService.merge (reached from the keyserver refresh via
KeyRefreshService.processFetchedArmored -> mergeFetchedPublicMaterial -> resolveDuplicate) overwrote the
stored public material and set expiresAt to the fetched value unconditionally, with no "prefer later expiry"
guard. His re-published keyserver copy has a no-expiry primary, so a background refresh (his screenshot shows
a recent "Last checked") replaced his stored 2050 key with the no-expiry one; the reconcile then correctly
showed Never for what was stored (the subkey kept 2050 from its own binding). gpg on his actual key confirms
the primary really does expire 2050-09-13. Fix: resolveDuplicate now bails to ALREADY_IN_KEYRING when
KeyDeduplicationService.isExpiryDowngrade(existing.expiresAt, fetched) is true (fetched removes or shortens an
expiry the stored key has); adding/extending/matching still merges, and a published revocation is scanned
separately upstream so it is not suppressed. KeyDeduplicationExpiryGuardTest locks the guard. lukas re-imports
the good key once and it sticks. rc3.

## 25. Onboarding toggle to drop the PGPony armor comment

Priority: low. Origin: NorseHorse (Sep 13 2026, rc3).

The "Comment: PGPony - PGPony.app" armor header on encrypted/signed output was already user-configurable
in Settings (ArmorCommentStore.setInclude, default on). Surfaced the same message-comment toggle on the
onboarding privacy slide so users can turn it off up front: OnboardingSlide.showCommentToggle (set on the
privacy slide), a CommentToggleRow in OnboardingPage wired to ArmorCommentStore.get(context).setInclude,
and onboarding_page_comment_toggle_title/subtitle strings. Reads its initial state from
ArmorCommentHeader.current, writes through the same DataStore the Settings screen uses, so the two stay in
sync. Message comment only (the pubkey-export comment keeps its own Settings toggle). UI-only, verified on
device. rc3.

## Carried-over follow-ups (optional, from the 4.4.x cycle)

- loadPublicKeyRing returns null for a private-only key, which breaks encrypt-to-self and
  export for such keys; add a derive-public-from-secret fallback.
- A freshly generated key needs an app restart before it can be selected for signing.
- Move the per-address signing-key pin off MODE_MULTI_PROCESS SharedPreferences to Room.


## Parked (not 4.5.0 unless promoted)

- Move a software key onto a hardware key (idea from lukascomer). Feasible direction only: writing an
  existing software key onto a security token / OpenPGP smartcard that supports key import (a keytocard
  style flow). The reverse (hardware to software) is impossible by design, a hardware key never releases
  its private key, and root does not bridge it (root reaches the phone's storage, not a token's protected
  key). If promoted, scope it to software-to-card import on tokens that allow it; PGPony already has the
  card plumbing (importCardKey / card-backed entities).

- Fully UID-less (fingerprint-only) v6 keys, if name-only (item 3) covers the need.
- UID revocation and primary-UID reordering for composite keys (beyond item 4's add/show).


## Delivery note

Android first per the new-feature procedure. iOS and desktop ports mirror the Android
implementation once each item is verified, and are tracked separately, not in this doc.
