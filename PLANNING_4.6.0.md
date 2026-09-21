# PGPony Android 4.6.0 — Planning

Status: planning (opened Sep 13 2026). Feature and fix list for the 4.6.0 cycle, seeded from
forum.dark.vegas user feedback. Android leads, then iOS mirrors each item once verified. Items are
detailed enough to build against; priorities and the RC breakdown are set once the list settles.

Context: the armor-comment onboarding toggle FreeDegenAuditor asked for (forum.dark.vegas, 31 Aug 2026)
already shipped in 4.5.0 rc3 as item 25 (Settings > Encryption toggle surfaced on the onboarding privacy
slide), so it is not a 4.6.0 item.


## 1. Key notes on the keyring list, and a reachable place to edit them

Priority: medium. Origin: SilverDefiFarmer (forum.dark.vegas, 0xf77e...17c7, 12 Sep 2026).

Reported: short local notes per key are useful for tying a key to a company or identity, especially when
the UID email is random or opaque (his example: label norsehorse@norsehor.se as "Pony" or "PGPony"). Two
concrete gaps: (a) a note can be added per key today, but it does NOT show on the keyring list screen, so
it can't act as the at-a-glance label he wants; (b) the add-note action sits at the bottom of Key Details,
so it is hard to find and reach.

What already exists: per-key notes are stored (PGPKeyEntity.notes, written via KeyRepository.updateNotes /
dao.update(key.copy(notes = ...))), and Key Details has a notes editor near the bottom. So this is a
surfacing and placement change, not new storage.

Work:

- Keyring list (KeyringScreen key row): when a key has a note, show it on the row as a local label, near
  the identity line, visually distinct from the UID (it is user-authored, not from the key). Truncate to a
  single line. Decide placement: under the name/email, or as a chip. Keys with no note render as today.
- Key Details: move the note edit affordance up to the identity area (near the top), instead of only at the
  bottom. Options: a small "add / edit label" control by the primary UID, or reorder the existing notes
  section higher. Keep the full editor, just make it reachable without scrolling to the end.
- Terminology: the user treats the note as a label/alias. Keep the single existing notes field (do not add a
  second field); just present it as a label on the list. If a distinct short "label" vs long "note" split is
  wanted later, scope it separately.

Research / unknowns:

- List truncation length and whether the label replaces or accompanies a random-looking email on the row.
- Whether a note should also be searchable / filterable in the keyring search (nice-to-have follow-on).
- iOS mirror: iOS KeyDetail has the same notes field; mirror both the list label and the reachable editor.

Delivery: a key with a note shows that note as a label on the keyring list, and the note editor is reachable
near the top of Key Details without scrolling to the bottom. Verified on device.


## 2. Import a public key from a URL, with a fingerprint check before it is added

Priority: medium. Origin: SwappingZkTrader (0x0b94...f3f3, 02 Sep 2026); verify-before-add refinement from
BanklessTechDev (0xd626...868c, 02 Sep 2026).

Reported: add an option to import a PGP key from a URL. And, before the key is actually added to the
keyring, display its fingerprint so the user can verify it is the key they expected (a manual trust check),
then confirm or cancel.

This is distinct from the existing keyserver lookup and from WKD (4.5.0 item 21): those resolve a key by
email/key-id from configured servers. This is fetching an arbitrary user-supplied URL (a raw .asc, a
key hosted on a site, a gist, a personal page).

Work:

- Entry point: an "Import from URL" action in the keyring import surface (alongside paste / file / scan).
- Fetch: reuse the existing proxy-aware HTTP client (the one KeyServerRepository / MultiKeyServerService use),
  so the fetch rides the offline switch and the Off/Orbot/Custom proxy setting for free. Enforce https (or warn
  loudly on plain http). Apply a response size cap. When offline mode is on, disable the action (same as
  keyserver lookups) rather than silently doing nothing.
- Parse: run the fetched body through ArmorExtractor (4.5.0 item 19) so a key embedded in an HTML page or with
  surrounding text still parses; handle a response carrying more than one key block.
- Verify-before-add sheet: after a successful fetch, show a confirmation sheet with the parsed key's
  fingerprint (full, monospace, groupable), primary UID(s), algorithm label, created/expiry, and a count if
  the response held multiple keys. The key is NOT written to the keyring until the user taps Add. Cancel
  discards it. This is the trust checkpoint BanklessTechDev asked for.
- On confirm: route through the normal import path (dedup / merge-on-matching-fingerprint, the same one paste
  and file import use), so a URL import of a key already held behaves like any other re-import.

Research / unknowns:

- HTTP redirects: follow within https only, cap the count, and verify the final content is a key, not an
  unrelated page.
- Whether to remember recently used import URLs (probably not, for privacy; leave it stateless).
- Security posture: an arbitrary-URL fetch is a network request from the app; it MUST go through the
  proxy-aware client, respect offline mode, and never auto-trust the fetched key. The fingerprint-verify sheet
  is the safeguard; the key gets no trust bump on import, same as any imported public key.
- iOS mirror: iOS already added the GitHub recipient-fetch-with-proxy pattern (AgePony 4.0.0 lineage / PGPony
  iOS), so an iOS URL import reuses that proxy plumbing.

Delivery: the user enters a URL, PGPony fetches it through the offline/proxy-aware client, shows the fetched
key's fingerprint and UID for verification before anything is stored, and only writes it to the keyring on
explicit confirm. Verified on device with a raw .asc URL and with a key embedded in an HTML page.


## 3. Offer ML-DSA-87 as a key-generation algorithm, paired with ML-KEM-1024

Priority: medium. Origin: Scott Lu (email, "PGPony Android Feedback (4.5.0)", Google Pixel 8, Android 17,
6:39 PM).

Reported: add ML-DSA-87 as an option when choosing the algorithm for key generation, paired with
ML-KEM-1024 as the default encryption key when generating the key pair.

What already exists: ML-DSA-87+Ed448 (KeyAlgorithm.MLDSA87_ED448_V6, algo 31) is a defined algorithm and is
already offered as a composite SIGNING SUBKEY (AddSubkeyChoice.PqSigning MLDSA87_ED448), and ML-KEM-1024+X448
(CompositeSuite.IETF_1024, algo 36) already generates both as an encryption primary and as an encryption
subkey. Two gaps remain for the primary composite-signing keygen: the picker list generatablePostQuantum in
KeyAlgorithm only carries MLKEM1024_X448_V6 and MLDSA65_ED25519_V6, so a composite ML-DSA-87 PRIMARY cannot
be generated from the UI; and CompositePrimaryKeyGen hardcodes the bundled encryption subkey to ML-KEM-768
(KEM_SUITE = IETF_768) regardless of the signing tier.

Work:

- Add MLDSA87_ED448_V6 to generatablePostQuantum so the primary keygen picker offers an ML-DSA-87 composite
  key alongside ML-DSA-65.
- Pair the bundled encryption subkey to the signing tier instead of hardcoding it: an ML-DSA-87 primary ships
  a ML-KEM-1024+X448 (IETF_1024) encryption subkey, an ML-DSA-65 primary keeps ML-KEM-768+X25519 (IETF_768).
  CompositePrimaryKeyGen.assemble takes the KEM suite from the chosen signing suite rather than the fixed
  KEM_SUITE constant.
- Thread the chosen signing suite from the keygen UI through the repository generate path into assemble.

Research / unknowns:

- Default vs option: Scott suggests ML-DSA-87 + ML-KEM-1024 as the default. These keys are much larger
  (ML-DSA-87 public material 2592 bytes, ML-KEM-1024 1568) and slower to generate and sign than the 65/768
  pair. Decide whether ML-DSA-65 + ML-KEM-768 stays the default with 87/1024 as an explicit stronger option,
  or 87/1024 becomes default. Leaning toward keeping 65 default and adding 87 as an option, since the larger
  keys cost size and speed for a security margin most users do not need yet.
- Size knock-on: larger keys affect armored export length and the QR export path (a 1024/87 public key may not
  fit a single scannable QR). Check the QR and share paths against the larger material.

Delivery: the key-generation picker offers an ML-DSA-87 composite primary, and generating one produces a
matching ML-KEM-1024 encryption subkey rather than a ML-KEM-768 one.

Refinement (Scott Lu, follow-up, 7:49 PM): frame the choice as two tiers rather than a single option. Keep
ML-DSA-65 + ML-KEM-768 as the DEFAULT for portability, speed, and already-ample security, and offer
ML-DSA-87 + ML-KEM-1024 as a max-security option with the larger, slower keys. That settles the default
question above: 65/768 stays default, 87/1024 is the explicit stronger opt-in.

Out of scope: Scott also suggested an even-lighter ML-DSA-44 + ML-KEM-512 tier. Those NIST levels exist, but
the OpenPGP PQC draft (draft-ietf-openpgp-pqc, the composite code points PGPony implements) registers
algorithm IDs only for ML-KEM-768, ML-KEM-1024, ML-DSA-65, and ML-DSA-87. There is no OpenPGP composite code
point for ML-DSA-44 or ML-KEM-512, so a 44/512 key would have no interoperable on-wire encoding and no other
OpenPGP tool could read it. Not viable until the spec registers those levels; revisit if it does.


## 4. File signing with composite ML-DSA keys (MOVED TO 4.5.3)

GitHub #65 (elnardosa). Implemented in the 4.5.3 tree, no longer 4.6.0 work. In-app file detached sign and file
encrypt-and-sign now route a composite ML-DSA signer through CompositeDocumentSigner / crypto.encrypt (buffered,
since a composite signature covers the whole document and cannot stream), instead of the classical BouncyCastle
signer that could not see an algo-30/31 key. See RELEASE_NOTES_4.5.3.md.

## 5. Key Detail avatar shortcut fix, additive encrypt recipients, and Default Key polish

Priority: medium (one bug, rest polish). Origin: CertainBot (GitHub #63), tested on 4.5.1.

Reported and confirmed:

- Bug: the Key Detail header-avatar shortcut works on a public key (opens Encrypt with that key preset as
  recipient) but on a KEY PAIR it opens Decrypt without setting the key, leaving the default in "Decrypt with."
  The key-pair side must preset the decrypt key the way the public side presets the recipient.
- Encrypt shortcut should be ADDITIVE: add the tapped key to the current recipient selection rather than
  replacing it. Clearing one recipient with the x is easy; rebuilding a whole set is not.
- Default Key (Settings > Keys & Servers): the picker lost the star visual cue and moved to the left under the
  title; restore the star and move it back to the right of the title. Consider dropping the oval control
  background if it reads cleaner.

Work: fix the key-pair avatar navigation to carry the key into the Decrypt screen's selection; make the encrypt
avatar append to the recipient set; restore the star and right-alignment on the Default Key picker.

Delivery: the avatar shortcut sets the key on both Encrypt (added to current recipients) and Decrypt; the
Default Key picker shows the star and sits to the right of the title. Verified on device.


## 6. One payload-aware share dialog (consolidate the share actions)

Priority: medium. Origin: CertainBot (GitHub #58), after the share-to-PGPony work shipped across 4.5.0 to 4.5.1.

Reported: the share paths that shipped separately (Import, Import and encrypt to key, Encrypt text) should live
in the single "What would you like to do?" dialog, so the user chooses in one place instead of picking among
share targets. Extend the same treatment to shared ciphertext or signed text.

Work:

- When shared text contains a public key, offer Import, Import and encrypt to key, and Encrypt text in the one
  dialog.
- When shared text contains an encrypted or signed PGP payload, offer Decrypt text (isolating the payload from
  any surrounding text), and offer Encrypt text as well when there is extra text alongside the payload.
- Show each option only when it applies to what was actually shared. This turns the sheet into a small
  payload-aware wizard for users who are not deep in PGP.

Delivery: sharing text to PGPony opens one dialog whose options match the payload (key, ciphertext, signed, or
plain text). Verified on device.

Also reported (a tester, 4.5.3 RC2 testing), same consolidation:

- The Quick Action is labeled "Decrypt / Verify" but only handles encrypted and encrypted+signed messages, not
  signed-only messages. Either it verifies signed-only input or the label should not promise it. The
  signed-only-verify piece is the one part worth pulling earlier, so the button stops advertising something it
  cannot do.
- The Quick Action encrypt direction offers only Encrypt, never Sign or Encrypt+Sign, for text or files.
- Sharing text into PGPony offers encryption only, not decrypt or verify. OpenKeychain offers both directions
  and handles signed-only, with a clear indication of whether the message was encrypted.


## 7. Open UX decision: trust-level colors and shield symbols

Priority: low (decision, not yet scheduled). Origin: AraafRoyall and CertainBot (GitHub #36).

Two users want opposite trust-ladder colorings (green at the top for Ultimate vs green for verified public keys
with blue for Ultimate), and CertainBot also proposed swapping the X and ! shield symbols (X for unknown/grey,
! for caution/yellow). Left unchanged across 4.4 to 4.5 rather than flipped mid-thread. Plan: split this into
its own GitHub issue where each side's reasoning is laid out, decide once, then apply. Not blocking 4.6.0.


## 8. Parallel effort (not release-gated): SOP interoperability wrapper

Tracked in GitHub #64, decoupled from the app release cadence. A Stateless OpenPGP CLI over PGPony's crypto so
it can join the sequoia-pgp interop test suite. hko-s confirmed the interop run needs only the core roundtrip
commands (skip revoke-key, update-key, merge-certs, certify-userid, validate-userid, armor, dearmor) and
pointed at rsop as a local reference. The value is roundtrip coverage of the composite ML-DSA / ML-KEM paths
against other implementations. Listed here for visibility; it does not gate the 4.6.0 app release.


## 9. Key Detail: "Upload to Key Server" disappears after the first upload

Priority: medium. Origin: NorseHorse, from the iOS 8.3.0 planning pass (Sep 21 2026), which compared both
Key Detail screens.

The overflow menu (KeyDetailScreen.kt) and the legacy ActionRow (KeyDetailSections.kt) both gate "Upload to
Key Server" on `!keyServerUploaded`, and nothing ever clears that flag (KeyRepository.markKeyServerUploaded is
the only writer; KeyDeduplicationService.merge copies it forward). So once a key has been uploaded, adding a
subkey or an identity, changing the primary, editing expiry or revoking a subkey leaves no way to publish the
change from Key Detail; the Exchange tab is the only path.

Work:

- Drop the `!keyServerUploaded` gate on both surfaces. Label reads "Upload to Key Server" before any upload
  and "Update on Key Servers" once `keyServerUploaded` is set or KeyPublicationStore has a record.
- PublishSheet on an update pre-checks only the servers the key was published to before (a first upload keeps
  every publish-enabled server checked), shows "Last uploaded <date>" per server, and lists per-address
  verification state so a newly added identity's confirmation is visible.
- Build the payload from the stored ring at upload time (exportArmoredPublicKey already does) and assert,
  before enabling Publish, that exactly one live User ID carries the primary flag and it is the one the entity
  shows; refuse with a local repair hint otherwise. Same builder for the Exchange upload.

Delivery: add a subkey to an already-published key, open Key Detail, "Update on Key Servers" is offered,
publishes to the servers used before, and a fresh lookup on each server shows the subkey. iOS mirror: 8.3.0
sections 2 and 3.


## 10. Key Detail overflow menu ignores offline mode

Priority: low (consistency). Origin: same planning pass.

The RC1 offline switch hid the keyserver check / refresh ActionRows while offline, but the 4.3.0 overflow
menu that replaced them (KeyDetailScreen.kt around line 340) shows Check key server, Refresh from key server
and Upload regardless of OfflineMode.enabled, so an offline user can trigger a request that then fails at the
client. Gate the three menu items on `!OfflineMode.enabled`, matching the ActionRows and the iOS rule that
every network action is hidden while offline.

Delivery: with offline mode on, the Key Detail overflow shows no keyserver items; off, all three return.


## 11. "Your published copy is out of date" marker

Priority: medium. Origin: same planning pass; the counterpart of item 9.

Neither app tells the user that a local key edit has not reached the servers. Add `lastLocalEditAt` to
PGPKeyEntity, set it on add / revoke / delete User ID, make-primary, add / revoke / remove subkey, expiry edit,
notation edit and key revocation, and compare it to `lastUploadedAt`. When newer on a published key: the
DetailsSection "Key server" row reads "Published (local changes not uploaded)", the overflow item reads
"Update on Key Servers", and an inline row under the header offers the update in one tap, reusing
PublishSheet the way the post-keygen prompt does. Key revocation gets the same offer right after the
certificate is produced, since a revocation that never reaches the servers protects nobody.

Delivery: edit a published key, see the marker and the one-tap update, update, marker clears; revoke a
published key, the publish offer appears in the revocation result.


## 12. Key-server refresh: union merge, and the local copy authoritative for key pairs

Priority: medium-high (correctness). Origin: same planning pass, following the lukascomer expiry-downgrade
fix (4.5.0 item 24) and the 4.5.1 deleted-UID tombstones.

KeyDeduplicationService.merge still replaces the stored public material with the fetched copy when they
differ. keys.openpgp.org and keys.pgpony.app both serve a key with every unverified User ID stripped (and no
User IDs at all when none is verified), and keys.openpgp.org strips third-party certifications, so a
background refresh of a key with an unconfirmed new address can drop that identity locally, and the
primary flag with it, on both apps. The expiry guard and the tombstones close two instances of this; the
general rule is missing.

Work:

- Public-only keys: a certificate union merge. Keep every local packet (User IDs, subkeys, self-certs,
  third-party certs, notations) and add from the fetched copy only what is new (a subkey, a User ID that is
  not tombstoned, a signature, a revocation). Packet identity: key packets by fingerprint, User IDs by bytes,
  signatures by type, issuer, creation time and digest prefix.
- Key pairs: the local copy is authoritative. A refresh imports only revocation signatures (0x20 on the
  primary, 0x28 on subkeys, 0x30 on User IDs) and third-party certifications; it never touches self-certs,
  User IDs, subkeys or expiry.
- The 4.5.0 isExpiryDowngrade guard and the 4.5.1 RemovedUserIdStore tombstones stay as they are and sit
  inside these rules.

Delivery: fixture pair per case (a local cert with two User IDs and a "server" cert with one; a key pair
against a server copy with an extra self-cert; a downgrade expiry), plus the on-device check: add an
identity, upload, do not confirm the email, Refresh from key server, identity and primary badge intact.
iOS mirror: 8.3.0 section 3.3(d).


## 13. LibrePGP ML-KEM-768 + brainpoolP256r1 keygen, and an "experimental" tag on PQC options

Priority: medium. Origin: Bart (limbodiver), Sep 2026, after cross-app testing against GnuPG/Kleopatra.

Bart asked for the two LibrePGP composite KEM pairings Kleopatra offers. One already ships:
ML-KEM-1024 + brainpoolP384r1 (LibrePGP), added in 4.3.x (issue #2). The missing one is
ML-KEM-768 + brainpoolP256r1 (LibrePGP). The LibrePGP algo-8 path, the Brainpool domain handling, and
the v5 KEM subkey under a v4 Ed25519 primary all already exist for the P-384 variant, so this is the P-256
sibling of existing code, not new machinery. The pairing is strength-matched (ML-KEM-768 with a ~128-bit
curve) and matches what Kleopatra generates.

Second half: mark the post-quantum algorithms as experimental in the key generation picker. PQC OpenPGP still
has two non-interoperating drafts in flight (the IETF composite draft PGPony's ML-DSA keys follow, and the
LibrePGP/GnuPG variant), and the LibrePGP KEM keys are the ones that interoperate across apps today. A plain
"experimental" tag on those entries sets expectations and cuts down interop confusion reports.

Note the interop reason the LibrePGP keys work better: they are classical Ed25519 signing plus a PQC encryption
subkey, so signatures stay classical and verify everywhere; only the key exchange is post-quantum. The IETF
composite ML-DSA signing keys are the interop liability (their signatures are unreadable to tools without
composite support). Not proposing to drop them, just to label the whole PQC set experimental.


## 14. Composite ML-DSA signature framing when encrypting to a v4-only recipient

Priority: low-medium (interop correctness). Origin: NorseHorse, Sep 2026, during the 4.5.3 composite work.

When a composite ML-DSA signing key signs and encrypts to a recipient whose only key is v4, the container
falls back to SEIPDv1, but the composite one-pass and signature packets are still v6. A v6 signature nested in
v4 framing is a shape a strict v4-only parser can choke on. This does not hit the common case (a composite
recipient forces SEIPDv2), and it was set aside in 4.5.3 in favor of the composite verify fix, so it is still
open. Options: force SEIPDv2 whenever composite-signing (clean framing, but a v4-only recipient then cannot
read the message at all), or accept the nesting and document it. Given the direction toward LibrePGP
classical-signing keys, where signatures stay classical, this may end up low priority. Decide placement and
approach; not yet scheduled.


## 15. Composite signatures not verified through the share-target Quick Action

Priority: low. Origin: surfaced during the 4.5.3 trust/verify work. Do this alongside item 6.

The 4.5.3 work taught the decrypt screen, file decrypt, the OpenPGP provider and the Verify tab to verify
composite inline signatures and to show signer trust. ShareTargetViewModel.publishDecryptResult still reads
only result.signatureVerified, so a composite-signed message opened through the Quick Action shows unverified
even though decryptStream now surfaces the composite fields. Mirror buildVerificationResultForStream's
composite branch (resolve the signer, verifyInline, set the banner state) in the share-target publish path.
Fold into the item 6 share rework since both touch the same screens.


## Delivery note

Android first per the new-feature procedure. iOS mirrors each item once the Android version is verified,
tracked separately. This document is seeded from the forum.dark.vegas thread; add further items here as they
come in before the 4.6.0 scope is locked.
