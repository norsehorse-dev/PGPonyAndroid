# PGPony Android 4.6.0 — Planning

Status: RC1 (Sep 23 2026). Opened Sep 13 2026. Feature and fix list for the 4.6.0 cycle, seeded from
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

Status: done, verified on device. The first line of a key's note shows on its keyring row as a
label (tag icon, one line), and under the Key Detail header as a tappable label (or "Add a label") that opens
the note editor. The single notes field is kept; notes were already searchable.

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

Status: done, verified on device. New "Link" import method: https only (http for .onion),
through the proxy-aware client, hidden in offline mode, redirects followed by hand (at most 5, each hop
https), body capped at 8 MiB. Public key blocks are pulled out of a raw .asc, a binary key or an HTML page and
validated like a key-server answer (KeyResponse); private keys and messages are a miss. The key shows in the
usual import preview (fingerprint, User IDs, extra-key count, and the full source link) and is only added on
Import, through the normal dedup/merge path.

## 3. Offer ML-DSA-87 as a key-generation algorithm, paired with ML-KEM-1024

Priority: medium. Origin: a tester (email, "PGPony Android Feedback (4.5.0)", Google Pixel 8, Android 17,
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

- Default vs option: the tester suggests ML-DSA-87 + ML-KEM-1024 as the default. These keys are much larger
  (ML-DSA-87 public material 2592 bytes, ML-KEM-1024 1568) and slower to generate and sign than the 65/768
  pair. Decide whether ML-DSA-65 + ML-KEM-768 stays the default with 87/1024 as an explicit stronger option,
  or 87/1024 becomes default. Leaning toward keeping 65 default and adding 87 as an option, since the larger
  keys cost size and speed for a security margin most users do not need yet.
- Size knock-on: larger keys affect armored export length and the QR export path (a 1024/87 public key may not
  fit a single scannable QR). Check the QR and share paths against the larger material.

Delivery: the key-generation picker offers an ML-DSA-87 composite primary, and generating one produces a
matching ML-KEM-1024 encryption subkey rather than a ML-KEM-768 one.

Refinement (same tester, follow-up, 7:49 PM): frame the choice as two tiers rather than a single option. Keep
ML-DSA-65 + ML-KEM-768 as the DEFAULT for portability, speed, and already-ample security, and offer
ML-DSA-87 + ML-KEM-1024 as a max-security option with the larger, slower keys. That settles the default
question above: 65/768 stays default, 87/1024 is the explicit stronger opt-in.

Out of scope: the tester also suggested an even-lighter ML-DSA-44 + ML-KEM-512 tier. Those NIST levels exist, but
the OpenPGP PQC draft (draft-ietf-openpgp-pqc, the composite code points PGPony implements) registers
algorithm IDs only for ML-KEM-768, ML-KEM-1024, ML-DSA-65, and ML-DSA-87. There is no OpenPGP composite code
point for ML-DSA-44 or ML-KEM-512, so a 44/512 key would have no interoperable on-wire encoding and no other
OpenPGP tool could read it. Not viable until the spec registers those levels; revisit if it does.

Status: done, verified on device. ML-DSA-87 + Ed448 is in the Post-Quantum picker group with
its own caption; ML-DSA-65 stays first. CompositePrimaryKeyGen pairs the bundled encryption subkey with the
signing tier (87 gets ML-KEM-1024 + X448, algo 36; 65 keeps ML-KEM-768 + X25519).

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

Status: done, verified on device. The key-pair avatar carries its key into "Decrypt with" (a
card key takes the PIN + tap path); the public-key avatar adds the key to the recipients already chosen; the
Default Key picker is a row again with the star on the left and the choice as a plain text button on the right.


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

Status: done, verified on device. The Quick Action splits shared text (or a text file) into
what it holds (SharePayload): a public key offers Import key and Import and encrypt to this key (both open
the import preview for the fingerprint check); an encrypted message offers Decrypt (only the PGP block is
decrypted, not the text around it); a signed-only message (cleartext-signed, or a PGP MESSAGE that is signed
but not encrypted) offers Verify signature, which opens it on the Decrypt screen and verifies at once there,
with signer lookup, trust and composite support; plain text offers Encrypt, plus Sign, or encrypt and sign,
which opens it on the Encrypt screen; text around a PGP block offers Encrypt the other text. The decrypt card
now reads "Decrypt" (no longer promising Verify). Quick Action decrypt also now tries composite keys (their
ML-KEM subkey and any classical subkey) and says when a message is signed by a key not in the keyring.

## 7. Open UX decision: trust-level colors and shield symbols

Priority: low (decision, not yet scheduled). Origin: AraafRoyall and CertainBot (GitHub #36).

Two users want opposite trust-ladder colorings (green at the top for Ultimate vs green for verified public keys
with blue for Ultimate), and CertainBot also proposed swapping the X and ! shield symbols (X for unknown/grey,
! for caution/yellow). Left unchanged across 4.4 to 4.5 rather than flipped mid-thread. Plan: split this into
its own GitHub issue where each side's reasoning is laid out, decide once, then apply. Not blocking 4.6.0.

Status: tabled (Sep 23 2026). The thread went quiet; revisit only if either side raises it again. Not in
4.6.0.


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

Status: done, verified on device. Upload stays on the menu and ActionRow after the first upload,
labelled "Update on Key Servers". KeyPublicationStore records each server a key went to; PublishSheet
pre-checks those, shows "Last uploaded" per server and each address's confirmation state (read from the
served copy's certified User IDs; the old check searched the armor text and never matched). Publishing from
Key Detail now sets the uploaded flag and date. KeyRepository.publishPayload refuses a key with more than one
primary-flagged User ID or a flagged one that differs from the shown identity, in both Key Detail and
Exchange; Make Primary now clears every other flag so it repairs that state.


## 10. Key Detail overflow menu ignores offline mode

Priority: low (consistency). Origin: same planning pass.

The RC1 offline switch hid the keyserver check / refresh ActionRows while offline, but the 4.3.0 overflow
menu that replaced them (KeyDetailScreen.kt around line 340) shows Check key server, Refresh from key server
and Upload regardless of OfflineMode.enabled, so an offline user can trigger a request that then fails at the
client. Gate the three menu items on `!OfflineMode.enabled`, matching the ActionRows and the iOS rule that
every network action is hidden while offline.

Delivery: with offline mode on, the Key Detail overflow shows no keyserver items; off, all three return.

Status: done, verified on device. The upload/update, check and refresh menu items are hidden
while offline.


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

Status: done, verified on device. PGPKeyEntity.lastLocalEditAt (DB v11, MIGRATION_10_11) is
stamped by every key-editing repository call; hasUnpublishedChanges drives the Key server row, the menu label
and an Update row under the header. The revocation result sheet offers "Publish revocation to key servers".


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

Status: done in code, landed with item 17.1 (crypto/CertificateMerge.kt, CertificateMergeTest). Its own
on-device check (add an identity, upload, leave the email unconfirmed, Refresh from key server, identity and
primary badge intact) goes in the RC1 pass.


## 13. LibrePGP ML-KEM-768 + brainpoolP256r1 keygen, and an "experimental" tag on PQC options

Priority: medium. Origin: limbodiver, Sep 2026, after cross-app testing against GnuPG/Kleopatra.

limbodiver asked for the two LibrePGP composite KEM pairings Kleopatra offers. One already ships:
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

Status: done, verified on device. ML-KEM-768 + brainpoolP256r1 (LibrePGP, gpg ky768_bp256)
generates from the Advanced group: v4 Ed25519 primary plus a v5 algo-8 subkey, SHA3-256 in the ECC KEM KDF,
round-trips in PGPony. Not yet checked against gpg 2.5 / Kleopatra (no gpg 2.5 available here); a tester
with Kleopatra should import it and encrypt both ways. Every post-quantum picker entry now shows a
"Limited app support" line (not "experimental": the keys are complete, other apps are the limit), and a
note under the caption says so.

Release gate (added Sep 23 2026, tester follow-up): the same tester reports the GnuPG Kyber + Brainpool
keys are the only hybrid keys that work cleanly between PGPony and Kleopatra today, and asked that both
Brainpool pairings be tested against Kleopatra before 4.6.0 ships. Before tagging 4.6.0, in the Windows
VMware VM with a current Gpg4win (GnuPG 2.5): generate ky768_bp256 and ky1024_bp384 in Kleopatra, import
into PGPony, encrypt and decrypt both directions; then the reverse with PGPony-generated keys imported into
Kleopatra. Also from the same report, for context only: ky1024_cv448 (ML-KEM-1024 + X448) exists in GnuPG
but Kleopatra does not offer it in its UI yet, and keys generated in GPGFrontend do not work correctly in
Kleopatra, so neither is a PGPony regression to chase.

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

Tested in 4.6.0 against gpg 2.4.4 and rnp 0.17 (Thunderbird's library): gpg prints the text but warns
"unknown version 6" and exits 2; rnp refuses the message outright ("no signatures", no plaintext). The
classical-signed control decrypts cleanly in both.

Decision: ask each time. PGPony itself reads that shape, signature included (decrypts, finds the composite
signer, verifies), so dropping the signature outright would cost PGPony-to-PGPony users for no reason. Status:
done, verified on device. When a composite ML-DSA signer encrypts text or a file to any v4
recipient (the SEIPDv1 case), the Encrypt screen shows a prompt: PGPony reads the signature, GnuPG shows the
message with an error, Thunderbird cannot open it. Buttons: Sign anyway, Send unsigned, Cancel. Send unsigned
leaves the composite one-pass and signature packets out (still encrypted to everyone); the result sheet then
drops the Signed badge and shows a note. All-v6 and composite recipient sets never prompt and stay signed. The
OpenPGP provider path (sign+encrypt from a mail app) keeps the signature, since the calling app asked for one
and has no prompt. Re-checked with Send unsigned: gpg and rnp decrypt the v4 case with exit 0.
CompositeSignV4RecipientTest covers: v4 signed by default and verified in PGPony, Send unsigned for v4 and for
mixed v6 + v4, and all-v6 staying signed. Strings in all 8 locales.


## 15. Composite signatures not verified through the share-target Quick Action

Priority: low. Origin: surfaced during the 4.5.3 trust/verify work. Do this alongside item 6.

The 4.5.3 work taught the decrypt screen, file decrypt, the OpenPGP provider and the Verify tab to verify
composite inline signatures and to show signer trust. ShareTargetViewModel.publishDecryptResult still reads
only result.signatureVerified, so a composite-signed message opened through the Quick Action shows unverified
even though decryptStream now surfaces the composite fields. Mirror buildVerificationResultForStream's
composite branch (resolve the signer, verifyInline, set the banner state) in the share-target publish path.
Fold into the item 6 share rework since both touch the same screens.

Status: done, verified on device. Quick Action decrypt results (text, MIME, in-memory file
and streamed file) verify an inline composite ML-DSA signature against the stored composite key, as the
Decrypt screen does, instead of reading only signatureVerified.

## 16. SSH authentication: expose auth-capable keys to an ssh-agent bridge

Priority: medium. Origin: issue #68, Sep 2026.

The ask: let PGPony act as the key store behind an ssh-agent in Termux, the way OpenKeychain does through
OkcAgent. In that setup the `okc-agents` Termux package runs a small fake ssh-agent (`okc-ssh-agent`); when
`ssh` asks it to sign a challenge, it hands the request off over the OpenKeychain SSH authentication API to
OpenKeychain, which holds the auth-capable key (soft key or card) and returns the signature. The private key
never leaves the app or the card. To be the target of that bridge, PGPony needs two pieces it does not fully
have yet.

First piece, the key material. The v6 keygen path deliberately omits the authentication subkey today
(PGPCryptoService, the v6 builder comment: layout is the Sequoia shape "MINUS the authentication subkey,
deferred to the SSH-auth phase"). So step one is generating an `[A]` authentication subkey (Ed25519 for the
classical layout; decide separately whether the PQC layouts get one). Card-backed auth is further along: the
card session already reads the AUTHENTICATION slot (algorithm attributes, fingerprint, gen time), so a
hardware key with a populated auth slot can be addressed; the signing op for that slot still needs wiring.

Second piece, the API surface. OkcAgent does not bind to the OpenPGP API PGPony already implements
(PGPonyOpenPgpService in :remote_api). It binds to OpenKeychain's separate SSH authentication AIDL service
(ISshAuthenticationService: describe the key, sign a challenge, return an SSH-format signature). Two ways to
be reachable: implement that same AIDL interface under PGPony's package so a client pointed at us can bind, or
ship/point a PGPony build of `okc-agents` at our service. Upstream `okc-agents` hardcodes OpenKeychain's
package and service names, so a stock install will not find PGPony without either a configurable target
package upstream or a small fork. The honest near-term shape is: PGPony provides the on-device SSH auth
service and auth keys, and the Termux client side is a fork or an upstream patch, not a stock `pkg install`.

Scope for 4.6.0: land the `[A]` subkey in keygen and the card auth-slot signing op, and implement the SSH
authentication service (challenge signing, key export in SSH/authorized_keys format, a consent/unlock gate per
request). The Termux-client integration (fork vs upstream configurable target) is tracked as a follow-up
rather than release-gated, since it lives outside this repo. Sequencing note: the `[A]` subkey work also
unblocks anything else that wants authentication keys, so it is the first sub-task regardless.

Decisions: keygen gets an opt-in "Add SSH authentication subkey" switch (off by default, so the default key
shape is unchanged); composite ML-DSA keys may carry a classical Ed25519 (or RSA) auth subkey for SSH; the
calling app is allowed once and a protected key unlocks once per session, like the OpenPGP provider; the
Termux side goes upstream as an OkcAgent patch, with a fork only if it stalls.

Status: done, verified on device.
- SshAuthenticationService (:remote_api, exported, action org.openintents.ssh.authentication.
  ISshAuthenticationService, API version 1): SELECT_KEY (PGPony's key picker in an SSH mode that lists only
  keys with a usable auth subkey), GET_SSH_PUBLIC_KEY, GET_PUBLIC_KEY (X.509), SIGN. Key id is the primary
  fingerprint; a decimal 64-bit key id (what OpenKeychain hands out) is accepted too. Consent, passphrase and
  card prompts reuse the provider activities and hand the request back so the client re-executes it.
- crypto/ssh/SshAuth: picks the newest bound, unrevoked, unexpired auth-flagged subkey from the certificate
  (CertificateBindings, so v4, v5, v6 and composite primaries alike); OpenSSH encoding for Ed25519 (algo 22
  and 27), RSA (ssh-rsa, rsa-sha2-256, rsa-sha2-512) and ECDSA P-256/384/521; signature blobs.
- Card: INTERNAL AUTHENTICATE on the auth slot (PW1 0x82), with a wrong-card and slot-mismatch guard.
- Keygen switch (simple mode; granular mode already offers the subkey): RSA 2048 / 4096 keys get an RSA
  auth subkey of the same size, every other key Ed25519. Key Detail menu: Copy SSH Public Key
  (authorized_keys line) when the key has an auth subkey.
- Verified: ssh-keygen -Y verify accepts signatures from every key type above (v4 and v6 Ed25519, RSA,
  ECDSA on all three curves, Ed25519 and RSA auth subkeys on a composite ML-DSA key), and a real OpenSSH login
  to sshd through an agent backed by this code works for Ed25519 and RSA (rsa-sha2-512). SshAuthTest covers
  the same in unit tests.
- On device: v4 Ed25519 auth subkey with a passphrase logged in to Termux sshd through the patched
  OkcAgent; the passphrase prompt arrived through OkcAgent's notification. OkcAgent needs notification
  permission on Android 13+, and an unanswered prompt blocks every later request until it is force-stopped.
- OkcAgent patch: a "Crypto provider" setting listing installed apps that offer the SSH or OpenPGP API
  (OpenKeychain stays the default), plus the matching <queries> entries. It also gives Termux gpg through
  PGPony's OpenPGP API. To be submitted upstream.

## 17. Security review remediation (preliminary review, September 2026)

Priority: HIGH (the first two sub-items are the highest-severity work in this cycle). Origin: an internal
preliminary security review of PGPony Android, PGPonyCore and PGPony iOS, run before the planned independent
audit. Full write-ups, exact sites, proof-of-concept inputs, unit tests and proposed patches live OUTSIDE this
repo, under `~/Apps/PGPony_PreAudit_2026-09/` (REPORT.md, patches/, poc/). This item tracks the Android
remediation; it does not restate the detail.

Embargo: this review is unpublished and some of it overlaps the earlier private review already tracked as item
11 in the 4.5.0 cycle, so the same embargo applies. Keep public release notes generic ("input-bounding,
trust and provider hardening") until the window is open; keep finding detail, credit and any reporter out of
public commits, issues and release notes. Do not commit the pre-audit folder or its findings verbatim into
this repo. Refer to findings by their pre-audit ID (PPA-...), never by any name.

Design constraints carry over from item 11: no legitimate message or key may start being rejected (every
bound sits above real GnuPG, Sequoia and PGPony values), fail closed with a typed error, and keep bounds in
`SecurityLimits`. Several findings extend guards that item 11 already shipped, so re-diff against HEAD before
editing.

### 17.1 Critical: verify binding signatures on every imported or refreshed component (PPA-MULTI-001 / 002)

The single most important fix. Import, keyserver refresh and WKD add subkeys, User IDs, expiry, key flags and
revocations to a stored certificate without verifying the binding signatures that tie them to the primary. A
hostile or compromised keyserver or WKD host (in the threat model) can serve a copy of a contact's real
certificate (so the primary fingerprint the user verified still matches) with an extra ML-KEM / X25519 / ECDH
encryption subkey bound by a forged signature; `KeyDeduplicationService.merge` stores the fetched bytes
verbatim, and `encryptionKeys` / `findEncryptionKey` then pick that subkey (they select on Bouncy Castle's
algorithm-level `isEncryptionKey` plus an Encrypt flag read from an unverified self-signature, preferring a
subkey), so the next message to that contact is encrypted to the attacker. The same missing check lets an
attacker graft a signing subkey so a real signature displays as coming from the victim (`SignerEvaluator`
checks only revocation, expiry and flags, never the 0x18 binding or the 0x19 back-signature).

Fix:
- Before adopting or using any subkey, require a subkey-binding signature (0x18) from the primary that
  verifies cryptographically, and a valid embedded back-signature (0x19) for a signing subkey. Apply the same
  to composite subkeys (`crypto/pqc/CompositeKeyFacade` selects composite subkeys and signers on tag plus
  algorithm only; the tag-2 bindings are present in the certificate and never verified).
- Select encryption recipients only from bound, unexpired, unrevoked encryption subkeys, on every encrypt
  path (compose, share target, provider, Autocrypt, contacts).
- On merge, add a component only when its binding self-signature verifies (a certificate union that verifies
  each packet), keeping the item-12 union / tombstone / expiry-downgrade rules inside it.
- Re-validate rings already stored, since a planted subkey may already be present.
- Land the check in a shared helper so decrypt-verify, VerifyService, the provider and the composite paths all
  use it.

Starting-point patches (partial, not a complete fix): `patches/AND-SIG_01_signer_evaluator_verified_bindings.diff`,
`patches/AND-SIG_02_ops_keyid_sigtype_and_enc_subkey_filter.diff`. The 0x19 back-signature check, the
composite-subkey binding check, and full recipient gating still need finishing and on-device testing. Open
question for the release: confirm whether keys.pgpony.app already validates self-signatures and strips unbound
subkeys server-side (it is queried first on refresh); if not, this is reachable without a third-party host.

### 17.2 High: stop releasing unverified plaintext on the provider stream (PPA-AND-003)

`streamDecryptedContent` writes the decrypted literal to the output stream as it reads, and the SEIPDv1 MDC is
checked only afterward; Bouncy Castle validates the MDC only on the explicit `verify()`. On the OpenPGP API
provider path that output is the calling app's pipe, so a local app with the API grant can submit an
intercepted ciphertext and read the released plaintext despite the integrity failure, and repeat it as a CFB
oracle (the EFAIL class). Confirmed against Bouncy Castle 1.85: all plaintext is delivered before `verify()`
returns false. SEIPDv1 is the default container for v4 recipients. In-app file and share paths are contained
(scratch deleted on failure) but still write plaintext to disk before verification.

Fix: for the provider path (and any streaming to an untrusted consumer), buffer the plaintext and run the
integrity gate before releasing it, or refuse to stream non-AEAD (SEIPDv1) messages over the API (AEAD /
SEIPDv2 is per-chunk authenticated and unaffected). Decision needed: buffer-and-verify vs refuse SEIPDv1 on
the API.

### 17.3 High: sanitize the literal-data filename on the Share write path (PPA-AND-005)

The buffered Share branch writes a decrypted file as `File(File(cacheDir, "exports"), outName)` where
`outName` is the OpenPGP literal filename taken verbatim from the message. A filename like
`../../files/secure_keystore_v2/pgpony_key_<fp>_private` climbs out of `exports/` and overwrites the stored
private key blob or its `.dek` envelope (the fingerprint is public), or `pgpony_prefs.xml` / `pgpony.db`.
Confirmed: the name survives decryption verbatim (GnuPG shows the same) and the two write statements overwrite
the target. The streaming path and `ScratchFiles.allocate` already sanitize; this buffered branch and the
Quick Action equivalent were missed.

Fix: reduce the literal filename to a basename at the source and write only through a canonical-path-checked
helper on every `exports/` write. Patch: `patches/AND-SYS_01_literal_filename_traversal.diff`. Also clear
`cacheDir/exports/` on start and on result-sheet dismiss (unprotected key exports and buffered plaintext
currently linger there).

### 17.4 High: provider / Autocrypt key injection (PPA-AND-008)

`ACTION_UPDATE_AUTOCRYPT_PEER` feeds client-supplied keydata straight into the main keyring with no user
prompt, the gossip path applies no From/addr binding, and the encrypt path encrypts to every non-revoked key
held for an address. So one email with a crafted Autocrypt header, or one connected app, silently adds an
attacker recipient key for a contact. Fix: hold API / Autocrypt-imported keys separate from the user keyring
and encrypt to the designated peer key; at minimum apply the From/addr binding to `updateKey` and
`updateGossipKey` and do not silently union an unverified API-imported key with a user key for the same
address. This compounds 17.1 (no binding verification). Partial patch:
`patches/AND-SYS_06_autocrypt_addr_binding.diff`.

### 17.5 Medium: close the decompression and Argon2 guard bypasses (PPA-AND-009 / 010 / 020)

Item 11 Findings A and B shipped but have gaps:
- `CompositeDocumentVerifier.inflate` (reached from `decrypt()` on every message, and from the pasted-text /
  file inline-verify pre-checks) fully inflates a leading Compressed Data packet with no cap, so a small zlib
  bomb OOM-crashes the app before the capped loop runs. Cap it at `SecurityLimits.MAX_MESSAGE_PLAINTEXT_BYTES`
  (or classify from a bounded head). Patch: `patches/AND-DEC_01_inline_decompress_cap.diff`. Also add the
  decompression-bomb regression unit test item 11 still lacks (`poc/AND-DEC_DecompressionBombTest.kt`).
- `decryptStream` only scans the first 64 KiB for the SKESK Argon2 guard, and the guard fails open on a
  truncated head, so a decoy PKESK larger than 64 KiB before the SKESK evades it and the unbounded KDF runs.
  Widen the scan to the whole leading ESK region. Patch: `patches/AND-DEC_02_stream_argon2_full_esk_scan.diff`.
- The composite secret-key unlock paths (`crypto/pqc/CompositeSecretKeyMaterial`, `CompositeSecretProtection`,
  `V4Algo35Protection`, `CompositeLibrePGPKeyMaterial`) call `makeKeyFromPassPhrase` with no
  `enforceArgon2Policy` first, unlike the classical sites. Add the guard before each.

### 17.6 Medium: raise the v4 secret-key S2K iteration count (PPA-MULTI-011)

v4 secret-key protection (keygen, export, change-passphrase) uses coded count `0x60` (65,536 octets),
about 1000x weaker than GnuPG's `0xFF`. Anyone who gets an exported protected key or a backup of one
brute-forces the passphrase cheaply. Raise to `0xFF` (or calibrate per device). Patch:
`patches/AND-SYS_10_v4_secret_key_s2k_count.diff`. Existing keys keep their weak S2K until the passphrase is
changed; the symmetric / backup path already uses `0xFF`. v6 (Argon2id) is unaffected.

### 17.7 Medium: provider and Quick Action hardening (PPA-AND-017, PPA-MULTI-018)

- `createOutputPipe` runs no authorization and leaks two FDs plus a map entry per call, so any bound app can
  exhaust the `:remote_api` FD table and kill the API for real clients. Cap un-consumed pipes per uid and
  close stale write ends. Patch: `patches/AND-PROV_01_createOutputPipe_dos_cap.diff`. Also cap decrypt input
  size (only card ops are capped today).
- The provider consent, passphrase and card-PIN activities have no FLAG_SECURE and no overlay protection, so
  the consent tap is tapjackable and the passphrase / PIN are screenshot-able and appear in Recents (issue #8
  was only half-addressed). The Quick Action (`ShareTargetActivity`) also skips the Recents protection and the
  app lock, so its decrypted output shows in the app switcher and it can decrypt / sign with passphrase-less
  keys while the app lock is on. Apply FLAG_SECURE + `setHideOverlayWindows` to the provider dialogs and the
  Recents protection + lock to the Quick Action. Patches:
  `patches/AND-PROV_02_provider_dialogs_flag_secure.diff`,
  `patches/AND-SYS_09_d2d_exclusion_quickaction_recents.diff`.

### 17.8 Medium: network privacy fixes (PPA-AND-013, PPA-MULTI-014 / 019)

- SOCKS stream-isolation credentials are never sent (the `Authenticator` filters on `RequestorType.PROXY`,
  but libcore requests them as `SERVER` for SOCKS5), and the proxy fails open when Custom mode is set with a
  blank host, so requests go direct while Settings shows a proxy. Match `requestingProtocol == "SOCKS5"` and
  fail closed on a missing host. Patch: `patches/AND-SYS_03_proxy_fail_closed_socks_auth.diff`. Confirm on a
  device whether the hostname is resolved through the proxy (Task 15 / the SOCKS logger in the pre-audit poc).
- WKD results are not filtered to the queried address and there is no response size cap on WKD or keyserver
  fetches, so a WKD host for any looked-up domain can return arbitrary UIDs or a gzip bomb. Keep only UIDs
  equal to the queried address, reject a response with none, cap the response size, and send
  `Accept-Encoding: identity`. Also lowercase ASCII only (non-ASCII local parts currently miss) and fall back
  advanced-to-direct only on NXDOMAIN.
- Background refresh sends the whole keyring to every enabled server in one burst (metadata leak, worse with
  the broken SOCKS isolation above). Randomize per-key timing, use one lookup server per key, and consider
  default-off or proxy-only (Parcimonie model).

### 17.9 Medium: import preview, keystore recovery, backup restore (PPA-AND-016 / 022 / 031)

- Import shows only the first key in the preview but commits every armored block found in the payload, so a
  noisy paste can slip a hidden second key into the keyring behind the one the user reviewed. Enumerate every
  ring in the preview, or import only the previewed ring and require an explicit multi-key confirmation.
- `SecureKeyStore` after a Keystore alias invalidation: any write mints a fresh DEK and rewrites the envelope
  with `pwPresent=false` (a background public-key refresh is enough), orphaning the passphrase-recovery wrap,
  and each recovery deletes the single shared hardware key, invalidating everything written since (a
  passphrase-less key is then lost for good). The legacy EncryptedSharedPreferences copy is also never
  deleted, so a fallback can resurrect a stale secret. Patch: `patches/AND-SYS_07_securekeystore_recovery_wrap.diff`
  (first two); delete legacy entries after a successful migration (third).
- Backup restore silently switches the proxy off, applies trust levels, and replaces the keyserver list from
  the file, so a crafted backup a user restores can downgrade Tor and plant trusted keys / servers. Ask
  before applying settings, never downgrade the proxy, and do not import trust from the file.

### 17.10 Low: verify-time digest policy, card bounds, ustar, cache clearing (PPA-MULTI-024 / 027 / 030, PPA-AND-028)

- No digest allowlist at verify time: SHA-1 (and MD5, RIPEMD160) data signatures, self-signatures and
  certifications are accepted. Add a `SignaturePolicy.isAcceptableDigest()` gate on all four verify paths
  (data sigs, and ideally self-sigs and certifications), and reject far-future creation times and v3
  signatures. The Swift core already restricts digests, so this is Android-specific.
- Card APDU layer: the 0x61xx GET RESPONSE and 0x6Cxx re-send loops have no cap, and the TLV 4-byte length can
  go negative and throw an untyped exception. A hostile card, NFC relay or HCE emulator can hang the NFC
  thread or grow the buffer. Cap the loops and bounds. Patch: `patches/AND-SYS_04_card_apdu_tlv_bounds.diff`.
- The ustar backup reader loops forever on a crafted negative (wrapped) entry size. Patch:
  `patches/AND-SYS_05_ustar_negative_size.diff`.
- "Clear" and "Clear all data" do not clear the in-app passphrase cache or the `:remote_api` card PIN, so a
  user who pressed Clear is not actually cleared. Patch: `patches/AND-SYS_02_secret_cache_clear.diff`.

### 17.11 Info: hardening directions (PPA-MULTI-033)

No zeroization of passphrases (Java strings) or key material; a real hardening direction, not a one-line fix,
already noted under item 11. Strip `Log.d` / `Log.v` in release (release logcat currently carries looked-up
email addresses; no key material or plaintext is logged). No action required this cycle beyond noting it.

### Status (Sep 23 2026): done. Code complete, Gradle build and on-device checks green

All of 17.1 to 17.11 is implemented in the working tree and covered by JVM unit tests (700 pass). What
landed, by sub-item:

- 17.1: `crypto/CertificateBindings.kt` verifies 0x18 / 0x19 / 0x28 / 0x20 / 0x30 and User ID self-certs at
  the packet level (BC rings, composite 30/31 primaries, v4 algo-35 rings). Unbound components are stripped
  on import, fetch and storage (`SecureKeyStore.storePublicKey`), stored rings are re-validated once at
  startup, recipients are chosen only from bound, unrevoked, unexpired keys (by fingerprint), and signers
  must be bound and back-signed. `crypto/CertificateMerge.kt` makes refresh a verified union (the union
  half of item 12). Verification work is bounded per certificate.
- 17.2: `decryptStream(releaseOnlyWhenVerified = true)` on the provider path holds non-AEAD plaintext
  (`VerifiedReleaseSink`) until the MDC check passes. Decision taken: buffer-and-verify, not refuse SEIPDv1.
- 17.3: `LiteralFilename.sanitize` at the three read sites, `ScratchFiles.safeChild` on every `exports/`
  write, `exports/` cleared at launch and on decrypt-result dismiss.
- 17.4: Autocrypt keys accepted only when every certified User ID is the peer address; new
  `autocryptImportedAt` column (Room 9 to 10, backfilled from autocrypt_peers); provider recipients never
  union an Autocrypt-origin key with a user-managed one.
- 17.5 to 17.9: inflate cap, Argon2 guard at the KDF (`GuardedPBEDataDecryptorFactory`) and on the composite
  unlocks, calibrated SHA-256 S2K (0xE0 to 0xFF), output-pipe and input caps, FLAG_SECURE + overlay
  protection on the provider screens, Quick Action lock and Recents, device-transfer exclusion, SOCKS auth
  fix, proxy fail-closed, identity encoding + 8 MiB response cap, WKD address filter / ASCII lowercase /
  NXDOMAIN-only fallback, randomized one-server-per-key refresh batches, full multi-key import preview,
  SecureKeyStore recovery fixes, backup restore asks before settings and never imports trust or drops a proxy.
- 17.10 / 17.11: verify-time digest and date policy (`SignaturePolicy`), card APDU / TLV bounds, ustar size,
  secret-cache clearing, `Log.d` / `Log.v` stripped in release.

Verified on the Mac and on device (Sep 23 2026): Gradle unit suite and release build, the pre-audit
Task 15 checks, keystore wipe and recovery, and the Room 9 to 10 upgrade from a 4.5.3 install.

Product calls, settled Sep 23 2026: background refresh stays default-on for play (foss stays off).
keys.pgpony.app: the site repo carries a server-side binding check (`api/keyserver/_binding.php`, wired
into upload and merge in `_ks_lib.php`, plus `api/migrate_keyserver_bindings.php` to prune stored keys).
It keeps a subkey only with a verified 0x18 from the primary (RSA, Ed25519 legacy and v6, NIST ECDSA,
ML-DSA-65 on its Ed25519 half); other primary algorithms pass through unchecked and are left to the
clients, which now verify every binding themselves. Confirmed live Sep 23 2026; the migration found no
stored key to prune or re-fingerprint, so nothing needed applying.

### Sequencing

17.1 first (the binding-verification helper unblocks 17.4 and the composite side too), then 17.2 and 17.3,
then the Medium set, then the Low set. 17.1 and the EFAIL fix (17.2) are the two that should not ship in a
release that claims security hardening without them. As with item 11, if the cycle runs long, pull 17.1 to
17.4 into a dedicated hardening release sooner.

## 18. Validate key-server / WKD responses before showing "Key Found"

Priority: medium (correctness, user-facing). Origin: tester report, Sep 2026.

A tester searched the Key Server tab for an address and got a "Key Found" card with an Import button that
does nothing usable. The card showed an armor block headed BEGIN PGP MESSAGE (not PGP PUBLIC KEY BLOCK) with
Version: BCPG v1.85. Two things are wrong. A PGP MESSAGE is never a key, so it should never present as an
importable key. And the payload was not PGP at all: the base64 body decoded to <!DOCTYPE html>, i.e. an HTML
page. One of the lookup steps (WKD, keys.pgpony.app, keys.openpgp.org) returned an HTTP 200 with an HTML body
(an error or landing page rather than a 404), and the lookup path took those raw bytes, ran them through the
BouncyCastle armor encoder (hence the BCPG version stamp and the defaulted MESSAGE armor type), and displayed
the result as a found key.

Root cause: the key-server/WKD lookup does not validate that a response is actually OpenPGP key material before
declaring success. It should reject anything that is not a parseable public key: check the HTTP content-type
(application/pgp-keys for keyservers, application/octet-stream for WKD; reject text/html outright), and confirm
the bytes parse as one or more public-key packets (or, for armored input, that the armor type is PUBLIC KEY
BLOCK) before showing "Key Found" and offering Import. On a non-key or unparseable response, show a clear "no
key found for this address" state instead of an import prompt. Never re-armor an arbitrary HTTP body as a PGP
MESSAGE for display.

Apply the same guard across all three lookup steps, since any of them can return an HTML error page. Consider
back-porting the guard to a point release if the timing works, since today it shows users junk plus an import
button that cannot succeed. iOS mirrors once verified on Android.

Status: done, verified on device. network/KeyResponse.kt validates every lookup body (WKD,
directory servers, keys.openpgp.org): text/html refused, armor must be PUBLIC KEY BLOCK only, binary must be
public-key packets only, by-fingerprint and by-key-ID answers must hold the key asked for (primary or subkey).
Output is re-armored from parsed packets, so a non-key body is a miss ("no key found"), never an import offer.

## 19. Composite ML-KEM subkeys not shown in Key Detail on a classical-primary key

Priority: medium (correctness, user-facing). Origin: tester report, Sep 2026.

A tester on an mlkem-768v4 key reported that adding a subkey "doesn't work or doesn't show the generated
subkeys," and that the same flow works on traditional keys. It is a display bug, not an add failure: the
subkey does land on the ring, it just never renders.

Cause is in KeyDetailViewModel.deriveSubkeys. It dispatches on the primary: a composite-signing primary
(ML-DSA, isCompositeSign) goes through compositeSubkeys / loadCompositeSubkeys, which enumerates every subkey
(the original ML-KEM plus any added ML-KEM / ML-DSA / classical) from the 0x18 bindings. Everything else goes
through a generic BouncyCastle path that walks ring.publicKeys and calls detectAlgorithm plus
SubkeyCapability.fromPgpPublicKey per subkey inside a try/catch that returns null on failure. An mlkem-768v4
key has a classical Ed25519 primary, so isCompositeSign is false and it takes the generic path. BC does not
cleanly parse the composite ML-KEM subkey packet there, the per-subkey mapping throws, and the catch silently
drops it. A traditional key has only algorithms BC understands, so all its subkeys render and adds appear.
That is exactly the traditional-vs-pq split the tester saw.

Fix: route any key that carries composite subkeys (not only composite-signing primaries) through the
loadCompositeSubkeys enumerator, or teach the generic per-subkey mapping to recognize composite ML-KEM
(algo 35/36/8) instead of swallowing it. First option is cleaner and reuses the proven composite enumerator.
Verify with an mlkem-768v4 key: the existing ML-KEM subkey shows, an added subkey shows, and capabilities and
labels are right. iOS mirrors once verified on Android.

Status: done, verified on device. Display: SubkeyRows lists any key with an algo 35/36 (or v5
algo 8) subkey from its certificate, with capabilities from the verified binding. Worse than the report: BC
loads an mlkem-768v4 key WITHOUT its ML-KEM subkey, so every BC-based edit (add subkey, User ID changes,
expiry, revoke, passphrase change) stored a ring with the ML-KEM subkey and its secret gone, and a second
ML-KEM add replaced the first. V4Algo35Carry now carries them through every such edit (re-protected on a
passphrase change); the decryptor and export handle more than one ML-KEM subkey. Follow-ups closed:
expiry edits re-sign the ML-KEM binding, and revoke/remove work on the ML-KEM row (V4Algo35Edit). The
last-encryption-subkey warning counts ML-KEM subkeys on these keys.

## 20. Show how many keys exist under a User ID

Priority: low-medium (feature). Origin: tester request, Sep 2026.

Same tester asked to surface how many keys exist under a username. When more than one key carries the same
User ID (a common case after a rotation or a re-import), nothing in the UI signals that the identity maps to
several keys, so a user can encrypt to or trust the wrong one without knowing a second exists. Add a count
indicator: a small badge on the keyring-list row when a User ID is shared by more than one stored key, and the
same count in key server search results when a lookup returns multiple keys for the queried address. Tapping
it lists the matching keys so the user can compare fingerprints and pick. Touches the same surfaces as the
keyring-list work (item 1) and the union-merge work (item 12); keep it as its own additive item so it can ship
independently. iOS mirrors once verified on Android.

Status: done, verified on device. A keyring row whose identity (email, else the User ID) is
shared by other stored keys shows an "N keys" pill; tapping it lists them with fingerprint, label, algorithm,
creation date and revoked/expired state, and a row opens that key. The Exchange "Key Found" card says how many
keys a lookup returned when more than one answered; the Keyring import preview already lists extra keys.

## 21. Allow RSA subkeys on composite ML-DSA keys

Priority: medium (interop, user-facing). Origin: tester thread, Sep 2026.

A tester on an ML-DSA-65 key wanted a classical encryption subkey so the key works in Thunderbird (whose RNP
backend cannot encrypt to the v6 ML-KEM subkey PGPony pairs with an ML-DSA primary). The only classical
subkeys the add-subkey flow offers on a composite ML-DSA key today are Ed25519 (sign/auth) and X25519
(encrypt): AddSubkeyChoice.classicalFor(isV6=true) omits RSA, and the composite graft path handles only
Ed/X25519. So RSA, the most broadly interoperable classical option and the one testers reach for, cannot be
added to a DSA key.

Add RSA (2048/4096, encrypt/sign/auth as ClassicalSubkeyGen already defines) as a classical subkey option on
composite ML-DSA keys. ClassicalSubkeyGen already builds RSA subkeys for the v4 classical path, so the work is
extending the composite add path and the classicalFor list to include RSA when the primary is a composite
ML-DSA key, then binding the RSA subkey onto the composite primary correctly. Verify a composite ML-DSA key
with an added RSA-4096 encryption subkey exports and imports cleanly in GnuPG and encrypts/decrypts in
Thunderbird. iOS mirrors once verified on Android.

Note: a classical encryption subkey on a v6/composite primary may itself be v6-framed, which Thunderbird's v6
support does not yet handle either. If verification shows Thunderbird still cannot encrypt to a v6-framed RSA
subkey, the reliable interop path is a separate classical key rather than a subkey graft; decide during
implementation and document whichever holds.

Status: done, verified on device; Thunderbird verification failed, as the note above feared.
RSA 2048/4096 (encrypt, sign with a 0x19 back-signature, auth) can be added to a composite ML-DSA key,
v6-framed, bound by the composite primary and protected with the key's passphrase. A message a classical
client encrypts to that subkey decrypts in PGPony (CompositeKeyFacade.classicalDecryptionRing), which also
fixes decryption to an X25519 subkey added to a composite key; that never worked before. Interop check: RNP
0.17 (Thunderbird's library) rejects the certificate outright ("wrong key packet version") and GnuPG 2.4 does
too ("Invalid packet"), because the primary is a v6 key; the subkey type does not matter. Per the 2026 OpenPGP
email summit, Thunderbird is working toward v4 PQC, not v6. For Thunderbird today the working path is a separate
v4 key, or an mlkem-768v4 key once Thunderbird ships v4 PQC. Decision: shipped, with a one-line note in the add-subkey
sheet on composite keys that Thunderbird and GnuPG cannot read v6 keys yet.

## 22. Considered, not taken: app icon redesign

A tester sent a redesigned icon with "PGP" lettered under the lock. Not adopting: the current icon is
the one users already recognize across iOS, Android and desktop. Recorded so it is not re-raised as new.

## Delivery note

Android first per the new-feature procedure. iOS mirrors each item once the Android version is verified,
tracked separately. This document is seeded from the forum.dark.vegas thread; add further items here as they
come in before the 4.6.0 scope is locked.
