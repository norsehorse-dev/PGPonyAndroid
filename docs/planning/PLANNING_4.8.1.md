# PGPony Android 4.8.1

A patch release for key edits on ML-DSA keys. Reported by email on 4.8.0 (Nov 12 2026): the expiry date of an
ML-DSA-87 key can't be changed, protected or not, and other key types are fine. versionCode 481, versionName 4.8.1.
PGPony Desktop vendors this code, so it gets the same fix in its next 4.0.x.

Same RC process as 4.8.0: one RC at a time as a GitHub pre-release with a signed tag, through the
reproducibility gate, and the reporter checks it on their own key before the release.

Items 1 to 7 went out in RC1 (Nov 15); item 7's cause isn't found yet, and RC1 carries a guard for it. Items 8 to
12 went out in RC2 (Nov 17). Item 13 went straight into the release.

## 1. Expiry on ML-DSA keys

What the user saw: changing the expiry of an ML-DSA-87+Ed448 v6 key fails, whether or not the key has a
passphrase. Other key types change fine.

Cause, from the code: KeyRepository.setKeyExpirationSoftwareEdit loads the key with loadSecretKeyRing and
loadPublicKeyRing and hands it to KeyExpirationService, which is Bouncy Castle. Bouncy Castle 1.85 can't load a
composite ML-DSA primary (algorithm 30 or 31), so the load returns null and the edit stops with "Secret key ring
could not be loaded". The other composite edits (add subkey, add and remove User ID, revoke and remove subkey)
already branch on algorithm.isCompositeSign and work on the raw packets through CompositePrimaryKeyGen; expiry
never got that branch. The same function serves all three targets, so these fail the same way:

- the primary's expiry (Target.Primary)
- a subkey's expiry (Target.Subkey)
- Refresh self-signatures (Target.Refresh)

Work: a composite branch in setKeyExpirationSoftwareEdit, with the signing in CompositePrimaryKeyGen next to
addUserId and revokeSubkey:

- Primary: a new direct-key signature (0x1F) and new certifications for each User ID, carrying the Key Expiration
  Time (subpacket 9), or none for Never, and otherwise the same subpackets as the self-signatures they replace
  (key flags, features, preferences, notations). Signed with the composite signer, ML-DSA and EdDSA halves, as the
  User ID certification in addUserId is.
- Subkey: a new binding signature for that subkey with its new expiry. An ML-DSA signing subkey's binding also
  needs its embedded back-signature (0x19) made again with the subkey.
- Refresh: the primary and subkey self-signatures made again with today's date and the expiries they already
  have.
- After the edit, the entity's expiresAt is set from CompositeKeyFacade, and the key is stamped as edited, as the
  Bouncy Castle path does.

PGPony signs ML-DSA self-signatures with SHA-256, which RFC 9980 allows for both suites (a digest of at least 256
bits), and Key Details shows no hash choice for these keys.

Tests: set, extend and remove the expiry on generated ML-DSA-65 and ML-DSA-87 keys, then check that
CompositeKeyFacade reads the new expiry back, that every new signature verifies with the composite verifier, and
that the newest self-signature wins (as primaryKeyFlags reads it). The key still encrypts, decrypts and signs after
each edit. An exported key imports in GnuPG 2.5 and the expiry shows there.

Done: setKeyExpirationSoftwareEdit and refreshSelfSignatures branch on isCompositeSign into
setCompositeExpiration, which calls CompositePrimaryKeyGen.setExpiry (Primary, with or without the subkeys valid
now, or one Subkey) and refreshSelfSignatures. An edit replaces the newest self-signature of each component it
touches in place, with a new creation time and the same subpackets apart from the expiry, so the key does not grow
with each edit. A signing subkey's back-signature stays as it was (a 0x19 covers only the primary and the subkey, so it
stays valid); one kept in the unhashed area, as GnuPG does, moves into the hashed area. The key packets are not touched,
so a protected key stays protected under its own passphrase. CompositeKeyFacade.listSubkeys and the primary's
expiry now read the newest binding and direct-key signature, so Key Details shows the edit. CompositeKeyEditsTest
(12 tests) checks each edit with CertificateBindings, which verifies every signature on its own. The GnuPG 2.5 check
is part of the RC test.

After an independent review:

- The edited key's public copy is merged into the stored one (CertificateMerge, then
  CompositePrimaryKeyGen.withMissingComponents) instead of written over it, so an edit keeps a subkey or User ID the
  stored copy has and the secret ring doesn't (one merged in from the owner's export by item 3), and keeps
  third-party certifications and revocations.
- An edit whose new signatures don't verify is refused: sanitize may drop no more of the edited key than of the key
  as it was. That catches a wrong passphrase on the old CFB protection, which has no integrity check and unlocks to
  the wrong secret.
- Only a failed unlock reads as a wrong passphrase. Before, any failure on a protected key did, so revoking the last
  User ID said the passphrase was wrong.
- An edit that would change nothing (the expiry of a revoked subkey, making a revoked User ID primary) is refused
  instead of reported as done. Self-signatures count as the primary's when an issuer in either area names it or
  none is given, as CertificateBindings counts them.
- PGPony-made ML-DSA keys put the key's expiry only in the direct-key signature, while CertificateBindings reads it
  from the newest self-signature of any kind, which is the User ID certification. So PGPony's own validity checks
  saw an ML-DSA key with an expiry as never expiring. New keys and added User IDs now carry it in the certification
  too, and every edit that rewrites a certification copies it from the direct-key signature. A key made before
  4.8.1 is read right after Refresh self-signatures, or any edit that rewrites its certifications.

Found on the way: Key Details offered no subkey expiry change on ML-DSA keys (their rows were not marked editable),
and it named the subkey by the last 16 hex digits of its fingerprint, which is the key ID of a v4 subkey only. On a
v6 key that found no subkey, so a subkey's expiry could not be changed on v6 Ed25519 keys either. It now passes the
row's key ID, the first eight octets of a v6 fingerprint. Refresh self-signatures offers no hash choice on ML-DSA
keys, since the algorithm sets it.

## 2. The other key edits on ML-DSA keys

These also started with loadSecretKeyRing and loadPublicKeyRing and had no composite branch, so on an ML-DSA key
they failed the same way:

- revoke the key (applyRevocationEdit)
- edit notations (setNotationsEdit)
- revoke a User ID (revokeUserIdEdit)
- make a User ID primary (setPrimaryUserIdEdit; noted as a follow-on in addUserIdEdit)

Revoking the key matters most: a key that can't be revoked can't be retired.

Done: each has a composite branch through CompositePrimaryKeyGen (revokeKey, setNotations and readNotations,
revokeUserId, setPrimaryUserId), and Add User ID with Make primary now works on ML-DSA keys too. Revoking the
last live User ID is refused. Key Details reads an ML-DSA key's User IDs with their primary and revoked state from
the packets, the row's name and email follow the primary User ID, and Refresh self-signatures is offered on these
keys. Each is in CompositeKeyEditsTest and gets a device check with an ML-DSA-65 and an ML-DSA-87 key, protected
and not.

## 3. Subkeys disappearing

A Play review says the subkeys "just disappear" and the app "has a serious problem remembering keys". It was first
left on 4.7.3 (Polish device language, Android 12) and updated to one star on 4.8.0, so 4.8.0 did not fix it.

A regular tester confirmed it on the GitHub APK: an ML-DSA-87 key with an ML-KEM-1024 subkey lost its subkey. They
don't remember what they did before it happened, and importing the key again brought the subkey back. So the
stored copy lost the subkey while the key file still had it: something rewrites the stored key after import and
drops the subkey.

Cause found (Nov 12): importing a key that is already held. For a composite ML-DSA key, and for a v4 key with an
algo-35 ML-KEM subkey, KeyRepository.importCompositeKey and importV4Algo35Key wrote the imported copy over the
stored public copy (store.storePublicKey) when the fingerprint was already in the keyring, even when the result was
reported as "already in keyring". Any subkey or User ID the imported copy lacked was gone from the stored key: an
older export, a copy from another device made before a subkey was added, or a copy a key server stripped. The
private copy keeps the subkey, which is why importing the full key again brought it back. Classical keys go through
KeyDeduplicationService.resolveDuplicate, which has merged since 4.6.0 (CertificateMerge), so they don't lose
subkeys this way.

Fix: mergeImportedPublic folds the imported copy into the stored one with CertificateMerge. A key pair's stored
copy stays authoritative, except that the key's own secret export may add back subkeys and User IDs its owner
bound, so importing the full key still repairs a key that already lost one. The row's cached armor follows the
stored copy. CompositeImportMergeTest generates ML-DSA-65 and ML-DSA-87 keys and checks that a copy without a subkey
never removes it and that the owner's full copy adds it back.

Backup restore and pairing import keys through importArmoredKeyDetailed, so restoring an older backup or pairing
with a device holding an older copy dropped subkeys the same way, and both are fixed with it. Checked and not
affected: keyserver refresh (a composite copy fails the Bouncy Castle parse and nothing is written), Recently
Deleted restore (it only moves the row back), the 4.8.0 duplicate merge (rows only, the stored key is shared) and
the 4.6.0 re-validation (sanitize only). The review doesn't say which key type was affected, so a classical key
losing subkeys is not ruled out; the reviewer has been asked.

Highest priority in 4.8.1: it loses part of a key.

## 4. The armor comment on provider signing (#121)

Signing through the OpenPGP API (K-9 and other apps) left out the Comment header set in Settings. The :remote_api
process only refreshed its copy of the comment for encryption (#57), so cleartext and detached signatures used
whatever it had read at start. PGPonyOpenPgpService now refreshes the comment before it dispatches any action.

## 5. Certifying with a YubiKey ECDSA key, and Quick Action with a card key (#117)

Certifying another key with a NIST P-256 or P-384 primary on a YubiKey failed: CertificationService's list of
algorithms a card can certify with had RSA and EdDSA but not ECDSA. ECDSA is in it now; the card signs with the
hash its curve needs, as card message signing already does.

Quick Action found no key for a key pair whose keys are on the card. ShareTargetViewModel looked for the card
recipient only among keys with armor, and a card-only key pair has none. It now looks at card keys with a
decryption fingerprint, and when the message names no key it takes the only card key if there is no software key
pair to choose instead. The reporter checks both on their YubiKey in the RC.

## 6. Subkeys labelled Expired under a date still to come (#120)

A tester's NIST subkeys show Expired in Key Details next to an expiry date in the future. The date and the label
come from two readers. The label is SubkeyAdmission's, from the newest verified binding (CertificateBindings). The
date on a classical key's row came from Bouncy Castle's validSeconds, which takes the latest expiry in any binding,
verified or not. A subkey whose newest binding expires sooner than an older one (an expiry shortened once, or an
older binding left on the key) shows both at once; gpg reads the newest binding too, as the label does.

Not reproduced with keys made in gpg 2.4 on P-256, P-384, P-521 and Ed25519, with expiry changed in gpg and in
PGPony with SHA-256 and SHA-512: the two readers agree on all of them.

The tester's key (Nov 13) has it: each of its six NIST subkeys has an Oct 2 binding with an expiry in 2030 or 2036,
or none, and a Nov 13 binding (SHA-512, every subkey re-signed in the same second by Refresh self-signatures) that
sets the expiry to 2026-10-04 20:20:05 UTC. gpg lists all six as expired on that date, as the label says; the row
showed 2030 or 2036 from the older bindings.

Cause of the Oct 4 date, found Nov 14: the tester's copy on GitHub, uploaded Oct 13, already carries a binding on
every subkey made on Oct 4 between 20:16 and 20:29 UTC outside PGPony (the tester edited the key with gpg
--edit-key). The NIST subkeys' bindings were signed at 20:16:46 and expire at 20:20:05; the others moved to noon UTC
on Jan 31. The Nov 13 bindings carry exactly those values, so Refresh kept each subkey's newest expiry as it should,
and PGPony isn't at fault. The display was: until 4.8.1 the row showed the Oct 2 dates.

Done meanwhile: the row now shows the expiry from the same binding as the label (SubkeyAdmission.shownExpiry), so
the two can't disagree, and the date says which binding PGPony reads. SubkeyShownExpiryTest builds subkeys bound
twice and checks the date and label agree. In RC1 the tester's NIST subkeys show Oct 4 2026 beside Expired.

## 7. A classical key losing its subkeys (#119)

A tester's Ed25519 key (passphrase, not on a card) lost all its subkeys and kept only the certify primary. They
found it when SSH through OKC-Agent failed with "key not found". Restoring the key brought the subkeys back. This is
a classical key, so the composite import fix in item 3 doesn't explain it.

From the reporter (Nov 13): it happened three times on 4.7.2 (F-Droid), with no edits to the key, on a phone that
kills background apps hard. Each time importing their own secret export from gpg brought the subkeys back, which is
SubkeyAdmission adding the subkeys the stored copy lacks; so the stored public copy lost them, not the key file. The
key they posted, as restored, is complete: authenticate, sign and encrypt subkeys bound until 2030 and an RSA subkey
revoked in September, with OpenKeychain-style critical subpackets.

Checked: every write of a stored public key goes through sanitize, which only drops a subkey whose binding doesn't
verify, and all of theirs verify; the classical import and the background keyserver refresh merge (CertificateMerge,
local copy authoritative for a key pair, never dropping a subkey); the expiry, refresh, add subkey and revoke subkey
services keep every subkey of a protected Ed25519 key with sign, encrypt and authenticate subkeys, and of NIST keys,
in a JVM run with sanitize after each step. No cause found.

Done: a guard in SecureKeyStore.storePublicKey (SubkeyKeep). A write that would leave out a subkey the stored copy
binds carries it over with its signatures, and logs the write with its caller. Only Remove subkey (classical, v4
ML-KEM and ML-DSA) names the subkey it takes out, and only that one may leave. SubkeyKeepTest covers a copy without
its subkeys, Remove subkey, a complete copy, another key's copy and an ML-DSA key. The reporter gets the RC to check
whether the loss stops.

## 8. Signing with a key made by Proton (OpenPGP.js)

Reported by email on 4.8.0: an Ed25519 key generated by Proton at the end of 2023 found no key to sign with
("No signing-capable key found"), in PGPony and in PGPony Desktop. Two causes, both on keys whose User ID is
certified with a generic certification (0x10), which OpenPGP.js makes, where GnuPG makes a positive one (0x13).

- UserIdService.latestSelfCert looked for 0x13 only, so on these keys it found no certification to copy from. Add
  User ID, Make primary and notations then issued the User ID's new certification with nothing but the
  primary-User-ID flag: the key lost its Key Flags and preferences. It now takes 0x10 to 0x13.
- With no Key Flags subpacket left, SubkeyCapability's fallback gave an Ed25519 primary Certify only, so nothing
  could sign. RFC 9580 reads no flags as no restriction; the fallback now gives an Ed25519 or Ed448 primary
  Certify and Sign.

GenericCertUserIdEditsTest builds an OpenPGP.js-style key and checks that every User ID edit keeps the flags and
preferences and that the key still signs; NoKeyFlagsSigningTest signs with a key that has no Key Flags at all, so
a key already stripped signs again.

## 9. Quick Action decrypt with keys only on a card (#117)

In RC1 the reporter confirmed certifying with the YubiKey, but Quick Action still said "No private keys
available". RC1 fixed how ShareTargetViewModel finds the card key, but ShareTargetScreen kept Decrypt disabled
whenever no key pair had its keys on the phone, so a message for a card-only key pair never reached the PIN.
Decrypt now stays enabled when the card has a decryption key.

## 10. Picking public keys through the OpenPGP API

CarrierPony 4.0's "Pick from a key app" on Add by public key asks the key app for keys without naming an address:
GET_KEY_IDS with an empty user_ids array, then GET_KEY with the first id and ascii_armor. OpenKeychain opens its
key picker for that request; PGPony answered success with no ids, so nothing happened.

GET_KEY_IDS with no user ids (the extra absent or empty), not opportunistic and without EXTRA_KEY_IDS_SELECTED now
returns USER_INTERACTION_REQUIRED with the recipient review in pick mode: the keyring's keys from
RecipientReview.offeredKeys (the same rules the re-run applies, so Don't use, revoked and, unless allowed, expired
keys are not offered), nothing ticked, its own title, intro naming the calling app, confirm and empty text, and
its own PendingIntent scheme and request code. On confirm it returns the request plus EXTRA_KEY_IDS_SELECTED and
the client's re-run is answered by the existing selection branch; on cancel RESULT_CANCELED. A request with no
user ids never reuses picks from an earlier review, and nothing is remembered for it. Requests that name
addresses, and opportunistic ones, behave as before; consent still comes first. Key ids go through longKeyId, which
GET_KEY's lookup parses too, so v6 and ML-DSA keys work. GET_KEY needed no change: with key_id and ascii_armor it
writes only the armored public key and returns success.

The branch decision is RecipientReview.keyIdsStep, covered by KeyIdsPickTest. Four new strings, in all 11 locales.

## 11. Decrypting a PGP/MIME message from a file (#123)

A PGP/MIME message with protected headers and a quoted-printable body showed decoded when pasted, but decrypted
from a .asc file the result sheet showed the raw MIME (=2E, and UTF-8 Chinese as =XX escapes). The paste path
decodes a message with no attachments (mimeBodyOnly); the file path, and the card file path, only parsed MIME to
look for attachments. A file that decrypts to a MIME message with no attachments now previews and copies the
decoded body; Save and Share keep the file as it decrypted. Files over the inline limit stream as before.
MimeBodyOnlyTest decodes the reporter's message shape.

## 12. Expiry reminders for other people's keys (#125)

A tester got "Your PGP key expires" for a contact's public key. App start, boot and the Settings toggle all
scheduled reminders for every key with an expiry date. Reminders are now for key pairs and card-backed keys that
are not revoked or binned (ExpiryReminderRule). Scheduling cancels the alarms of every key first, so the ones set
for public keys go, and the receiver looks the key up when an alarm fires and posts nothing for a key that isn't
the user's, is gone, or whose expiry has moved. ExpiryReminderRuleTest covers both.

## 13. Pass entries on a card with an offline primary (#128)

Reported Nov 18 against main: a pass entry encrypted to a card whose primary is offline (three NIST P-256 subkeys
on the card) failed with "pair this card's public key first", while the same message and PIN decrypted in the
Decrypt tab. PassEntryScreen.runCardDecrypt looked the card's signature-slot fingerprint up with loadPublicKeyRing,
which is keyed by the primary; on that layout the slot holds a subkey. It now uses
loadPublicKeyRingByCardFingerprint, as CardDecryptScreen and the provider do. That helper tries the primary first,
so a card that worked before takes the same path. It went into the release without an RC of its own.

## Not in 4.8.1

New features and the 4.8.0 carry-overs stay in the next minor release. Apart from item 10, which CarrierPony 4.0
needs, this one only fixes bugs.

- Choosing which authentication subkey SSH uses (#124). PGPony takes the newest authentication-only subkey that is
  bound and not revoked or expired. A per-key choice in Key Details needs new UI, so it is on the 4.9.0 list.
