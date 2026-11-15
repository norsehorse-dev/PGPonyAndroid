# PGPony Android 4.8.1

A patch release for key edits on ML-DSA keys. Reported by email on 4.8.0 (Nov 12 2026): the expiry date of an
ML-DSA-87 key can't be changed, protected or not, and other key types are fine. versionCode 481, versionName 4.8.1.
PGPony Desktop vendors this code, so it gets the same fix in its next 4.0.x.

Same RC process as 4.8.0: one RC at a time as a GitHub pre-release with a signed tag, through the
reproducibility gate, and the reporter checks it on their own key before the release.

Everything below goes out together in RC1. Item 7's cause isn't found yet; RC1 carries a guard for it.

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

The tester's key (Nov 13) has it: each of its six NIST subkeys has an Oct 2 binding with an expiry in 2030 or 2036
and a Nov 13 binding (SHA-512, every subkey re-signed in the same second) that sets the expiry to 2026-10-04 20:20
UTC. gpg lists all six as expired on that date, as the label says; the row showed 2030 or 2036 from the older
bindings. Asked the tester whether they expired those subkeys around Oct 4, and which tool made the Nov 13
signatures: a Refresh self-signatures with SHA-512 in 4.8.0 would look like that and carry an earlier expiry
forward.

Done meanwhile: the row now shows the expiry from the same binding as the label (SubkeyAdmission.shownExpiry), so
the two can't disagree, and the date says which binding PGPony reads. SubkeyShownExpiryTest builds subkeys bound
twice and checks the date and label agree. If the tester's key shows a binding that should verify and doesn't,
that is a separate fix.

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

## Not in 4.8.1

New features and the 4.8.0 carry-overs stay in the next minor release. This one only fixes bugs.
