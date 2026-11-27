# PGPony Android 4.8.2

A patch release whose main item is a PGPony-specific X25519 key-agreement action on the OpenPGP provider, so
StegPony can reveal with a key held in PGPony, on the phone or on a security key, through PGPony's card support.
Four small fixes ride along, moved forward from the 4.9.0 plan or new since 4.8.1. versionCode 482, versionName
4.8.2. PGPony Desktop vendors this code but has no OpenPGP provider, so of this release it picks up items 2 to 5.

Released Nov 26 2026 with no release candidate: everything below was tested on a device first, so the release went
straight through the reproducibility gate. StegPony is built against the documented action after this is settled; StegPony itself isn't touched here.

## 1. X25519 key agreement through the provider (for StegPony)

Why: StegPony reveals with a hardware key by asking the key for one raw X25519 agreement per slot it tries (its
core's KeyDevice: recipient(), and agree(point: 32 bytes) returning the 32-byte shared secret; on a card that is
PSO:DECIPHER with the point in the Cipher DO). PGPonyOpenPgpService only has the standard OpenPGP actions, and
DECRYPT_VERIFY can't hand back a raw shared secret, so StegPony can't use PGPony's keys or its card support.

Three new actions on the existing IOpenPgpService2 binding, named like PGPony's other own actions
(com.pgpony.android.action.*). They go through the same API version gate and the same signature-pinned allow-list
(consent first for an app not yet allowed) as every other action, before dispatch. The OpenPGP API version stays
7 to 12; a client finds the new actions with GET_CAPABILITIES. PGPony 4.8.1 and older answer every unknown action
with GENERIC_ERROR "Unknown OpenPGP API action", so that error on GET_CAPABILITIES means "not supported".

- com.pgpony.android.action.GET_CAPABILITIES: success with the list of PGPony actions this build has
  (X25519_KEYS, X25519_AGREE), a PGPony API level (1) and the batch cap (32). No key data, no confirmation.
- com.pgpony.android.action.X25519_KEYS: the user's own Curve25519 encryption subkeys that are usable now
  (bound, not revoked, not expired, on a key pair or a card-backed key): for each, the subkey fingerprint, the
  32-byte public point, the primary fingerprint, a label (the primary User ID) and whether it is on a security
  key. Public data, so the allow-list is the gate and there is no confirmation. StegPony builds recipient() from
  the point without parsing OpenPGP.
- com.pgpony.android.action.X25519_AGREE: the subkey fingerprint and 1 to 32 points of 32 bytes each, in one
  byte array. Success returns one 32-byte shared secret per point, in order, in one byte array.

Keys: Curve25519 encryption subkeys only, v4 ECDH on Curve25519Legacy (algorithm 18 with the 1.3.6.1.4.1.3029.1.5.1
OID) and v6 X25519 (algorithm 25). Anything else (RSA, NIST and brainpool ECDH, X448, ML-KEM, a signing or
authentication subkey, a key that isn't the user's) is refused with a clear error naming why. The fingerprint is
the subkey's, as StegPony's card code reads it from the card (40 hex for v4, 64 for v6).

Confirmation on every use: X25519_AGREE never runs without the user's yes for that call. The first call stores the
request and returns USER_INTERACTION_REQUIRED with a PendingIntent; the activity it opens names the calling app,
the key (label and short fingerprint) and the number of agreements, and on Allow does the work and stores the
result; it returns RESULT_OK with the client's request echoed back (EXTRA_API_DATA, the #61 shape), and the
client's re-call with the same request is answered from the stored result. Cancel returns RESULT_CANCELED. The
stored request and result are keyed by a hash of action, calling package, subkey and points, live five minutes,
and are consumed once, so a re-call can't replay a past answer and another app can't collect it.

- Software key: a new ProviderX25519Activity. The passphrase field shows when the key is protected and
  ProviderPassphraseCache has nothing for it; a passphrase entered there is cached as decrypt caches one. The
  provider's decrypt has no biometric step, so neither does this. The X25519 secret comes from Bouncy Castle's
  key converter (it handles the reversed scalar of a v4 Curve25519Legacy key) and the agreement is Bouncy
  Castle's RFC 7748 X25519, on a scalar copy PGPony wipes.
- Security key: ProviderCardOpActivity, the activity every provider card operation uses, with a new branch: PIN
  (PW1, 0x82), then one PSO:DECIPHER per point on the slot the subkey sits in (decryption, or authentication
  through MANAGE SECURITY ENVIRONMENT as #108 does), over NFC or USB. The dialog text names the calling app and
  the number of agreements. A card answer of 33 bytes starting 0x40 is cut to the 32-byte secret.

Safety:
- Points must be exactly 32 bytes. Low-order points (the small-order u-coordinates and the non-canonical
  forms of 0 and 1, libsodium's list of seven, with bit 255 ignored) are refused before any key is touched.
- An all-zero shared secret fails the whole call; nothing partial is returned.
- At most 32 points per call; more is refused before the confirmation.
- Shared secrets and the X25519 private key bytes are wiped after use; the stored result is wiped when consumed
  or swept. Points, secrets and keys are never logged.

Tests: X25519 software path against the RFC 7748 vectors (section 5.2 and the Alice/Bob pair in 6.1), on a v6
X25519 subkey and a v4 Curve25519Legacy subkey built in the test; the refusals (wrong length, low-order point,
empty and oversize batch, non-Curve25519 subkey, unknown fingerprint); the Cipher DO for a point; the op key.
PGPonyApiTest gets GET_CAPABILITIES, X25519_KEYS and X25519_AGREE buttons: it makes fresh ephemeral points,
calls the action, and checks each answer against X25519 of the ephemeral secret with the key's public point, on a
soft key and on a card.

Docs: docs/PROVIDER_PGPONY_ACTIONS.md, every extra, result, error and the call sequence.

New strings (the two dialogs) in all 11 languages, several agents plus reviewers.

## 2. Ed25519 subkeys on protected ML-DSA keys (moved from 4.9.0 item 7)

CompositeSecretProtection.protect picked the key to encrypt by algorithm alone, so for an Ed25519 subkey
(algorithm 27) it encrypted the throwaway Ed25519 primary it builds instead, and the subkey's own secret was never
stored. Every later re-protect (Add User ID, Add subkey, Change passphrase) then failed on that packet. Reported by
email on 4.8.1. Fix: pick the subkey (not isMasterKey). Also: CompositeKeyFacade.reprotect leaves a subkey it can't
open as it was, once the primary has opened with the passphrase, so a key damaged before the fix can still be
edited and its broken subkey removed. Tests: the reported sequence and a key damaged the old way.

## 3. Text selection in the Decrypt output (#130)

Long-pressing a word in the decrypted text selected it, and lifting the finger deselected it. dismissKeyboardOnTap
counts any one-finger touch that doesn't move past the touch slop as a tap, however long it lasts, so the lift
after a long press cleared focus, and the selection with it. A touch held past the long-press timeout is no longer
a tap. KeyboardDismissTest covers the rule.

## 4. A LibrePGP key without the X25519 subkey (moved from 4.9.0 item 11)

The LibrePGP options build an Ed25519 primary with a classical X25519 encryption subkey and graft the Kyber subkey
on top, so GnuPG and Kleopatra may encrypt to the classical one. GnuPG's own ky768_cv25519 keys have only the
Kyber subkey, and it is already a hybrid with X25519. Generate Key shows the existing "Include default encryption
subkey" switch for the LibrePGP options (on by default, as now) and leaves the X25519 subkey out when it's off. No
new strings. Requested by email (Nov 24).

## 5. Certifying your own key pair (#126, moved from 4.9.0 item 3)

Certify was limited to other people's keys (4.7.0 item 31, #79), so one key pair can't certify another of yours.
canBeCertified and the Key Details menu accept key pairs and card-backed keys; certifierChoices already leaves the
target out of "Certify with". After certifying your own key, "Mark as Verified" isn't offered (it is already
Ultimate). ML-DSA targets stay out until 4.9.0 item 8.
