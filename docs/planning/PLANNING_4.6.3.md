# PGPony Android 4.6.3: Planning

Status: draft (Oct 2 2026). A fixes release that pulls the bug fixes deferred to 4.7.0 forward, fixes the mail-app
passphrase duration for real (#15, reopened), lets one SSH client hold several keys (#68), and adds pairing with
PGPony Desktop 3.0.0 to move keys over the local network (4.7.0 item 21).

versionCode 463. Branch: `4.6.x` (at v4.6.2), not main. Main carries 4.7.0 work (SOP engine hooks, the SOP interop
engine changes, KeyValueSettings, the Add Subkey lifetime change) and none of that ships here unless an item below
says so. Every change lands on `4.6.x` first and is cherry-picked onto main the same day, so 4.7.0 keeps it.

Database: no schema change. Room stays at version 12 on both branches (item 1 keeps the SSH keys in the existing
column instead of a new table), so main and 4.7.0 need no migration coordination for this release.

4.7.0 items moved here: 1 (remainder), 2, 5, the bug half of 15, 12a, 14, 16, 19, 20, 21. Mark them "moved to 4.6.3"
in PLANNING_4.7.0.md once this list settles.


## 1. SSH: one app, several keys (#68)

Priority: high (bug, usability). Origin: #68 follow-up.

Reported: with two keys loaded in OkcAgent, every git operation raises about six approval notifications, and a
third key adds more. One key works.

Cause: ApiClientEntity holds a single sshKeyFingerprint per app, and ApiClientAuthorizer.bindSshKey overwrites it.
OkcAgent fetches the public key of every configured key at the start of each ssh connection, then signs with the
one the server accepts. Each request for the key that is not bound fails sshKeyAllowed, the service returns the
picker limited to that key, and approving it moves the binding there, which locks out the other key. The binding
ping-pongs on every connection, and git opens more than one.

Work:

- No schema change: the existing sshKeyFingerprint column holds every approved key, uppercase hex fingerprints
  joined by commas (hex never contains one). A 4.6.0 to 4.6.2 row holds a single fingerprint, which reads as a
  set of one, so upgrades need no migration and main stays on version 12.
- bindSshKey adds to the set (idempotent). sshKeyAllowed checks membership. unbindSshKey withdraws one key.
  Revoking the SSH scope clears them all. The picker limited to one key stays as the approval for a key the app has not used before, so it
  appears once per key, never again.
- Settings > Connected apps: under an app with the SSH scope, list each allowed key (user ID and short
  fingerprint) with its own Remove. Removing the last key leaves the scope; the next request shows the picker.
- SELECT_KEY with no key id still opens the full picker; picking adds to the set.

Test: unit tests for the authorizer set logic, a 4.6.0 single-key row, and parsing. On device
with the OkcAgent fork: one, two and three keys across several git fetches and pushes, prompts only on first use
of each key; remove one key in Connected apps and confirm only that key prompts again; a card key (tap and PIN
per signature is by design).


## 2. Mail apps still keep the passphrase for 5 minutes (#15, reopened)

Priority: high (bug, regression of a promised fix). Origin: #15.

Reported on 4.6.1 and again on 4.6.2: a passphrase entered while decrypting in Thunderbird stays exactly 5
minutes whatever the setting (1 minute, 1 hour, until cleared, until the phone locks). Force-stopping PGPony and
Thunderbird did not change it.

What 4.6.1 did: SessionPolicy reads pgpony_prefs with MODE_MULTI_PROCESS. That did not fix it. "Exactly 5 minutes,
every option, survives a force stop" means the :remote_api process reads the default (300), not a stale value.

Find the cause before changing anything:

- Reproduce on device: set 1 minute in Settings, then from adb read
  `shared_prefs/pgpony_prefs.xml` and check session_cache_duration_sec is in the file. Then decrypt from
  Thunderbird and log SessionPolicy.durationSec() inside :remote_api.
- Suspects, in order: (a) a :remote_api writer of pgpony_prefs (PGPonyOpenPgpService.rememberSignKeyFor)
  applying its own stale copy of the map over the file and dropping the duration key; (b)
  MODE_MULTI_PROCESS's reload being async and the read racing it; (c) the prompt Thunderbird reaches not being
  ProviderPassphraseActivity, so the passphrase lands in a different cache.

Fix (built): the duration now lives in its own file (files/session_policy), written atomically by
SessionPolicy.setDurationSec and read straight from disk on every SessionPolicy.durationSec() call in either
process, so there is no per-process copy to go stale. The pgpony_prefs value is still written (for a downgrade)
and read only when the file does not exist yet (a duration chosen before 4.6.3). CardPinCache's enable switch
moves to a MODE_MULTI_PROCESS read for the same reason. This settles 4.7.0 item 19's note about caching
SessionPolicy with a change listener: listeners do not fire across processes, so that idea is dropped.

The device check below still decides whether this closes #15. The prompt now states the duration as the
:remote_api process reads it, so the dialog itself shows whether that process sees the setting.

Also from 4.7.0 item 1 (built):

- The provider passphrase prompt is built from the request and the policy: title and first sentence for sign,
  decrypt (ACTION_DECRYPT_VERIFY / ACTION_DECRYPT_METADATA) or SSH login, then how long it is kept (minutes,
  hours, until cleared, until the phone locks), in every locale but Korean (falls back to English). "Sign with a
  different key" shows only when signing. provider_passphrase_body_format is gone from every locale.
- Settings: when the main process holds nothing, the text no longer claims nothing is held anywhere (a mail app's
  passphrase lives in :remote_api), and Clear now stays available so it can reach that process.
- InAppPassphraseCache reads SessionPolicy, so it follows the file too.

Test: on device with Thunderbird, every option: 1 minute (asks after a minute), 1 hour (does not ask at 6
minutes), until cleared (does not ask until Clear), until the phone locks (asks after lock and unlock). Change the
option while a passphrase is held and confirm the new value applies. Required before release; the reopened issue
promises it.


## 3. v6 recipient key ID from the wrong end of the fingerprint (#73)

4.7.0 item 14, unchanged. One helper derives the key ID by fingerprint length (32 octets: first 8; 20 octets: last
8), used in CompositeDecryptor.findRawCompositeByKeyId and anywhere a v3 PKESK or issuer key ID meets a v6 key.
Unit test from the fingerprint and PKESK octets only; no reporter key material in the repo.


## 4. Protected ML-DSA key: Add User ID and Revoke Subkey always fail

4.7.0 item 20, unchanged. Pass the passphrase as the old one to reprotect (or drop the reprotect where the ring
comes back protected already), sweep every composite edit for reprotect(..., null, ...), and map
ProtectedKeyException to the normal passphrase messages.


## 5. ML-DSA signing in package mode, and the recipient loader sweep (#72, 4.7.0 item 5)

- Bug half of 4.7.0 item 15 only: route the package signer through the composite signer and verify a signed
  package on decrypt. The per-file mode stays in 4.7.0.
- 4.7.0 item 5: move every remaining loadPublicKeyRing call that chooses recipients or signers (Contacts, Exchange,
  bundle encrypt, Autocrypt, the provider) to loadEncryptionRecipientRing plus the v4 algo-35 channel. A selected
  recipient that cannot be loaded stops the operation and is never dropped.


## 6. Shared images read as signatures; .gpg / .pgp routed to Encrypt (#67)

4.7.0 item 2, unchanged: a real packet parse instead of the first-byte sniff, known image and archive magic numbers
short-circuit, and Quick Action routing by content with the extension as a tie-breaker.


## 7. Keyring tip flashes on every launch (#74)

4.7.0 item 16, unchanged: a loaded-once flag gates the tooltip and the empty-keyring state.


## 8. Play vitals: ANRs and crashes (4.7.0 item 19)

ANR rate is over the bad-behavior threshold and only Play builds count, so this goes out in the first build Play
gets.

- A: every public Key Detail edit in KeyRepository runs in withContext(Dispatchers.Default).
- B: file picks for Encrypt, Decrypt and Verify read on Dispatchers.IO with a loading state.
- C: Save and Share on the three result sheets copy on Dispatchers.IO with progress.
- ProviderCardOpActivity.onCreate's runBlocking Room read moves into lifecycleScope.
- E: intent handling waits for the nav graph before navigating.
- F: cap key-import reads, "too large to be a key" above the cap, String only when the head looks like armor.
- G: CompositeSigPacket.dearmor throws a typed parse error; every caller shows "the signature block is damaged".
- StrictMode in debug builds, both processes.
- D and H: watch only, no change.


## 9. Message grammar walker and card result (4.7.0 item 12a)

Gate: failed. Reading v4.6.2's four content walks shows a second literal replacing (in memory, card) or
following (streaming) the signed one after its signature verified. Main's ContentWalker is entangled with the
SignerStatus, signer-identity and proxy work in 770f5be, so instead of that port 4.6.3 carries:

- MessageGrammar.kt and MessageGrammarTest.kt from main (adc109c), byte for byte, so cherry-picking to main is a
  no-op for them.
- MessageGrammar.normalizePlaintext on the in-memory decrypt (as on main), the signed-only path and the card
  path (the card's decrypted content is now read whole within the existing size cap, then walked).
- A one-literal guard in every walk: memory, signed-only, streaming (refused before a byte of the second literal
  is written) and card.
- LiteralGuardTest: the forged layouts are refused on the software paths, and an ordinary signed message still
  verifies on each. The card path needs a card to exercise.

normalizeOuter (ESK filtering before decryption) stays on main only: it changes which ESKs Bouncy Castle sees,
which is interop work rather than this fix. Release notes say "message handling hardening" only.


## 10. Pair with PGPony Desktop and move keys (4.7.0 item 21)

Priority: medium-high (feature). The protocol is docs/PAIRING_PROTOCOL.md (v1, Oct 1 revision), which desktop
3.0.0 speaks.

Port: copy `com.pgpony.android.pair` (PairCrypto, PairWire, PairProtocol, PairSession, PairInvite, PairPeer) and
its tests and vectors from main as of 770f5be onto `4.6.x` unchanged. It needs only the JDK, Bouncy Castle X25519
and kotlinx.serialization JSON, all already on `4.6.x`. Main stays the source of truth; the files must stay
byte-identical between branches, and desktop keeps vendoring from main.

Scope: the phone can host or join, and moves public keys, key pairs and a full backup both ways.

Work:

- Entry points: Settings > "Pair with another device", and the Keyring overflow menu.
- Join: scan the `pgpony-pair:1?...` invite QR (reuse the existing ZXing scanner), or type `address:port`.
- Host: open a 10-minute window, listen on an ephemeral port off cellular interfaces, show the invite QR and the
  address. One connection per window; show the connecting address as soon as it arrives.
- Code screen: the host types the joiner's six-digit code (three tries); the joiner confirms Same code or
  Different. A failure ends the window.
- Paired screen: an offer list (key pairs, public keys, backup) and incoming offers accepted per item, with a
  recovery-code field for a backup. Mirrors desktop's PairDialog.
- PairController, like desktop's: candidates, prepare (a key without a passphrase exports under a transfer
  passphrase; a backup exports under a fresh recovery code), apply (import and restore through the existing
  services, so imports get the same proven-secret checks as any other import).
- INFO lists all three kinds in `accepts`.
- Offline mode blocks pairing. With it on, the pairing screen explains that pairing uses the local network
  and asks the user to turn Offline mode off first; no socket opens while it is on.
- Runs on Dispatchers.IO, keeps the screen on, and leaving the screen ends the pairing and wipes the session keys.
- Respect the biometric lock and the signing-requirement setting before any key pair or backup leaves the phone.
- targetSdk stays 36, so no ACCESS_LOCAL_NETWORK runtime permission yet. Note it for the SDK 37 bump.
- Strings in every locale; Korean falls back to English where untranslated.

Built (RC2): ui/pair/PairController.kt (desktop's controller, phone-adjusted: the host lists and accepts only
Wi-Fi, Ethernet, tethering and USB interfaces, and a peer must reach it on a listed address), PairScreen.kt
(desktop's dialog as a screen: Choose, Hosting with the invite QR, Joining by scan or typed address, the two
compare panes, the session), PairKeyProtection.kt (main's SecretKeyCheck.protectionOf rule, so no key pair goes
out or comes in with a secret in the clear), a "pair" route reached from Settings and the Keyring overflow, and
100 strings in every locale but Korean (falls back to English). Desktop 3.0.x needs no change: it already shows
the invite QR when hosting and takes a typed address or pasted invite when joining.

Test: the pair unit tests and the four vector files on `4.6.x`, plus PairControllerTest. On device against desktop 3.0.0 (macOS and Linux):
phone joins by scan and by typed address, phone hosts and desktop joins, a wrong typed code, a Different, a
connection from a non-local address refused, one item of each kind each way, a backup restored with its recovery
code, and a key pair moved and then used to decrypt on the receiving side.

Security note: new network code that moves private keys. It goes to the next external review with the rest of the
4.6.x diff.


## Release

- RC1 from `4.6.x`: items 1 to 9 (fixes, including the #15 Thunderbird check). RC2: RC1 plus pairing (item 10),
  once it works against desktop 3.0.0. Then the reproducibility gate on v4.6.3 (docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md).
- fastlane/metadata/android/en-US/changelogs/463.txt: one short paragraph, no names, finalized before tagging.
- Release notes pasted inline for review before anything is published.
- Push to the Play track promptly so item 8 starts counting.
- Stage by path; drafts/, _archive/ and _to_delete/ stay out.
