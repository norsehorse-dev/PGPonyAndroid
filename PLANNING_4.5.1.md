# PGPony 4.5.1 planning

Status: planning. A quick fix-and-small-feature release after 4.5.0. Two features chosen by
NorseHorse (a thorough translations pass, delete User IDs), plus items from the open-issue
triage of Sep 16 2026. versionCode 445, versionName "4.5.1". Android first per the
new-feature procedure.

## 1. Thorough translations pass

Priority: high. Origin: NorseHorse.

4.5.0 added a large batch of new strings (post-quantum keygen captions, key-server dialogs,
the destructive-action lock, revoke/remove flows, the subkey selector, recipient-picker copy)
that the existing translations do not cover. Audit every values-*/strings.xml against the base
values/strings.xml, produce a per-language gap list (missing and stale keys), and top them up.
Revisit Korean (4.5.0 item 9, deferred): if it can be brought to a shippable level, enable it
(KO in SupportedLanguage, "ko" in locales_config.xml).

## 2. Delete User IDs

Priority: medium. Origin: NorseHorse.

UserIdService has add and revoke but no local delete, the User ID analog of the item-16 subkey
remove. Add removeUserId for the BouncyCastle and composite-primary paths (strip the UID packet
and its self-certification, rebuild the ring), guard against removing the last UID or the
primary UID, and wire it into the Key Detail User ID rows next to the existing revoke action.
Mirror SubkeyRemoveTest. revokeUserId already covers the "proper retire, tell correspondents"
case; this adds the local-strip case.

Implemented. UserIdService.removeUserId (classical, BC removeCertification + replacePublicKeys)
and CompositePrimaryKeyGen.removeUserId (byte-splice) with a last-UID guard; KeyRepository.removeUserId
dispatches and moves the cached identity to the first remaining UID when the removed one was the
display name. Key Detail gets a Remove action per editable non-revoked UID (shown only when the key has
more than one UID) opening the existing action sheet with a remove-specific, passphrase-free confirm.
Keyserver reality: key servers are append-only, so an upload never removes a UID and a refresh would
overwrite the local strip and bring it back. New RemovedUserIdStore tombstones removed UIDs per key and
mergeFetchedPublicMaterial re-strips them from fetched material on refresh (classical path; keeps at
least one UID). Add User ID clears a tombstone; purge clears all. Sheet copy points at revoke as the way
to retire a UID for others. Tests: UserIdRemoveTest, CompositeRemoveUserIdTest (both green). On-device:
remove a UID, upload, refresh, confirm it stays removed.

## 3. QR code scannability regression (#63, CertainBot)

Priority: high (regression). Origin: CertainBot (#63), from the 4.5.0 item-26 QR capacity bump.

Item 26 raised QrChunking PAYLOAD_MAX 1000 -> 1800 and MAX_FRAMES 16 -> 24 so a post-quantum key
would fit. The denser per-frame payload pushes each symbol to a higher QR version with smaller
modules, and with the fixed quiet zone the codes render smaller and harder to scan; the final
frame looks bigger only because it carries less data. Rebalance: lower PAYLOAD_MAX and lean on
the higher frame count (more frames of readable QRs beats fewer dense ones), render the symbol
larger, and trim the quiet-zone margin, keeping a PQ-only key within the frame cap. Re-verify a
PQ-only key still chunks and round-trips screen to screen.

Implemented. QrChunking: PAYLOAD_MAX 1,800 -> 1,000 and SINGLE_MAX 2,000 -> 1,200 (back to a scannable
density) with MAX_FRAMES 24 -> 32 so a ~18.5 KB PQ-only cert still fits (~19 frames) on frame count
rather than symbol density. QrBitmap.encodeOne now renders at the QR's natural module resolution and
scales up by an integer factor itself, instead of letting ZXing center a dense symbol inside a fixed
800px field: this removes the variable white border CertainBot flagged and fills each frame uniformly
with crisp modules. QrChunkingTest is symbolic over the constants, so it holds. Render quality is
on-device only: Share Public Key -> QR on a PQ-only key, confirm the multipart frames fill the box and a
second phone scans them.

## 4. "Encrypt in PGPony" share action for shared text (#58, CertainBot)

Priority: medium. Origin: CertainBot (#58).

Clarified after the 4.5.0 encrypt-to-this-key work, which was not what he meant. When text is
shared to PGPony the share sheet shows "Open in PGPony"; add a second action "Encrypt in PGPony"
that takes the shared text straight to the Encrypt screen as the plaintext to encrypt, not a key
import and not encrypt-to-key. A second ACTION_SEND text share target routed to encrypt with the
shared text prefilled.

## 5. Interactive Default Key setting (#63, CertainBot)

Priority: low. Origin: CertainBot (#63).

Settings > Keys & Servers > Key Management > Default Key is display-only. Make it a picker so the
default signing key can be chosen from Settings, consistent with it living there.

## 6. Key Details encrypt/decrypt shortcut (#63, CertainBot)

Priority: low. Origin: CertainBot (#63).

From Key Detail, a direct "Encrypt with this key" on a public key and "Decrypt with this key" on
a key pair, to shortcut browsing keys then encrypting. CertainBot floated the header avatar
circle as the button, or adding the key to the current recipient set. UI decision needed; keep
Key Detail uncluttered.

## 7. Revoke option in the subkey-remove dialog (#36, CertainBot)

Priority: low. Origin: CertainBot (#36).

The delete-key dialog got a "revoke instead" button in 4.5.0 (item 28). CertainBot asks for the
same on the "Remove this subkey" dialog, since a removed subkey cannot be revoked afterward
either. Add a revoke-first affordance alongside Cancel/Remove, reusing the item-16 subkey revoke
path.

## 8. Opt-in switch to fully disable destructive actions (#36, Araaf)

Priority: low. Origin: Araaf (#36), resolved as a happy medium.

4.5.0's "Protect destructive actions" gates delete / remove / clear behind device auth, on by
default. Araaf wants them fully disabled. The middle path: a SEPARATE switch, OFF by default,
set in Settings and offered on onboarding, that when ON hides or disables delete key, remove
subkey, remove User ID, and clear-all-data entirely until the user turns it back off. Off by
default keeps the UI clean for everyone else; only opt-in users lose the actions. Distinct from
the auth-gate toggle, which stays as is.

## Decisions and replies owed (not code unless decided)

- #36 (CertainBot vs Araaf): trust-level colors and the X / ! shield-symbol swap. Opposed
  preferences; CertainBot suggested a separate issue to settle it. Spin it out rather than flip
  colors mid-release.

## Housekeeping

- Close #55 (all items shipped in 4.4.1 and 4.5.0), #57 (multi-recipient composite decrypt,
  RC1), #56 (v4 ML-KEM-768+X25519, RC2).
- Open a standalone issue for the SOP / stateless-CLI wrapper so PGPony can join the Sequoia
  interop test suite (hko-s, #56). Separate from the app release.

## 9. Contacts refresh ANR: provider queries on the main thread (Play vitals)

Priority: high (ANR). Origin: NorseHorse (Play Console, 4.5.0, versionCode 444).

Main-thread Binder ANR. ContactsViewModel.refreshContacts ran on viewModelScope (Dispatchers.Main)
and called ContactsService.buildContactsList, which queries the contacts provider and eagerly decodes
a photo per contact via ContactsContract openContactPhotoInputStream, a synchronous Binder call. On a
device with many contacts that blocks the main thread until the ANR watchdog fires (the reported stack
sits in BinderProxy.transactNative under buildContactsList). Fix: refreshContacts wraps the key load and
buildContactsList in withContext(Dispatchers.IO). buildContactsList has a single caller, so one hop
covers it. Verify on device: open Contacts on an account with many photo contacts, no ANR.

## 10. Raise DEX code optimization (R8 keep-rule narrowing) (Play vitals)

Priority: medium. Origin: NorseHorse (Play Console). The "DEX code optimization" insight sits at 13%
(Optimization / Obfuscation / Shrinking). 4.5.0's isShrinkResources moved the resource metric, not this
one, which is held down by broad -keep class X.** { *; } rules in proguard-rules.pro. Two graded passes,
committed separately from the feature work so they can be reverted alone. Pass 1: drop the redundant
whole-library keeps for Compose, Ktor, coroutines, CameraX, and biometric, all of which ship their own
consumer R8 rules (keep the -dontwarn lines). Pass 2: drop the broad app-package keeps for
com.pgpony.android.crypto/data/network; app code is called directly, not by name, so R8 can shrink and
obfuscate it, while the composite PQ path, Room entities/DAOs (by annotation), Parcelables (CREATOR
rule), serializers (kotlinx rules), and manifest components (entry points) stay covered. Left verbatim
as load-bearing: BouncyCastle (reflective provider/algorithm lookup), the org.openintents.openpgp Binder
contract (documented BadParcelableException crash history), androidx.security.crypto / Tink (reflective
key managers guarding the stored keys), and Room. R8 breakage is runtime-only, so verification is a full
release build plus on-device smoke test: keygen, encrypt, decrypt, sign, verify, import/export, the
K-9 / Thunderbird provider path, QR, and card.
