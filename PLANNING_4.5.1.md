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

Done (gap top-up, all 7 locales). Audited every values-*/strings.xml against base: base carries 1479
translatable strings; the union gap was 107 keys (de/es/fr/ja/pt-rBR each missing all 107, ru 104, ko 97),
no stale/extra keys anywhere. Filled every gap, matching each locale's shipped terminology (subkey,
passphrase, key server, revoke, User ID, offline mode, post-quantum/classical), preserving %1$s/%2$s
placeholders and escaping, keeping brand and algorithm tokens (PGPony, ML-KEM/ML-DSA, Ed25519, RSA, Argon2,
Tor, SOCKS, HKPS, Web Key Directory) verbatim. Only gaps were filled; no existing translation was touched.
Verified: all seven parse as XML, zero missing keys, placeholder sets match base, no double-escaping.
de/es/fr/ja/pt-rBR now at full key coverage; ru full; ko now has every key present.
Residual still-English present strings in de/es/fr/ja/pt/ru are cognates and proper tokens (Passphrase,
Contacts, Port, AID, Password Store, version numbers) that read correctly as-is or were deliberately left
by the existing translators, so they are left untouched.
DECIDED: Korean stays as-is for 4.5.1 (NorseHorse). It remains dormant (not in SupportedLanguage /
locales_config.xml), ~967 strings still English; not enabled, not further translated this release. The 97
union-gap keys added to ko during the audit are kept (harmless, since ko is not user-selectable) but do not
make it shippable. 4.5.1 ships fully localized in the six active locales: de, es, fr, ja, pt-rBR, ru.

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

Follow-up (NorseHorse, found on RC1): the Exchange screen took ~10 s to show its QR codes after the tab
opened. Generation already runs on Dispatchers.Default, so the UI was not blocked, it was encodeOne being
slow: it wrote every scaled pixel with Bitmap.setPixel, hundreds of thousands of JNI calls per frame times
up to MAX_FRAMES (32) frames. Rewrote encodeOne to fill one module-resolution IntArray, build a small
RGB_565 bitmap from it in one call, and scale it up nearest-neighbor with Bitmap.createScaledBitmap. Pixels
are identical to the old integer-replication loop, so scannability and the #63 sizing are unchanged, but
the render drops from seconds to well under one. Not JVM-unit-testable (Android Bitmap); on-device: open
Exchange on a PQ-only key and confirm the QR appears effectively immediately. Needs an RC2 (RC1 already
shipped the slow path).

## 4. "Encrypt in PGPony" share action for shared text (#58, CertainBot)

Priority: medium. Origin: CertainBot (#58).

Clarified after the 4.5.0 encrypt-to-this-key work, which was not what he meant. When text is
shared to PGPony the share sheet shows "Open in PGPony"; add a second action "Encrypt in PGPony"
that takes the shared text straight to the Encrypt screen as the plaintext to encrypt, not a key
import and not encrypt-to-key. A second ACTION_SEND text share target routed to encrypt with the
shared text prefilled.

Implemented. New activity-alias EncryptTextShareAlias (label "Encrypt in PGPony") of ShareTargetActivity
with an ACTION_SEND text/plain filter, so the share sheet shows a second PGPony entry beside the Quick
Action. Launched through the alias, ShareTargetActivity.forwardEncryptTextIfNeeded forwards the text to
MainActivity as IntentHandler.ACTION_ENCRYPT_TEXT, which process() maps to the existing
IntentAction.EncryptText, landing on Encrypt with the text prefilled and skipping classify. New string
share_encrypt_text_label (joins the translation pass). Verify on device: share text from a notes app or
browser, confirm both "Open in PGPony" and "Encrypt in PGPony" appear, and the latter opens Encrypt with
the text ready.

## 5. Interactive Default Key setting (#63, CertainBot)

Priority: low. Origin: CertainBot (#63).

Settings > Keys & Servers > Key Management > Default Key is display-only. Make it a picker so the
default signing key can be chosen from Settings, consistent with it living there.

Implemented. The Default Key row in Settings > Key Management is now a dropdown picker (reusing the
default-recipient pattern) over the signing key pairs, letting the user switch it via
SettingsViewModel.setDefaultSigningKey -> repo.setDefaultKey. It shows even when no default is set yet
("Choose a default key"). New string settings_key_default_choose (joins the translation pass). UI-only;
verify on device.

## 6. Key Details encrypt/decrypt shortcut (#63, CertainBot)

Priority: low. Origin: CertainBot (#63).

From Key Detail, a direct "Encrypt with this key" on a public key and "Decrypt with this key" on
a key pair, to shortcut browsing keys then encrypting. CertainBot floated the header avatar
circle as the button, or adding the key to the current recipient set. UI decision needed; keep
Key Detail uncluttered.

Implemented (option 2, avatar as tap target, with a first-open hint). The Key Detail header avatar is
the tap target: on a public key it goes to Encrypt with that key preselected as recipient; on a key
pair it goes to Decrypt. KeyHeaderSection wraps KeyAvatarHero in a clickable, circle-clipped Box when
onAvatarClick is non-null; KeyDetailScreen wires onAvatarClick to onDecryptWithKey (key pair) or
onEncryptToKey(fingerprint) (public), and MainActivity routes those to Screen.Encrypt (via
encDecVm.preselectRecipient) and Screen.Decrypt. A one-time snackbar hint fires on first open of any Key
Detail (LaunchedEffect on fingerprint, guarded by pref kd_avatar_shortcut_hint_shown): kd_avatar_hint_decrypt
for a key pair, kd_avatar_hint_encrypt otherwise. New strings kd_avatar_hint_encrypt/decrypt (join the
translation pass). Gated by nothing destructive, so no hide-destructive interaction. UI/navigation only;
verify on device.

## 7. Revoke option in the subkey-remove dialog (#36, CertainBot)

Priority: low. Origin: CertainBot (#36).

The delete-key dialog got a "revoke instead" button in 4.5.0 (item 28). CertainBot asks for the
same on the "Remove this subkey" dialog, since a removed subkey cannot be revoked afterward
either. Add a revoke-first affordance alongside Cancel/Remove, reusing the item-16 subkey revoke
path.

Implemented. The subkey-remove AlertDialog gains a "Revoke this subkey instead" button below the body
(hidden when the subkey is already revoked, matching the key-delete revoke-instead). It calls a new
KeyDetailViewModel.revokeSubkeyInstead which closes the remove dialog and opens the existing subkey
revoke sheet (showSubkeyRevokeSheet). New string key_detail_subkey_revoke_instead_button (joins the
translation pass). UI-only; verify on device.

## 8. Opt-in switch to fully disable destructive actions (#36, Araaf)

Priority: low. Origin: Araaf (#36), resolved as a happy medium.

4.5.0's "Protect destructive actions" gates delete / remove / clear behind device auth, on by
default. Araaf wants them fully disabled. The middle path: a SEPARATE switch, OFF by default,
set in Settings and offered on onboarding, that when ON hides or disables delete key, remove
subkey, remove User ID, and clear-all-data entirely until the user turns it back off. Off by
default keeps the UI clean for everyone else; only opt-in users lose the actions. Distinct from
the auth-gate toggle, which stays as is.

Implemented (Settings + gating). New DestructiveActionsDisabled store (pref disable_destructive_actions,
default off) in BiometricGate.kt, alongside DestructiveActionLock. A "Hide destructive actions" toggle in
Settings > Security (guarded like the protect toggle) via SettingsViewModel.setDestructiveActionsDisabled.
When on, the data-loss actions are hidden: the Delete key menu item (KeyDetailScreen), the Remove subkey
menu item and the Remove User ID button (both already hide on a null callback, so the wrapper passes null
when hideDestructiveActions), and the Clear all data button in Settings. Revoke and every non-loss action
stay. New strings settings_disable_destructive_title/subtitle (join the translation pass). Onboarding surface added: the privacy slide (slide 5, alongside biometric / offline / armor-comment)
gains a "Hide destructive actions" toggle via DestructiveToggleRow, off by default. It shares the pref with
Settings through a new DestructiveActionsDisabled.setEnabled, so a choice made in onboarding shows in
Settings and vice versa. New strings onboarding_page_destructive_toggle_title/subtitle (join the translation
pass). UI-only; verify on device: flip it on in onboarding, confirm Settings shows it on and delete/remove/
clear are hidden; flip off, confirm they return.

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

## 11. Dead privacy policy link (user email)

Priority: medium. Origin: user email. The privacy policy link pointed at pgpony.norsehor.se/privacy,
which is dead after the site moved to pgpony.app. Replaced every pgpony.norsehor.se instance with
pgpony.app: the clickable link in SettingsScreen (https://pgpony.app/privacy) and the security_info_footer
string in the base plus all seven locales. Repo-wide grep confirms none remain. Left as-is (still correct):
the pony.norsehor.se "whole family" link and the norsehorse@norsehor.se feedback email.
