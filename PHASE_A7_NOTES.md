# Phase A7 — Per-key private key export with biometric

## What this phase ships

Closes the last remaining action stub in KeyDetailScreen. Export
Private Key now does the actual thing instead of routing to
"coming in a later update":

1. **Tap Export Private Key** in the Actions section (key pairs only).
2. **AlertDialog** warns the user — names the key, calls out that the
   export contains secret material, notes that PGPony can't take it
   back once shared.
3. **On Continue → BiometricGate** invokes the system biometric prompt.
   API 30+ gets BIOMETRIC_STRONG | DEVICE_CREDENTIAL (auto PIN/pattern/
   password fallback). API 28-29 gets BIOMETRIC_STRONG with a Cancel
   button. API 26-27 (Oreo) gets BIOMETRIC_WEAK only — Android's
   limitation, not ours.
4. **On biometric success → Intent.ACTION_SEND chooser** with the
   armored private key as EXTRA_TEXT and "PGP PRIVATE KEY (sensitive)"
   in the subject + chooser title. The shouty subject line is
   intentional — it's the user's last visual stop before sharing.
5. **On biometric cancel/error → snackbar** with Android's localized
   message ("Authentication cancelled.", "Too many attempts. Try again
   later.", etc.) — same language the prompt itself used.

### Fallback path (no biometric / no screen lock)

If `BiometricManager.canAuthenticate` returns NoneEnrolled or
Unavailable, the biometric step is skipped and the share Intent fires
directly. The AlertDialog confirmation was the only gate.

This avoids dead-ending users who own the keys they're trying to
export but happen to not have biometric configured. Forcing them to
set up biometric in Android Settings to export their own key would
be hostile UX.

## New files (1)

| File | Lines | Purpose |
|------|------:|---------|
| `ui/keyring/BiometricGate.kt` | 176 | Wrapper around `androidx.biometric.BiometricPrompt`. `canAuthenticate(context): BiometricAvailability` for the pre-check; `authenticate(activity, title, subtitle, onSuccess, onError)` for the prompt. Authenticator bitmask varies by API level — see the file's header comment for the matrix. |

## Modified files (additive)

| File | Before | After | Δ | Notes |
|------|------:|------:|--:|-------|
| `MainActivity.kt` | 292 | 300 | +8 | Bumped from `androidx.activity.ComponentActivity` to `androidx.fragment.app.FragmentActivity`. Required by BiometricPrompt (it internally shows itself as a DialogFragment). FragmentActivity extends ComponentActivity, so setContent, enableEdgeToEdge, intent handling, and the existing onCreate body all work unchanged. |
| `ui/keyring/KeyDetailScreen.kt` | 550 | 686 | +136 | Dispatcher routes "Export Private Key" to `viewModel.showExportPrivateConfirm()`; new AlertDialog rendered when the flag is set; new `doExportPrivateWithBiometric` private helper that runs the BiometricGate flow. |
| `ui/keyring/KeyDetailViewModel.kt` | 620 | 657 | +37 | New state field `showExportPrivateConfirm`, three actions (`showExportPrivateConfirm`, `dismissExportPrivateConfirm`, `armoredPrivateKeyForShare`). |
| `ui/keyring/KeyShareIntents.kt` | 110 | 151 | +41 | New `shareArmoredPrivateKey(context, armoredPrivate, keyOwnerLabel)` helper. Same Intent.ACTION_SEND pattern as the public-key/cert helpers, but EXTRA_SUBJECT and chooser title both call out "PRIVATE" so the user can't miss what they're sending. |

Total: 1 new file (176 lines), 4 modified files (+222 lines additive).

## Architectural notes

### Why FragmentActivity

`androidx.biometric.BiometricPrompt`'s primary constructor takes a
`FragmentActivity` because it internally shows itself as a
`DialogFragment`. `ComponentActivity` doesn't have the fragment manager
machinery to host it. Bumping MainActivity from
`androidx.activity.ComponentActivity` to
`androidx.fragment.app.FragmentActivity` is a 2-line change
(import + class declaration). FragmentActivity extends
ComponentActivity, so every existing capability — setContent,
enableEdgeToEdge, onCreate, intent handling, billingService init,
the whole bottom-nav scaffold — is inherited intact.

The fragment dependency was already in the project transitively via
`androidx.biometric:biometric:1.2.0-alpha05`. No new dep needed.

### Authenticator matrix by API level

The `setAllowedAuthenticators` bitmask we request from BiometricPrompt
varies by API:

```
API 30+  (Android 11+):  BIOMETRIC_STRONG | DEVICE_CREDENTIAL
API 28-29 (Pie/Q):       BIOMETRIC_STRONG
API 26-27 (Oreo):        BIOMETRIC_WEAK
```

Reasoning:
- **BIOMETRIC_STRONG | DEVICE_CREDENTIAL** on API 30+ gives the user the
  best of both worlds: fingerprint/face primary, PIN/pattern/password
  fallback rendered by the OS itself. Common case: user has PIN but no
  fingerprint enrolled — they still get authenticated, no friction.
  Caveat: `setNegativeButtonText` is illegal when DEVICE_CREDENTIAL is
  set — the OS provides its own "Use PIN" button.
- **BIOMETRIC_STRONG** on API 28-29 because DEVICE_CREDENTIAL
  combination support didn't land until API 30. Adds a Cancel button.
- **BIOMETRIC_WEAK** on API 26-27 because that's the only authenticator
  the androidx.biometric library supports at those levels. STRONG
  requires API 28+. Most Oreo devices that PGPony runs on don't have
  Class 3 biometrics anyway.

`BiometricGate.authenticatorsForCurrentApi()` encapsulates this; both
`canAuthenticate` and `authenticate` use it so what the user is told
matches what they get.

### Why AlertDialog before biometric

The biometric prompt itself says "Authenticate to export your private
key" but most users don't read prompt subtitles carefully. Putting the
AlertDialog FIRST forces a meaningful confirmation read:

> "This exports your PRIVATE key for {owner} as armored text.
> Anyone who gets this file can decrypt messages sent to you AND sign
> messages as you. Once shared, PGPony cannot take it back."

The biometric step then confirms the right hand belongs to the body.
Two gates with different purposes — info vs. identity.

### Dialog Continue button uses error tint

The Continue button on the export-private-key AlertDialog uses
`ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)`
— same red as Delete and Revoke. Visual consistency: red = "this is
destructive or irreversible if you mean the wrong thing".

### Caller is responsible for the gate; helpers are not

`KeyShareIntents.shareArmoredPrivateKey` is intentionally
unauthenticated. It builds and launches the Intent — that's it. The
biometric / confirmation gate lives in the caller because:

1. **Testability** — KeyShareIntents stays pure; tests can verify the
   Intent shape without needing a FragmentActivity + biometric mock.
2. **Separation of concerns** — KeyShareIntents knows about Intents.
   BiometricGate knows about authentication. Neither knows about UI.
   The screen orchestrates.
3. **Reusability** — if a future flow needs to share an armored
   private key without biometric (very hypothetical, but e.g. a debug
   menu), it can call the helper directly without bypassing the
   wrong-place gate.

## Verified

- Structural preservation in all modified files (all original
  Composables / functions / classes still present)
- Additive delta on every modified file (no removals)
- New BiometricGate file is self-contained (only depends on
  androidx.biometric, androidx.fragment.app, androidx.core.content,
  android.os.Build — all already available)
- KeyDetailScreen's new dialog body and helper compile cleanly against
  the existing imports (AlertDialog, TextButton, ButtonDefaults already
  imported from A4b; FragmentActivity referenced as FQN to avoid an
  unused import elsewhere)
- All three remaining "MISS" patterns in the structural-check were
  expected — checking cross-file patterns

## How to test on device

Pixel 10 Pro AVD typically reports BIOMETRIC_SUCCESS once you configure
a fake fingerprint in Settings → Security → Fingerprint. To exercise
the fallback paths, factory-reset the AVD or unenroll the fingerprint.

### Happy path (biometric enrolled)

1. Generate a key (or use an existing one) → tap into Key Details
2. Scroll to Actions section → tap "Export Private Key"
3. AlertDialog appears — read the warning, tap Continue
4. BiometricPrompt appears with title "Verify identity" + subtitle
   "Authenticate to export your private key"
5. On the AVD: `adb -e emu finger touch 1` to fake-fingerprint
6. Prompt dismisses → system share chooser appears with
   "Share PRIVATE key (sensitive)" title
7. Pick a destination (Gmail draft is a good test) → verify
   EXTRA_SUBJECT reads "{owner} — PGP PRIVATE KEY (sensitive)"
   and the body contains the BEGIN PGP PRIVATE KEY BLOCK armored
   text

### Biometric cancel

1. Same flow up to step 4
2. Tap Cancel (or "Use PIN" on API 30+ → cancel that too)
3. Snackbar: "Authentication cancelled." (or whatever Android's
   localized message says)
4. No share Intent fires

### Wrong fingerprint (transient failure)

1. Same flow up to step 4
2. Use a different / not-enrolled fingerprint
3. Prompt itself shows "Fingerprint not recognized" and stays open
4. User can retry — no snackbar/error from our side because
   onAuthenticationFailed is deliberately a no-op
5. Eventually either correct fingerprint (→ success) or too many
   attempts (→ onAuthenticationError fires with lockout message)

### No biometric configured

1. AVD with no fingerprint enrolled and no screen lock
2. Same Export Private Key flow
3. AlertDialog appears as usual
4. Continue → share chooser fires directly (no biometric step)
5. This is intentional — the AlertDialog confirm IS the gate

### AlertDialog dismissal

1. Export Private Key → AlertDialog appears
2. Tap Cancel (or tap outside the dialog area)
3. Dialog dismisses, no biometric, no share

## Pending after A7

Per the plan v2: **Phase A8** — WKD (Web Key Directory) discovery for
the Encrypt tab's recipient lookup. Independent of KeyDetailScreen
which is now feature-complete for v1.0.

## Suggested entry for NorseHorse_Android_Update_Log.md

```
## PGPony Android Phase A7 — Per-key private export with biometric (2026-05-27)

Last KeyDetailScreen stub resolved. Export Private Key now gates the
share Intent behind an AlertDialog confirmation and a BiometricPrompt
(with PIN/credential fallback on API 30+). Devices without biometric
or screen lock fall through to the AlertDialog as the sole gate.

### Added
- ui/keyring/BiometricGate.kt — BiometricPrompt wrapper.
  canAuthenticate() returns BiometricAvailability enum (Available /
  NoneEnrolled / Unavailable); authenticate() shows the prompt with
  API-level-appropriate authenticator bitmask (BIOMETRIC_STRONG |
  DEVICE_CREDENTIAL on 30+, BIOMETRIC_STRONG on 28-29, BIOMETRIC_WEAK
  on 26-27).

### Modified (additive)
- MainActivity.kt: +8 lines. Bumped from ComponentActivity to
  FragmentActivity. Required by BiometricPrompt. FragmentActivity
  extends ComponentActivity, so all existing setContent /
  enableEdgeToEdge / onCreate behavior is preserved unchanged.
- ui/keyring/KeyDetailScreen.kt: +136 lines. "Export Private Key"
  dispatcher entry; new AlertDialog warning the user about
  sensitivity; new doExportPrivateWithBiometric private helper that
  runs the BiometricGate flow.
- ui/keyring/KeyDetailViewModel.kt: +37 lines. showExportPrivateConfirm
  state field; show/dismiss/armoredPrivateKeyForShare actions.
- ui/keyring/KeyShareIntents.kt: +41 lines. shareArmoredPrivateKey
  helper. Same Intent.ACTION_SEND pattern as the public-key/cert
  helpers; EXTRA_SUBJECT yells "PRIVATE" so user can't miss what
  they're sending.

### iOS port equivalents
- BiometricGate              = iOS LAContext.evaluatePolicy(
                                 .deviceOwnerAuthentication, ...)
                               (iOS uses LAContext directly; Android
                               uses androidx.biometric which wraps
                               the OS biometric APIs across versions)
- Export Private Key dialog  = iOS Alert with "Export Private Key?" /
                               "Continue" / "Cancel"
- shareArmoredPrivateKey     = iOS UIActivityViewController with
                               armored private key + "PRIVATE" subject
```
