// LockScreen.kt
// PGPony Android — Phase A11
//
// Biometric lock screen shown at app launch (and after the activity
// returns from background) when the user has enabled the "Biometric
// Lock" setting. Mirrors iOS LockScreenView.swift functionally and
// visually:
//
//   • Centered lock icon at the top (Material 3 colorScheme.primary
//     instead of iOS's purple/indigo gradient — keeps the look on
//     the user's chosen color scheme)
//   • "PGPony" headline + "Your keys are stabled" tagline
//   • Big "Unlock" button that calls BiometricGate.authenticate
//     against the host MainActivity
//   • Auto-prompts the biometric dialog ~300ms after the screen
//     appears (matches iOS LockScreenView's task delay) so the
//     user normally doesn't need to tap the button — but it's there
//     as a fallback in case they dismiss the auto-prompt and need
//     to retry, or the auto-prompt didn't fire for some reason.
//   • On authentication error (cancel, lockout) the screen shows
//     a small inline error message and the unlock button stays
//     available for retry.
//   • On success it invokes onUnlock — MainActivity flips the
//     lock state to false and the main app navigates in.
//
// Subtle parity differences from iOS:
//   • No symbol-pulse animation on the lock icon during the auth
//     prompt — Compose has no direct equivalent to SwiftUI's
//     .symbolEffect(.pulse), and synthesizing one with rememberInfiniteTransition
//     is more code than it's worth for a screen most users see for
//     <1s.
//   • iOS adapts the button text and icon to faceID/touchID/opticID
//     via biometricType. AndroidX BiometricManager doesn't expose
//     a clean "what kind of biometric do you have" probe pre-API 30,
//     and post-API 30 the system prompt itself handles the icon/copy.
//     We just say "Unlock" — clear enough since the OS prompt that
//     follows will show the right glyph.

package com.pgpony.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.pgpony.android.R
import com.pgpony.android.ui.keyring.BiometricAvailability
import com.pgpony.android.ui.keyring.BiometricGate
import kotlinx.coroutines.delay

/**
 * Full-screen lock gate. Hosted by MainActivity ahead of the navigation
 * scaffold whenever the user has biometric lock enabled and the runtime
 * lock state is `true` (which happens at fresh launch and whenever the
 * activity returns from background — see MainActivity's lifecycle
 * observer).
 *
 * Caller is responsible for:
 *   • Reading the SharedPreferences flag and deciding whether to render
 *     this screen.
 *   • Resolving the host MainActivity through the LocalContext chain
 *     (this composable does the unwrap itself via ContextWrapper
 *     traversal, same pattern A10a Fix2 established).
 *   • Implementing `onUnlock` to flip its own lock state to false.
 *
 * @param onUnlock invoked on successful authentication. The composable
 *                 stays on screen until the caller stops rendering it.
 */
@Composable
fun LockScreen(onUnlock: () -> Unit) {
    val context = LocalContext.current
    // Walk the ContextWrapper chain to the FragmentActivity — same
    // pattern as findEncryptMainActivity / findImportMainActivity in
    // the encrypt/keyring files. ModalBottomSheet doesn't wrap us
    // here (LockScreen is rendered at the top level of MainActivity's
    // setContent), but the unwrap is cheap and future-proofs against
    // any later wrapping.
    val activity = remember(context) {
        var c: android.content.Context? = context
        while (c != null && c !is FragmentActivity) {
            c = (c as? android.content.ContextWrapper)?.baseContext
        }
        c as? FragmentActivity
    }

    // Local error state — survives recomposition but not process
    // death (intentional; a stale auth error shouldn't outlive the
    // process).
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var isAuthenticating by remember { mutableStateOf(false) }

    // Drive the biometric prompt off the activity's ON_RESUME, not a
    // one-shot timer. The lock re-engages on ON_STOP (MainActivity's
    // observer), which means this screen can enter composition while the
    // app is still backgrounded — a fixed-delay LaunchedEffect would then
    // call BiometricPrompt.authenticate() from a STOPPED activity, where
    // the fragment transaction fails and the screen wedges on
    // "Authenticating…" with no way to recover (the effect never re-runs).
    //
    // Tying the trigger to ON_RESUME guarantees we only prompt when the
    // activity is genuinely in the foreground, and that we RE-prompt every
    // time the user returns from another app. Resetting isAuthenticating
    // first clears any stuck state from an attempt that was interrupted by
    // backgrounding.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, activity) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                isAuthenticating = false
                triggerAuthenticate(
                    activity = activity,
                    onStart = { isAuthenticating = true; errorMessage = null },
                    onSuccess = { isAuthenticating = false; onUnlock() },
                    onError = { msg ->
                        isAuthenticating = false
                        errorMessage = msg
                    }
                )
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        // addObserver doesn't replay a past ON_RESUME, so if the screen
        // appears while already resumed (lock re-engaged in the
        // foreground), prompt now.
        if (lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
            isAuthenticating = false
            triggerAuthenticate(
                activity = activity,
                onStart = { isAuthenticating = true; errorMessage = null },
                onSuccess = { isAuthenticating = false; onUnlock() },
                onError = { msg ->
                    isAuthenticating = false
                    errorMessage = msg
                }
            )
        }
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // ── Lock icon ────────────────────────────────────────
            Box(
                modifier = Modifier
                    .size(120.dp)
                    .background(
                        color = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
                        shape = RoundedCornerShape(32.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Filled.Lock,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(64.dp)
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            // ── Headline ─────────────────────────────────────────
            Text(
                stringResource(R.string.app_name),
                fontSize = 32.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                stringResource(R.string.lock_screen_tagline),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(48.dp))

            // ── Unlock button ────────────────────────────────────
            //
            // Always shown so the user can manually retry if the
            // auto-prompt was dismissed without a successful auth.
            // Disabled briefly while authenticating to avoid a
            // double-trigger (BiometricPrompt won't accept overlapping
            // calls anyway, but the UI affordance is clearer).
            Button(
                onClick = {
                    triggerAuthenticate(
                        activity = activity,
                        onStart = { isAuthenticating = true; errorMessage = null },
                        onSuccess = { isAuthenticating = false; onUnlock() },
                        onError = { msg ->
                            isAuthenticating = false
                            errorMessage = msg
                        }
                    )
                },
                enabled = !isAuthenticating && activity != null,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                )
            ) {
                Icon(
                    imageVector = Icons.Filled.Lock,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    if (isAuthenticating) stringResource(R.string.common_authenticating) else stringResource(R.string.lock_screen_unlock_button),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }

            // Inline error message. Only rendered when an authentication
            // attempt failed — most users will never see this. Styled
            // muted-red to match the error scheme used elsewhere in
            // the app (encrypt/decrypt error rows).
            errorMessage?.let {
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
            }
        }
    }
}

/**
 * Internal helper that hands off to BiometricGate.authenticate. Lives
 * outside the @Composable body so the auto-prompt LaunchedEffect and
 * the manual-tap Button can share a single call site. Defensive about
 * the activity being null (which would only happen if the LocalContext
 * unwrap failed — shouldn't happen in production but the null check
 * costs nothing).
 *
 * The "Authentication unavailable" branch handles the case where
 * BiometricGate.canAuthenticate returns NoneEnrolled or Unavailable
 * at the moment of the call — for example if the user disabled
 * fingerprint mid-session. Rather than freezing the lock screen
 * with no way out, we surface a message; the user can then go to
 * System Settings, enroll a fingerprint, and tap Unlock again.
 */
private fun triggerAuthenticate(
    activity: FragmentActivity?,
    onStart: () -> Unit,
    onSuccess: () -> Unit,
    onError: (String) -> Unit
) {
    if (activity == null) {
        // No Context available since activity is null — surface a
        // hardcoded English message as a last-resort fallback. This
        // path is unreachable in production (LocalContext.current
        // always resolves to MainActivity) but the null-check costs
        // nothing.
        onError("Activity context unavailable.")
        return
    }
    val availability = BiometricGate.canAuthenticate(activity)
    if (availability != BiometricAvailability.Available) {
        onError(activity.getString(R.string.lock_error_biometric_unavailable))
        return
    }
    onStart()
    try {
        BiometricGate.authenticate(
            activity = activity,
            title = activity.getString(R.string.lock_prompt_title),
            subtitle = activity.getString(R.string.lock_prompt_subtitle),
            onSuccess = onSuccess,
            onError = { _, message -> onError(message) }
        )
    } catch (e: Exception) {
        // BiometricPrompt can throw (e.g. IllegalStateException committing
        // its fragment) if invoked at a bad lifecycle moment. Surface it as
        // a normal error so the screen never gets stuck on "Authenticating…"
        // — the Unlock button stays available and the next ON_RESUME retries.
        onError(e.message ?: activity.getString(R.string.lock_error_biometric_unavailable))
    }
}
