// BiometricGate.kt
// PGPony Android — Phase A7
//
// Compose-friendly wrapper around androidx.biometric.BiometricPrompt.
// Used by the "Export Private Key" flow in KeyDetailScreen to gate the
// production of armored private key material behind device authentication.
//
// Two responsibilities:
//
//   1. canAuthenticate(context) — surface what the device can offer, so
//      the caller knows whether to invoke the prompt or proceed without
//      it. Three buckets:
//        • Available — biometric (or device PIN/credential) ready to use
//        • NoneEnrolled — hardware exists but the user hasn't set up
//          biometrics or a screen lock; we fall back to alert-only confirm
//        • Unavailable — hardware missing or temporarily disabled; same
//          fallback as NoneEnrolled
//
//   2. authenticate(activity, ...) — actually show the prompt. Wraps
//      construction of BiometricPrompt + PromptInfo and forwards the
//      callbacks. Caller passes plain lambdas, doesn't see BC's API.
//
// API-level handling for the authenticator set:
//   • API 30+ (R / Android 11): use BIOMETRIC_STRONG | DEVICE_CREDENTIAL.
//     The OS auto-handles fallback to PIN/pattern/password without us
//     needing a custom Cancel button (and BiometricPrompt actually
//     rejects setNegativeButtonText when DEVICE_CREDENTIAL is in the
//     authenticator set).
//   • API 28-29: BIOMETRIC_STRONG only, with a Cancel button. The OS
//     doesn't support the combined authenticator set on those versions.
//   • API 26-27 (Oreo): BIOMETRIC_WEAK only. STRONG is API 28+ via this
//     library. WEAK is the only option here.
//
// PGPony's minSdk is 26 so we cover the full matrix. Most users on
// devices new enough to install A7 (compileSdk 35 / targetSdk 35) will
// be on API 30+ and get the full credential fallback.

package com.pgpony.android.ui.keyring

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

// ── Availability check ────────────────────────────────────────────────

/**
 * Whether biometric / device-credential authentication is available
 * RIGHT NOW. Determined by [BiometricManager.canAuthenticate].
 */
enum class BiometricAvailability {
    /** Ready to authenticate — biometric is enrolled or device credential is set. */
    Available,
    /** Hardware exists but no biometric enrolled AND no screen lock — the
     *  user can't authenticate without first configuring one in Android
     *  Settings. KeyDetailScreen treats this as "no biometric gate" and
     *  uses the AlertDialog confirm alone. */
    NoneEnrolled,
    /** No hardware OR temporarily unavailable. Same fallback as
     *  [NoneEnrolled]. */
    Unavailable
}

object BiometricGate {

    /**
     * Probe whether the device can authenticate. Use the result to
     * decide whether to call [authenticate] or to proceed without
     * biometric gating. Idempotent and cheap — fine to call from a
     * remembered block.
     */
    fun canAuthenticate(context: Context): BiometricAvailability {
        val mgr = BiometricManager.from(context)
        // Match the authenticator set we'll request in authenticate()
        // so canAuthenticate's verdict actually reflects what the user
        // will see. Reading the resulting code:
        //   • BIOMETRIC_SUCCESS  → ready
        //   • NONE_ENROLLED      → hardware OK, user hasn't configured
        //   • everything else    → unavailable (no HW, security update
        //     pending, hw temp unavailable, etc.)
        val authenticators = authenticatorsForCurrentApi()
        return when (mgr.canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS               -> BiometricAvailability.Available
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED   -> BiometricAvailability.NoneEnrolled
            else                                             -> BiometricAvailability.Unavailable
        }
    }

    /**
     * Show the biometric prompt. Must be called from an Activity that
     * is a [FragmentActivity] (MainActivity is the only one in PGPony,
     * bumped from ComponentActivity in Phase A7).
     *
     * Callbacks:
     *   • [onSuccess] fires once authentication completes — the caller
     *     can safely proceed with the sensitive operation.
     *   • [onError] fires on user cancellation, lockout, or any
     *     unrecoverable error. The string is BC's localized message
     *     ("Authentication cancelled.", "Too many attempts. Try
     *     again later.", etc.) suitable for surfacing in a snackbar.
     *
     * [onError] does NOT fire on a transient failed attempt (wrong
     * finger, etc.) — BC surfaces those as
     * `onAuthenticationFailed` which we deliberately swallow because
     * the prompt itself renders the "Not recognized" state and lets
     * the user retry.
     */
    fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onError: (errorCode: Int, message: String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errorCode, errString.toString())
                }
                // onAuthenticationFailed left at default no-op — see
                // KDoc above.
            }
        )

        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)

        val authenticators = authenticatorsForCurrentApi()
        builder.setAllowedAuthenticators(authenticators)

        // setNegativeButtonText is illegal when DEVICE_CREDENTIAL is in
        // the authenticator set (the OS provides its own "Use PIN" or
        // similar fallback button instead). Only set it for the
        // biometric-only paths on older APIs.
        if (authenticators and DEVICE_CREDENTIAL == 0) {
            builder.setNegativeButtonText("Cancel")
        }

        prompt.authenticate(builder.build())
    }

    /**
     * Return the authenticator bitmask appropriate for the current API
     * level. See file header for the API-level rationale.
     */
    private fun authenticatorsForCurrentApi(): Int {
        return when {
            // API 30+ (Android 11): biometric strong + device credential.
            // Credential fallback handles "user has PIN but no fingerprint",
            // which is a common scenario.
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R ->
                BIOMETRIC_STRONG or DEVICE_CREDENTIAL
            // API 28-29: BIOMETRIC_STRONG is supported; DEVICE_CREDENTIAL
            // combination is not. Cancel button takes the place of any
            // credential fallback.
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ->
                BIOMETRIC_STRONG
            // API 26-27 (Oreo): only BIOMETRIC_WEAK is supported via the
            // androidx.biometric library on these levels.
            else ->
                BIOMETRIC_WEAK
        }
    }
}
