// OnboardingSlide.kt
// PGPony Android
//
// Data model + static content for the first-run onboarding carousel.
// Five slides walk the user through: welcome, key generation, encryption,
// key exchange, and privacy/biometric setup.
//
// Added in Phase 3 (Tester Feedback Implementation Plan).
//
// Phase A13 — refactored to hold @StringRes Int IDs instead of literal
// String values for `title` + `body`, so the slide copy localizes
// through Android string resources. OnboardingPage now reads each ID
// through stringResource() at render time. Data structure shape is
// identical; only the title/body field types change (String → Int).

package com.pgpony.android.ui.onboarding

import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.WavingHand
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import com.pgpony.android.R

data class OnboardingSlide(
    val icon: ImageVector,
    val iconTint: Color,
    @StringRes val titleResId: Int,
    @StringRes val bodyResId: Int,
    val showGenerateCta: Boolean = false,
    val showBiometricToggle: Boolean = false,
    // A14 Picker — inline language picker is shown on slide 0. The body
    // text + title localize automatically once the user taps a language
    // since AppCompat recreates the Activity, which rebuilds the entire
    // onboarding carousel with the new locale active. From the user's
    // perspective the picker IS the slide content; the slide's title/body
    // are intentionally short ("Language" / "Choose…") to leave vertical
    // room for the six-row picker beneath them.
    val showLanguagePicker: Boolean = false,
)

object OnboardingSlides {

    val all: List<OnboardingSlide> = listOf(

        // ── Slide 0 — Language (A14 Picker) ──────────────────────────────
        //
        // First-run language picker. iOS adds this as slide 0 (before the
        // Welcome slide) so first-time users land on a language choice
        // before any other onboarding copy is shown. We mirror that
        // exactly. The detected device language is already applied at
        // this point (via LanguageState.initFromAppCompat in
        // PGPonyApp.onCreate), so a German-speaking user sees German
        // slide copy from the very first frame and just taps "Next" if
        // they're happy with the auto-detection.
        OnboardingSlide(
            icon = Icons.Filled.Language,
            iconTint = Color(0xFF3B82F6),
            titleResId = R.string.onboarding_slide_language_title,
            bodyResId = R.string.onboarding_slide_language_body,
            showLanguagePicker = true,
        ),

        // ── Slide 1 — Welcome ────────────────────────────────────────────
        OnboardingSlide(
            icon = Icons.Filled.WavingHand,
            iconTint = Color(0xFF8B5CF6),
            titleResId = R.string.onboarding_slide_welcome_title,
            bodyResId = R.string.onboarding_slide_welcome_body
        ),

        // ── Slide 2 — Generate a key ─────────────────────────────────────
        OnboardingSlide(
            icon = Icons.Filled.VpnKey,
            iconTint = Color(0xFFF59E0B),
            titleResId = R.string.onboarding_slide_key_title,
            bodyResId = R.string.onboarding_slide_key_body,
            showGenerateCta = true
        ),

        // ── Slide 3 — Encrypt a message ──────────────────────────────────
        OnboardingSlide(
            icon = Icons.Filled.Lock,
            iconTint = Color(0xFF6366F1),
            titleResId = R.string.onboarding_slide_encrypt_title,
            bodyResId = R.string.onboarding_slide_encrypt_body
        ),

        // ── Slide 4 — Share your public key ──────────────────────────────
        OnboardingSlide(
            icon = Icons.Filled.QrCode2,
            iconTint = Color(0xFFA78BFA),
            titleResId = R.string.onboarding_slide_exchange_title,
            bodyResId = R.string.onboarding_slide_exchange_body
        ),

        // ── Slide 5 — Privacy & biometric ────────────────────────────────
        OnboardingSlide(
            icon = Icons.Filled.Fingerprint,
            iconTint = Color(0xFF22C55E),
            titleResId = R.string.onboarding_slide_privacy_title,
            bodyResId = R.string.onboarding_slide_privacy_body,
            showBiometricToggle = true
        )
    )
}
