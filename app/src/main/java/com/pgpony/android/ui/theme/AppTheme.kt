// AppTheme.kt
// PGPony Android — Phase A12
//
// Theme picker support. Three modes mirroring iOS's AppTheme enum
// (App/AppState.swift:173):
//
//   • System — follow the device-level dark/light setting
//   • Light  — force light mode regardless of device
//   • Dark   — force dark mode regardless of device
//
// Before A12, PGPonyTheme in MainActivity.kt hardcoded a dark color
// scheme. A12 splits that into PGPonyDarkColorScheme (preserves the
// exact pre-A12 palette) and a new PGPonyLightColorScheme, then has
// MainActivity.PGPonyTheme pick between them via resolveColorScheme.
//
// Storage key matches iOS's UserDefaults pattern: a single string
// ("system" / "light" / "dark") persisted to SharedPreferences key
// "selected_theme". Default is System on first launch.

package com.pgpony.android.ui.theme

import android.content.Context
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.graphics.Color

enum class AppTheme(val displayName: String, val storageKey: String) {
    System("System", "system"),
    Light("Light", "light"),
    Dark("Dark", "dark");

    companion object {
        /** Inverse of [storageKey]. Unknown values fall through to [System]. */
        fun fromStorage(value: String?): AppTheme = when (value) {
            Light.storageKey -> Light
            Dark.storageKey -> Dark
            else -> System
        }
    }
}

// ── Phase A12 Fix1: observable theme state ─────────────────────────────
//
// Why this exists: the original A12 design had PGPonyTheme read
// SharedPreferences directly inside its @Composable body. That looked
// correct (re-read on every composition) but SharedPreferences reads
// are opaque to Compose's snapshot system — they don't create a
// subscription, so Compose has no way to know it should re-evaluate
// PGPonyTheme when the pref changes. Result: theme picker only took
// effect on next activity launch.
//
// Fix: keep a process-wide MutableState<AppTheme> that PGPonyTheme reads
// (snapshot subscription) and SettingsViewModel.setTheme writes
// (triggers recomposition). Initialized once from prefs in
// PGPonyApp.onCreate so the first render of any composable already
// sees the persisted value — no flash-of-default-theme on cold start.

object ThemeState {
    /** Live theme value. Read by PGPonyTheme via `by ThemeState.current`,
     *  written by both PGPonyApp.onCreate (bootstrap) and
     *  SettingsViewModel.setTheme (user toggle). Defaults to System
     *  before initFromPrefs runs — in practice never observed because
     *  PGPonyApp.onCreate fires before any Composable. */
    val current: MutableState<AppTheme> = mutableStateOf(AppTheme.System)

    /** Idempotent bootstrap from SharedPreferences. Safe to call from
     *  PGPonyApp.onCreate. Reads "selected_theme" and seeds [current].
     *  Calling again is harmless — it just re-reads and re-assigns
     *  (no-op if the value matches). */
    fun initFromPrefs(context: Context) {
        val prefs = context.getSharedPreferences("pgpony_prefs", Context.MODE_PRIVATE)
        current.value = AppTheme.fromStorage(prefs.getString("selected_theme", null))
    }
}

/**
 * Returns the ColorScheme that should be applied for [theme] at the
 * current moment. For [AppTheme.System] this reads
 * [isSystemInDarkTheme] reactively, so the in-app theme follows the
 * device-level toggle without an app relaunch.
 */
@Composable
fun resolveColorScheme(theme: AppTheme): ColorScheme {
    val isDark = when (theme) {
        AppTheme.System -> isSystemInDarkTheme()
        AppTheme.Light -> false
        AppTheme.Dark -> true
    }
    return if (isDark) PGPonyDarkColorScheme else PGPonyLightColorScheme
}

// ── Dark scheme ────────────────────────────────────────────────────────
//
// Lifted verbatim from the pre-A12 hardcoded PGPonyTheme in
// MainActivity.kt. Same purple primary, deep neutral backgrounds.
// Kept as an exported val so MainActivity can reference it directly
// (the @Composable resolveColorScheme is used by PGPonyTheme; the
// raw val is available for any future composable that needs to bypass
// the resolver).

val PGPonyDarkColorScheme: ColorScheme = darkColorScheme(
    primary = Color(0xFF8B5CF6),
    secondary = Color(0xFF6366F1),
    tertiary = Color(0xFFA78BFA),
    background = Color(0xFF0F0F0F),
    surface = Color(0xFF1A1A1A),
    surfaceVariant = Color(0xFF252525),
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = Color.White,
    onSurface = Color.White,
    onSurfaceVariant = Color(0xFFB0B0B0),
    error = Color(0xFFEF4444)
)

// ── Light scheme ───────────────────────────────────────────────────────
//
// New in A12. Designed to hold the PGPony purple identity while
// achieving WCAG AA contrast on a near-white background.
//
//   • primary is shifted darker (#7C3AED vs #8B5CF6) so purple text /
//     icons stay readable on white surfaces
//   • surface is pure white; surfaceVariant is a faint gray for
//     "elevated" rows (settings list, dialog backdrops)
//   • on* colors flip to near-black for legibility
//   • error is shifted darker (#DC2626 vs #EF4444) for the same
//     contrast reason
//
// Colors were eyeballed against iOS PGPony's light mode behavior
// (which inherits SwiftUI's automatic light scheme); future polish
// could be a side-by-side screenshot pass.

val PGPonyLightColorScheme: ColorScheme = lightColorScheme(
    primary = Color(0xFF7C3AED),
    secondary = Color(0xFF4F46E5),
    tertiary = Color(0xFF8B5CF6),
    background = Color(0xFFFAFAFA),
    surface = Color.White,
    surfaceVariant = Color(0xFFF1F1F4),
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = Color(0xFF1A1A1A),
    onSurface = Color(0xFF1A1A1A),
    onSurfaceVariant = Color(0xFF505050),
    error = Color(0xFFDC2626)
)
