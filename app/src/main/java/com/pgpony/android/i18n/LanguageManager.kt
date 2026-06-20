// LanguageManager.kt
// PGPony Android — A14 Picker (in-app language selector)
//
// Android port of iOS's SupportedLanguage enum + AppState.selectedLanguageCode
// + AppState.detectInitialLanguage(). Same surface, same six locales, same
// nativeName strings — just the persistence mechanism is different:
//
//   iOS:     UserDefaults.standard.set([code], forKey: "AppleLanguages")
//   Android: AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(code))
//
// AppCompat owns the persistence end-to-end:
//   • API 33+ (Android 13+): per-app language preference saved by the system.
//     User can also override from system Settings → System → Languages →
//     App languages → PGPony.
//   • API 26–32: AppCompat persists in its own metadata holder service
//     (AppLocalesMetadataHolderService — declared in AndroidManifest.xml).
//     Activities that extend AppCompatActivity automatically recreate when
//     the locale changes; activities that extend plain ComponentActivity or
//     FragmentActivity do not — which is why MainActivity + ShareTargetActivity
//     both extend AppCompatActivity as of this phase.
//
// Why we don't write to SharedPreferences ourselves:
//   AppCompat already persists. Adding a second cache would just create drift
//   between the two storage layers when the user changes language from the
//   system Settings page (which only updates AppCompat's store, not ours).
//   We treat AppCompatDelegate.getApplicationLocales() as the single source
//   of truth.
//
// LanguageState mirrors ThemeState: a process-wide observable MutableState<String>
// that Composables read via `by LanguageState.current` for reactive recomposition.
// LanguageManager.setLanguage updates both AppCompat (for persistence + Activity
// recreation) and LanguageState (for any Composable that wants to react without
// a full recreation, e.g. the picker row's checkmark).

package com.pgpony.android.i18n

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.core.os.LocaleListCompat
import java.util.Locale

// ── Supported languages ────────────────────────────────────────────────
//
// Six entries, same set as iOS PGPony.xcstrings supports. The `tag` field
// is the IETF BCP-47 language tag — what AppCompat and Android's resource
// loader use to look up values-XX/strings.xml at runtime.
//
// Note Brazilian Portuguese: BCP-47 tag is "pt-BR", but Android resource
// folder uses "values-pt-rBR" (legacy region prefix). LocaleListCompat
// understands "pt-BR" just fine — it normalizes to the underlying Locale
// internally — so we use BCP-47 throughout the Kotlin layer and trust the
// resource loader to bridge to its folder convention.

enum class SupportedLanguage(val tag: String, val nativeName: String) {
    EN("en", "English"),
    DE("de", "Deutsch"),
    ES("es", "Español"),
    FR("fr", "Français"),
    JA("ja", "日本語"),
    PT_BR("pt-BR", "Português (Brasil)");

    companion object {
        /**
         * Resolve a language tag (or BCP-47 locale) to one of our six
         * supported languages, snapping region variants to the closest
         * canonical entry. Returns null if nothing matches at all.
         *
         * Snapping rules (mirrors iOS detectInitialLanguage):
         *   • "de-CH" → DE, "de-AT" → DE
         *   • "es-MX" → ES, "es-AR" → ES, "es-419" → ES
         *   • "pt-PT" → PT_BR (Brazil is our only Portuguese)
         *   • "en-GB" → EN, "en-AU" → EN
         *   • "fr-CA" → FR
         *   • "ja-JP" → JA
         *
         * Exact "pt-BR" match wins over the "pt" prefix snap so we don't
         * lose the region tag when the device explicitly asks for Brazilian
         * Portuguese.
         */
        fun resolve(tag: String?): SupportedLanguage? {
            if (tag.isNullOrBlank()) return null
            val normalized = tag.replace('_', '-')
            // Exact match first (handles "pt-BR" cleanly)
            entries.firstOrNull { it.tag.equals(normalized, ignoreCase = true) }?.let { return it }
            // Prefix match — strip everything after the first dash
            val primary = normalized.substringBefore('-').lowercase()
            return when (primary) {
                "en" -> EN
                "de" -> DE
                "es" -> ES
                "fr" -> FR
                "ja" -> JA
                "pt" -> PT_BR
                else -> null
            }
        }
    }
}

// ── Process-wide observable state ──────────────────────────────────────

object LanguageState {
    /**
     * Currently-applied language tag (BCP-47). Read by Composables that
     * need to react to selection changes without waiting for Activity
     * recreation — for instance the picker rows themselves, which update
     * the checkmark immediately on tap.
     *
     * Defaults to "en" before [initFromAppCompat] runs. In practice that
     * branch is never observed because PGPonyApp.onCreate calls the
     * initializer before any Composable mounts.
     */
    val current: MutableState<String> = mutableStateOf("en")

    /**
     * Idempotent bootstrap from AppCompat's persisted locale list. Safe
     * to call from PGPonyApp.onCreate.
     *
     * If AppCompat has never been told a preference (fresh install, no
     * onboarding-stage selection yet), the persisted list is empty —
     * we fall back to detectInitialLanguage(), which inspects the
     * device's preferred languages and picks the closest supported entry.
     * That detection result is then applied via setLanguage so AppCompat
     * has a value to persist going forward.
     */
    fun initFromAppCompat(context: Context) {
        val persisted = AppCompatDelegate.getApplicationLocales()
        val tag = (0 until persisted.size())
            .asSequence()
            .mapNotNull { persisted.get(it)?.toLanguageTag() }
            .firstOrNull()
        if (tag != null) {
            val resolved = SupportedLanguage.resolve(tag) ?: SupportedLanguage.EN
            current.value = resolved.tag
        } else {
            // First launch — no persisted choice. Detect from device prefs
            // and seed AppCompat so the picker UI shows a sane checkmark.
            val detected = LanguageManager.detectInitialLanguage(context)
            current.value = detected.tag
            // We deliberately do NOT call AppCompatDelegate.setApplicationLocales
            // here from onCreate — that triggers Activity recreation before the
            // first Activity even reaches setContent on some API levels. The
            // detected language matches the system language anyway (Android
            // already loaded values-XX/strings.xml from the system locale), so
            // not persisting until the user makes an explicit choice in the
            // picker keeps everything aligned.
        }
    }
}

// ── Manager ────────────────────────────────────────────────────────────

object LanguageManager {

    /**
     * Pick a starting language from the device's preferred locales. Same
     * snap-to-closest-supported behaviour as iOS PGPony's
     * AppState.detectInitialLanguage(). Returns SupportedLanguage.EN as
     * the universal fallback.
     */
    fun detectInitialLanguage(context: Context): SupportedLanguage {
        val configLocales = context.resources.configuration.locales
        for (i in 0 until configLocales.size()) {
            val locale: Locale = configLocales.get(i)
            SupportedLanguage.resolve(locale.toLanguageTag())?.let { return it }
        }
        return SupportedLanguage.EN
    }

    /**
     * Apply [lang] as the per-app language. AppCompat handles persistence,
     * Activity recreation (for AppCompatActivity instances), and resource
     * cache invalidation. LanguageState.current is also updated so any
     * Composable that's currently subscribed re-renders before the
     * Activity recreate cycle completes — the picker row's checkmark
     * relies on this for instant feedback.
     */
    fun setLanguage(lang: SupportedLanguage) {
        LanguageState.current.value = lang.tag
        AppCompatDelegate.setApplicationLocales(
            LocaleListCompat.forLanguageTags(lang.tag)
        )
    }

    /**
     * Currently-applied language. Reads LanguageState (faster than going
     * through AppCompat every time, which crosses an IPC boundary on
     * API 33+ to fetch from the system LocaleManager).
     */
    fun current(): SupportedLanguage {
        return SupportedLanguage.resolve(LanguageState.current.value) ?: SupportedLanguage.EN
    }
}
