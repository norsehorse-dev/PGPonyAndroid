## A14 Picker — In-App Language Selector (2026-05-27)

### User-visible
Two new ways to change PGPony Android's display language without going through Android system Settings:

1. **Settings → Appearance → Language row.** Below the theme chips. Tap to open a full-screen picker listing the six supported languages by their native names (English, Deutsch, Español, Français, 日本語, Português (Brasil)). Checkmark on the currently selected one. Tapping any other language recreates the Activity within ~200ms with the new locale applied — entire UI re-renders translated.

2. **First onboarding slide is a language picker.** New installs land on slide 0 with the title "Language" + an inline 6-row picker. The auto-detected device language is pre-selected. Tapping a different language immediately re-renders the carousel in the chosen language, so the rest of onboarding is already translated by the time the user swipes to slide 1.

Plus a third surface: Android 13+ users now see PGPony in **System Settings → System → Languages → App languages → PGPony** (driven by the new `locales_config.xml`). Picking a language there stays in sync with the in-app picker via AppCompat's shared persistence layer.

iOS PGPony has had both surfaces since v5.0 Phase 5.1; this brings Android to parity.

### Android impl
New files (~378 new Kotlin/XML lines):

- `i18n/LanguageManager.kt` (220 lines): `SupportedLanguage` enum with six entries (`en, de, es, fr, ja, pt-BR`) and hardcoded `nativeName` constants ("English", "Deutsch", "Español", "Français", "日本語", "Português (Brasil)") — deliberately NOT localized so the picker reads consistently in any locale. `SupportedLanguage.resolve(tag)` snaps device locale variants to the closest supported entry with rules mirroring iOS (`pt-PT` → `pt-BR`, `es-MX` → `es`, `de-CH` → `de`, etc.). `LanguageState` is an observable `MutableState<String>` sibling to `ThemeState`. `LanguageManager.setLanguage()` updates both `LanguageState.current` (for instant picker checkmark feedback) and calls `AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))` for persistence + Activity recreation.

- `ui/settings/LanguagePickerScreen.kt` (130 lines): Full-screen Scaffold + LazyColumn of 6 rows. Subscribes to `LanguageState.current` for live checkmark updates. Footer footnote mirrors iOS verbatim: "Most screens update immediately. Restart PGPony if some text remains in the previous language."

- `res/xml/locales_config.xml` (28 lines): Declares the six supported BCP-47 tags + `android:defaultLocale="en"`. Referenced from `<application android:localeConfig="@xml/locales_config">` so Android 13+ exposes PGPony in the per-app system Settings language picker.

Modified files (all additive growth):

- `app/build.gradle.kts`: added `androidx.appcompat:appcompat:1.7.0` dependency. We don't use AppCompat themes or activities-as-such — the library is pulled in solely for `AppCompatDelegate.setApplicationLocales()` plumbing. ~15 lines including the comment block explaining why.

- `AndroidManifest.xml`: added `android:localeConfig="@xml/locales_config"` attribute on `<application>` for API 33+ integration, plus `<service android:name="androidx.appcompat.app.AppLocalesMetadataHolderService" ...>` declaration with `<meta-data android:name="autoStoreLocales" android:value="true" />` for API 26-32 persistence. Service is `enabled=false, exported=false` because AppCompat only reads its manifest metadata — the service never executes.

- `MainActivity.kt`: one-word change `class MainActivity : FragmentActivity()` → `: androidx.appcompat.app.AppCompatActivity()`. AppCompatActivity extends FragmentActivity, so all biometric / FragmentManager / lifecycle behaviour is preserved verbatim. No theme/widget/import changes needed — Compose + Material 3 remain the entire UI layer.

- `ShareTargetActivity.kt`: one-word change `ComponentActivity` → `AppCompatActivity`. Same reasoning: needed for the auto-recreation-on-locale-change to fire on API <33.

- `PGPonyApp.kt`: 6 new lines in `onCreate()` calling `com.pgpony.android.i18n.LanguageState.initFromAppCompat(applicationContext)` immediately after the existing `ThemeState.initFromPrefs(applicationContext)`. Reads AppCompat's persisted locale list; if empty (fresh install), detects from device prefs but deliberately doesn't write back to AppCompat until the user makes an explicit choice in the picker.

- `ui/onboarding/OnboardingSlide.kt`: added `showLanguagePicker: Boolean = false` field to the data class. Added new `OnboardingSlide` entry at position 0 with title `R.string.onboarding_slide_language_title`, body `R.string.onboarding_slide_language_body`, icon `Icons.Filled.Language`, iconTint blue (#3B82F6), and `showLanguagePicker = true`. The five pre-existing slides shift to positions 1-5; no other changes needed because `OnboardingScreen` iterates `OnboardingSlides.all`.

- `ui/onboarding/OnboardingPage.kt`: rendered `OnboardingLanguagePicker()` inline when `slide.showLanguagePicker` is true, mirroring the pattern of `BiometricToggleRow` for `slide.showBiometricToggle`. Added private `OnboardingLanguagePicker` Composable (~50 lines) that renders 6 rows in a rounded Surface with HorizontalDivider between them. Calls `LanguageManager.setLanguage()` on tap and reads `LanguageState.current` for live checkmark.

- `ui/settings/SettingsScreen.kt`: added `showLanguagePicker: Boolean` state, a `SettingsAction(...)` row in the Appearance section below the theme chips, and a conditional overlay block `if (showLanguagePicker) LanguagePickerScreen(...)` rendered next to the existing `SecurityInfoScreen` overlay. Row subtitle dynamically reads `LanguageManager.current().nativeName` so it always shows the active language's native name.

Strings: 5 new entries × 5 langs = 25 translations. All 6 strings.xml files now at 718 entries.

- `settings_language_row_title`, `language_picker_title` → "Language" / "Sprache" / "Idioma" / "Langue" / "言語" / "Idioma"
- `language_picker_footer` → translated footnote about most screens updating immediately
- `onboarding_slide_language_title` → "Language" / native equivalents
- `onboarding_slide_language_body` → "Choose the language you'd like to use.\n\nYou can change this anytime in Settings." + native translations

### iOS port notes
Maps to three iOS sources:

| Android file | iOS counterpart |
|---|---|
| `i18n/LanguageManager.kt`'s `SupportedLanguage` enum | `App/AppState.swift`'s `SupportedLanguage` enum (lines 207-228) |
| `i18n/LanguageManager.kt`'s `LanguageManager.detectInitialLanguage()` | `App/AppState.swift`'s `AppState.detectInitialLanguage()` static method |
| `i18n/LanguageManager.kt`'s `LanguageManager.setLanguage()` | `App/AppState.swift`'s `@Published var selectedLanguageCode { didSet }` |
| `ui/settings/LanguagePickerScreen.kt` | `Views/Settings/LanguagePickerView.swift` (52 lines) |
| `ui/onboarding/OnboardingPage.kt`'s `OnboardingLanguagePicker` Composable | `Views/Onboarding/OnboardingPage.swift`'s `languagePicker` view (lines 175-200) |
| `OnboardingSlide.kt`'s slide 0 entry | `Views/Onboarding/OnboardingSlide.swift`'s `OnboardingSlides.all[0]` |

Notable design divergences from iOS:

- **iOS uses UserDefaults + "AppleLanguages" key directly. Android uses `AppCompatDelegate.setApplicationLocales()`.** AppCompat owns persistence in two ways: API 33+ via platform `LocaleManager`, API 26-32 via `AppLocalesMetadataHolderService`. We don't write to SharedPreferences ourselves to avoid drift if the user changes language from system Settings on Android 13+.

- **iOS triggers UI rebuild via `.id(selectedLanguageCode)` on the root view. Android triggers it via AppCompat's Activity recreation.** Both achieve the same effect: full UI rebuild in the new locale within ~200ms. Android's path requires activities to extend `AppCompatActivity` (otherwise the recreation only fires on API 33+); iOS doesn't have this restriction because SwiftUI doesn't have an Activity equivalent.

- **iOS `LocalizedStringKey` auto-resolves at every Text() call. Android `stringResource()` is explicit at every call site.** No behavioural difference — both look up the active locale's resource at render time — just a syntactic difference in how the lookup is invoked.

### Files touched + iOS counterparts

| Android file | iOS counterpart | Notes |
|---|---|---|
| `app/build.gradle.kts` | (n/a — iOS doesn't need an extra package) | added `androidx.appcompat:appcompat:1.7.0` |
| `app/src/main/AndroidManifest.xml` | `PGPony-Info.plist`'s `CFBundleLocalizations` array | added `localeConfig` + `AppLocalesMetadataHolderService` |
| `app/src/main/res/xml/locales_config.xml` | `PGPony-Info.plist`'s `CFBundleLocalizations` array | new file |
| `i18n/LanguageManager.kt` | `App/AppState.swift` (subset) | new file |
| `MainActivity.kt`, `ShareTargetActivity.kt` | `App/PGPonyApp.swift` (root view modifier) | one-word superclass change each |
| `PGPonyApp.kt` | `App/AppState.swift` init | added 6-line bootstrap |
| `ui/onboarding/OnboardingSlide.kt`, `OnboardingPage.kt` | `Views/Onboarding/OnboardingSlide.swift`, `OnboardingPage.swift` | added slide 0 + inline picker |
| `ui/settings/SettingsScreen.kt`, `LanguagePickerScreen.kt` | `Views/Settings/SettingsView.swift`, `LanguagePickerView.swift` | row + overlay |
| `res/values/strings.xml` + 5 lang variants | `Resources/Localizable.xcstrings` | +5 strings, +25 translations |

### Parity progress

After A14 Picker ships, both halves of the A14 scope from the parity plan are closed:
- ✅ A14a-e — translation catalog (5 langs × 666 strings, hand-translated + iOS-sourced where matching)
- ✅ A14 Picker — in-app language selector (Settings + Onboarding)
- ✅ A15 — Rich share-target activity (shipped earlier today)
- ⏳ A16 — Final polish + Play Store submission (last phase)

PGPony Android is one phase away from v1.0 production launch and full iOS parity.
