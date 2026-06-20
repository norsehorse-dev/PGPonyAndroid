# A13 String Extraction — Progress Tracker

## Status as of Turn 8

**strings.xml:** 617 entries

## Turn 8 (this turn) — Service-layer + notifications

### PromoCodeService.kt (154 → 179 lines)
- `PromoCodeError` sealed class refactored: messages now resolved via `PGPonyApp.instance.getString(R.string.promo_error_*)` at construction time. SecretUnlockScreen reads `e.message` directly so these flow through to the user automatically.
- Success messages externalized: `promo_status_unlocked_default` (server), `promo_status_unlocked_offline` (offline fallback)
- Unknown-error fallback: `promo_error_unknown`

### KeyExpirationReceiver.kt (111 → 118 lines)
- Notification title + body now use `context.getString(R.string.key_expiration_notif_title_format, …)` / `_body_format`
- `labelForDays(daysBefore)` refactored to `labelForDays(context, daysBefore)` resolving against 5 string resources (`in 30 days` / `in 7 days` / `tomorrow` / `today` / `in %1$d days`)
- Fallback display-name resolved via `key_expiration_notif_display_name_fallback`

### KeyExpirationService.kt (230 → 237 lines)
- `NOTIFICATION_CHANNEL_NAME` and `NOTIFICATION_CHANNEL_DESCRIPTION` const vals removed (can't reference `R.string.*` at compile time)
- `createNotificationChannel(context)` now resolves channel name + description via `context.getString(R.string.key_expiration_channel_*)` — labels in Android Settings → Apps → PGPony → Notifications will now localize
- `displayName` fallback "Key XXXXXXXX" externalized via `key_expiration_fallback_display_name_format`

### Skipped (intentionally, for A13 scope)
- **PGPCryptoService.kt, RevocationService.kt, SigningService.kt, KeyServerRepository.kt** — exception class default messages (e.g. `PGPCryptoError.EncryptionFailed`, `KeyServerError.NotFound`). VMs catch these and either (a) translate at the catch site (already done in turns 2/3/5/7 — `EncryptDecryptViewModel`, `KeyDetailViewModel`, `ContactsViewModel`, `ExchangeViewModel`), or (b) concatenate `e.message` into a localized format string. Localizing the exception class messages themselves would require refactoring every catch site to drop `e.message` — out of scope for A13. The localized fallbacks at the catch boundary are what users actually see.

## New architectural pattern this turn

**Exception class messages → string resources via `PGPonyApp.instance`** — exception subclasses can resolve their message argument from `R.string.*` at construction time using the singleton Application context. Pattern: `class InvalidCode : PromoCodeError(PGPonyApp.instance.getString(R.string.promo_error_invalid_code))`. Works because (a) `PromoCodeError` constructor takes `message: String`, (b) `PGPonyApp.instance` is initialized before any non-system service can instantiate the exception. Used selectively where the exception messages are read directly via `e.message` in UI (PromoCodeService → SecretUnlockScreen).

## Cumulative work (Turns 1–8)

- UI screens: Settings (incl. SecurityInfoScreen), Encrypt/Decrypt, Keyring (incl. KeyDetail family + TrustLevelSheet + RevokeKeySheet), Help (FaqContent + HelpScreen), Onboarding (slide carousel + GenerateSheet), Contacts (Screen + VM), Exchange (Screen + VM), Pro (ProGateSheet + SecretUnlockScreen), Decrypt sheets (SignerLookupSheet + VerificationBanner), App chrome (MainActivity + LockScreen), KeyCard
- ViewModels: 8 total (settings, encdec, keyring, keydetail, contacts, exchange, plus 2 reused)
- Services: PromoCodeService, KeyExpirationReceiver, KeyExpirationService
- Refactor patterns deployed:
  - `@StringRes Int` data-class refactor (FaqItem, FaqSection, OnboardingSlide, Screen)
  - `@Composable internal fun Enum.localizedName()` extensions (TrustLevel, RevocationReason, ProFeature, ImportMethod, ExpirationOption, AppTheme)
  - Action-routing decoupling (KeyDetailActionIds internal object)
  - `@Composable` promotion of non-Composable formatters (VerificationBanner subtitle formatters)
  - Exception messages → string resources via `PGPonyApp.instance.getString` (PromoCodeError)

## Final turn (Turn 9)

- Tail sweep of ~30-40 small files not yet touched (estimated ~150 strings remaining)
- README.md for the bundle
- Zip as `/mnt/user-data/outputs/PGPonyAndroid_PhaseA13.zip`
- Deploy command: `cp -R ~/Downloads/PGPonyAndroid_PhaseA13/. ~/Apps/PGPonyAndroid/`
- Update NorseHorse_Android_Update_Log.md per convention
