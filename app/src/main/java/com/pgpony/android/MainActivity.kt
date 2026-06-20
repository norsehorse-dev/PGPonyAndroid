// MainActivity.kt
// PGPony Android
//
// Phase 3 (v1.3.0): Added first-run onboarding gate. Before the main
// bottom-nav scaffold renders, check the SharedPreferences flag
// `onboarding_completed`. If false, show OnboardingScreen full-screen
// until the user completes or skips it.
//
// Phase 3.1: Pass keyringVm into OnboardingScreen so slide 2 can offer
// inline key generation. The onComplete callback is now a simple unit
// callback — the "Generate Now" branch is handled inside onboarding.
//
// Phase A7: Bumped from androidx.activity.ComponentActivity to
// androidx.fragment.app.FragmentActivity. Required by
// androidx.biometric.BiometricPrompt, which internally shows itself
// as a DialogFragment and so needs FragmentActivity (or Fragment) as
// host. No behavioral change for non-biometric flows — FragmentActivity
// extends ComponentActivity, so setContent, enableEdgeToEdge, intent
// handling, and onCreate semantics are all inherited intact.
//
// Phase A9 Fix1 — runtime permission helper added to work around an
// incompatibility between FragmentActivity and Compose's
// ActivityResultRegistry. FragmentActivity overrides
// validateRequestPermissionsRequestCode() (final method, no super
// route) and enforces (requestCode & 0xFFFF0000) == 0, while
// ActivityResultRegistry generates 32-bit random request codes well
// above the 65536 ceiling. Result: tapping a Compose-launched
// permission request crashes with
// `IllegalArgumentException: Can only use lower 16 bits for requestCode`.
//
// Fix: requestRuntimePermission(permission, callback) launches the
// system permission UI via ActivityCompat.requestPermissions with a
// known small request code (REQ_RUNTIME_PERMISSION = 1001),
// bypassing the Compose launcher's random code generation. The
// result is dispatched through onRequestPermissionsResult to the
// stored callback. Non-permission Activity-result launches (camera,
// file picker, biometric) still use the Compose path since they
// don't hit validateRequestPermissionsRequestCode at all.
//
// Phase A10a Fix1 — second instance of the FragmentActivity 16-bit
// crash, this time from ACTION_OPEN_DOCUMENT via the file-import
// path. The earlier A9 Fix1 comment turned out to be wrong: it isn't
// only requestPermissions that gets the 16-bit check. FragmentActivity
// also overrides startActivityForResult and runs the same
// checkForValidRequestCode() against any code Compose passes in
// (Compose still uses 32-bit random codes there). So any Compose
// rememberLauncherForActivityResult contract that ends up calling
// startActivityForResult — OpenDocument, CreateDocument, GetContent,
// CaptureVideo, StartActivityForResult — will crash with the same
// "Can only use lower 16 bits for requestCode" exception on first tap.
//
// Fix: startDocumentPicker(mimeTypes, callback) launches the system
// file picker via ActivityCompat.startActivityForResult with a known
// small request code (REQ_DOCUMENT_PICKER = 1002), then dispatches
// the chosen URI back through onActivityResult. Mirrors the
// requestRuntimePermission pattern exactly. The biometric prompt is
// unaffected because BiometricPrompt doesn't go through
// startActivityForResult — it shows itself as a DialogFragment.
//
// Phase A10b — added startDocumentCreator(mimeType, suggestedName,
// callback) sibling helper for ACTION_CREATE_DOCUMENT (file-mode
// encrypt's Save flow needs to write out a .pgp file picked by the
// user). Same workaround, REQ_DOCUMENT_CREATOR = 1003. The two
// helpers share onActivityResult since each owns a distinct request
// code; the dispatched callback's type changes (Uri? in both cases)
// but is stored in separate state slots.

package com.pgpony.android

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.pgpony.android.billing.BillingService
import com.pgpony.android.crypto.card.CardInfo
import com.pgpony.android.intent.IntentAction
import com.pgpony.android.intent.IntentHandler
import com.pgpony.android.nfc.OpenPgpCardReader
import com.pgpony.android.ui.PGPonyViewModelFactory
import com.pgpony.android.ui.card.CardScanScreen
import com.pgpony.android.ui.card.CardPinChangeScreen
import com.pgpony.android.ui.card.CardSignScreen
import com.pgpony.android.ui.card.CardManagementScreen
import com.pgpony.android.ui.card.CardKeygenScreen
import com.pgpony.android.ui.pass.PassStoreListScreen
import com.pgpony.android.ui.pass.PassBrowserScreen
import com.pgpony.android.ui.pass.PassEntryScreen
import com.pgpony.android.ui.card.CardDecryptScreen
import com.pgpony.android.ui.components.LockScreen
import com.pgpony.android.ui.keyring.KeyDetailScreen
import com.pgpony.android.ui.keyring.KeyDetailViewModel
import com.pgpony.android.ui.keyring.KeyringScreen
import com.pgpony.android.ui.keyring.KeyringViewModel
import com.pgpony.android.ui.encrypt.EncryptScreen
import com.pgpony.android.ui.encrypt.DecryptScreen
import com.pgpony.android.ui.encrypt.EncryptDecryptViewModel
import com.pgpony.android.ui.exchange.ExchangeScreen
import com.pgpony.android.ui.exchange.ExchangeViewModel
import com.pgpony.android.ui.contacts.ContactsScreen
import com.pgpony.android.ui.contacts.ContactsViewModel
import com.pgpony.android.ui.onboarding.OnboardingScreen
import com.pgpony.android.ui.settings.SettingsScreen
import com.pgpony.android.ui.settings.SettingsViewModel
import com.pgpony.android.ui.theme.AppTheme
import com.pgpony.android.ui.theme.ThemeState
import com.pgpony.android.ui.theme.resolveColorScheme

// ── CompositionLocal for BillingService ────────────────────────────────

val LocalBillingService = staticCompositionLocalOf<BillingService> {
    error("BillingService not provided")
}

// ── Navigation ─────────────────────────────────────────────────────────

/**
 * Phase A13 — Screen titles now carry [titleResId] (a @StringRes Int)
 * instead of a hardcoded English String. The bottom-nav consumer
 * resolves each title via stringResource(screen.titleResId) at render
 * time, so navigation labels localize cleanly. The route string stays
 * English — it's a stable internal navigation key, not user-facing.
 */
sealed class Screen(
    val route: String,
    @androidx.annotation.StringRes val titleResId: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
) {
    data object Keyring : Screen("keyring", R.string.main_tab_keyring, Icons.Filled.VpnKey, Icons.Outlined.VpnKey)
    data object Encrypt : Screen("encrypt", R.string.main_tab_encrypt, Icons.Filled.Lock, Icons.Outlined.Lock)
    data object Decrypt : Screen("decrypt", R.string.main_tab_decrypt, Icons.Filled.LockOpen, Icons.Outlined.LockOpen)
    data object Exchange : Screen("exchange", R.string.main_tab_exchange, Icons.Filled.Share, Icons.Outlined.Share)
    data object Contacts : Screen("contacts", R.string.main_tab_contacts, Icons.Filled.Contacts, Icons.Outlined.Contacts)
    data object Settings : Screen("settings", R.string.main_tab_settings, Icons.Filled.Settings, Icons.Outlined.Settings)
}

val bottomNavScreens = listOf(
    Screen.Keyring, Screen.Encrypt, Screen.Decrypt, Screen.Exchange, Screen.Contacts, Screen.Settings
)

// ── Activity ───────────────────────────────────────────────────────────

class MainActivity : androidx.appcompat.app.AppCompatActivity() {

    private var pendingAction = mutableStateOf<IntentAction>(IntentAction.None)
    private lateinit var billingService: BillingService

    // ── Phase A9 Fix1: Runtime permission helper ──────────────────────
    //
    // Stores the callback for the in-flight permission request so
    // onRequestPermissionsResult can dispatch the grant decision back
    // to the call site. Only one runtime permission can be in flight
    // at a time — Android queues parallel requests anyway, so a single
    // slot suffices.
    //
    // If the activity is destroyed and recreated while the system
    // permission dialog is showing (e.g. config change during dialog),
    // the callback is lost. The user can re-tap the trigger button to
    // re-issue the request — Android's "Allow" dialog is not
    // re-shown for already-granted permissions, so this degrades
    // gracefully.
    private var pendingPermissionCallback: ((Boolean) -> Unit)? = null

    // ── Phase A10a Fix1: Document picker helper ───────────────────────
    //
    // Same shape as pendingPermissionCallback: one slot for the
    // in-flight file picker, dispatched through onActivityResult. If
    // a config change tears down the activity while the picker is
    // showing the callback is lost — the user just re-taps Browse to
    // re-issue the request. Acceptable for a one-shot file-pick flow.
    private var pendingDocumentPickerCallback: ((android.net.Uri?) -> Unit)? = null

    // ── Phase A10b: Document creator helper ───────────────────────────
    //
    // Sibling slot for ACTION_CREATE_DOCUMENT — the Save flow in
    // file-mode encrypt and (eventually) file-mode decrypt asks the
    // user to pick a destination URI for the output. Separate from
    // pendingDocumentPickerCallback so a save-after-open chain can
    // queue both without clobbering each other (rare but possible if
    // a result sheet were ever to show both buttons enabled).
    private var pendingDocumentCreatorCallback: ((android.net.Uri?) -> Unit)? = null

    // ── HW Phase 1: NFC OpenPGP-card reader ───────────────────────────
    //
    // Holds the reader-mode controller while a CardScanScreen is on
    // screen. enableReaderMode / disableReaderMode are Activity-scoped
    // (the NFC dispatch is bound to the foreground Activity), so the
    // controller lives here and the Compose screen drives it through
    // startCardScan / stopCardScan in a DisposableEffect. Only one scan
    // can be active at a time — a single slot suffices.
    private var cardReader: OpenPgpCardReader? = null

    // HW Phase 3 — when true, the biometric auto-lock observer does NOT
    // re-lock on ON_STOP. Set around in-app excursions that legitimately
    // background the activity but shouldn't trigger a re-lock: NFC card
    // operations, the system document picker, and the document creator.
    // Without this, a file card flow (pick → tap → save) would re-lock
    // several times and each unlock would reset navigation to the start
    // tab. Always cleared when the excursion returns.
    var suppressAutoLock: Boolean = false

    /** True if the device has NFC hardware at all. */
    fun isNfcAvailable(): Boolean = OpenPgpCardReader.isNfcAvailable(this)

    /** True if NFC hardware is present AND currently switched on. */
    fun isNfcEnabled(): Boolean = OpenPgpCardReader.isNfcEnabled(this)

    /**
     * Begin NFC reader-mode polling for an OpenPGP card. [onResult] is
     * invoked on the main thread once per tap with either the parsed
     * card info or a failure. Polling continues (so the user can retry
     * a fumbled tap) until [stopCardScan] is called. Returns false if
     * NFC is unavailable/disabled, in which case [onResult] never fires.
     */
    fun startCardScan(onResult: (Result<CardInfo>) -> Unit): Boolean {
        val reader = OpenPgpCardReader(this)
        cardReader = reader
        val started = reader.start(onResult)
        if (!started) cardReader = null
        if (started) suppressAutoLock = true
        return started
    }

    /** Stop NFC reader-mode polling and release the reader. */
    fun stopCardScan() {
        cardReader?.stop()
        cardReader = null
        suppressAutoLock = false
    }

    /**
     * Re-arm the active reader for one more tap (reader mode stays on).
     * Lets a screen read again in place without re-entering.
     */
    fun rearmCardScan() {
        cardReader?.rearm()
    }

    /**
     * HW Phase 2 — run an arbitrary card [operation] on the next tap and
     * deliver its result on the main thread. The operation runs on the
     * NFC binder thread with a fresh session (it SELECTs as needed).
     * Used by the Change-User-PIN flow now and signing later. Returns
     * false if NFC is unavailable/disabled.
     */
    fun <T> startCardOperation(
        operation: (com.pgpony.android.crypto.card.OpenPgpCardSession) -> T,
        onResult: (Result<T>) -> Unit
    ): Boolean {
        val reader = OpenPgpCardReader(this)
        cardReader = reader
        val started = reader.startOperation(operation, onResult)
        if (!started) cardReader = null
        if (started) suppressAutoLock = true
        return started
    }

    companion object {
        /**
         * Small request code so FragmentActivity's
         * validateRequestPermissionsRequestCode (which masks against
         * 0xFFFF0000) accepts it. Any value in [1, 65535] works.
         */
        private const val REQ_RUNTIME_PERMISSION = 1001

        /** A10a Fix1: small request code for ACTION_OPEN_DOCUMENT. */
        private const val REQ_DOCUMENT_PICKER = 1002

        /** A10b: small request code for ACTION_CREATE_DOCUMENT. */
        private const val REQ_DOCUMENT_CREATOR = 1003
    }

    /**
     * Request a single runtime permission and call back with the
     * grant decision. Public entry point for any Composable that
     * needs to ask for a permission. Replaces direct use of
     * `rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission())`
     * which crashes because Compose's ActivityResultRegistry generates
     * request codes above the 16-bit limit FragmentActivity enforces.
     *
     * Fast path: if the permission is already granted,
     * [callback] fires synchronously with `true` and no system UI is
     * shown.
     *
     * Slow path: ActivityCompat.requestPermissions is called with
     * [REQ_RUNTIME_PERMISSION]; the system shows the standard
     * "Allow/Don't allow" dialog; onRequestPermissionsResult routes
     * the result back to [callback].
     */
    fun requestRuntimePermission(permission: String, callback: (Boolean) -> Unit) {
        if (ContextCompat.checkSelfPermission(this, permission)
            == PackageManager.PERMISSION_GRANTED) {
            callback(true)
            return
        }
        pendingPermissionCallback = callback
        ActivityCompat.requestPermissions(
            this,
            arrayOf(permission),
            REQ_RUNTIME_PERMISSION
        )
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_RUNTIME_PERMISSION) {
            // Empty grantResults can happen if the user dismissed the
            // dialog without choosing (back gesture / volume key on
            // some devices). Treat as denial.
            val granted = grantResults.isNotEmpty()
                    && grantResults[0] == PackageManager.PERMISSION_GRANTED
            val cb = pendingPermissionCallback
            pendingPermissionCallback = null
            cb?.invoke(granted)
        }
    }

    /**
     * Phase A10a Fix1: open the system file picker
     * (ACTION_OPEN_DOCUMENT) restricted to the given MIME types and
     * call back with the chosen content:// URI, or null if the user
     * cancelled.
     *
     * Replaces direct use of
     * `rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument())`,
     * which crashes on FragmentActivity hosts because Compose's
     * ActivityResultRegistry generates 32-bit random request codes
     * that fail FragmentActivity.checkForValidRequestCode's 16-bit
     * mask.
     *
     * The Intent is built the same way OpenDocument's contract
     * builds it: CATEGORY_OPENABLE, the supplied MIME types under
     * EXTRA_MIME_TYPES, and a top-level type of `* / *` when more
     * than one is specified. FLAG_GRANT_READ_URI_PERMISSION is
     * implicit — the system file picker grants it automatically on
     * the URI it returns.
     */
    fun startDocumentPicker(mimeTypes: Array<String>, callback: (android.net.Uri?) -> Unit) {
        pendingDocumentPickerCallback = callback
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = if (mimeTypes.size == 1) mimeTypes[0] else "*/*"
            if (mimeTypes.size > 1) {
                putExtra(Intent.EXTRA_MIME_TYPES, mimeTypes)
            }
        }
        try {
            suppressAutoLock = true
            ActivityCompat.startActivityForResult(
                this,
                intent,
                REQ_DOCUMENT_PICKER,
                null
            )
        } catch (e: android.content.ActivityNotFoundException) {
            // No documents UI available — extremely rare on real
            // devices (every shipping Android has DocumentsUI) but
            // possible on cut-down emulators or kiosk builds. Clear
            // the pending callback and surface null so the caller can
            // show its own error.
            suppressAutoLock = false
            pendingDocumentPickerCallback = null
            callback(null)
        }
    }

    @Deprecated("Required for A10a Fix1 file picker; use startDocumentPicker callback for results.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQ_DOCUMENT_PICKER -> {
                suppressAutoLock = false
                val uri = if (resultCode == RESULT_OK) data?.data else null
                val cb = pendingDocumentPickerCallback
                pendingDocumentPickerCallback = null
                cb?.invoke(uri)
            }
            REQ_DOCUMENT_CREATOR -> {
                suppressAutoLock = false
                val uri = if (resultCode == RESULT_OK) data?.data else null
                val cb = pendingDocumentCreatorCallback
                pendingDocumentCreatorCallback = null
                cb?.invoke(uri)
            }
        }
    }

    /**
     * Phase A10b: open the system file creator
     * (ACTION_CREATE_DOCUMENT) to let the user choose a destination
     * for a write — the file-mode encrypt Save flow needs this so it
     * can persist the encrypted .pgp output anywhere the user picks
     * (Downloads, a cloud drive folder, an attached USB device,
     * etc.).
     *
     * Same FragmentActivity workaround as startDocumentPicker. The
     * Intent is built the way CreateDocument's contract builds it:
     * CATEGORY_OPENABLE, the supplied MIME type as type, and the
     * suggested filename pre-populated via EXTRA_TITLE. Returns the
     * content:// URI the system handed us — writes via
     * contentResolver.openOutputStream(uri) happen at the call site.
     */
    fun startDocumentCreator(
        mimeType: String,
        suggestedName: String,
        callback: (android.net.Uri?) -> Unit
    ) {
        pendingDocumentCreatorCallback = callback
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = mimeType
            putExtra(Intent.EXTRA_TITLE, suggestedName)
        }
        try {
            suppressAutoLock = true
            ActivityCompat.startActivityForResult(
                this,
                intent,
                REQ_DOCUMENT_CREATOR,
                null
            )
        } catch (e: android.content.ActivityNotFoundException) {
            suppressAutoLock = false
            pendingDocumentCreatorCallback = null
            callback(null)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val prefs = getSharedPreferences("pgpony_prefs", MODE_PRIVATE)
        billingService = BillingService(this, prefs)
        billingService.connect()

        pendingAction.value = IntentHandler.process(intent, contentResolver)

        setContent {
            PGPonyTheme {
                CompositionLocalProvider(LocalBillingService provides billingService) {
                    PGPonyMainScreen(
                        pendingAction,
                        isAutoLockSuppressed = { suppressAutoLock }
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        pendingAction.value = IntentHandler.process(intent, contentResolver)
    }

    override fun onDestroy() {
        billingService.disconnect()
        super.onDestroy()
    }
}

// ── Theme ──────────────────────────────────────────────────────────────
//
// Phase A12 — theme picker support. Reads the persisted "selected_theme"
// SharedPreferences entry on each composition and resolves to either the
// light or dark color scheme defined in ui/theme/AppTheme.kt. The legacy
// hardcoded darkColorScheme stays here as PGPonyLegacyDarkTheme
// (@Suppress unused) per the additive-edit rule, in case we ever need
// to compare against the pre-A12 baseline.
//
// Phase A12 Fix1 — reactive theme switching. The original A12
// implementation read SharedPreferences directly inside the @Composable
// body, which doesn't establish a Compose snapshot subscription, so the
// picker only took effect on next activity launch. The new path reads
// from ThemeState.current (an observable MutableState<AppTheme>),
// seeded once from prefs in PGPonyApp.onCreate and updated by
// SettingsViewModel.setTheme. That gives Compose the signal it needs
// to recompose PGPonyTheme — and therefore the entire UI — instantly
// when the user picks a new theme. The A12 prefs-reading body stays
// here as PGPonyThemeA12 (@Suppress unused) for reference.

@Composable
fun PGPonyTheme(content: @Composable () -> Unit) {
    val theme by ThemeState.current
    val colorScheme = resolveColorScheme(theme)
    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}

@Suppress("unused")
@Composable
fun PGPonyThemeA12(content: @Composable () -> Unit) {
    // Original A12 implementation — read prefs directly. Kept for
    // reference but unused; PGPonyTheme above is the live entry
    // point. The bug here is that the SharedPreferences read isn't
    // an observable source in the Compose snapshot model, so a
    // pref change after first composition doesn't trigger
    // recomposition.
    val context = androidx.compose.ui.platform.LocalContext.current
    val themeKey = context.getSharedPreferences(
        "pgpony_prefs",
        android.content.Context.MODE_PRIVATE
    ).getString("selected_theme", AppTheme.System.storageKey)
    val theme = AppTheme.fromStorage(themeKey)
    val colorScheme = resolveColorScheme(theme)

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}

@Suppress("unused")
@Composable
fun PGPonyLegacyDarkTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
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
        ),
        content = content
    )
}

// ── Main Screen ────────────────────────────────────────────────────────

@Composable
fun PGPonyMainScreen(
    pendingAction: MutableState<IntentAction>,
    isAutoLockSuppressed: () -> Boolean = { false }
) {
    val app = PGPonyApp.instance
    val prefs = remember { app.getSharedPreferences("pgpony_prefs", android.content.Context.MODE_PRIVATE) }
    val factory = remember { PGPonyViewModelFactory(app.keyRepository, prefs, app.contactsService) }

    val keyringVm: KeyringViewModel = viewModel(factory = factory)
    val encDecVm: EncryptDecryptViewModel = viewModel(factory = factory)
    val exchangeVm: ExchangeViewModel = viewModel(factory = factory)
    val contactsVm: ContactsViewModel = viewModel(factory = factory)
    val settingsVm: SettingsViewModel = viewModel(factory = factory)

    // ── First-run onboarding gate (Phase 3, inline-gen in Phase 3.1) ────
    //
    // A14 Picker fix — rememberSaveable instead of remember so this
    // state survives Activity recreation. AppCompatDelegate.setApplicationLocales()
    // (called from the language picker, Settings or Onboarding) triggers
    // Activity.recreate() so the new locale takes effect across the UI.
    // With plain `remember`, the recreated Composable would re-read
    // `prefs.getBoolean("onboarding_completed", false)` — which returns
    // `true` for anyone who completed onboarding before tapping "Replay
    // first-run intro" (replay only mutates the in-memory flag, not the
    // persisted one). The recreate would then drop them straight into
    // the main app instead of back into the replayed onboarding.
    // rememberSaveable persists through onSaveInstanceState so the
    // in-memory value survives the recreate.
    var onboardingDone by rememberSaveable {
        mutableStateOf(prefs.getBoolean("onboarding_completed", false))
    }

    if (!onboardingDone) {
        OnboardingScreen(
            prefs = prefs,
            keyringVm = keyringVm,
            onComplete = {
                prefs.edit().putBoolean("onboarding_completed", true).apply()
                onboardingDone = true
            }
        )
        return
    }

    // ── Phase A11: Biometric lock gate ───────────────────────────────────
    //
    // When the user has enabled "Biometric Lock" in Settings the
    // SharedPreferences key `biometric_lock` is true. On a fresh
    // launch we start locked; LockScreen handles the auth prompt and
    // calls `onUnlock` on success. The DisposableEffect below
    // re-engages the lock whenever the activity goes ON_STOP (user
    // backgrounds the app, switches to another app, or any other
    // activity comes in front).
    //
    // Slight iOS divergence: this fires ON_STOP on the activity,
    // which also triggers for the system file picker and CREATE_DOCUMENT
    // flows. That means picking a file to encrypt or saving a
    // decrypted file will re-lock when control returns to MainActivity.
    // Deliberate trade-off in favor of security and against pulling in
    // `androidx.lifecycle:lifecycle-process` for ProcessLifecycleOwner;
    // can revisit if the file-picker re-prompt becomes annoying in
    // practice. iOS doesn't see this because UIDocumentPicker on iOS
    // is a sheet within the same app context — no willResignActive
    // firing.
    //
    // The toggle's enabledness in Settings is gated on
    // BiometricGate.canAuthenticate (A11 SettingsViewModel change),
    // so when the flag is true we can trust biometric is available
    // at launch. If the user later disables biometric in System
    // Settings without untoggling here, the LockScreen surfaces a
    // clear error message and keeps the unlock button available
    // for a retry — they can re-enroll and unlock without uninstall.
    val biometricLockEnabled = remember {
        prefs.getBoolean("biometric_lock", false)
    }
    var isLocked by remember { mutableStateOf(biometricLockEnabled) }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, biometricLockEnabled) {
        // Re-lock observer is only attached when the user opted in.
        // No-op disposer when biometricLockEnabled is false so we
        // don't pay the observer cost for users who aren't using
        // the feature.
        if (biometricLockEnabled) {
            val observer = LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_STOP && !isAutoLockSuppressed()) {
                    isLocked = true
                }
            }
            lifecycleOwner.lifecycle.addObserver(observer)
            onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
        } else {
            onDispose { }
        }
    }

    if (isLocked) {
        LockScreen(onUnlock = { isLocked = false })
        return
    }

    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentDestination = navBackStackEntry?.destination

    // Handle pending intent actions
    val action = pendingAction.value
    LaunchedEffect(action) {
        when (action) {
            is IntentAction.EncryptText -> {
                encDecVm.updateEncryptInput(action.text)
                navController.navigate(Screen.Encrypt.route) {
                    popUpTo(navController.graph.startDestinationId) { saveState = true }
                    launchSingleTop = true
                }
                pendingAction.value = IntentAction.None
            }
            is IntentAction.DecryptText -> {
                encDecVm.updateDecryptInput(action.armoredMessage)
                navController.navigate(Screen.Decrypt.route) {
                    popUpTo(navController.graph.startDestinationId) { saveState = true }
                    launchSingleTop = true
                }
                pendingAction.value = IntentAction.None
            }
            is IntentAction.ImportKey -> {
                keyringVm.showImport()
                keyringVm.updateImportText(action.armoredKey)
                navController.navigate(Screen.Keyring.route) {
                    popUpTo(navController.graph.startDestinationId) { saveState = true }
                    launchSingleTop = true
                }
                pendingAction.value = IntentAction.None
            }
            is IntentAction.DecryptFile -> {
                val b64 = android.util.Base64.encodeToString(action.data, android.util.Base64.NO_WRAP)
                encDecVm.updateDecryptInput("(Binary PGP file: ${action.filename ?: "unknown"})\n$b64")
                navController.navigate(Screen.Decrypt.route) {
                    popUpTo(navController.graph.startDestinationId) { saveState = true }
                    launchSingleTop = true
                }
                pendingAction.value = IntentAction.None
            }
            IntentAction.None -> { /* no-op */ }
        }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                bottomNavScreens.forEach { screen ->
                    val selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true
                    NavigationBarItem(
                        icon = {
                            Icon(
                                imageVector = if (selected) screen.selectedIcon else screen.unselectedIcon,
                                contentDescription = stringResource(screen.titleResId)
                            )
                        },
                        label = { Text(stringResource(screen.titleResId), fontSize = 10.sp, maxLines = 1) },
                        selected = selected,
                        onClick = {
                            navController.navigate(screen.route) {
                                popUpTo(navController.graph.startDestinationId) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Keyring.route,
            modifier = Modifier.padding(padding)
        ) {
            composable(Screen.Keyring.route) {
                // Phase A4a: tapping a key card navigates to the new
                // KeyDetailScreen. The route uses the key's fingerprint
                // as a path arg; the detail VM loads the key in a
                // LaunchedEffect on the resolved arg.
                KeyringScreen(
                    viewModel = keyringVm,
                    onKeyClick = { fingerprint ->
                        navController.navigate("keyring/$fingerprint")
                    },
                    onScanCard = { navController.navigate("card_scan") }
                )
            }
            // Phase A4a: KeyDetailScreen route.
            composable(
                route = "keyring/{fingerprint}",
                arguments = listOf(navArgument("fingerprint") { type = NavType.StringType })
            ) { backStackEntry ->
                val fingerprint = backStackEntry.arguments?.getString("fingerprint").orEmpty()
                // viewModel() with a factory parameter produces a
                // back-stack-entry-scoped VM — fresh instance per
                // navigation, disposed when popped. Matches the
                // ephemeral semantics of a per-key detail screen.
                val detailVm: KeyDetailViewModel = viewModel(factory = factory)
                KeyDetailScreen(
                    fingerprint = fingerprint,
                    viewModel = detailVm,
                    onBack = { navController.popBackStack() },
                    onChangeCardPin = { navController.navigate("card_pin_change") }
                )
            }
            // HW Phase 1: NFC hardware-key scan destination. Reached from
            // the Keyring FAB. Self-contained — talks to KeyRepository and
            // the Activity's reader-mode helpers directly, no shared VM.
            composable("card_scan") {
                CardScanScreen(
                    onBack = { navController.popBackStack() },
                    onChangePin = { navController.navigate("card_pin_change") },
                    onSignTest = { navController.navigate("card_sign") },
                    onDecryptTest = { navController.navigate("card_decrypt") },
                    onManageCard = { navController.navigate("card_management") },
                    onGenerateKey = { navController.navigate("card_keygen") }
                )
            }
            // HW Phase 2: Change the card's user PIN (PW1).
            composable("card_pin_change") {
                CardPinChangeScreen(
                    onBack = { navController.popBackStack() },
                    // After a successful change there's nothing left to do on
                    // the card screens, so return straight to the Keyring tab
                    // (popping card_scan + card_pin_change off the stack).
                    onDone = {
                        navController.navigate(Screen.Keyring.route) {
                            popUpTo(Screen.Keyring.route) { inclusive = false }
                            launchSingleTop = true
                        }
                    }
                )
            }
            // Phase C0: Password Store (pass) — list + import. Opt-in via Settings.
            composable("pass_store") {
                PassStoreListScreen(
                    onBack = { navController.popBackStack() },
                    onOpenStore = { storeId -> navController.navigate("pass_browser/$storeId") }
                )
            }
            // Phase C1: browse a store's folder tree.
            composable(
                "pass_browser/{storeId}",
                arguments = listOf(navArgument("storeId") { type = NavType.StringType })
            ) { entry ->
                val storeId = entry.arguments?.getString("storeId") ?: ""
                PassBrowserScreen(
                    storeId = storeId,
                    onBack = { navController.popBackStack() },
                    onOpenEntry = { sid, rel ->
                        navController.navigate("pass_entry/$sid/${android.net.Uri.encode(rel)}")
                    }
                )
            }
            // Phase C1: decrypt + view a single entry.
            composable(
                "pass_entry/{storeId}/{relPath}",
                arguments = listOf(
                    navArgument("storeId") { type = NavType.StringType },
                    navArgument("relPath") { type = NavType.StringType }
                )
            ) { entry ->
                val storeId = entry.arguments?.getString("storeId") ?: ""
                val relPath = entry.arguments?.getString("relPath") ?: ""
                PassEntryScreen(
                    storeId = storeId,
                    relativePath = relPath,
                    onBack = { navController.popBackStack() }
                )
            }
            // Phase B1: on-card key generation.
            composable("card_keygen") {
                CardKeygenScreen(
                    onBack = { navController.popBackStack() },
                    onDone = {
                        navController.navigate(Screen.Keyring.route) {
                            popUpTo(Screen.Keyring.route) { inclusive = false }
                            launchSingleTop = true
                        }
                    }
                )
            }
            // Phase B2: admin-PIN lifecycle (change admin PIN, unblock user
            // PIN, factory reset).
            composable("card_management") {
                CardManagementScreen(
                    onBack = { navController.popBackStack() },
                    onDone = {
                        navController.navigate(Screen.Keyring.route) {
                            popUpTo(Screen.Keyring.route) { inclusive = false }
                            launchSingleTop = true
                        }
                    }
                )
            }
            // HW Phase 2b: clear-sign a test message with the card key.
            composable("card_sign") {
                CardSignScreen(onBack = { navController.popBackStack() })
            }
            // HW Phase 3b: decrypt a test message with the card key.
            composable("card_decrypt") {
                CardDecryptScreen(onBack = { navController.popBackStack() })
            }
            composable(Screen.Encrypt.route) { EncryptScreen(viewModel = encDecVm) }
            composable(Screen.Decrypt.route) { DecryptScreen(viewModel = encDecVm) }
            composable(Screen.Exchange.route) { ExchangeScreen(viewModel = exchangeVm) }
            composable(Screen.Contacts.route) { ContactsScreen(viewModel = contactsVm) }
            composable(Screen.Settings.route) {
                SettingsScreen(
                    viewModel = settingsVm,
                    onReplayOnboarding = { onboardingDone = false },
                    onOpenPassStore = { navController.navigate("pass_store") }
                )
            }
        }
    }
}
