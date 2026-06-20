// BillingService.kt
// PGPony Android — v1.0.0 STUB
//
// Google Play Billing is intentionally NOT included in v1.0.0 builds because
// the developer cannot legally monetize apps until November 2026. To keep
// existing call sites compiling without code churn, this file preserves the
// public API of the original BillingService but no-ops every billing-related
// method. isPro is hardcoded to true so all Pro-gated features unlock for
// everyone during the closed beta period.
//
// To restore real IAP behavior post-November 2026:
//   1. Restore the original BillingService.kt from the .bak file in the
//      project (created by the deploy script).
//   2. Re-add the dep in app/build.gradle.kts:
//        implementation("com.android.billingclient:billing-ktx:7.1.1")
//   3. Configure the com.pgpony.pro product in Play Console.
//   4. Bump versionCode and submit a new build.

package com.pgpony.android.billing

import android.app.Activity
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class BillingState(
    val isPro: Boolean = true,
    val isLoading: Boolean = false,
    val proPrice: String = "$2.99",
    val errorMessage: String? = null
)

class BillingService(
    activity: Activity,
    prefs: SharedPreferences
) {
    companion object {
        const val PRO_PRODUCT_ID = "com.pgpony.pro"
    }

    // v1.0.0 is unconditionally Pro for everyone. State never changes after
    // construction — there's no purchase flow, no async query, no error path.
    private val _state = MutableStateFlow(BillingState(isPro = true))
    val state: StateFlow<BillingState> = _state.asStateFlow()

    val isPro: Boolean get() = true

    // Lifecycle — no-ops since there's no BillingClient to manage.
    fun connect() {}
    fun disconnect() {}

    // Purchase actions — no-ops. UI gates that call these should never
    // be reachable since isPro is always true; if one slips through, the
    // user just gets nothing happening, which is better than a crash.
    fun purchasePro() {}
    fun restorePurchases() {}

    // Promo unlock — already Pro, but kept for the SecretUnlockScreen call site.
    fun applyPromoUnlock() {}

    // Error clearing — no errors to clear, but kept for the call sites.
    fun clearError() {}
}
