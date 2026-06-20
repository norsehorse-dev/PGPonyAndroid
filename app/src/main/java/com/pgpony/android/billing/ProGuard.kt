// ProGuard.kt
// PGPony Android
//
// Centralized Pro status checks. UI composables call these to determine
// whether to show the ProGateSheet or allow the action.
// Keeps paywall logic out of ViewModels — composables read BillingService.state directly.

package com.pgpony.android.billing

/**
 * Free tier limits — matches iOS ProGateView.swift feature gates.
 */
object ProGuard {
    const val FREE_MAX_KEY_PAIRS = 1
    const val FREE_MAX_RECIPIENTS = 1

    /** Can the user generate another key pair? */
    fun canGenerateKey(currentKeyPairCount: Int, isPro: Boolean): Boolean {
        return isPro || currentKeyPairCount < FREE_MAX_KEY_PAIRS
    }

    /** Ed25519 requires Pro on iOS. We match that gate. */
    fun canUseEd25519(isPro: Boolean): Boolean = isPro

    /** Key server upload requires Pro. */
    fun canUploadToKeyServer(isPro: Boolean): Boolean = isPro

    /** Multiple recipients require Pro. Free allows 1. */
    fun canUseMultipleRecipients(selectedCount: Int, isPro: Boolean): Boolean {
        return isPro || selectedCount <= FREE_MAX_RECIPIENTS
    }
}
