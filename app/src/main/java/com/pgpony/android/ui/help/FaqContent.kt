// FaqContent.kt
// PGPony Android
//
// Static FAQ content displayed by HelpScreen. Organized into three sections
// covering onboarding fundamentals, encrypt/decrypt workflows, and the
// security model.
//
// Added in Phase 2 (Tester Feedback Implementation Plan).
//
// Phase A13 — refactored to hold @StringRes Int IDs instead of literal
// String values, so question + answer + section-title text can be
// localized through Android string resources. The HelpScreen now reads
// each ID through stringResource() at render time. The data structure
// shape is identical; only the field type changes (String → Int).

package com.pgpony.android.ui.help

import androidx.annotation.StringRes
import com.pgpony.android.R

data class FaqItem(
    @StringRes val questionResId: Int,
    @StringRes val answerResId: Int
)

data class FaqSection(
    @StringRes val titleResId: Int,
    val items: List<FaqItem>
)

object FaqContent {

    val sections: List<FaqSection> = listOf(

        // ── Getting Started ──────────────────────────────────────────────
        FaqSection(
            titleResId = R.string.faq_section_getting_started,
            items = listOf(
                FaqItem(R.string.faq_q_what_is_pgp,           R.string.faq_a_what_is_pgp),
                FaqItem(R.string.faq_q_need_key,              R.string.faq_a_need_key),
                FaqItem(R.string.faq_q_my_keys_vs_contacts,   R.string.faq_a_my_keys_vs_contacts),
                FaqItem(R.string.faq_q_share_public_key,      R.string.faq_a_share_public_key)
            )
        ),

        // ── Encrypt & Decrypt ────────────────────────────────────────────
        FaqSection(
            titleResId = R.string.faq_section_encrypt_decrypt,
            items = listOf(
                FaqItem(R.string.faq_q_how_to_encrypt,        R.string.faq_a_how_to_encrypt),
                FaqItem(R.string.faq_q_how_to_decrypt,        R.string.faq_a_how_to_decrypt),
                FaqItem(R.string.faq_q_armored_toggle,        R.string.faq_a_armored_toggle),
                FaqItem(R.string.faq_q_encrypt_files,         R.string.faq_a_encrypt_files)
            )
        ),

        // ── Security & Privacy ───────────────────────────────────────────
        FaqSection(
            titleResId = R.string.faq_section_security_privacy,
            items = listOf(
                FaqItem(R.string.faq_q_where_keys_stored,     R.string.faq_a_where_keys_stored),
                FaqItem(R.string.faq_q_lost_passphrase,       R.string.faq_a_lost_passphrase),
                FaqItem(R.string.faq_q_server_data,           R.string.faq_a_server_data),
                FaqItem(R.string.faq_q_biometric_lock,        R.string.faq_a_biometric_lock),
                FaqItem(R.string.faq_q_algorithms,            R.string.faq_a_algorithms)
            )
        )
    )
}
