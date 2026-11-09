// ProviderRecipientReviewActivity.kt
// PGPony Android 4.7.0 (item 41, #25)
//
// The recipient review for OpenPGP API clients: what opens when a mail app
// asks PGPony to encrypt to an address it has no usable key for. Launched only
// through the PendingIntent PGPonyOpenPgpService returns with
// USER_INTERACTION_REQUIRED from an encrypt (NOT exported). Same look and the
// same :remote_api constraints as ProviderKeyPickerActivity: the repository
// comes from PGPonyApp, which this process sets up too, and the "Allow expired
// keys" pref is read cross-process the way the service reads it.
//
// Round-trip contract (OpenKeychain's "Please review the list of recipients"):
//   1. the screen lists the addresses without a key (and those whose only key
//      is marked Don't use), then the keyring with checkboxes, the sender's own
//      key ticked
//   2. on confirm: setResult(RESULT_OK, <original api data> +
//      EXTRA_KEY_IDS_SELECTED), and the client re-runs the same encrypt with it
//   3. on cancel: RESULT_CANCELED, so the mail app keeps its draft

package com.pgpony.android.provider

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.PersonOff
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.pgpony.android.PGPonyApp
import com.pgpony.android.PGPonyTheme
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.TrustLevel
import com.pgpony.android.ui.components.TrustMark
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.openintents.openpgp.util.OpenPgpApi

class ProviderRecipientReviewActivity : ComponentActivity() {

    companion object {
        /** The client's original API request intent, echoed back with the selection. */
        const val EXTRA_API_DATA = "com.pgpony.android.provider.REVIEW_API_DATA"

        /** String[]: the addresses (or key ids) PGPony has no usable key for. */
        const val EXTRA_MISSING = "com.pgpony.android.provider.REVIEW_MISSING"

        /** String[]: the recipients whose only key is marked Don't use (item 10). */
        const val EXTRA_DONT_USE = "com.pgpony.android.provider.REVIEW_DONT_USE"

        /** The send's from-address, for preselecting the sender's own key. */
        const val EXTRA_SENDER_EMAIL = "com.pgpony.android.provider.REVIEW_SENDER_EMAIL"

        /** The client's signing key id (0 when none), preselected when offered. */
        const val EXTRA_SIGN_KEY_ID = "com.pgpony.android.provider.REVIEW_SIGN_KEY_ID"

        /** 4.7.0 (item 56, #25): key ids picked in this app's last review,
         *  ticked again. */
        const val EXTRA_PREVIOUS_PICKS = "com.pgpony.android.provider.REVIEW_PREVIOUS_PICKS"

        /** 4.7.0 RC6 (item 67, #25): String[] of the fingerprints the request
         *  already resolves from its own addresses or key ids, shown ticked
         *  and locked, with [EXTRA_INCLUDED_FOR] (same order) naming what
         *  includes each one. */
        const val EXTRA_INCLUDED_FPS = "com.pgpony.android.provider.REVIEW_INCLUDED_FPS"
        const val EXTRA_INCLUDED_FOR = "com.pgpony.android.provider.REVIEW_INCLUDED_FOR"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ProviderWindowGuard.harden(this) // 4.6.0 (item 17.7)

        @Suppress("DEPRECATION")
        val apiData: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(EXTRA_API_DATA, Intent::class.java)
        } else {
            intent.getParcelableExtra(EXTRA_API_DATA)
        }
        if (apiData == null) {
            // Nothing to re-run: without the request the client cannot resume.
            cancel()
            return
        }
        val missing: List<String> = intent.getStringArrayExtra(EXTRA_MISSING)?.toList() ?: emptyList()
        val dontUse: List<String> = intent.getStringArrayExtra(EXTRA_DONT_USE)?.toList() ?: emptyList()
        val senderEmail: String? = intent.getStringExtra(EXTRA_SENDER_EMAIL)?.takeIf { it.isNotBlank() }
        val signKeyId = intent.getLongExtra(EXTRA_SIGN_KEY_ID, 0L)
        val previousPicks: Set<Long> = intent.getLongArrayExtra(EXTRA_PREVIOUS_PICKS)?.toSet() ?: emptySet()
        val includedFor: Map<String, String> = RecipientReview.includedMap(
            intent.getStringArrayExtra(EXTRA_INCLUDED_FPS),
            intent.getStringArrayExtra(EXTRA_INCLUDED_FOR)
        )

        val repo = (application as PGPonyApp).keyRepository

        setContent {
            PGPonyTheme {
                val loaded by produceState<ReviewKeys?>(initialValue = null) {
                    value = withContext(Dispatchers.IO) {
                        val offered = RecipientReview.offeredKeys(
                            repo.getAllKeys(), allowExpiredKeys(), senderEmail
                        )
                        ReviewKeys(offered, RecipientReview.preselect(offered, signKeyId, senderEmail))
                    }
                }
                var query by rememberSaveable { mutableStateOf("") }
                var selected by remember { mutableStateOf<Set<String>?>(null) }
                val current = loaded
                LaunchedEffect(current) {
                    if (current != null && selected == null) {
                        selected = setOfNotNull(current.preselected) + current.keys
                            .filter { RecipientReview.keyIdOf(it) in previousPicks }
                            .map { it.fingerprint }
                    }
                }
                val chosen: Set<String> = selected ?: emptySet()
                // Keys the request already includes are always part of the
                // answer (deduped by the service), so confirming with only
                // those works as it did when the sender's key was preselected.
                val included: Set<String> = current?.keys
                    ?.map { it.fingerprint }
                    ?.filter { RecipientReview.normalizeFingerprint(it) in includedFor }
                    ?.toSet() ?: emptySet()
                val answer: Set<String> = chosen + included

                AlertDialog(
                    onDismissRequest = { cancel() },
                    title = { Text(stringResource(R.string.provider_review_title)) },
                    text = {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .verticalScroll(rememberScrollState())
                        ) {
                            Text(
                                stringResource(R.string.provider_review_intro),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(bottom = 8.dp)
                            )
                            missing.forEach { label ->
                                UnresolvedRow(
                                    text = stringResource(R.string.provider_review_missing_format, label),
                                    dontUse = false
                                )
                            }
                            dontUse.forEach { label ->
                                UnresolvedRow(
                                    text = stringResource(R.string.provider_review_dont_use_format, label),
                                    dontUse = true
                                )
                            }
                            if (dontUse.isNotEmpty()) {
                                Text(
                                    stringResource(R.string.provider_review_dont_use_hint),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(top = 4.dp)
                                )
                            }
                            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                            OutlinedTextField(
                                value = query,
                                onValueChange = { query = it },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                label = { Text(stringResource(R.string.encrypt_recipients_search_label)) },
                                leadingIcon = {
                                    Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(20.dp))
                                },
                                trailingIcon = {
                                    if (query.isNotEmpty()) {
                                        IconButton(onClick = { query = "" }) {
                                            Icon(
                                                Icons.Filled.Clear,
                                                contentDescription = stringResource(R.string.encrypt_recipients_clear_search),
                                                modifier = Modifier.size(20.dp)
                                            )
                                        }
                                    }
                                }
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            if (current != null) {
                                val shown = current.keys.filter { RecipientReview.matchesQuery(it, query) }
                                when {
                                    current.keys.isEmpty() -> EmptyText(stringResource(R.string.provider_review_no_keys))
                                    shown.isEmpty() -> EmptyText(stringResource(R.string.decrypt_picker_none))
                                    else -> shown.forEach { key ->
                                        ReviewKeyRow(
                                            key = key,
                                            checked = key.fingerprint in answer,
                                            includedFor = includedFor[RecipientReview.normalizeFingerprint(key.fingerprint)],
                                            onToggle = { on ->
                                                selected = if (on) chosen + key.fingerprint else chosen - key.fingerprint
                                            }
                                        )
                                    }
                                }
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(
                            onClick = { confirm(apiData, current?.keys ?: emptyList(), answer) },
                            enabled = answer.isNotEmpty()
                        ) {
                            Text(stringResource(R.string.provider_review_confirm))
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { cancel() }) {
                            Text(stringResource(R.string.common_button_cancel))
                        }
                    }
                )
            }
        }
    }

    // #57: the same cross-process read of "Allow expired keys" the service does.
    @Suppress("DEPRECATION")
    private fun allowExpiredKeys(): Boolean =
        applicationContext
            .getSharedPreferences("pgpony_prefs", Context.MODE_MULTI_PROCESS)
            .getBoolean("allow_expired_keys", false)

    private fun confirm(apiData: Intent, offered: List<PGPKeyEntity>, chosen: Set<String>) {
        val ids = RecipientReview.selectedKeyIds(offered, chosen)
        if (ids.isEmpty()) return
        // The client re-executes the original request with exactly this
        // intent, so it must be the original request plus the selection.
        val result = Intent(apiData)
        result.putExtra(OpenPgpApi.EXTRA_KEY_IDS_SELECTED, ids)
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private fun cancel() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    /** 4.6.0 (item 17.7): ignore touches delivered through an obscuring overlay. */
    override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean {
        if (ProviderWindowGuard.isObscured(ev)) return false
        return super.dispatchTouchEvent(ev)
    }
}

private class ReviewKeys(val keys: List<PGPKeyEntity>, val preselected: String?)

// ── Rows ───────────────────────────────────────────────────────────────

@Composable
private fun UnresolvedRow(text: String, dontUse: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (dontUse) {
            TrustMark(TrustLevel.DONT_USE, size = 20.dp, contentDescription = null)
        } else {
            Icon(
                Icons.Filled.PersonOff,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp)
            )
        }
        Spacer(modifier = Modifier.width(12.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun EmptyText(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(vertical = 8.dp)
    )
}

// 4.7.0 (item 41, #25): the whole row is the checkbox (Role.Checkbox on the
// row, the Checkbox itself not clickable), so a tap anywhere toggles it and
// TalkBack reads one control with the key's name.
// 4.7.0 RC6 (item 67, #25): a key the request already includes is ticked and
// locked, with a line naming the address (or key id) that includes it.
@Composable
private fun ReviewKeyRow(
    key: PGPKeyEntity,
    checked: Boolean,
    includedFor: String?,
    onToggle: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(
                value = checked,
                enabled = includedFor == null,
                role = Role.Checkbox,
                onValueChange = onToggle
            )
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = checked, onCheckedChange = null, enabled = includedFor == null)
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                key.userName.ifBlank { key.userEmail.ifBlank { key.userID } },
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                if (key.userEmail.isNotEmpty()) {
                    "${key.userEmail} · ${key.shortFingerprint}"
                } else {
                    key.shortFingerprint
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            if (includedFor != null) {
                Text(
                    stringResource(R.string.provider_review_included_format, includedFor),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            if (key.isExpired) {
                Text(
                    stringResource(R.string.key_card_expired_badge),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
        Spacer(modifier = Modifier.width(8.dp))
        // 4.8.0 RC8 (#115): the shown level, as on the Keyring.
        TrustMark(trust = com.pgpony.android.data.CertifiedTrust.effective(key), size = 18.dp)
    }
}
