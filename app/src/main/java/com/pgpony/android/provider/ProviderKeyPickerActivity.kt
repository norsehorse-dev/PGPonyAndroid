// ProviderKeyPickerActivity.kt
// PGPony Android — 4.0.0 Succession Phase P2a-1 (GET_SIGN_KEY_ID)
//
// The signing-key picker for OpenPGP API clients — what opens when the
// user taps "Configure end-to-end key" in Thunderbird for Android.
// Launched only via the PendingIntent PGPonyOpenPgpService attaches to
// every GET_SIGN_KEY_ID response (NOT exported).
//
// Round-trip contract (matches OpenKeychain's SelectSignKeyId flow,
// verified against openpgp-api's OpenPgpKeyPreference):
//   1. service response carries RESULT_INTENT → client fires it
//   2. this activity shows the user's signing-capable keys, preselect
//      hint = the account email the client sent in EXTRA_USER_ID
//   3. on pick: setResult(RESULT_OK, <original api data intent> +
//      RESULT_SIGN_KEY_ID) — the client CACHES that intent and
//      re-executes GET_SIGN_KEY_ID with it, and the service echoes the
//      selection back with primary user id + creation time
//
// The "No key" row returns key id 0 (the API's NO_KEY sentinel): the
// client disables signing for that account. Dismissing = CANCELED, no
// change.

package com.pgpony.android.provider

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.PGPonyApp
import com.pgpony.android.PGPonyTheme
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import org.openintents.openpgp.util.OpenPgpApi

class ProviderKeyPickerActivity : ComponentActivity() {

    companion object {
        /** The client's original API request intent, echoed back with the selection. */
        const val EXTRA_API_DATA = "com.pgpony.android.provider.API_DATA"

        /** The account user id (email) the client wants a key for. */
        const val EXTRA_PRESELECT_USER_ID = "com.pgpony.android.provider.PRESELECT_USER_ID"

        /** #51: the resolved send address, used to scope the per-send list to
         *  the keys on that address and to highlight the address match. */
        const val EXTRA_PRESELECT_EMAIL = "com.pgpony.android.provider.PRESELECT_EMAIL"

        /** #51: the key the client is currently locked to, marked "In use". */
        const val EXTRA_CURRENT_KEY_ID = "com.pgpony.android.provider.CURRENT_KEY_ID"

        /** The API's NO_KEY sentinel — "sign with no key" / disable signing. */
        const val KEY_ID_NONE = 0L

        /** #51: per-send mode. In this mode the picker is opened by a sign
         *  operation (not GET_SIGN_KEY_ID), so on pick it returns
         *  EXTRA_SIGN_KEY_ID plus [EXTRA_SIGN_CHOICE_MADE] for the client to
         *  re-run the same sign op with, and the "No key" row is hidden. */
        const val EXTRA_FOR_OP = "com.pgpony.android.provider.FOR_OP"

        /** #51: marks a resumed sign op so the service does not prompt again. */
        const val EXTRA_SIGN_CHOICE_MADE = "com.pgpony.android.provider.SIGN_CHOICE_MADE"
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
        val forOp = intent.getBooleanExtra(EXTRA_FOR_OP, false)
        val currentKeyId = intent.getLongExtra(EXTRA_CURRENT_KEY_ID, 0L)
        val preselectUserId = intent.getStringExtra(EXTRA_PRESELECT_USER_ID)
        val preselectEmail = intent.getStringExtra(EXTRA_PRESELECT_EMAIL)
            ?.takeIf { it.isNotBlank() }
            ?: preselectUserId
                ?.substringAfterLast('<')?.substringBefore('>')?.trim()
                ?.ifEmpty { preselectUserId.trim() }

        val repo = (application as PGPonyApp).keyRepository

        setContent {
            PGPonyTheme {
                val keys by produceState<List<PGPKeyEntity>?>(initialValue = null) {
                    // Signing needs private material: software key pairs
                    // plus card-backed keys (their secret lives on the
                    // card; provider card signing arrives with the rest
                    // of Phase 2). Revoked keys are never offered.
                    value = repo.getAllKeys()
                        .filter { (it.isKeyPair || it.isCardBacked) && !it.isRevoked }
                        // #51: per-send mode scopes to the sending address, so
                        // the choice is between the keys ON that address, not
                        // every key in the ring. Only scope when the address is
                        // known; otherwise fall back to the full list.
                        .filter { key ->
                            !forOp || preselectEmail.isNullOrBlank() ||
                                key.userEmail.equals(preselectEmail, ignoreCase = true)
                        }
                        .sortedWith(
                            compareByDescending<PGPKeyEntity> {
                                it.userEmail.equals(preselectEmail ?: "", ignoreCase = true)
                            }.thenByDescending { it.isDefault }
                                .thenBy { it.userName.lowercase() }
                        )
                }

                AlertDialog(
                    onDismissRequest = { cancel() },
                    title = { Text(stringResource(R.string.provider_keypicker_title)) },
                    text = {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .verticalScroll(rememberScrollState())
                        ) {
                            if (!preselectUserId.isNullOrEmpty()) {
                                Text(
                                    stringResource(
                                        R.string.provider_keypicker_for_format,
                                        preselectUserId
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(bottom = 12.dp)
                                )
                            }
                            keys?.forEach { key ->
                                val isCurrent = currentKeyId != 0L && runCatching {
                                    java.lang.Long.parseUnsignedLong(key.longKeyId, 16)
                                }.getOrNull() == currentKeyId
                                KeyRow(
                                    key = key,
                                    highlighted = if (forOp) isCurrent else key.userEmail.equals(
                                        preselectEmail ?: "", ignoreCase = true
                                    ),
                                    isCurrent = isCurrent,
                                    onClick = { pick(apiData, key, forOp) }
                                )
                            }
                            if (keys?.isEmpty() == true) {
                                Text(
                                    stringResource(R.string.provider_keypicker_empty),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(vertical = 8.dp)
                                )
                            }
                            if (!keys.isNullOrEmpty()) {
                                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                            }
                            if (keys != null && !forOp) {
                                NoKeyRow(onClick = { pickNone(apiData) })
                            }
                        }
                    },
                    confirmButton = {},
                    dismissButton = {
                        TextButton(onClick = { cancel() }) {
                            Text(stringResource(R.string.common_button_cancel))
                        }
                    }
                )
            }
        }
    }

    private fun pick(apiData: Intent?, key: PGPKeyEntity, forOp: Boolean) {
        val keyId = try {
            java.lang.Long.parseUnsignedLong(key.longKeyId, 16)
        } catch (e: NumberFormatException) {
            cancel(); return
        }
        finishWithKeyId(apiData, keyId, forOp)
    }

    private fun pickNone(apiData: Intent?) = finishWithKeyId(apiData, KEY_ID_NONE, forOp = false)

    private fun finishWithKeyId(apiData: Intent?, keyId: Long, forOp: Boolean) {
        // The client re-executes the original request with exactly this
        // intent, so it must be the original request plus the selection.
        val result = Intent(apiData ?: Intent())
        if (forOp) {
            // #51: per-send sign pick — feed the chosen key straight back into
            // the sign op and mark it resumed so the service does not re-prompt.
            result.putExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, keyId)
            result.putExtra(EXTRA_SIGN_CHOICE_MADE, true)
        } else {
            result.putExtra(OpenPgpApi.RESULT_SIGN_KEY_ID, keyId)
        }
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

// ── Rows ───────────────────────────────────────────────────────────────

@Composable
private fun KeyRow(
    key: PGPKeyEntity,
    highlighted: Boolean,
    isCurrent: Boolean = false,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            if (key.isCardBacked) Icons.Filled.CreditCard else Icons.Filled.Key,
            contentDescription = null,
            tint = if (highlighted) Color(0xFF8B5CF6)
            else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column {
            Text(
                key.userName.ifEmpty { key.userEmail },
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = if (highlighted) FontWeight.SemiBold else FontWeight.Normal
            )
            if (isCurrent) {
                Text(
                    stringResource(R.string.provider_keypicker_in_use),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }
            Text(
                if (key.userEmail.isNotEmpty()) {
                    "${key.userEmail} · ${key.shortFingerprint}"
                } else {
                    key.shortFingerprint
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun NoKeyRow(onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.Block,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Text(
            stringResource(R.string.provider_keypicker_none),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
