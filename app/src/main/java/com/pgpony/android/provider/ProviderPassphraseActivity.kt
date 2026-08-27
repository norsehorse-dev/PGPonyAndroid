// ProviderPassphraseActivity.kt
// PGPony Android — 4.0.0 Succession Phase P2a-2 (provider send path)
//
// Passphrase prompt for provider operations on a protected signing
// key. Launched only via the PendingIntent the service attaches when a
// sign/encrypt call throws PassphraseRequired / InvalidPassphrase (NOT
// exported). On confirm the passphrase goes into
// ProviderPassphraseCache (in-process only — never back across the
// binder), the activity returns RESULT_OK with the client's original
// request intent echoed back, and the client re-executes that call,
// which now finds the cached passphrase.

package com.pgpony.android.provider

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pgpony.android.PGPonyTheme
import com.pgpony.android.R
import com.pgpony.android.ui.util.autofillPassword

class ProviderPassphraseActivity : ComponentActivity() {

    companion object {
        const val EXTRA_KEY_ID = "com.pgpony.android.provider.PASSPHRASE_KEY_ID"
        const val EXTRA_KEY_LABEL = "com.pgpony.android.provider.PASSPHRASE_KEY_LABEL"
        const val EXTRA_WRONG = "com.pgpony.android.provider.PASSPHRASE_WRONG"

        /** The client's original API request intent, echoed back on unlock. */
        const val EXTRA_API_DATA = "com.pgpony.android.provider.PASSPHRASE_API_DATA"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        @Suppress("DEPRECATION")
        val apiData: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(EXTRA_API_DATA, Intent::class.java)
        } else {
            intent.getParcelableExtra(EXTRA_API_DATA)
        }
        val keyId = intent.getLongExtra(EXTRA_KEY_ID, 0L)
        val keyLabel = intent.getStringExtra(EXTRA_KEY_LABEL) ?: ""
        val wasWrong = intent.getBooleanExtra(EXTRA_WRONG, false)

        if (keyId == 0L) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        setContent {
            PGPonyTheme {
                val context = LocalContext.current
                // RandomNam3 (#51): let the user switch signing key right here.
                // Opens the full key list (no address filtering), and relays the
                // pick back so the client re-runs the sign with the chosen key.
                val pickerLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.StartActivityForResult()
                ) { result ->
                    if (result.resultCode == Activity.RESULT_OK && result.data != null) {
                        setResult(Activity.RESULT_OK, result.data)
                        finish()
                    }
                }
                var passphrase by remember { mutableStateOf("") }
                AlertDialog(
                    onDismissRequest = { cancel() },
                    title = { Text(stringResource(R.string.provider_passphrase_title)) },
                    text = {
                        Column {
                            Text(
                                stringResource(
                                    R.string.provider_passphrase_body_format, keyLabel
                                ),
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.padding(bottom = 12.dp)
                            )
                            if (wasWrong) {
                                Text(
                                    stringResource(R.string.provider_passphrase_wrong),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.padding(bottom = 8.dp)
                                )
                            }
                            OutlinedTextField(
                                value = passphrase,
                                onValueChange = { passphrase = it },
                                singleLine = true,
                                visualTransformation = PasswordVisualTransformation(),
                                keyboardOptions = KeyboardOptions(
                                    keyboardType = KeyboardType.Password
                                ),
                                label = {
                                    Text(stringResource(R.string.provider_passphrase_hint))
                                },
                                // 4.1.0 §3.4 (issue #8) — the provider-invoked
                                // prompt, i.e. the exact field the reporter hits
                                // decrypting in FairEmail. It runs in a PGPony
                                // activity launched by the mail app, so it is
                                // the one worth confirming on device: autofill
                                // has to see THIS window, not just the in-app
                                // ones. See ui/util/Autofill.kt.
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .autofillPassword { passphrase = it }
                            )
                            TextButton(
                                onClick = {
                                    val pickerIntent = Intent(
                                        context, ProviderKeyPickerActivity::class.java
                                    ).apply {
                                        putExtra(ProviderKeyPickerActivity.EXTRA_API_DATA, apiData)
                                        putExtra(ProviderKeyPickerActivity.EXTRA_FOR_OP, true)
                                        putExtra(
                                            ProviderKeyPickerActivity.EXTRA_CURRENT_KEY_ID, keyId
                                        )
                                    }
                                    pickerLauncher.launch(pickerIntent)
                                },
                                modifier = Modifier.padding(top = 4.dp)
                            ) {
                                Text(stringResource(R.string.provider_passphrase_change_key))
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(
                            enabled = passphrase.isNotEmpty(),
                            onClick = {
                                ProviderPassphraseCache.put(keyId, passphrase)
                                // 4.0.4: hand the original request back so the
                                // client can re-execute it immediately, the
                                // same contract ProviderKeyPickerActivity uses.
                                // A bare RESULT_OK made FairEmail wait for a
                                // second Unlock press before showing the mail.
                                setResult(Activity.RESULT_OK, Intent(apiData ?: Intent()))
                                finish()
                            }
                        ) { Text(stringResource(R.string.provider_passphrase_unlock)) }
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

    private fun cancel() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }
}
