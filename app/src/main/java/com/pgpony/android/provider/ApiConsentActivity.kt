// ApiConsentActivity.kt
// PGPony Android — 4.0.0 Succession Phase 1 (OpenPGP API provider)
//
// The first-use consent dialog for OpenPGP API clients. Launched only
// via the PendingIntent that PGPonyOpenPgpService hands back with
// RESULT_CODE_USER_INTERACTION_REQUIRED (the activity is NOT exported —
// nothing else can start it). The client fires the PendingIntent with
// startIntentSenderForResult, the user decides here, and the client
// retries its API call on RESULT_OK.
//
// Presents as a dialog-first screen: the activity's only content is a
// Compose AlertDialog, so the user reads it as a consent interruption
// and is returned straight to the client app on either choice. Mirrors
// OpenKeychain's RemoteServiceActivity consent hop, which is the UX
// client apps and their documentation assume.
//
// The Allow path pins the caller's CURRENT signing certificate via
// ApiClientAuthorizer.grant — see ApiClientEntity for the model.

package com.pgpony.android.provider

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.lifecycleScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.PGPonyTheme
import com.pgpony.android.R
import kotlinx.coroutines.launch

class ApiConsentActivity : ComponentActivity() {

    companion object {
        const val EXTRA_PACKAGE_NAME = "com.pgpony.android.provider.PACKAGE_NAME"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ProviderWindowGuard.harden(this) // 4.6.0 (item 17.7)

        val clientPackage = intent.getStringExtra(EXTRA_PACKAGE_NAME)
        if (clientPackage.isNullOrEmpty()) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        // Resolve a human-readable label; fall back to the raw package
        // name if the app vanished between the call and the consent tap.
        val clientLabel = try {
            val info = packageManager.getApplicationInfo(clientPackage, 0)
            packageManager.getApplicationLabel(info).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            clientPackage
        }

        val authorizer = ApiClientAuthorizer(
            dao = (application as PGPonyApp).database.apiClientDao(),
            signatureSha256Of = ApiClientAuthorizer.platformSignatureLookup(packageManager)
        )

        setContent {
            PGPonyTheme {
                var busy by remember { mutableStateOf(false) }
                AlertDialog(
                    onDismissRequest = { deny() },
                    title = {
                        Text(stringResource(R.string.provider_consent_title, clientLabel))
                    },
                    text = {
                        Text(
                            stringResource(
                                R.string.provider_consent_body,
                                clientLabel,
                                clientPackage
                            ),
                            style = MaterialTheme.typography.bodyMedium
                        )
                    },
                    confirmButton = {
                        TextButton(
                            enabled = !busy,
                            onClick = {
                                busy = true
                                lifecycleScope.launch {
                                    val ok = authorizer.grant(clientPackage)
                                    setResult(
                                        if (ok) Activity.RESULT_OK else Activity.RESULT_CANCELED
                                    )
                                    finish()
                                }
                            }
                        ) { Text(stringResource(R.string.provider_consent_allow)) }
                    },
                    dismissButton = {
                        TextButton(
                            enabled = !busy,
                            onClick = { deny() }
                        ) { Text(stringResource(R.string.provider_consent_deny)) }
                    }
                )
            }
        }
    }

    private fun deny() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    /** 4.6.0 (item 17.7): ignore touches delivered through an obscuring overlay. */
    override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean {
        if (ProviderWindowGuard.isObscured(ev)) return false
        return super.dispatchTouchEvent(ev)
    }
}
