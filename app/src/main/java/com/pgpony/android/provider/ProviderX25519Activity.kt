// ProviderX25519Activity.kt
// PGPony Android 4.8.2 (item 1): the confirmation for X25519_AGREE with a key
// whose secret is on this device.
//
// Every X25519_AGREE call comes here (a key on a security key goes to
// ProviderCardOpActivity instead): the dialog names the calling app, the key
// and the number of agreements, and nothing is computed until the user taps
// Allow. The passphrase field shows only when the key is protected and
// neither the client (EXTRA_PASSPHRASE) nor ProviderPassphraseCache has one,
// as the provider's decrypt does; a passphrase typed here is cached the same
// way. The provider's decrypt has no biometric step, so neither does this.
//
// On Allow the agreement runs and its result (or why it failed) is stored in
// ProviderCardOpStore under the request's op key; the activity returns
// RESULT_OK with the client's request echoed back (#61), and the client's
// identical re-call collects it once. Cancel returns RESULT_CANCELED and
// drops the request. Launched only through the service's PendingIntent (not
// exported); runs in the provider's :remote_api process.

package com.pgpony.android.provider

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.PGPonyTheme
import com.pgpony.android.R
import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.SecretKeyUnlock
import com.pgpony.android.crypto.X25519Agreement
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.ui.components.PassphraseVisibilityToggle
import com.pgpony.android.ui.util.autofillPassword
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSecretKey

class ProviderX25519Activity : ComponentActivity() {

    companion object {
        const val EXTRA_OP_KEY = "com.pgpony.android.provider.X25519_OP_KEY"

        /** The client's original request, echoed back on RESULT_OK (#61). */
        const val EXTRA_API_DATA = "com.pgpony.android.provider.X25519_API_DATA"

        /** Same text as a card fingerprint row: four-digit groups. */
        internal fun groupedFingerprint(fp: String): String = fp.uppercase().chunked(4).joinToString(" ")
    }

    private class Loaded(val entity: PGPKeyEntity, val secretKey: PGPSecretKey, val keyId: Long)

    private sealed class Outcome {
        object Done : Outcome()
        object WrongPassphrase : Outcome()
    }

    private var opKey: String = ""
    private var apiData: Intent? = null

    private val busy = mutableStateOf(false)
    private val wrong = mutableStateOf(false)
    private val askPassphrase = mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ProviderWindowGuard.harden(this)

        opKey = intent.getStringExtra(EXTRA_OP_KEY) ?: ""
        @Suppress("DEPRECATION")
        apiData = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(EXTRA_API_DATA, Intent::class.java)
        } else {
            intent.getParcelableExtra(EXTRA_API_DATA)
        }
        val op = ProviderCardOpStore.getPending(opKey)
        if (op == null || op.action != PGPonyActions.ACTION_X25519_AGREE || op.x25519SubkeyFingerprint == null) {
            // Expired or already handled: the client's next call starts over.
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        lifecycleScope.launch {
            val l = withContext(Dispatchers.IO) { load(op) }
            if (l == null) {
                // The secret is gone since the request was taken (key deleted,
                // storage invalidated). Nothing to confirm; tell the client.
                finishWith(
                    ProviderCardOpStore.CompletedOp.AgreeFailed(
                        X25519Agreement.Refusal.KEY_UNAVAILABLE.code,
                        "The secret of this key is not available on this device."
                    )
                )
                return@launch
            }
            val protectedKey = l.secretKey.s2KUsage.toInt() != 0
            askPassphrase.value = protectedKey && (op.clientPassphrase ?: ProviderPassphraseCache.get(l.keyId)).isNullOrEmpty()
            show(op, l)
        }
    }

    private fun load(op: ProviderCardOpStore.PendingOp): Loaded? = runCatching {
        val repo = (application as PGPonyApp).keyRepository
        val entity = kotlinx.coroutines.runBlocking { repo.getByFingerprint(op.cardEntityFingerprint) } ?: return null
        val ring = X25519SecretKeys.ring(repo, entity.fingerprint) ?: return null
        val key = X25519SecretKeys.key(ring, op.x25519SubkeyFingerprint!!) ?: return null
        val keyId = runCatching { java.lang.Long.parseUnsignedLong(entity.longKeyId, 16) }.getOrDefault(0L)
        Loaded(entity, key, keyId)
    }.getOrNull()

    private fun clientLabel(pkg: String?): String {
        if (pkg.isNullOrEmpty()) return ""
        return try {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
        } catch (_: PackageManager.NameNotFoundException) {
            pkg
        }
    }

    private fun show(op: ProviderCardOpStore.PendingOp, l: Loaded) {
        val app = clientLabel(op.clientPackage)
        val count = op.input.size / X25519Agreement.POINT_LEN
        val fp = groupedFingerprint(op.x25519SubkeyFingerprint!!)
        setContent {
            PGPonyTheme {
                var passphrase by remember { mutableStateOf("") }
                var shown by remember { mutableStateOf(false) }
                val working by busy
                val wasWrong by wrong
                val needsPassphrase by askPassphrase
                val onAllow: () -> Unit = {
                    if (!working && (!needsPassphrase || passphrase.isNotEmpty())) runAllow(op, l, passphrase)
                }
                AlertDialog(
                    onDismissRequest = { if (!working) cancel() },
                    title = { Text(stringResource(R.string.provider_x25519_title)) },
                    text = {
                        Column {
                            Text(
                                stringResource(R.string.provider_x25519_body, app),
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.padding(bottom = 12.dp)
                            )
                            Text(
                                stringResource(R.string.provider_x25519_key, l.entity.userID, fp),
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.padding(bottom = 4.dp)
                            )
                            Text(
                                stringResource(R.string.provider_x25519_count, count),
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.padding(bottom = 12.dp)
                            )
                            if (needsPassphrase) {
                                // Only with the field on screen: it takes focus and the keyboard opens.
                                val focus = rememberProviderAutoFocus()
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
                                    enabled = !working,
                                    singleLine = true,
                                    visualTransformation = if (shown) VisualTransformation.None else PasswordVisualTransformation(),
                                    trailingIcon = { PassphraseVisibilityToggle(shown) { shown = !shown } },
                                    keyboardOptions = KeyboardOptions(
                                        keyboardType = KeyboardType.Password,
                                        imeAction = ImeAction.Done
                                    ),
                                    keyboardActions = KeyboardActions(onDone = { onAllow() }),
                                    label = { Text(stringResource(R.string.provider_passphrase_hint)) },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .focusRequester(focus)
                                        .autofillPassword { passphrase = it }
                                )
                                Text(
                                    keepSentence(com.pgpony.android.session.SessionPolicy.durationSec()),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(top = 8.dp)
                                )
                            }
                            if (working) CircularProgressIndicator(modifier = Modifier.padding(top = 12.dp))
                        }
                    },
                    confirmButton = {
                        TextButton(
                            enabled = !working && (!needsPassphrase || passphrase.isNotEmpty()),
                            onClick = onAllow
                        ) { Text(stringResource(R.string.provider_consent_allow)) }
                    },
                    dismissButton = {
                        TextButton(enabled = !working, onClick = { cancel() }) {
                            Text(stringResource(R.string.common_button_cancel))
                        }
                    }
                )
            }
        }
    }

    private fun runAllow(op: ProviderCardOpStore.PendingOp, l: Loaded, typed: String) {
        busy.value = true
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.Default) { agree(op, l, typed) }
            when (outcome) {
                Outcome.WrongPassphrase -> {
                    busy.value = false
                    wrong.value = true
                    askPassphrase.value = true
                }
                Outcome.Done -> {
                    setResult(Activity.RESULT_OK, Intent(apiData ?: Intent()))
                    finish()
                }
            }
        }
    }

    /** Runs off the main thread. Stores the result, or returns WrongPassphrase. */
    private fun agree(op: ProviderCardOpStore.PendingOp, l: Loaded, typed: String): Outcome {
        val protectedKey = l.secretKey.s2KUsage.toInt() != 0
        val fromCache = typed.isEmpty()
        val passphrase = typed.ifEmpty { op.clientPassphrase ?: ProviderPassphraseCache.get(l.keyId) ?: "" }
        if (protectedKey && passphrase.isEmpty()) return Outcome.WrongPassphrase
        val privateKey: org.bouncycastle.openpgp.PGPPrivateKey? = try {
            SecretKeyUnlock.extract(l.secretKey, passphrase.toCharArray())
        } catch (e: PGPCryptoError.ResourceLimitExceeded) {
            return store(ProviderCardOpStore.CompletedOp.AgreeFailed(X25519Agreement.Refusal.KEY_UNAVAILABLE.code, e.message ?: "The key's passphrase protection exceeds the allowed cost"))
        } catch (_: PGPException) {
            if (!protectedKey) {
                return store(ProviderCardOpStore.CompletedOp.AgreeFailed(X25519Agreement.Refusal.KEY_UNAVAILABLE.code, "Could not read this key."))
            }
            // A cached passphrase that no longer opens the key is dropped, as decrypt does.
            if (fromCache && op.clientPassphrase == null) ProviderPassphraseCache.clear(l.keyId)
            return Outcome.WrongPassphrase
        }
        if (privateKey == null) {
            return store(ProviderCardOpStore.CompletedOp.AgreeFailed(X25519Agreement.Refusal.KEY_UNAVAILABLE.code, "Could not read this key."))
        }

        val result = try {
            ProviderCardOpStore.CompletedOp.Agreed(X25519Agreement.agree(privateKey, X25519Agreement.splitPoints(op.input)))
        } catch (e: X25519Agreement.RefusedException) {
            ProviderCardOpStore.CompletedOp.AgreeFailed(e.refusal.code, e.message ?: e.refusal.code)
        }

        if (protectedKey && passphrase.isNotEmpty()) {
            if (!fromCache) {
                ProviderPassphraseCache.put(l.keyId, passphrase)
                PassphraseHoldService.startIfWanted(this)
            }
            // 4.5.3 (#57), as the provider's decrypt: a proven passphrase gets a recovery wrap.
            val repo = (application as PGPonyApp).keyRepository
            val fp = l.entity.fingerprint
            Thread { runCatching { repo.ensureKeyRecoverable(fp, passphrase) } }.start()
        }
        return store(result)
    }

    private fun store(result: ProviderCardOpStore.CompletedOp): Outcome {
        ProviderCardOpStore.complete(opKey, result)
        return Outcome.Done
    }

    private fun finishWith(result: ProviderCardOpStore.CompletedOp) {
        ProviderCardOpStore.complete(opKey, result)
        setResult(Activity.RESULT_OK, Intent(apiData ?: Intent()))
        finish()
    }

    private fun cancel() {
        ProviderCardOpStore.abandon(opKey)
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    /** As the other provider dialogs: ignore touches through an obscuring overlay. */
    override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean {
        if (ProviderWindowGuard.isObscured(ev)) return false
        return super.dispatchTouchEvent(ev)
    }
}
