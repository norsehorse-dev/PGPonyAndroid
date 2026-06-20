// OnboardingGenerateSheet.kt
// PGPony Android
//
// Inline key-generation form shown when the user taps "Generate my first
// key now" on onboarding slide 2. Drives the existing KeyringViewModel
// so the resulting key lands in the same Room database and SecureKeyStore
// as keys generated from the Keyring tab.
//
// Internal state machine: Form -> Loading -> Success | Error.
// On Success, user taps Continue, which dismisses the sheet AND triggers
// the parent OnboardingScreen to advance the pager to the next slide.
//
// Added in Phase 3.1 (Tester Feedback Implementation Plan).

package com.pgpony.android.ui.onboarding

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.background
import com.pgpony.android.R
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.ui.keyring.KeyringViewModel

private sealed interface GenerateMode {
    data object Form : GenerateMode
    data object Loading : GenerateMode
    data object Success : GenerateMode
    data class Error(val message: String) : GenerateMode
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OnboardingGenerateSheet(
    keyringVm: KeyringViewModel,
    onSuccess: () -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val vmState by keyringVm.state.collectAsState()

    var name by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var algorithm by remember { mutableStateOf(KeyAlgorithm.ED25519_CV25519) }
    var passphrase by remember { mutableStateOf("") }
    var confirmPassphrase by remember { mutableStateOf("") }
    var mode by remember { mutableStateOf<GenerateMode>(GenerateMode.Form) }

    // Watch the VM's isGenerating / errorMessage transitions to drive our mode.
    LaunchedEffect(vmState.isGenerating, vmState.errorMessage) {
        if (mode == GenerateMode.Loading && !vmState.isGenerating) {
            val errMsg = vmState.errorMessage
            mode = if (errMsg != null) {
                GenerateMode.Error(errMsg)
            } else {
                GenerateMode.Success
            }
        }
    }

    ModalBottomSheet(
        onDismissRequest = {
            if (mode != GenerateMode.Loading) onDismiss()
        },
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp)
        ) {
            when (val m = mode) {
                GenerateMode.Form -> FormContent(
                    name = name,
                    onNameChange = { name = it },
                    email = email,
                    onEmailChange = { email = it },
                    algorithm = algorithm,
                    onAlgorithmChange = { algorithm = it },
                    passphrase = passphrase,
                    onPassphraseChange = { passphrase = it },
                    confirmPassphrase = confirmPassphrase,
                    onConfirmPassphraseChange = { confirmPassphrase = it },
                    inlineError = (mode as? GenerateMode.Error)?.message,
                    onCancel = onDismiss,
                    onGenerate = {
                        keyringVm.clearError()
                        keyringVm.updateGenerateName(name.trim())
                        keyringVm.updateGenerateEmail(email.trim())
                        keyringVm.updateGenerateAlgorithm(algorithm)
                        keyringVm.updateGeneratePassphrase(passphrase)
                        keyringVm.updateGenerateConfirmPassphrase(confirmPassphrase)
                        mode = GenerateMode.Loading
                        keyringVm.generateKey()
                    }
                )

                GenerateMode.Loading -> LoadingContent()

                GenerateMode.Success -> SuccessContent(
                    onContinue = {
                        keyringVm.clearSuccess()
                        onSuccess()
                    }
                )

                is GenerateMode.Error -> FormContent(
                    name = name,
                    onNameChange = { name = it },
                    email = email,
                    onEmailChange = { email = it },
                    algorithm = algorithm,
                    onAlgorithmChange = { algorithm = it },
                    passphrase = passphrase,
                    onPassphraseChange = { passphrase = it },
                    confirmPassphrase = confirmPassphrase,
                    onConfirmPassphraseChange = { confirmPassphrase = it },
                    inlineError = m.message,
                    onCancel = onDismiss,
                    onGenerate = {
                        keyringVm.clearError()
                        keyringVm.updateGenerateName(name.trim())
                        keyringVm.updateGenerateEmail(email.trim())
                        keyringVm.updateGenerateAlgorithm(algorithm)
                        keyringVm.updateGeneratePassphrase(passphrase)
                        keyringVm.updateGenerateConfirmPassphrase(confirmPassphrase)
                        mode = GenerateMode.Loading
                        keyringVm.generateKey()
                    }
                )
            }
        }
    }
}

// ── Form ───────────────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FormContent(
    name: String,
    onNameChange: (String) -> Unit,
    email: String,
    onEmailChange: (String) -> Unit,
    algorithm: KeyAlgorithm,
    onAlgorithmChange: (KeyAlgorithm) -> Unit,
    passphrase: String,
    onPassphraseChange: (String) -> Unit,
    confirmPassphrase: String,
    onConfirmPassphraseChange: (String) -> Unit,
    inlineError: String?,
    onCancel: () -> Unit,
    onGenerate: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.VpnKey,
            contentDescription = null,
            tint = Color(0xFFF59E0B),
            modifier = Modifier.size(32.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Text(
            stringResource(R.string.onboarding_generate_title),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
    }
    Text(
        stringResource(R.string.onboarding_generate_subtitle),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(bottom = 20.dp)
    )

    // Name
    OutlinedTextField(
        value = name,
        onValueChange = onNameChange,
        label = { Text(stringResource(R.string.keyring_generate_name_label)) },
        placeholder = { Text(stringResource(R.string.onboarding_generate_name_placeholder)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(modifier = Modifier.height(12.dp))

    // Email
    OutlinedTextField(
        value = email,
        onValueChange = onEmailChange,
        label = { Text(stringResource(R.string.keyring_generate_email_label)) },
        placeholder = { Text(stringResource(R.string.onboarding_generate_email_placeholder)) },
        singleLine = true,
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
            keyboardType = KeyboardType.Email
        ),
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(modifier = Modifier.height(16.dp))

    // Key type (v4 vs v6). Mirrors the Keyring-tab generator so a first key
    // created during onboarding can be an RFC 9580 v6 key instead of v4 only.
    // Only the two Ed25519 options are offered here; RSA stays in the full
    // Keyring generator. Reuses the existing algorithm string resources so no
    // new strings are introduced.
    Text(
        stringResource(R.string.keyring_generate_algorithm_label),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(modifier = Modifier.height(4.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        listOf(KeyAlgorithm.ED25519_CV25519, KeyAlgorithm.V6_ED25519).forEach { algo ->
            FilterChip(
                selected = algorithm == algo,
                onClick = { onAlgorithmChange(algo) },
                label = { Text(algo.shortName) }
            )
        }
    }
    Spacer(modifier = Modifier.height(6.dp))
    Text(
        text = if (algorithm.isV6) {
            stringResource(R.string.keyring_generate_algorithm_caption_v6)
        } else {
            stringResource(R.string.keyring_generate_algorithm_caption_ed25519)
        },
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(modifier = Modifier.height(16.dp))

    Text(
        stringResource(R.string.onboarding_generate_passphrase_section_label),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Text(
        stringResource(R.string.onboarding_generate_passphrase_explainer),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
    )

    OutlinedTextField(
        value = passphrase,
        onValueChange = onPassphraseChange,
        label = { Text(stringResource(R.string.encrypt_passphrase_label)) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
            keyboardType = KeyboardType.Password
        ),
        modifier = Modifier.fillMaxWidth()
    )
    if (passphrase.isNotEmpty()) {
        Spacer(modifier = Modifier.height(12.dp))
        OutlinedTextField(
            value = confirmPassphrase,
            onValueChange = onConfirmPassphraseChange,
            label = { Text(stringResource(R.string.keyring_generate_passphrase_confirm_label)) },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = KeyboardType.Password
            ),
            modifier = Modifier.fillMaxWidth()
        )
    }

    // Inline error
    if (inlineError != null) {
        Spacer(modifier = Modifier.height(16.dp))
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
            color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Filled.ErrorOutline,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    inlineError,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }

    Spacer(modifier = Modifier.height(24.dp))

    // Buttons
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        OutlinedButton(
            onClick = onCancel,
            modifier = Modifier.weight(1f).height(48.dp)
        ) {
            Text(stringResource(R.string.common_button_cancel))
        }
        Button(
            onClick = onGenerate,
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8B5CF6)),
            modifier = Modifier.weight(1f).height(48.dp)
        ) {
            Text(stringResource(R.string.onboarding_generate_button), style = MaterialTheme.typography.titleMedium)
        }
    }
}

// ── Loading ───────────────────────────────────────────────────────────

@Composable
private fun LoadingContent() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        CircularProgressIndicator(
            color = Color(0xFF8B5CF6),
            modifier = Modifier.size(48.dp)
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            stringResource(R.string.onboarding_generate_in_progress_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Medium
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            stringResource(R.string.onboarding_generate_in_progress_subtitle),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
    }
}

// ── Success ───────────────────────────────────────────────────────────

@Composable
private fun SuccessContent(onContinue: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .size(80.dp)
                .clip(CircleShape)
                .background(Color(0xFF22C55E).copy(alpha = 0.15f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                Icons.Filled.CheckCircle,
                contentDescription = null,
                tint = Color(0xFF22C55E),
                modifier = Modifier.size(56.dp)
            )
        }
        Spacer(modifier = Modifier.height(20.dp))
        Text(
            stringResource(R.string.onboarding_generate_done_title),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            stringResource(R.string.onboarding_generate_done_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(28.dp))
        Button(
            onClick = onContinue,
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8B5CF6)),
            modifier = Modifier.fillMaxWidth().height(48.dp)
        ) {
            Text(stringResource(R.string.common_button_continue), style = MaterialTheme.typography.titleMedium)
        }
    }
}
