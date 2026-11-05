// PassphraseVisibilityToggle.kt
// PGPony Android, 4.7.2 RC4 (moved here in 4.8.0 so every passphrase field can use it).

package com.pgpony.android.ui.components

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.pgpony.android.R

/**
 * The eye button on a passphrase field. Masked by default; a tester could not
 * tell that a paste had gone wrong because only dots showed. Card PIN fields
 * deliberately do not get one.
 */
@Composable
fun PassphraseVisibilityToggle(shown: Boolean, onToggle: () -> Unit) {
    IconButton(onClick = onToggle) {
        Icon(
            if (shown) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
            contentDescription = stringResource(
                if (shown) R.string.encrypt_password_hide else R.string.encrypt_password_show
            )
        )
    }
}
