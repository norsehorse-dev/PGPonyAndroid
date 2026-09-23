// SshTermuxSheet.kt
// PGPony Android, 4.6.0 (item 16): how to use PGPony keys for SSH in Termux.
//
// PGPony answers SSH sign requests through its SSH authentication service
// (SshAuthenticationService). The bridge from Termux to that service is
// OkcAgent; upstream OkcAgent is unmaintained and only talks to OpenKeychain,
// so PGPony points to the maintained fork, which lets the user pick PGPony as
// its crypto provider and keeps working with the stock "okc-agents" Termux
// package. Reached from Settings and from Key Detail's menu.

package com.pgpony.android.ui.settings

import android.content.Intent
import android.net.Uri
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
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pgpony.android.R

/** Where the OkcAgent fork's releases live. */
const val OKCAGENT_FORK_URL = "https://github.com/norsehorse-dev/OkcAgent/releases/latest"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SshTermuxSheet(onDismiss: () -> Unit) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val context = LocalContext.current
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
                .padding(bottom = 32.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Filled.Terminal, null, tint = Color(0xFF8B5CF6), modifier = Modifier.size(36.dp))
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    stringResource(R.string.ssh_help_title),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                stringResource(R.string.ssh_help_body),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(bottom = 16.dp)
            )
            Button(
                onClick = {
                    runCatching {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(OKCAGENT_FORK_URL)))
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text(stringResource(R.string.ssh_help_get)) }
            Text(
                stringResource(R.string.ssh_help_steps),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 16.dp, bottom = 12.dp)
            )
            Text(
                stringResource(R.string.ssh_help_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
