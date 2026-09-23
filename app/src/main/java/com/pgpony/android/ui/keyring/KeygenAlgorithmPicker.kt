// KeygenAlgorithmPicker.kt
// PGPony Android, 4.4.0 RC3
//
// The key-generation algorithm picker, shared by the Keyring generate sheet
// and the onboarding generate sheet so the two cannot drift. Organized by
// security tier (Classical, Post-Quantum) with the niche compatibility options
// (RSA, LibrePGP) tucked behind an Advanced expander, and a caption explaining
// the selected algorithm. The group lists live on KeyAlgorithm.

package com.pgpony.android.ui.keyring

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.crypto.KeyAlgorithm

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun KeygenAlgorithmPicker(
    selected: KeyAlgorithm,
    onSelect: (KeyAlgorithm) -> Unit,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier.fillMaxWidth()) {
        Text(
            stringResource(R.string.keyring_generate_algorithm_label),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(8.dp))

        AlgorithmGroup(
            title = stringResource(R.string.keyring_generate_algorithm_group_classical),
            algorithms = KeyAlgorithm.generatableClassical,
            selected = selected,
            onSelect = onSelect
        )
        Spacer(Modifier.height(10.dp))
        AlgorithmGroup(
            title = stringResource(R.string.keyring_generate_algorithm_group_pqc),
            algorithms = KeyAlgorithm.generatablePostQuantum,
            selected = selected,
            onSelect = onSelect
        )
        Spacer(Modifier.height(10.dp))

        // item 14 (#56): interop tier — the three ML-KEM-768+X25519 wire shapes
        // (v6 / v4 / v5), the same key for different tools. Collapsed unless the
        // selection lives here, since it is a compatibility choice, not a
        // recommended one.
        var interopExpanded by remember {
            mutableStateOf(selected in KeyAlgorithm.generatableInterop)
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { interopExpanded = !interopExpanded }
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = if (interopExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.width(4.dp))
            Text(
                stringResource(R.string.keyring_generate_algorithm_group_interop),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        AnimatedVisibility(visible = interopExpanded) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                KeyAlgorithm.generatableInterop.forEach { algo ->
                    FilterChip(
                        selected = selected == algo,
                        onClick = { onSelect(algo) },
                        label = { AlgorithmChipLabel(algo) }
                    )
                }
            }
        }

        Spacer(Modifier.height(10.dp))

        // Advanced / compatibility, collapsed unless the selection lives here.
        var advancedExpanded by remember {
            mutableStateOf(selected in KeyAlgorithm.generatableAdvanced)
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { advancedExpanded = !advancedExpanded }
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = if (advancedExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.width(4.dp))
            Text(
                stringResource(R.string.keyring_generate_algorithm_group_advanced),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        AnimatedVisibility(visible = advancedExpanded) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                KeyAlgorithm.generatableAdvanced.forEach { algo ->
                    FilterChip(
                        selected = selected == algo,
                        onClick = { onSelect(algo) },
                        label = { AlgorithmChipLabel(algo) }
                    )
                }
            }
        }

        Spacer(Modifier.height(8.dp))
        Text(
            text = captionFor(selected),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        // 4.6.0 (item 13): set expectations for every post-quantum choice.
        if (selected.isPostQuantum) {
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.keyring_generate_algorithm_experimental_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.tertiary
            )
        }
    }
}

/** 4.6.0 (item 13): the chip text, with an "Experimental" line on post-quantum keys. */
@Composable
private fun AlgorithmChipLabel(algo: KeyAlgorithm) {
    if (!algo.isPostQuantum) {
        Text(algo.shortName)
        return
    }
    Column(modifier = Modifier.padding(vertical = 4.dp)) {
        Text(algo.shortName)
        Text(
            stringResource(R.string.keyring_generate_algorithm_experimental),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.tertiary
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AlgorithmGroup(
    title: String,
    algorithms: List<KeyAlgorithm>,
    selected: KeyAlgorithm,
    onSelect: (KeyAlgorithm) -> Unit
) {
    Text(
        title,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(Modifier.height(4.dp))
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        algorithms.forEach { algo ->
            FilterChip(
                selected = selected == algo,
                onClick = { onSelect(algo) },
                label = { AlgorithmChipLabel(algo) }
            )
        }
    }
}

@Composable
private fun captionFor(algorithm: KeyAlgorithm): String = when {
    algorithm == KeyAlgorithm.MLDSA87_ED448_V6 ->
        stringResource(R.string.keyring_generate_algorithm_caption_pqc_sign_87)
    algorithm.isCompositeSign ->
        stringResource(R.string.keyring_generate_algorithm_caption_pqc_sign)
    algorithm == KeyAlgorithm.MLKEM768_X25519_V4 ->
        stringResource(R.string.keyring_generate_algorithm_caption_pqc_v4)
    algorithm.isComposite && algorithm.isV6 ->
        stringResource(R.string.keyring_generate_algorithm_caption_pqc_ietf)
    algorithm.isComposite ->
        stringResource(R.string.keyring_generate_algorithm_caption_pqc_librepgp)
    algorithm.isV6 ->
        stringResource(R.string.keyring_generate_algorithm_caption_v6)
    algorithm == KeyAlgorithm.ED25519_CV25519 ->
        stringResource(R.string.keyring_generate_algorithm_caption_ed25519)
    else ->
        stringResource(R.string.keyring_generate_algorithm_caption_rsa)
}
