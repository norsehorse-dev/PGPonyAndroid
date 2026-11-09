// KeyGroupsItem.kt
// PGPony Android, 4.8.0 RC8 (item 4n): the Groups section on Key Details.
//
// Owns its own GroupsViewModel (scoped to the Key Details back stack entry),
// so the Key Details view model and screen take no group state. Draws nothing
// until the first read, so the section never flashes "in no group".

package com.pgpony.android.ui.groups

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.viewmodel.compose.viewModel
import com.pgpony.android.R
import com.pgpony.android.data.groups.RecipientGroups
import com.pgpony.android.ui.keyring.KeyGroupsSection

@Composable
fun KeyGroupsItem(fingerprint: String) {
    val vm: GroupsViewModel = viewModel()
    val state by vm.state.collectAsState()
    var naming by remember { mutableStateOf(false) }
    LaunchedEffect(fingerprint) { vm.refresh() }
    if (!state.loaded || state.loadFailed) return

    val fp = RecipientGroups.normalize(fingerprint)
    val (memberOf, others) = state.groups.partition { g -> g.members.any { RecipientGroups.normalize(it) == fp } }
    KeyGroupsSection(
        memberOf = memberOf,
        otherGroups = others,
        onAdd = { vm.addKey(it.id, fingerprint) },
        onRemove = { vm.removeKey(it.id, fingerprint) },
        onNewGroup = { naming = true }
    )
    if (naming) {
        GroupNameDialog(
            title = stringResource(R.string.groups_new),
            onConfirm = { vm.create(it, listOf(fingerprint)) },
            onDismiss = { naming = false }
        )
    }
}
