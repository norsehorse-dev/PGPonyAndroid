// GroupsViewModel.kt
// PGPony Android, 4.8.0 RC8 (item 4n): drives the Groups page under the Keyring
// and the Groups section on Key Details. Every call goes through
// RecipientGroupStore on Dispatchers.IO; a failure reaches the screen as a
// string resource, never exception text. Name problems are returned to the
// dialog that asked, which shows them under the field.

package com.pgpony.android.ui.groups

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.groups.GroupMemberFacts
import com.pgpony.android.data.groups.GroupNameException
import com.pgpony.android.data.groups.GroupNameProblem
import com.pgpony.android.data.groups.LeftOutReason
import com.pgpony.android.data.groups.RecipientGroup
import com.pgpony.android.data.groups.RecipientGroupStore
import com.pgpony.android.data.groups.RecipientGroups
import com.pgpony.android.data.groups.groupMemberFacts
import com.pgpony.android.data.groups.inPickerOrder
import com.pgpony.android.data.repository.KeyRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class GroupsViewModel : ViewModel() {

    data class UiState(
        /** False until the first read, so no empty state flashes. */
        val loaded: Boolean = false,
        val loadFailed: Boolean = false,
        val groups: List<RecipientGroup> = emptyList(),
        /** The keyring's live keys, in the picker's order. */
        val keys: List<PGPKeyEntity> = emptyList(),
        /** Live and binned keys by normalized fingerprint. */
        val facts: Map<String, GroupMemberFacts> = emptyMap(),
        /** One snackbar line; the screen calls [consumeMessage] once shown. */
        val message: String? = null
    )

    private val store: RecipientGroupStore get() = PGPonyApp.instance.recipientGroups
    private val repo: KeyRepository get() = PGPonyApp.instance.keyRepository

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun refresh() {
        viewModelScope.launch { reload() }
    }

    fun consumeMessage() {
        _state.value = _state.value.copy(message = null)
    }

    private suspend fun reload() {
        val read = withContext(Dispatchers.IO) {
            runCatching {
                val live = repo.getAllKeys()
                val binned = repo.getDeletedKeys()
                Triple(store.all(), live.inPickerOrder(), groupMemberFacts(live, binned))
            }
        }
        read.onSuccess { (groups, keys, facts) ->
            _state.value = _state.value.copy(
                loaded = true, loadFailed = false, groups = groups, keys = keys, facts = facts
            )
        }.onFailure {
            _state.value = _state.value.copy(loaded = true, loadFailed = true)
        }
    }

    /** Why [fingerprint] cannot be picked from a group now, or null when it can. */
    fun reasonFor(fingerprint: String): LeftOutReason? =
        RecipientGroups.reasonFor(_state.value.facts[RecipientGroups.normalize(fingerprint)])

    /** The label for a member, whether or not its key is live. */
    fun labelFor(fingerprint: String): String {
        val fp = RecipientGroups.normalize(fingerprint)
        return _state.value.facts[fp]?.label ?: RecipientGroups.shortFingerprint(fp)
    }

    /** A new group. Returns null once saved, or why the name was refused. */
    suspend fun create(name: String, fingerprints: Collection<String>): GroupNameProblem? =
        nameChange { store.create(name, fingerprints) }

    /** Renames a group. Returns null once saved, or why the name was refused. */
    suspend fun rename(id: String, name: String): GroupNameProblem? =
        nameChange { store.rename(id, name) }

    fun setMembers(id: String, fingerprints: Collection<String>) = change { store.setMembers(id, fingerprints) }

    fun delete(id: String) = change { store.delete(id) }

    fun addKey(id: String, fingerprint: String) = change { store.addMember(id, fingerprint) }

    fun removeKey(id: String, fingerprint: String) = change { store.removeMember(id, fingerprint) }

    private suspend fun nameChange(block: suspend () -> Unit): GroupNameProblem? {
        val problem = withContext(Dispatchers.IO) {
            try {
                block()
                null
            } catch (e: GroupNameException) {
                e.problem
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                failed()
                null
            }
        }
        reload()
        return problem
    }

    private fun change(block: suspend () -> Unit) {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    block()
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    failed()
                }
            }
            reload()
        }
    }

    private fun failed() {
        _state.value = _state.value.copy(message = PGPonyApp.instance.getString(R.string.groups_error_save))
    }
}
