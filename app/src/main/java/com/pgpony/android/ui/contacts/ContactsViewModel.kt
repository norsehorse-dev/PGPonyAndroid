// ContactsViewModel.kt
// PGPony Android — Phase A0 + A9
//
// ViewModel for the Contacts screen. Manages permission state,
// contacts list with key linkage, auto-match, and bulk keyserver
// discovery.
//
// Phase A9 additions:
//   • searchQuery state + setSearchQuery action — drives the search
//     bar at top of ContactsScreen. Filter is applied via
//     [filteredLinkedContacts] / [filteredUnlinkedContacts] derived
//     properties on the UI state (matches iOS searchText behavior).
//   • checkedEmails exposed as part of state — lets the
//     UnlinkedContactRow show a "minus-circle, already checked"
//     indicator instead of the search icon for emails that already
//     returned no result during bulk scan or single-row lookup. The
//     set is reloaded from prefs on every state-relevant mutation
//     (single discovery, bulk scan finish, cache clear).

package com.pgpony.android.ui.contacts

import android.content.SharedPreferences
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.contacts.ContactWithKeys
import com.pgpony.android.contacts.ContactsService
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.network.KeyServerRepository
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class ContactsUiState(
    val isAuthorized: Boolean = false,
    val isLoading: Boolean = false,
    val contactsList: List<ContactWithKeys> = emptyList(),
    // Bulk scan
    val bulkScanActive: Boolean = false,
    val bulkScanProgress: Int = 0,
    val bulkScanTotal: Int = 0,
    val bulkScanFound: Int = 0,
    val bulkScanFinished: Boolean = false,
    // Single discovery
    val discoveringEmail: String? = null,
    // Messages
    val errorMessage: String? = null,
    val successMessage: String? = null,
    // ── Phase A9 ──────────────────────────────────────────────────────
    /** Search bar text. Empty string disables filtering — both
     *  linked and unlinked sections show all rows. Matching is
     *  case-insensitive substring on displayName OR any email
     *  address, matching iOS searchText behavior. */
    val searchQuery: String = "",
    /** Emails that have already been checked against keyservers and
     *  came up empty. Persisted in SharedPreferences under
     *  `pgpony_keyserver_checked_emails`; this field mirrors it for
     *  UI use without forcing the screen to read prefs directly.
     *  Refreshed by [ContactsViewModel.reloadCheckedEmails] after
     *  any mutation (single discovery, bulk-scan finish, cache
     *  clear). */
    val checkedEmails: Set<String> = emptySet()
) {
    val linkedContacts: List<ContactWithKeys>
        get() = contactsList.filter { it.linkedKeys.isNotEmpty() }
    val unlinkedContacts: List<ContactWithKeys>
        get() = contactsList.filter { it.linkedKeys.isEmpty() }

    /**
     * Phase A9 — linked contacts narrowed by the current search
     * query. Empty query → all linked contacts. Non-empty query →
     * case-insensitive match on displayName OR any email address
     * substring. Matches iOS matchesSearch().
     */
    val filteredLinkedContacts: List<ContactWithKeys>
        get() = if (searchQuery.isBlank()) linkedContacts
                else linkedContacts.filter { matchesQuery(it, searchQuery) }

    /** Phase A9 — unlinked contacts narrowed by search query. */
    val filteredUnlinkedContacts: List<ContactWithKeys>
        get() = if (searchQuery.isBlank()) unlinkedContacts
                else unlinkedContacts.filter { matchesQuery(it, searchQuery) }

    /**
     * Phase A9 — case-insensitive substring match on a contact's
     * displayName OR any of its email addresses. Helper for the
     * filteredLinkedContacts / filteredUnlinkedContacts derived
     * properties.
     */
    private fun matchesQuery(contact: ContactWithKeys, query: String): Boolean {
        val q = query.lowercase()
        if (contact.displayName.lowercase().contains(q)) return true
        return contact.emails.any { it.lowercase().contains(q) }
    }
}

class ContactsViewModel(
    private val repo: KeyRepository,
    private val contactsService: ContactsService,
    private val prefs: SharedPreferences
) : ViewModel() {

    private val _state = MutableStateFlow(ContactsUiState())
    val state: StateFlow<ContactsUiState> = _state.asStateFlow()

    private var bulkScanJob: Job? = null

    companion object {
        private const val CHECKED_EMAILS_KEY = "pgpony_keyserver_checked_emails"
    }

    fun checkAuthorization() {
        _state.value = _state.value.copy(isAuthorized = contactsService.isAuthorized())
        if (contactsService.isAuthorized()) {
            // A9 — load the checked-emails set so the UnlinkedContactRow
            // indicators are correct on first paint after a cold start.
            reloadCheckedEmails()
            refreshContacts()
        }
    }

    fun onPermissionGranted() {
        _state.value = _state.value.copy(isAuthorized = true)
        // A9 — same as checkAuthorization, but in the just-granted path.
        reloadCheckedEmails()
        refreshContacts()
    }

    // ── Refresh Contacts List ──────────────────────────────────────────

    fun refreshContacts() {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true)
            try {
                val allKeys = repo.getAllKeys()
                val contacts = contactsService.buildContactsList(allKeys)
                _state.value = _state.value.copy(
                    contactsList = contacts,
                    isLoading = false
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isLoading = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.contacts_vm_error_load_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── Auto-Match ─────────────────────────────────────────────────────

    fun runAutoMatch() {
        viewModelScope.launch {
            try {
                val allKeys = repo.getAllKeys()
                val matches = contactsService.batchAutoMatch(allKeys)
                var count = 0
                for ((fingerprint, match) in matches) {
                    repo.getByFingerprint(fingerprint)?.let { key ->
                        repo.updateContactLink(
                            fingerprint = fingerprint,
                            contactId = match.contactId,
                            contactName = match.displayName,
                            contactPhotoUri = match.photoUri
                        )
                        count++
                    }
                }
                if (count > 0) {
                    _state.value = _state.value.copy(
                        successMessage = if (count == 1) PGPonyApp.instance.getString(R.string.contacts_vm_status_linked_one_format, count) else PGPonyApp.instance.getString(R.string.contacts_vm_status_linked_many_format, count)
                    )
                    refreshContacts()
                } else {
                    _state.value = _state.value.copy(
                        successMessage = PGPonyApp.instance.getString(R.string.contacts_vm_status_no_new_matches)
                    )
                }
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    errorMessage = PGPonyApp.instance.getString(R.string.contacts_vm_error_auto_match_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── Single Key Discovery ───────────────────────────────────────────

    fun discoverKeyForEmail(email: String, contactName: String) {
        viewModelScope.launch {
            _state.value = _state.value.copy(discoveringEmail = email)
            try {
                val result = KeyServerRepository.shared.searchByEmail(email)
                if (result != null) {
                    repo.importArmoredKey(result)
                    markEmailChecked(email)
                    _state.value = _state.value.copy(
                        discoveringEmail = null,
                        successMessage = "Key found and imported for $contactName"
                    )
                    refreshContacts()
                } else {
                    markEmailChecked(email)
                    _state.value = _state.value.copy(
                        discoveringEmail = null,
                        errorMessage = PGPonyApp.instance.getString(R.string.contacts_vm_error_no_key_for_email_format, email)
                    )
                }
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    discoveringEmail = null,
                    errorMessage = PGPonyApp.instance.getString(R.string.contacts_vm_error_search_failed_format, e.message ?: "")
                )
            }
        }
    }

    // ── Bulk Keyserver Discovery ────────────────────────────────────────

    fun startBulkScan() {
        if (_state.value.bulkScanActive) return

        bulkScanJob = viewModelScope.launch {
            _state.value = _state.value.copy(
                bulkScanActive = true,
                bulkScanProgress = 0,
                bulkScanTotal = 0,
                bulkScanFound = 0,
                bulkScanFinished = false
            )

            try {
                val contacts = contactsService.fetchContactsWithEmail()
                val checked = getCheckedEmails()

                contactsService.bulkKeyserverDiscovery(
                    contacts = contacts,
                    checkedEmails = checked,
                    onProgress = { current, total, found ->
                        _state.value = _state.value.copy(
                            bulkScanProgress = current,
                            bulkScanTotal = total,
                            bulkScanFound = found
                        )
                    },
                    onFound = { email, armoredKey ->
                        try {
                            repo.importArmoredKey(armoredKey)
                            markEmailChecked(email)
                        } catch (_: Exception) {
                            // Key might already exist — mark as checked anyway
                            markEmailChecked(email)
                        }
                    },
                    // A9 — fires for every queried email, including
                    // no-result and network-failure cases. Without this
                    // the "already checked" indicator would never light
                    // up after bulk scans (pre-A9 bug).
                    onChecked = { email -> markEmailChecked(email) }
                )

                _state.value = _state.value.copy(
                    bulkScanActive = false,
                    bulkScanFinished = true
                )
                refreshContacts()
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    bulkScanActive = false,
                    errorMessage = PGPonyApp.instance.getString(R.string.contacts_vm_error_bulk_scan_failed_format, e.message ?: "")
                )
            }
        }
    }

    fun cancelBulkScan() {
        bulkScanJob?.cancel()
        _state.value = _state.value.copy(bulkScanActive = false)
    }

    // ── Phase A9: Search ──────────────────────────────────────────────

    /**
     * Update the search query. ContactsScreen's SearchBar calls this
     * on every keystroke; the derived [ContactsUiState.filteredLinkedContacts]
     * + [ContactsUiState.filteredUnlinkedContacts] recompute via Compose
     * recomposition of the StateFlow consumer.
     *
     * No debouncing — the filter is in-memory list filtering (cheap
     * even for 500+ contacts) and debouncing would feel laggy
     * compared to iOS's instant-filter searchable bar.
     */
    fun setSearchQuery(query: String) {
        _state.value = _state.value.copy(searchQuery = query)
    }

    /** Phase A9 convenience — clear the search bar from the X button. */
    fun clearSearchQuery() {
        _state.value = _state.value.copy(searchQuery = "")
    }

    // ── Checked Emails Cache ───────────────────────────────────────────

    private fun getCheckedEmails(): Set<String> {
        return prefs.getStringSet(CHECKED_EMAILS_KEY, emptySet()) ?: emptySet()
    }

    /**
     * Phase A9 — re-read the prefs-backed checked-emails set into
     * UI state. Called after any operation that may have added or
     * cleared entries (single discovery, bulk-scan finish, cache
     * reset). Cheap (single SharedPreferences read).
     */
    private fun reloadCheckedEmails() {
        _state.value = _state.value.copy(checkedEmails = getCheckedEmails())
    }

    private fun markEmailChecked(email: String) {
        val current = getCheckedEmails().toMutableSet()
        current.add(email.lowercase().trim())
        prefs.edit().putStringSet(CHECKED_EMAILS_KEY, current).apply()
        // A9 — mirror into UI state so UnlinkedContactRow can show
        // the "already checked" indicator immediately.
        reloadCheckedEmails()
    }

    fun clearCheckedEmails() {
        prefs.edit().remove(CHECKED_EMAILS_KEY).apply()
        // A9 — also reflect the clear in UI state so any rows
        // currently showing the minus-circle revert to the search
        // icon without needing a manual refresh.
        _state.value = _state.value.copy(
            successMessage = PGPonyApp.instance.getString(R.string.contacts_vm_status_cache_cleared),
            checkedEmails = emptySet()
        )
    }

    fun clearError() { _state.value = _state.value.copy(errorMessage = null) }
    fun clearSuccess() { _state.value = _state.value.copy(successMessage = null) }
}
