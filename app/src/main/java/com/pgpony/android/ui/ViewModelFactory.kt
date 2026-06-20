// ViewModelFactory.kt
// PGPony Android

package com.pgpony.android.ui

import android.content.SharedPreferences
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.pgpony.android.contacts.ContactsService
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.ui.contacts.ContactsViewModel
import com.pgpony.android.ui.encrypt.EncryptDecryptViewModel
import com.pgpony.android.ui.exchange.ExchangeViewModel
import com.pgpony.android.ui.keyring.KeyDetailViewModel
import com.pgpony.android.ui.keyring.KeyringViewModel
import com.pgpony.android.ui.settings.SettingsViewModel

class PGPonyViewModelFactory(
    private val repo: KeyRepository,
    private val prefs: SharedPreferences,
    private val contactsService: ContactsService
) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        return when {
            modelClass.isAssignableFrom(KeyringViewModel::class.java) ->
                KeyringViewModel(repo) as T
            // Phase A4a: per-screen VM for the key-detail surface. The
            // load(fingerprint) call is made by the screen in a
            // LaunchedEffect; the factory itself doesn't need the
            // fingerprint at construction time.
            //
            // Phase A4b: ContactsService injected for the Link to
            // Contact / Auto-match flows.
            modelClass.isAssignableFrom(KeyDetailViewModel::class.java) ->
                KeyDetailViewModel(repo, contactsService) as T
            modelClass.isAssignableFrom(EncryptDecryptViewModel::class.java) ->
                EncryptDecryptViewModel(repo) as T
            modelClass.isAssignableFrom(ExchangeViewModel::class.java) ->
                ExchangeViewModel(repo) as T
            modelClass.isAssignableFrom(SettingsViewModel::class.java) ->
                SettingsViewModel(repo, prefs) as T
            modelClass.isAssignableFrom(ContactsViewModel::class.java) ->
                ContactsViewModel(repo, contactsService, prefs) as T
            else -> throw IllegalArgumentException("Unknown ViewModel: ${modelClass.name}")
        }
    }
}
