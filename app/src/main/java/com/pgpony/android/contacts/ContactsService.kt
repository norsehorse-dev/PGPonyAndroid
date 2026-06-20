// ContactsService.kt
// PGPony Android — Phase A0 + A9
//
// Android equivalent of iOS ContactsService.swift. Queries
// ContactsContract by email, auto-matches PGP keys to contacts,
// retrieves contact photos, and performs bulk keyserver discovery.
//
// Phase A9 additions:
//   • ContactWithKeys.thumbnail — Bitmap loaded eagerly in
//     buildContactsList so the ContactsScreen avatar UI doesn't
//     need to plumb the service down through composables.
//   • findContactByIdentifier — parity with iOS findContact(byIdentifier:);
//     used when a PGPKeyEntity has a contactId but the cached
//     contactName might be stale.
//   • contactDisplayName(forId) — looks up the current name for a
//     contact identifier so other surfaces (KeyDetailScreen, etc.)
//     can refresh stale name caches.
//
// Permission: android.permission.READ_CONTACTS (runtime request)

package com.pgpony.android.contacts

import android.Manifest
import android.content.ContentResolver
import android.content.Context
import android.content.pm.PackageManager
import android.database.Cursor
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.ContactsContract
import androidx.core.content.ContextCompat
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.network.KeyServerRepository
import kotlinx.coroutines.delay

// ── Data Classes ───────────────────────────────────────────────────────

data class ContactMatch(
    val contactId: String,
    val displayName: String,
    val emails: List<String>,
    val photoUri: String?,
    val matchedEmail: String
)

/**
 * Contact + the PGP keys linked to it. Phase A9 added [thumbnail]
 * (eagerly loaded by [ContactsService.buildContactsList]) so the
 * avatar UI on ContactsScreen can render synchronously without
 * needing a reference to ContactsService.
 *
 * [thumbnail] is null when:
 *   • the contact has no photo in the device's address book
 *   • the photo couldn't be decoded (rare)
 *   • the BitmapFactory call failed under memory pressure
 *
 * In all null cases the UI falls back to a gradient circle with
 * initials (see ContactAvatar.kt).
 */
data class ContactWithKeys(
    val contactId: String,
    val displayName: String,
    val emails: List<String>,
    val photoUri: String?,
    val linkedKeys: List<PGPKeyEntity>,
    val thumbnail: Bitmap? = null
)

data class DeviceContact(
    val contactId: String,
    val displayName: String,
    val emails: List<String>,
    val photoUri: String?
)

// ── ContactsService ────────────────────────────────────────────────────

class ContactsService(private val context: Context) {

    private val resolver: ContentResolver = context.contentResolver

    // Photo cache by contact ID
    private val photoCache = mutableMapOf<String, Bitmap?>()

    companion object {
        @Volatile private var instance: ContactsService? = null

        fun getInstance(context: Context): ContactsService {
            return instance ?: synchronized(this) {
                instance ?: ContactsService(context.applicationContext).also { instance = it }
            }
        }
    }

    // ── Authorization ──────────────────────────────────────────────────

    fun isAuthorized(): Boolean {
        return ContextCompat.checkSelfPermission(
            context, Manifest.permission.READ_CONTACTS
        ) == PackageManager.PERMISSION_GRANTED
    }

    // ── Fetch All Contacts With Email ──────────────────────────────────

    fun fetchContactsWithEmail(): List<DeviceContact> {
        if (!isAuthorized()) return emptyList()

        val contactsMap = mutableMapOf<String, DeviceContact>()

        val projection = arrayOf(
            ContactsContract.CommonDataKinds.Email.CONTACT_ID,
            ContactsContract.CommonDataKinds.Email.DISPLAY_NAME_PRIMARY,
            ContactsContract.CommonDataKinds.Email.ADDRESS,
            ContactsContract.CommonDataKinds.Email.PHOTO_URI
        )

        val cursor: Cursor? = resolver.query(
            ContactsContract.CommonDataKinds.Email.CONTENT_URI,
            projection,
            null, null,
            "${ContactsContract.CommonDataKinds.Email.DISPLAY_NAME_PRIMARY} ASC"
        )

        cursor?.use {
            val idCol = it.getColumnIndex(ContactsContract.CommonDataKinds.Email.CONTACT_ID)
            val nameCol = it.getColumnIndex(ContactsContract.CommonDataKinds.Email.DISPLAY_NAME_PRIMARY)
            val emailCol = it.getColumnIndex(ContactsContract.CommonDataKinds.Email.ADDRESS)
            val photoCol = it.getColumnIndex(ContactsContract.CommonDataKinds.Email.PHOTO_URI)

            while (it.moveToNext()) {
                val contactId = it.getString(idCol) ?: continue
                val name = it.getString(nameCol) ?: ""
                val email = it.getString(emailCol) ?: continue
                val photoUri = it.getString(photoCol)

                val existing = contactsMap[contactId]
                if (existing != null) {
                    // Add email to existing contact
                    contactsMap[contactId] = existing.copy(
                        emails = existing.emails + email
                    )
                } else {
                    contactsMap[contactId] = DeviceContact(
                        contactId = contactId,
                        displayName = name,
                        emails = listOf(email),
                        photoUri = photoUri
                    )
                }
            }
        }

        return contactsMap.values.toList()
    }

    // ── Find Contact by Email ──────────────────────────────────────────

    fun findContactByEmail(email: String): DeviceContact? {
        if (!isAuthorized() || email.isBlank()) return null

        val projection = arrayOf(
            ContactsContract.CommonDataKinds.Email.CONTACT_ID,
            ContactsContract.CommonDataKinds.Email.DISPLAY_NAME_PRIMARY,
            ContactsContract.CommonDataKinds.Email.ADDRESS,
            ContactsContract.CommonDataKinds.Email.PHOTO_URI
        )

        val cursor: Cursor? = resolver.query(
            ContactsContract.CommonDataKinds.Email.CONTENT_URI,
            projection,
            "${ContactsContract.CommonDataKinds.Email.ADDRESS} = ?",
            arrayOf(email.lowercase().trim()),
            null
        )

        cursor?.use {
            if (it.moveToFirst()) {
                val contactId = it.getString(it.getColumnIndex(ContactsContract.CommonDataKinds.Email.CONTACT_ID)) ?: return null
                val name = it.getString(it.getColumnIndex(ContactsContract.CommonDataKinds.Email.DISPLAY_NAME_PRIMARY)) ?: ""
                val addr = it.getString(it.getColumnIndex(ContactsContract.CommonDataKinds.Email.ADDRESS)) ?: email
                val photoUri = it.getString(it.getColumnIndex(ContactsContract.CommonDataKinds.Email.PHOTO_URI))

                return DeviceContact(
                    contactId = contactId,
                    displayName = name,
                    emails = listOf(addr),
                    photoUri = photoUri
                )
            }
        }
        return null
    }

    // ── A9: Find Contact by Identifier ─────────────────────────────────

    /**
     * Look up a contact by its ContactsContract identifier — the same
     * value PGPKeyEntity.contactId stores after a link operation.
     *
     * Equivalent to iOS findContact(byIdentifier:). Used when a key
     * has a contactId but the cached contactName might be stale
     * (e.g. user renamed a contact in Contacts after linking).
     *
     * Returns null if the contact has been deleted from the device
     * since linking, or if READ_CONTACTS permission has been
     * revoked.
     */
    fun findContactByIdentifier(contactId: String): DeviceContact? {
        if (!isAuthorized() || contactId.isBlank()) return null

        val projection = arrayOf(
            ContactsContract.Contacts._ID,
            ContactsContract.Contacts.DISPLAY_NAME_PRIMARY,
            ContactsContract.Contacts.PHOTO_URI
        )

        val cursor: Cursor? = resolver.query(
            ContactsContract.Contacts.CONTENT_URI,
            projection,
            "${ContactsContract.Contacts._ID} = ?",
            arrayOf(contactId),
            null
        )

        cursor?.use {
            if (it.moveToFirst()) {
                val idIdx = it.getColumnIndex(ContactsContract.Contacts._ID)
                val nameIdx = it.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME_PRIMARY)
                val photoIdx = it.getColumnIndex(ContactsContract.Contacts.PHOTO_URI)
                if (idIdx < 0 || nameIdx < 0) return null

                val id = it.getString(idIdx) ?: return null
                val name = it.getString(nameIdx) ?: ""
                val photoUri = if (photoIdx >= 0) it.getString(photoIdx) else null

                // Fetch emails for this contact in a second query.
                val emails = fetchEmailsForContact(id)
                return DeviceContact(
                    contactId = id,
                    displayName = name,
                    emails = emails,
                    photoUri = photoUri
                )
            }
        }
        return null
    }

    /**
     * Helper for [findContactByIdentifier] — returns all email
     * addresses associated with a contact identifier. Used to
     * populate DeviceContact.emails when fetching by ID rather than
     * by email (the email-based fetch in [findContactByEmail]
     * already has the address in hand).
     */
    private fun fetchEmailsForContact(contactId: String): List<String> {
        val out = mutableListOf<String>()
        val cursor = resolver.query(
            ContactsContract.CommonDataKinds.Email.CONTENT_URI,
            arrayOf(ContactsContract.CommonDataKinds.Email.ADDRESS),
            "${ContactsContract.CommonDataKinds.Email.CONTACT_ID} = ?",
            arrayOf(contactId),
            null
        )
        cursor?.use {
            val addrIdx = it.getColumnIndex(ContactsContract.CommonDataKinds.Email.ADDRESS)
            if (addrIdx < 0) return@use
            while (it.moveToNext()) {
                it.getString(addrIdx)?.let { addr -> out.add(addr) }
            }
        }
        return out
    }

    /**
     * Convenience — returns just the display name for a contact
     * identifier, or null if not found. Used by other surfaces
     * (KeyDetailScreen, KeyringScreen) to refresh stale cached
     * names without needing to materialize a full DeviceContact.
     */
    fun contactDisplayName(forId: String?): String? {
        if (forId.isNullOrBlank()) return null
        return findContactByIdentifier(forId)?.displayName
    }

    // ── Auto-Match Key to Contact ──────────────────────────────────────

    fun autoMatch(keyEmail: String): ContactMatch? {
        if (keyEmail.isBlank()) return null
        val contact = findContactByEmail(keyEmail.lowercase().trim()) ?: return null

        return ContactMatch(
            contactId = contact.contactId,
            displayName = contact.displayName,
            emails = contact.emails,
            photoUri = contact.photoUri,
            matchedEmail = keyEmail.lowercase().trim()
        )
    }

    /**
     * Match all keys that don't already have a contactId.
     * Returns list of (fingerprint, ContactMatch) pairs.
     */
    fun batchAutoMatch(keys: List<PGPKeyEntity>): List<Pair<String, ContactMatch>> {
        val results = mutableListOf<Pair<String, ContactMatch>>()
        for (key in keys) {
            if (key.contactId == null && key.userEmail.isNotBlank()) {
                val match = autoMatch(key.userEmail)
                if (match != null) {
                    results.add(key.fingerprint to match)
                }
            }
        }
        return results
    }

    // ── Build Contacts List ────────────────────────────────────────────

    /**
     * Build a list of all contacts with email addresses, annotated with
     * which PGP keys are linked to each contact. Matches iOS
     * buildContactsList.
     *
     * Phase A9 — also eagerly loads each contact's thumbnail bitmap
     * via [getContactPhoto]. Bitmaps are cached on the service so
     * subsequent rebuilds are cheap; the first build is N decodes
     * where N is the number of contacts with email addresses,
     * typically <500 even on big address books and gated behind
     * the isLoading spinner.
     *
     * Eager loading was chosen over lazy-load-per-row because:
     *   • The avatar UI lives in a LazyColumn — lazy loading at row
     *     scroll time would mean photoCache misses during scroll,
     *     producing visible pop-in.
     *   • photoCache survives across rebuilds, so subsequent refreshes
     *     are effectively free.
     */
    fun buildContactsList(allKeys: List<PGPKeyEntity>): List<ContactWithKeys> {
        val contacts = fetchContactsWithEmail()
        val keysByContactId = allKeys.filter { it.contactId != null }.groupBy { it.contactId!! }
        val keysByEmail = allKeys.filter { it.contactId == null && it.userEmail.isNotBlank() }
            .groupBy { it.userEmail.lowercase() }

        return contacts.map { contact ->
            val linked = mutableListOf<PGPKeyEntity>()

            // Keys linked by contactId
            keysByContactId[contact.contactId]?.let { linked.addAll(it) }

            // Keys matching by email (not already linked)
            for (email in contact.emails) {
                keysByEmail[email.lowercase()]?.forEach { key ->
                    if (linked.none { it.fingerprint == key.fingerprint }) {
                        linked.add(key)
                    }
                }
            }

            ContactWithKeys(
                contactId = contact.contactId,
                displayName = contact.displayName,
                emails = contact.emails,
                photoUri = contact.photoUri,
                linkedKeys = linked,
                // A9: eager photo load (cached after first hit)
                thumbnail = getContactPhoto(contact.contactId)
            )
        }
    }

    // ── Contact Photo ──────────────────────────────────────────────────

    fun getContactPhoto(contactId: String?): Bitmap? {
        if (contactId == null) return null
        photoCache[contactId]?.let { return it }

        try {
            val contactUri = ContactsContract.Contacts.CONTENT_URI.buildUpon()
                .appendPath(contactId).build()
            val photoStream = ContactsContract.Contacts.openContactPhotoInputStream(
                resolver, contactUri, false
            ) ?: return null

            val bitmap = BitmapFactory.decodeStream(photoStream)
            photoStream.close()
            photoCache[contactId] = bitmap
            return bitmap
        } catch (_: Exception) {
            return null
        }
    }

    fun clearPhotoCache() {
        photoCache.clear()
    }

    // ── Bulk Keyserver Discovery ────────────────────────────────────────

    /**
     * Search keys.openpgp.org for public keys matching contact
     * emails. Throttled to 1 request per second to avoid rate
     * limiting. Matches iOS bulk scan behavior.
     *
     * @param contacts      List of contacts to check.
     * @param checkedEmails Set of emails already checked (skipped —
     *                      avoids re-querying addresses that already
     *                      returned no result on a previous run).
     * @param onProgress    Called with (current, total, found) for
     *                      progress UI.
     * @param onFound       Called when a key IS found for an email.
     *                      Receives the email + the armored key text
     *                      so the caller can import + mark linked.
     * @param onChecked     Phase A9 — called for EVERY queried email
     *                      regardless of outcome (success, no-result,
     *                      network failure). Lets the caller persist
     *                      to the "already checked" set so the
     *                      UnlinkedContactRow can show the muted
     *                      minus-circle indicator on next render.
     *                      Pre-A9 the no-result and failure paths
     *                      didn't notify, so checkedEmails never grew
     *                      from bulk scans — only single-row lookups.
     */
    suspend fun bulkKeyserverDiscovery(
        contacts: List<DeviceContact>,
        checkedEmails: Set<String>,
        onProgress: (current: Int, total: Int, found: Int) -> Unit,
        onFound: suspend (email: String, armoredKey: String) -> Unit,
        onChecked: (email: String) -> Unit = {}
    ) {
        val keyServer = KeyServerRepository.shared
        val emailsToCheck = contacts.flatMap { it.emails }
            .map { it.lowercase().trim() }
            .distinct()
            .filter { it !in checkedEmails }

        val total = emailsToCheck.size
        var found = 0

        for ((index, email) in emailsToCheck.withIndex()) {
            onProgress(index + 1, total, found)

            try {
                val result = keyServer.searchByEmail(email)
                if (result != null) {
                    found++
                    onFound(email, result)
                }
                // A9 — mark checked whether or not a key was found.
                onChecked(email)
            } catch (_: Exception) {
                // A9 — also mark on network failure. The user can
                // clear the cache from the Options menu to retry
                // later if they suspect the failure was transient.
                onChecked(email)
            }

            // Throttle: 1 request per second
            if (index < emailsToCheck.size - 1) {
                delay(1000)
            }
        }

        onProgress(total, total, found)
    }
}
