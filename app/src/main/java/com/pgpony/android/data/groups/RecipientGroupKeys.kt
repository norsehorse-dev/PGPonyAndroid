// RecipientGroupKeys.kt
// PGPony Android, 4.8.0 RC8 (item 4n): RecipientGroups' rules applied to
// PGPKeyEntity rows, for the Encrypt picker, the share target's picker, the
// Groups screen and Key Details. Data layer only (no Compose), so PGPony
// Desktop can take it with PGPKeyEntity.

package com.pgpony.android.data.groups

import com.pgpony.android.data.PGPKeyEntity

/** The recipient picker's order: your own keys first, then everyone else A to Z. */
fun List<PGPKeyEntity>.inPickerOrder(): List<PGPKeyEntity> =
    RecipientGroups.pickerOrder(
        this,
        isOwn = { it.isOwnKey },
        name = { it.userName },
        email = { it.userEmail },
        userId = { it.userID },
        fingerprint = { it.fingerprint }
    )

/** How a key is named in a group's left-out list and member rows. */
val PGPKeyEntity.groupLabel: String
    get() = userName.ifBlank { userEmail.ifBlank { shortFingerprint } }

/**
 * What a group pick needs to know about each key, by normalized fingerprint.
 * [live] are the keyring's keys, [binned] the ones in Recently Deleted; a
 * fingerprint in both counts as live.
 */
fun groupMemberFacts(live: List<PGPKeyEntity>, binned: List<PGPKeyEntity>): Map<String, GroupMemberFacts> {
    val out = HashMap<String, GroupMemberFacts>()
    for (k in binned) {
        val fp = RecipientGroups.normalize(k.fingerprint)
        out[fp] = GroupMemberFacts(fp, k.groupLabel, deleted = true)
    }
    for (k in live) {
        val fp = RecipientGroups.normalize(k.fingerprint)
        out[fp] = GroupMemberFacts(
            fingerprint = fp,
            label = k.groupLabel,
            revoked = k.isRevoked,
            expired = k.isExpired,
            noCertificate = k.isCardBacked && k.armoredPublicKey == null
        )
    }
    return out
}
