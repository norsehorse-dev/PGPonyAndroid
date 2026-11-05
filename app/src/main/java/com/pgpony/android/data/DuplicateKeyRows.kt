// DuplicateKeyRows.kt
// PGPony Android, 4.8.0 (item 4c): one pgp_keys row per fingerprint.
//
// Two rows could share a fingerprint because the import paths only looked
// for a live row. Delete a key (it moves to Recently Deleted), import the
// same key again, and a second row appeared next to the binned one; restore
// the binned row and the keyring held the key twice. Worse, purging the
// binned row later (Empty bin, or the retention window) wiped the secure
// store entry the two rows share, taking the live copy's material with it.
//
// MIGRATION_12_13 collapses every group of rows that share a fingerprint
// into one, then adds a unique index on the column. This file is the pure
// part: given the rows of one group as column maps, which row stays and
// what it takes from the others. No Android types, so it is unit tested on
// the JVM. Same choices as KeyDeduplicationService's 4.0.0 sweep (secret
// material first, then a card link, then local metadata), plus what that
// sweep never saw: a live row beats a binned one, the merged row is live
// when any row was, and notes from both rows are kept.

package com.pgpony.android.data

object DuplicateKeyRows {

    /** Which row stays, the columns it changes, and the rows to delete. */
    data class Plan(
        val keeperId: String,
        val changes: Map<String, Any?>,
        val deleteIds: List<String>
    )

    /** Bare lowercase hex, the form fingerprints are compared in. */
    fun normalize(fingerprint: String?): String =
        fingerprint.orEmpty().lowercase().filter { !it.isWhitespace() }

    /** The groups of rows that share a fingerprint, two or more rows each. */
    fun groups(rows: List<Map<String, Any?>>): List<List<Map<String, Any?>>> =
        rows.groupBy { normalize(it["fingerprint"] as? String) }
            .filter { (fp, group) -> fp.isNotEmpty() && group.size > 1 }
            .values.toList()

    fun plan(group: List<Map<String, Any?>>): Plan {
        require(group.size > 1) { "a group has at least two rows" }
        val ordered = group.sortedWith(
            compareByDescending<Map<String, Any?>> { score(it) }
                .thenByDescending { long(it, "createdAt") ?: 0L }
                .thenBy { it["id"] as String }
        )
        val keeper = ordered.first()
        val others = ordered.drop(1)
        val merged = LinkedHashMap<String, Any?>()

        fun firstNonNull(vararg cols: String): Map<String, Any?>? =
            ordered.firstOrNull { row -> cols.all { str(row, it) != null } }

        if (str(keeper, "contactId") == null) {
            firstNonNull("contactId")?.let { src ->
                merged["contactId"] = src["contactId"]
                merged["contactName"] = src["contactName"]
                merged["contactPhotoUri"] = src["contactPhotoUri"]
            }
        }
        ordered.maxByOrNull { trustRank(str(it, "trustLevel")) }?.let { best ->
            if (trustRank(str(best, "trustLevel")) > trustRank(str(keeper, "trustLevel"))) {
                merged["trustLevel"] = best["trustLevel"]
            }
        }
        if (!bool(keeper, "isKeyPair") && others.any { bool(it, "isKeyPair") }) merged["isKeyPair"] = 1L
        if (!bool(keeper, "isDefault") && others.any { bool(it, "isDefault") && long(it, "deletedAt") == null }) {
            merged["isDefault"] = 1L
        }
        if (!bool(keeper, "keyServerUploaded") && others.any { bool(it, "keyServerUploaded") }) {
            merged["keyServerUploaded"] = 1L
        }
        if (!bool(keeper, "isSynced") && others.any { bool(it, "isSynced") }) merged["isSynced"] = 1L

        val maxUse = ordered.maxOf { long(it, "decryptUseCount") ?: 0L }
        if (maxUse > (long(keeper, "decryptUseCount") ?: 0L)) merged["decryptUseCount"] = maxUse

        for (col in listOf("lastUploadedAt", "lastCheckedAt", "lastLocalEditAt", "lastBackedUpAt")) {
            val latest = ordered.mapNotNull { long(it, col) }.maxOrNull()
            if (latest != null && latest != long(keeper, col)) merged[col] = latest
        }

        if (str(keeper, "armoredPublicKey").isNullOrEmpty()) {
            ordered.firstOrNull { !str(it, "armoredPublicKey").isNullOrEmpty() }?.let {
                merged["armoredPublicKey"] = it["armoredPublicKey"]
            }
        }

        val notes = ordered.mapNotNull { str(it, "notes")?.trim()?.takeIf { n -> n.isNotEmpty() } }.distinct()
        if (notes.isNotEmpty()) {
            val joined = notes.joinToString("\n\n")
            if (joined != str(keeper, "notes")?.trim()) merged["notes"] = joined
        }

        if (!bool(keeper, "isCardBacked")) {
            others.firstOrNull { bool(it, "isCardBacked") }?.let { src ->
                for (col in CARD_COLUMNS) merged[col] = src[col]
                merged["isCardBacked"] = 1L
            }
        }

        if (!bool(keeper, "isRevoked")) {
            others.firstOrNull { bool(it, "isRevoked") }?.let { src ->
                merged["isRevoked"] = 1L
                merged["revokedAt"] = src["revokedAt"]
                merged["revocationReason"] = src["revocationReason"]
            }
        }
        if (str(keeper, "revocationCertificate") == null) {
            others.firstOrNull { str(it, "revocationCertificate") != null }?.let {
                merged["revocationCertificate"] = it["revocationCertificate"]
            }
        }

        // Live when any row is live; Autocrypt-only when every row is.
        if (long(keeper, "deletedAt") != null && ordered.any { long(it, "deletedAt") == null }) {
            merged["deletedAt"] = null
        }
        if (long(keeper, "autocryptImportedAt") != null && ordered.any { long(it, "autocryptImportedAt") == null }) {
            merged["autocryptImportedAt"] = null
        }

        return Plan(keeper["id"] as String, merged, others.map { it["id"] as String })
    }

    private val CARD_COLUMNS = listOf(
        "cardSerial", "cardAid", "cardManufacturer",
        "cardSigFingerprint", "cardDecFingerprint", "cardAuthFingerprint"
    )

    /** Secret material first, then a card link, then a live row, then local metadata. */
    internal fun score(row: Map<String, Any?>): Long {
        var score = 0L
        if (bool(row, "isKeyPair")) score += 1_000_000
        if (bool(row, "isCardBacked")) score += 100_000
        if (long(row, "deletedAt") == null) score += 50_000
        if (str(row, "contactId") != null) score += 10_000
        score += trustRank(str(row, "trustLevel")) * 1_000L
        if (bool(row, "isDefault")) score += 500
        if (!str(row, "armoredPublicKey").isNullOrEmpty()) score += 100
        score += minOf(long(row, "decryptUseCount") ?: 0L, 9L)
        return score
    }

    /** TrustLevel by stored name, in enum order; an unknown name ranks lowest. */
    private fun trustRank(name: String?): Int =
        TrustLevel.entries.indexOfFirst { it.name == name }

    private fun bool(row: Map<String, Any?>, col: String): Boolean =
        when (val v = row[col]) {
            is Number -> v.toLong() != 0L
            is Boolean -> v
            else -> false
        }

    private fun long(row: Map<String, Any?>, col: String): Long? = (row[col] as? Number)?.toLong()

    private fun str(row: Map<String, Any?>, col: String): String? = row[col] as? String
}
