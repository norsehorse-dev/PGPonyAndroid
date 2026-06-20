// CardModels.kt
// PGPony Android — HW Phase 0
//
// Friendly, UI- and repository-facing models summarizing what's on an
// OpenPGP card. Built by OpenPgpCardSession.readCardInfo() from the
// parsed Application Related Data. No Android dependencies.

package com.pgpony.android.crypto.card

import com.pgpony.android.crypto.KeyAlgorithm

/** The three key slots an OpenPGP card exposes. */
enum class CardSlot(val crtTag: Int) {
    SIGNATURE(OpenPgpCard.CRT_SIGNATURE),
    DECRYPTION(OpenPgpCard.CRT_DECRYPTION),
    AUTHENTICATION(OpenPgpCard.CRT_AUTHENTICATION)
}

/** What a single slot holds. [fingerprint] is null when the slot is empty. */
data class CardSlotInfo(
    val slot: CardSlot,
    val algorithm: KeyAlgorithm?,
    val displayAlgorithm: String,
    val fingerprint: String?,
    /** Key generation time as epoch milliseconds, or null if unknown. */
    val generationTime: Long?
) {
    val hasKey: Boolean get() = fingerprint != null
}

/** Summary of an OpenPGP card and the keys provisioned on it. */
data class CardInfo(
    val aidHex: String,
    val manufacturerName: String,
    val serialHex: String,
    val slots: List<CardSlotInfo>,
    val pw1TriesRemaining: Int,
    val pw3TriesRemaining: Int
) {
    fun slotFor(slot: CardSlot): CardSlotInfo? = slots.firstOrNull { it.slot == slot }

    fun fingerprintFor(slot: CardSlot): String? = slotFor(slot)?.fingerprint

    val hasAnyKey: Boolean get() = slots.any { it.hasKey }

    /**
     * The card's primary identity for keyring purposes: the signature
     * slot's fingerprint, falling back to the first populated slot.
     */
    val primaryFingerprint: String?
        get() = fingerprintFor(CardSlot.SIGNATURE) ?: slots.firstOrNull { it.hasKey }?.fingerprint

    val displayName: String get() = "$manufacturerName • $serialHex"
}
