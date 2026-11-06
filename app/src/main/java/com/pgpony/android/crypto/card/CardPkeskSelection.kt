// CardPkeskSelection.kt
// PGPony Android, 4.7.2 RC6, 4.8.0 RC4
//
// Which addressed PKESK a card decrypt opens.
//
// A message is often encrypted to more than one subkey of the same
// certificate. GnuPG adds every ADSK (key flag 0x0400) next to the newest
// encryption subkey, and a sender may simply list several of the
// recipient's subkeys. Every one of those key IDs is in the paired ring, so
// taking the first PKESK the ring recognises can pick a packet addressed to
// a key that is not in the card's decryption slot. PSO:DECIPHER always uses
// the decryption slot, so that packet fails on the card even though another
// packet in the same message would have opened (issue #108).
//
// 4.8.0 (#108): a card whose decryption slot has no packet may still hold
// one in its authentication slot (an ADSK kept there). PSO:DECIPHER reaches
// that key after MANAGE SECURITY ENVIRONMENT on a 3.3 or later card; see
// pickForCard and OpenPgpCardSession.withDecipherKey.

package com.pgpony.android.crypto.card

internal object CardPkeskSelection {

    /**
     * The v4 key ID of a 40-hex-digit fingerprint (its last 8 bytes), or
     * null for anything else, an empty slot included.
     */
    fun v4KeyId(fingerprintHex: String?): Long? {
        val fp = fingerprintHex?.filterNot { it.isWhitespace() } ?: return null
        if (fp.length != 40) return null
        return fp.substring(24).toULongOrNull(16)?.toLong()
    }

    /**
     * Index into [keyIds] of the addressed packet to open, or -1 when none
     * fits. A packet addressed to [slotKeyId] (the key in the card's
     * decryption slot) wins when the ring has that key. Otherwise the first
     * key ID [inRing] accepts, which is the order used before 4.7.2 RC6.
     * Wildcard (zero) key IDs are never chosen here; pass 2 handles them.
     */
    fun pickAddressed(keyIds: List<Long>, slotKeyId: Long?, inRing: (Long) -> Boolean): Int {
        if (slotKeyId != null && slotKeyId != 0L) {
            val i = keyIds.indexOfFirst { it == slotKeyId && inRing(it) }
            if (i >= 0) return i
        }
        return keyIds.indexOfFirst { it != 0L && inRing(it) }
    }

    /** 4.8.0 (#108): what [pickForCard] decided. */
    sealed class CardPick {
        /** Open the packet at [index] with the key in [slot]. */
        data class Open(val index: Int, val slot: CardSlot) : CardPick()

        /** The only packet this card holds a key for names its authentication
         *  key, and the card has no MSE to decipher with it. */
        data class AuthSlotWithoutMse(val index: Int) : CardPick()

        /** No addressed packet names a key in the ring. */
        object None : CardPick()
    }

    /**
     * 4.8.0 (#108): the addressed packet to open on a card, and with which
     * slot. In order:
     *   1. a packet addressed to [decSlotKeyId] (the decryption slot), opened
     *      as before with no MSE;
     *   2. a packet addressed to [authSlotKeyId] (the authentication slot,
     *      where a user keeps an ADSK): opened through that slot when
     *      [mseSupported], otherwise [CardPick.AuthSlotWithoutMse];
     *   3. the first key ID [inRing] accepts, through the decryption slot,
     *      which is the pre-4.7.2 fallback for a card whose slots could not
     *      be read.
     * Only packets whose key is in the ring count. Wildcard (zero) key IDs are
     * never chosen here; pass 2 handles them.
     */
    fun pickForCard(
        keyIds: List<Long>,
        decSlotKeyId: Long?,
        authSlotKeyId: Long?,
        mseSupported: Boolean,
        inRing: (Long) -> Boolean
    ): CardPick {
        if (decSlotKeyId != null && decSlotKeyId != 0L) {
            val i = keyIds.indexOfFirst { it == decSlotKeyId && inRing(it) }
            if (i >= 0) return CardPick.Open(i, CardSlot.DECRYPTION)
        }
        if (authSlotKeyId != null && authSlotKeyId != 0L) {
            val i = keyIds.indexOfFirst { it == authSlotKeyId && inRing(it) }
            if (i >= 0) {
                return if (mseSupported) CardPick.Open(i, CardSlot.AUTHENTICATION) else CardPick.AuthSlotWithoutMse(i)
            }
        }
        val i = pickAddressed(keyIds, null, inRing)
        return if (i >= 0) CardPick.Open(i, CardSlot.DECRYPTION) else CardPick.None
    }
}
