// CardPkeskSelection.kt
// PGPony Android, 4.7.2 RC6
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
}
