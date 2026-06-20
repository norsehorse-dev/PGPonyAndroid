// ResponseApdu.kt
// PGPony Android — HW Phase 0
//
// Parses a raw card response into its data body and 2-byte status word.
// No Android dependencies — unit-testable.

package com.pgpony.android.crypto.card

data class ResponseApdu(val data: ByteArray, val sw1: Int, val sw2: Int) {

    /** Combined status word, e.g. 0x9000. */
    val sw: Int get() = (sw1 shl 8) or sw2

    val isSuccess: Boolean get() = sw == OpenPgpCard.SW_SUCCESS

    /** True when SW1 = 0x61 — more response data is available via GET RESPONSE. */
    val hasMoreData: Boolean get() = sw1 == OpenPgpCard.SW1_MORE_DATA

    /** True when SW1 = 0x6C — wrong Le; SW2 carries the correct length. */
    val wrongLe: Boolean get() = sw1 == OpenPgpCard.SW1_WRONG_LE

    fun swHex(): String = "0x%04X".format(sw)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ResponseApdu) return false
        return sw1 == other.sw1 && sw2 == other.sw2 && data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + sw1
        result = 31 * result + sw2
        return result
    }

    companion object {
        /** Split a raw response (… data … SW1 SW2) into a ResponseApdu. */
        fun parse(raw: ByteArray): ResponseApdu {
            if (raw.size < 2) {
                throw OpenPgpCardException.Communication(
                    "Response too short (${raw.size} bytes) — expected at least the status word"
                )
            }
            val sw1 = raw[raw.size - 2].toInt() and 0xFF
            val sw2 = raw[raw.size - 1].toInt() and 0xFF
            val body = raw.copyOfRange(0, raw.size - 2)
            return ResponseApdu(body, sw1, sw2)
        }
    }
}
