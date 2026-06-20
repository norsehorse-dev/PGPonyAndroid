// OpenPgpCardException.kt
// PGPony Android — HW Phase 0
//
// Error taxonomy for the OpenPGP card layer. Kept transport-agnostic
// (no android.nfc types) so the protocol code and its tests don't pull
// in the framework. The IsoDep transport translates TagLostException
// into Communication / TagLost here.

package com.pgpony.android.crypto.card

sealed class OpenPgpCardException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {

    /** SELECT failed or the AID isn't an OpenPGP application. */
    class NotAnOpenPgpCard(message: String = "This card is not an OpenPGP card") :
        OpenPgpCardException(message)

    /** Tag/IO error while talking to the card (link dropped, removed mid-op). */
    class Communication(message: String, cause: Throwable? = null) :
        OpenPgpCardException(message, cause)

    /** The card left the field before the operation completed. */
    class TagLost(message: String = "Card moved away — hold it still and try again", cause: Throwable? = null) :
        OpenPgpCardException(message, cause)

    /** The card returned a non-success status word. */
    class CardStatus(val sw: Int, message: String) : OpenPgpCardException(message) {
        companion object {
            fun of(sw: Int): OpenPgpCardException {
                val sw1 = (sw ushr 8) and 0xFF
                // 0x63 0xCx — verification failed, x tries remaining.
                if (sw1 == OpenPgpCard.SW1_VERIFY_REMAINING) {
                    return WrongPin(sw and 0x0F)
                }
                val text = when (sw) {
                    OpenPgpCard.SW_SECURITY_NOT_SATISFIED ->
                        "PIN verification required (0x6982)"
                    OpenPgpCard.SW_AUTH_METHOD_BLOCKED ->
                        "PIN is blocked — too many wrong attempts (0x6983)"
                    OpenPgpCard.SW_CONDITIONS_NOT_SATISFIED ->
                        "Conditions of use not satisfied (0x6985)"
                    OpenPgpCard.SW_FILE_NOT_FOUND ->
                        "Data object not found (0x6A82)"
                    OpenPgpCard.SW_INS_NOT_SUPPORTED ->
                        "Instruction not supported by this card (0x6D00)"
                    else -> "Card returned status 0x%04X".format(sw)
                }
                return CardStatus(sw, text)
            }
        }
    }

    /**
     * VERIFY / CHANGE REFERENCE DATA rejected the supplied PIN.
     * [triesRemaining] is how many attempts are left before the PIN
     * blocks (0 means it just blocked, or is already blocked).
     */
    class WrongPin(val triesRemaining: Int) : OpenPgpCardException(
        if (triesRemaining > 0)
            "Wrong PIN — $triesRemaining ${if (triesRemaining == 1) "try" else "tries"} remaining"
        else
            "Wrong PIN — no tries remaining; the PIN is now blocked"
    )

    /** A response was structurally invalid (bad TLV, short data, etc.). */
    class Malformed(message: String, cause: Throwable? = null) :
        OpenPgpCardException(message, cause)
}
