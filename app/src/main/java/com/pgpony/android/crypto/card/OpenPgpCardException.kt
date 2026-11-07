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

    /** SELECT failed or the AID isn't an OpenPGP application. [sw] is the
     *  status word SELECT returned, when it got that far. */
    class NotAnOpenPgpCard(
        message: String = "This card is not an OpenPGP card",
        val sw: Int? = null,
        /** 4.7.0 (item 29, #43): SELECT got no status word back at all. */
        val noResponse: Boolean = false
    ) : OpenPgpCardException(message)

    /** Tag/IO error while talking to the card (link dropped, removed mid-op). */
    class Communication(
        message: String,
        cause: Throwable? = null,
        /** 4.7.0 (item 29): the reply was shorter than a status word. */
        val shortResponse: Boolean = false
    ) : OpenPgpCardException(message, cause)

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

    /**
     * 4.7.0 (item 13): the ADMIN PIN (PW3) was wrong, kept apart from
     * [WrongPin] so the screen can name it: a blocked admin PIN needs a card
     * reset, a blocked user PIN only the admin PIN.
     */
    class WrongAdminPin(val triesRemaining: Int) : OpenPgpCardException(
        "Wrong admin PIN. Tries remaining: $triesRemaining"
    )

    /**
     * 4.7.0 RC4 (item 13): a slot chosen for a move already holds a different
     * key and the user did not ask to replace it. Raised before any PIN is sent.
     */
    class SlotsOccupied : OpenPgpCardException(
        "A chosen slot on this security key already holds another key"
    )

    /**
     * 4.8.0 (4p): the card cannot hold a key chosen for a move, with what it
     * answered in protocol terms ([detail], e.g. "slot B6: key import, status
     * 6A80"). The message is the usual "cannot hold" text with the detail in
     * parentheses after it; the move screen shows the localized text followed
     * by the same untranslated detail, so a report says which command failed.
     */
    class CardRefused(val detail: String, cause: Throwable? = null) : OpenPgpCardException(
        "${KeyToCardService.UNSUPPORTED_MESSAGE} ($detail)", cause
    )

    /** A response was structurally invalid (bad TLV, short data, etc.). */
    class Malformed(message: String, cause: Throwable? = null) :
        OpenPgpCardException(message, cause)
}
