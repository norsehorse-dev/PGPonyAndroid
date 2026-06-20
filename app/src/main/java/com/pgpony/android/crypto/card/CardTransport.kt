// CardTransport.kt
// PGPony Android — HW Phase 0
//
// The seam between the OpenPGP card protocol logic and the physical
// link. OpenPgpCardSession depends only on this interface, so the
// protocol is unit-testable with a fake transport and the real
// implementation (IsoDepCardTransport, Phase 1) can be swapped without
// touching the protocol code. A future USB-CCID transport would also
// implement this.

package com.pgpony.android.crypto.card

interface CardTransport {

    /**
     * Send one raw command APDU and return the raw response APDU
     * (response data followed by the 2-byte status word). Implementations
     * should throw [OpenPgpCardException.Communication] /
     * [OpenPgpCardException.TagLost] on link failure.
     */
    @Throws(OpenPgpCardException::class)
    fun transceive(commandApdu: ByteArray): ByteArray
}
