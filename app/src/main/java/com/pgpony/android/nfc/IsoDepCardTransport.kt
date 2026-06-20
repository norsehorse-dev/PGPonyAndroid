// IsoDepCardTransport.kt
// PGPony Android — HW Phase 1
//
// CardTransport over android.nfc.tech.IsoDep — the ISO 14443-4 / 7816
// channel an OpenPGP card (YubiKey 5 NFC, Token2 PIN+, Nitrokey 3 NFC)
// exposes over NFC. transceive() must run off the main thread; the NFC
// reader-mode callback already delivers on a binder thread, so callers
// satisfy that for free.

package com.pgpony.android.nfc

import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import com.pgpony.android.crypto.card.CardTransport
import com.pgpony.android.crypto.card.OpenPgpCardException
import java.io.IOException

class IsoDepCardTransport(private val isoDep: IsoDep) : CardTransport {

    init {
        if (!isoDep.isConnected) {
            try {
                isoDep.connect()
            } catch (e: IOException) {
                throw OpenPgpCardException.Communication("Could not connect to card: ${e.message}", e)
            }
        }
        // Generous timeout — on-card RSA-4096 / touch-confirm (UIF) can
        // take a couple of seconds. (UIF prompting itself is Phase 2.)
        runCatching { isoDep.timeout = 20_000 }
    }

    override fun transceive(commandApdu: ByteArray): ByteArray {
        return try {
            isoDep.transceive(commandApdu)
        } catch (e: TagLostException) {
            throw OpenPgpCardException.TagLost(cause = e)
        } catch (e: IOException) {
            throw OpenPgpCardException.Communication("Card I/O failed: ${e.message}", e)
        }
    }

    fun close() {
        runCatching { isoDep.close() }
    }
}
