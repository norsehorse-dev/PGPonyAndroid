// OpenPgpCardReader.kt
// PGPony Android — HW Phase 1
//
// Drives NFC reader mode for the duration of a card scan. enableReaderMode
// binds NFC dispatch to the foreground Activity, so this is owned by
// MainActivity (via startCardScan / stopCardScan) and driven by the
// CardScanScreen's lifecycle.
//
// onTagDiscovered runs on a binder thread — exactly where we want the
// blocking APDU exchange to happen (never the main thread). The parsed
// result is posted back to the main thread so Compose state updates are
// safe.

package com.pgpony.android.nfc

import android.app.Activity
import android.content.Context
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import com.pgpony.android.crypto.card.CardInfo
import com.pgpony.android.crypto.card.OpenPgpCardException
import com.pgpony.android.crypto.card.OpenPgpCardSession
import java.util.concurrent.atomic.AtomicBoolean

class OpenPgpCardReader(private val activity: Activity) {

    private val adapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(activity)
    private val mainHandler = Handler(Looper.getMainLooper())

    // One-shot guard. Reader mode stays enabled for the whole screen
    // (so the OS never grabs the tag and shows "no supported application"),
    // but only the FIRST tap after each start runs the operation —
    // subsequent taps are ignored until the next start() / startOperation().
    // Without this, holding the card after a completed operation would
    // re-run it (e.g. re-attempting a PIN change with the now-wrong old
    // PIN and burning a retry).
    private val handled = AtomicBoolean(false)

    /**
     * Start reader-mode polling. [onResult] fires on the main thread once
     * per tap (success or failure) and polling continues until [stop], so
     * a fumbled tap can simply be retried. Returns false (and never calls
     * [onResult]) if NFC is unavailable or disabled.
     */
    fun start(onResult: (Result<CardInfo>) -> Unit): Boolean =
        startOperation({ it.readCardInfo() }, onResult)

    /**
     * HW Phase 2 — generalized form: run an arbitrary [operation] against
     * the card on each tap and deliver its result on the main thread. The
     * [operation] runs on the NFC binder thread (the right place for the
     * blocking APDU exchange) and is handed a freshly-constructed
     * [OpenPgpCardSession]; it's responsible for SELECTing as needed
     * (readCardInfo and changeUserPin both do). Used for PIN change now
     * and signing in Phase 2b.
     */
    fun <T> startOperation(
        operation: (OpenPgpCardSession) -> T,
        onResult: (Result<T>) -> Unit
    ): Boolean {
        val nfc = adapter ?: return false
        if (!nfc.isEnabled) return false

        handled.set(false)

        val flags = NfcAdapter.FLAG_READER_NFC_A or
            NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK

        val extras = Bundle().apply {
            // Slow the presence-check a little so a brief wobble doesn't
            // read as a removal mid-exchange.
            putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250)
        }

        nfc.enableReaderMode(activity, { tag ->
            // One tap per start. Ignored taps leave reader mode engaged,
            // so the system NFC dispatcher never sees the tag.
            if (handled.compareAndSet(false, true)) {
                handleTag(tag, operation, onResult)
            }
        }, flags, extras)
        return true
    }

    fun stop() {
        adapter?.disableReaderMode(activity)
    }

    /**
     * Re-arm for one more tap WITHOUT re-enabling reader mode. Used by the
     * scan screen so the user can lift-and-tap to read again in place.
     * We only reset the one-shot flag — reader mode stays engaged (so the
     * OS never grabs the tag) and, because enableReaderMode isn't called
     * again, an already-present card isn't re-dispatched, so there's no
     * re-read loop: the next genuine tap is what fires onTagDiscovered.
     */
    fun rearm() {
        handled.set(false)
    }

    private fun <T> handleTag(
        tag: Tag,
        operation: (OpenPgpCardSession) -> T,
        onResult: (Result<T>) -> Unit
    ) {
        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            mainHandler.post {
                onResult(Result.failure(
                    OpenPgpCardException.NotAnOpenPgpCard("This tag doesn't speak ISO-DEP / 7816")
                ))
            }
            return
        }
        var transport: IsoDepCardTransport? = null
        val result: Result<T> = try {
            transport = IsoDepCardTransport(isoDep)
            Result.success(operation(OpenPgpCardSession(transport)))
        } catch (e: OpenPgpCardException) {
            Result.failure(e)
        } catch (e: Exception) {
            Result.failure(
                OpenPgpCardException.Communication("Unexpected error talking to card: ${e.message}", e)
            )
        } finally {
            transport?.close()
        }
        mainHandler.post { onResult(result) }
    }

    companion object {
        fun isNfcAvailable(context: Context): Boolean =
            NfcAdapter.getDefaultAdapter(context) != null

        fun isNfcEnabled(context: Context): Boolean =
            NfcAdapter.getDefaultAdapter(context)?.isEnabled == true
    }
}
