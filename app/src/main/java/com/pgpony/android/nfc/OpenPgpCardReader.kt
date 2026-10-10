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
import com.pgpony.android.crypto.card.OpenPgpCard
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
    /**
     * 4.1.0 - [holdUntilRemovedMs], when greater than zero, keeps the card
     * connected and reader mode engaged after a SUCCESSFUL operation until
     * the user lifts the card (or the cap elapses). [onResult] is delivered
     * only once that wait is over, so a caller that tears down reader mode on
     * result - ProviderCardOpActivity, which must close to return its result
     * to the calling mail app - never leaves a tag sitting in the field for
     * the platform dispatcher to grab. [onAwaitingRemoval] fires on the main
     * thread when the wait begins, so the UI can say why it is still up.
     *
     * The in-app card screens do not need this: they hold reader mode for as
     * long as the screen is on top, which already covers the lift.
     */
    fun <T> startOperation(
        operation: (OpenPgpCardSession) -> T,
        onResult: (Result<T>) -> Unit,
        holdUntilRemovedMs: Long = 0L,
        onAwaitingRemoval: (() -> Unit)? = null
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
                handleTag(tag, operation, onResult, holdUntilRemovedMs, onAwaitingRemoval)
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
        onResult: (Result<T>) -> Unit,
        holdUntilRemovedMs: Long = 0L,
        onAwaitingRemoval: (() -> Unit)? = null
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
            val t = IsoDepCardTransport(isoDep)
            transport = t
            val value = operation(OpenPgpCardSession(t))
            // 4.1.0 - hold the card before anyone can tear reader mode down.
            // awaitRemoval swallows its own failures and returns, so this can
            // only delay the result, never turn a completed operation into a
            // failed one.
            if (holdUntilRemovedMs > 0L) {
                onAwaitingRemoval?.let { cb -> mainHandler.post { cb() } }
                t.awaitRemoval(holdUntilRemovedMs)
            }
            Result.success(value)
        } catch (e: OpenPgpCardException.NotAnOpenPgpCard) {
            // 4.7.0 (item 29, #43): a key that answers but will not open its
            // OpenPGP application over NFC (the Nitrokey 3 turns it off there)
            // gets a plain explanation instead of the raw status word.
            Result.failure(
                if (e.noResponse || e.sw == OpenPgpCard.SW_FILE_NOT_FOUND || e.sw == OpenPgpCard.SW_CONDITIONS_NOT_SATISFIED)
                    OpenPgpCardException.NotAnOpenPgpCard(NFC_OPENPGP_UNAVAILABLE, e.sw, e.noResponse)
                else e
            )
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
        /** Matched by ErrorTextRules (err_nfc_openpgp_unavailable). */
        const val NFC_OPENPGP_UNAVAILABLE =
            "This key did not open its OpenPGP application over NFC. Some keys, the Nitrokey 3 among them, " +
                "turn OpenPGP off over NFC. If your key has USB, plug it in and try again."

        fun isNfcAvailable(context: Context): Boolean =
            NfcAdapter.getDefaultAdapter(context) != null

        fun isNfcEnabled(context: Context): Boolean =
            NfcAdapter.getDefaultAdapter(context)?.isEnabled == true
    }
}
