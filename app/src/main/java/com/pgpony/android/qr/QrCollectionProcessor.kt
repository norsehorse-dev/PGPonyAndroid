package com.pgpony.android.qr

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Serializes public-key collection and recovery without queuing camera payloads.
 * Call submit on the main thread with a scope whose dispatcher is Main. Collection runs
 * on the worker dispatcher; results return through the scope only while their token is active.
 * Cancel the owning scope on disposal. A running CPU operation may finish, but cannot deliver.
 */
class QrCollectionProcessor(
    private val session: QrScanSession,
    private val scope: CoroutineScope,
    private val workerDispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val collect: (String) -> PublicKeyQrResult
) {
    private val busy = AtomicBoolean(false)
    val isBusy: Boolean get() = busy.get()

    /** Returns false when stopped or busy; rejected text is never retained for later processing. */
    fun submit(text: String, token: Long, onResult: (PublicKeyQrResult) -> Unit): Boolean {
        if (!session.isActive(token) || !scope.isActive || !busy.compareAndSet(false,true)) return false
        val job = scope.launch {
            if (!session.isActive(token)) return@launch
            val result = try {
                withContext(workerDispatcher) {
                    if (session.isActive(token)) collect(text) else null
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                PublicKeyQrResult.Malformed
            }
            // Callback failures propagate once; they must never be retried as collection failures.
            if (result != null && session.isActive(token)) onResult(result)
        }
        // Completion also covers cancellation before the launch body starts. Only this handler
        // releases admission, so an older completion cannot clear a newer operation's busy flag.
        job.invokeOnCompletion { busy.set(false) }
        return true
    }
}
