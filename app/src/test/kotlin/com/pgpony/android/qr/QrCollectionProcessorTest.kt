package com.pgpony.android.qr

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

class QrCollectionProcessorTest {
    @Test fun serializesCollectionOffUiThreadAndRejectsBusyFrames() = runBlocking {
        Executors.newSingleThreadExecutor { Thread(it,"qr-collection-ui") }.asCoroutineDispatcher().use { ui ->
            Executors.newSingleThreadExecutor { Thread(it,"qr-collection-worker") }.asCoroutineDispatcher().use { worker ->
                val session = QrScanSession().apply { resume() }
                val scope = CoroutineScope(SupervisorJob() + ui)
                val entered = CountDownLatch(1)
                val release = CountDownLatch(1)
                val delivered = CompletableDeferred<Unit>()
                val calls = AtomicInteger()
                val processor = QrCollectionProcessor(session,scope,worker) {
                    calls.incrementAndGet()
                    assertTrue(Thread.currentThread().name.startsWith("qr-collection-worker"))
                    entered.countDown()
                    check(release.await(5,TimeUnit.SECONDS))
                    PublicKeyQrResult.Progress(1,2,true,false)
                }
                try {
                    withContext(ui) {
                        assertTrue(processor.submit("first",session.token) {
                            assertTrue(Thread.currentThread().name.startsWith("qr-collection-ui"))
                            assertEquals(PublicKeyQrResult.Progress(1,2,true,false),it)
                            delivered.complete(Unit)
                        })
                    }
                    // Coroutine debug mode appends its ID to executor thread names.
                    assertTrue(entered.await(5,TimeUnit.SECONDS))
                    withContext(ui) {
                        assertTrue(processor.isBusy)
                        repeat(20) { assertFalse(processor.submit("busy",session.token) { fail("Busy frame delivered") }) }
                    }
                    release.countDown()
                    withTimeout(5000) { delivered.await() }
                    withContext(ui) { assertFalse(processor.isBusy) }
                    assertEquals(1,calls.get())
                } finally { release.countDown(); scope.cancel() }
            }
        }
    }

    @Test fun dropsCompletedCollectionFromPausedGeneration() = runBlocking {
        Executors.newSingleThreadExecutor().asCoroutineDispatcher().use { ui ->
            Executors.newSingleThreadExecutor().asCoroutineDispatcher().use { worker ->
                val session = QrScanSession().apply { resume() }
                val scope = CoroutineScope(SupervisorJob() + ui)
                val entered = CountDownLatch(1)
                val release = CountDownLatch(1)
                val exited = CountDownLatch(1)
                val callbacks = AtomicInteger()
                val processor = QrCollectionProcessor(session,scope,worker) {
                    entered.countDown()
                    check(release.await(5,TimeUnit.SECONDS))
                    exited.countDown()
                    PublicKeyQrResult.Complete("late")
                }
                try {
                    withContext(ui) { assertTrue(processor.submit("frame",session.token) { callbacks.incrementAndGet() }) }
                    assertTrue(entered.await(5,TimeUnit.SECONDS))
                    session.pause()
                    session.resume()
                    release.countDown()
                    assertTrue(exited.await(5,TimeUnit.SECONDS))
                    withContext(worker) {}
                    withContext(ui) { assertFalse(processor.isBusy) }
                    assertEquals(0,callbacks.get())
                } finally { release.countDown(); scope.cancel() }
            }
        }
    }

    @Test fun cancellationBeforeLaunchRunsReleasesBusyAndRejectsFurtherSubmissions() = runBlocking {
        Executors.newSingleThreadExecutor().asCoroutineDispatcher().use { ui ->
            val session = QrScanSession().apply { resume() }
            val scope = CoroutineScope(SupervisorJob() + ui)
            val processor = QrCollectionProcessor(session,scope,ui) { fail("Cancelled collection ran"); PublicKeyQrResult.Malformed }
            withContext(ui) {
                assertTrue(processor.submit("frame",session.token) { fail("Cancelled result delivered") })
                assertTrue(processor.isBusy)
                scope.cancel()
            }
            withContext(ui) {
                assertFalse(processor.isBusy)
                assertFalse(processor.submit("frame",session.token) { fail("Closed scope delivered") })
            }
        }
    }

    @Test fun collectionFailureDeliversOneMalformedResultAndCallbackFailureIsNotRetried() = runBlocking {
        Executors.newSingleThreadExecutor().asCoroutineDispatcher().use { ui ->
            Executors.newSingleThreadExecutor().asCoroutineDispatcher().use { worker ->
                val session = QrScanSession().apply { resume() }
                val callbackError = CompletableDeferred<Throwable>()
                val scope = CoroutineScope(SupervisorJob() + ui + CoroutineExceptionHandler { _,error -> callbackError.complete(error) })
                val callbackCount = AtomicInteger()
                val processor = QrCollectionProcessor(session,scope,worker) { error("invalid recovered certificate") }
                try {
                    withContext(ui) { assertTrue(processor.submit("frame",session.token) {
                        callbackCount.incrementAndGet()
                        assertEquals(PublicKeyQrResult.Malformed,it)
                        error("callback failed")
                    }) }
                    assertEquals("callback failed",withTimeout(5000) { callbackError.await() }.message)
                    withContext(ui) { assertFalse(processor.isBusy) }
                    assertEquals(1,callbackCount.get())
                } finally { scope.cancel() }
            }
        }
    }
}
