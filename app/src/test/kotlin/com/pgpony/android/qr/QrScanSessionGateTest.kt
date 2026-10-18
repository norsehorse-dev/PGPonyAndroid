package com.pgpony.android.qr

import org.junit.Assert.*
import org.junit.Test

class QrScanSessionGateTest {
    @Test fun invalidatesQueuedFramesAcrossPauseAndResume() {
        val session = QrScanSession()
        session.resume()
        val old = session.token
        assertTrue(session.isActive(old))
        session.pause()
        assertFalse(session.isActive(old))
        session.resume()
        assertFalse(session.isActive(old))
        assertTrue(session.isActive(session.token))
    }
    @Test fun completesOnceAndCannotReopenAfterCompletionOrClose() {
        val session = QrScanSession()
        session.resume()
        val token = session.token
        assertTrue(session.tryComplete(token))
        assertFalse(session.tryComplete(token))
        session.resume()
        assertFalse(session.isActive(session.token))
        val disposed = QrScanSession()
        disposed.resume()
        disposed.close()
        disposed.resume()
        assertFalse(disposed.isActive(disposed.token))
    }
}
