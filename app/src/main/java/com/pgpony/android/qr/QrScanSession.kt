package com.pgpony.android.qr

import java.util.concurrent.atomic.AtomicLong

/** Invalidates queued camera results on pause, disposal, and the first completed scan. */
class QrScanSession {
    val id: Long = nextId.incrementAndGet()
    private var generation = 0L
    private var active = false
    private var closed = false
    val token: Long @Synchronized get() = generation

    @Synchronized fun resume() {
        if (!closed && !active) { generation++; active = true }
    }
    @Synchronized fun pause() { active = false; generation++ }
    @Synchronized fun close() { closed = true; pause() }
    @Synchronized fun isActive(token: Long): Boolean = active && !closed && token == generation
    @Synchronized fun tryComplete(token: Long): Boolean {
        if (!isActive(token)) return false
        close()
        return true
    }

    private companion object { val nextId = AtomicLong() }
}
