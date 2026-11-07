package com.pgpony.android.ui.scanner

/** Main-thread state for deferred camera acquisition, geometry readiness, and explicit retry. */
internal class ScannerCameraBinding(private val onError: () -> Unit) {
    private var closed = false
    private var failed = false
    private var bound = false

    fun providerReady(obtain: () -> Unit) {
        if(closed || failed) return
        try { obtain() } catch (_: Exception) { fail() }
    }

    /** A false result means PreviewView geometry is not ready; a later layout may retry. */
    fun bindWhenReady(bind: () -> Boolean) {
        if(closed || failed || bound) return
        try { bound = bind() } catch (_: Exception) { fail() }
    }

    fun close(release: () -> Unit) {
        if(closed) return
        closed = true
        release()
    }

    private fun fail() { failed = true; onError() }
}
