package com.pgpony.android.ui.scanner

import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.pgpony.android.qr.QrScanSession
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean

/** Camera frames stay on one executor; only a bounded decoded event crosses to the main executor. */
class CameraQrAnalyzer(
    private val session: QrScanSession,
    private val mainExecutor: Executor,
    private val decodeFrame: (ImageProxy) -> String?,
    private val onDecoded: (String,Long) -> Unit
) : ImageAnalysis.Analyzer {
    private val pending = AtomicBoolean(false)

    override fun analyze(image: ImageProxy) {
        val token = session.token
        try {
            if(!session.isActive(token) || pending.get()) return
            val text = decodeFrame(image) ?: return
            if(!session.isActive(token) || !pending.compareAndSet(false,true)) return
            try {
                mainExecutor.execute {
                    try { if(session.isActive(token)) onDecoded(text,token) }
                    finally { pending.set(false) }
                }
            } catch (_: RuntimeException) { pending.set(false) }
        } catch (_: RuntimeException) {
            // Malformed camera metadata must not retain a frame or stop subsequent analysis.
        } finally { image.close() }
    }
}
