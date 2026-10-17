package com.pgpony.android.qr

import androidx.camera.core.ImageProxy
import com.pgpony.android.ui.scanner.CameraQrAnalyzer
import java.lang.reflect.Proxy
import java.util.concurrent.Executor
import org.junit.Assert.*
import org.junit.Test

class QrScannerDispatchTest {
    private fun image(onClose: () -> Unit): ImageProxy = Proxy.newProxyInstance(
        ImageProxy::class.java.classLoader,arrayOf(ImageProxy::class.java)
    ) { _,method,_ -> if(method.name == "close") onClose(); null } as ImageProxy

    @Test fun closesMalformedAndStoppedFramesAndDropsQueuedResultOnDispose() {
        val session = QrScanSession().apply { resume() }
        val pending = ArrayDeque<Runnable>()
        var callbacks = 0
        var closed = 0
        val analyzer = CameraQrAnalyzer(session,Executor { pending.add(it) },{ "decoded" }) { _,_ -> callbacks++ }
        analyzer.analyze(image { closed++ })
        assertEquals(1,closed)
        assertEquals(0,callbacks)
        session.close()
        pending.removeFirst().run()
        assertEquals(0,callbacks)
        analyzer.analyze(image { closed++ })
        assertEquals(2,closed)
        val active = QrScanSession().apply { resume() }
        val broken = CameraQrAnalyzer(active,Executor { it.run() },{ error("malformed plane") }) { _,_ -> callbacks++ }
        broken.analyze(image { closed++ })
        assertEquals(3,closed)
        assertEquals(0,callbacks)
    }

    @Test fun boundsPendingEventsAndCompletesOnlyOnce() {
        val session = QrScanSession().apply { resume() }
        val pending = ArrayDeque<Runnable>()
        var completed = 0
        var closed = 0
        val analyzer = CameraQrAnalyzer(session,Executor { pending.add(it) },{ "decoded" }) { _,token ->
            if(session.tryComplete(token)) completed++
        }
        repeat(10) { analyzer.analyze(image { closed++ }) }
        assertEquals(10,closed)
        assertEquals(1,pending.size)
        pending.removeFirst().run()
        analyzer.analyze(image { closed++ })
        assertEquals(1,completed)
        assertTrue(pending.isEmpty())
    }
}
