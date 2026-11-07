package com.pgpony.android.qr

import com.pgpony.android.ui.scanner.ScannerCameraBinding
import org.junit.Assert.*
import org.junit.Test

class QrCameraBindingGateTest {
    @Test fun bindsOnlyOnceAfterGeometryIsReadyAndClosesOnce() {
        var errors = 0
        var binds = 0
        var releases = 0
        val gate = ScannerCameraBinding { errors++ }
        gate.bindWhenReady { false }
        gate.providerReady { gate.bindWhenReady { binds++; true } }
        gate.bindWhenReady { binds++; true }
        gate.close { releases++ }
        gate.close { releases++ }
        assertEquals(1,binds)
        assertEquals(1,releases)
        assertEquals(0,errors)
    }
    @Test fun ignoresProviderThatCompletesAfterDisposal() {
        var callbacks = 0
        val gate = ScannerCameraBinding { callbacks++ }
        gate.close {}
        gate.providerReady { callbacks++; error("late provider") }
        gate.bindWhenReady { callbacks++; true }
        assertEquals(0,callbacks)
    }
    @Test fun reportsProviderAndBindingErrorsOnceUntilExplicitRetryCreatesNewGate() {
        var errors = 0
        val providerFailure = ScannerCameraBinding { errors++ }
        providerFailure.providerReady { error("provider unavailable") }
        providerFailure.providerReady { error("provider unavailable") }
        val bindFailure = ScannerCameraBinding { errors++ }
        bindFailure.bindWhenReady { error("binding unavailable") }
        bindFailure.bindWhenReady { error("binding unavailable") }
        assertEquals(2,errors)
    }
}
