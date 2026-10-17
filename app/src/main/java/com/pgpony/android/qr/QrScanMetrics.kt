package com.pgpony.android.qr

/** Local metadata only: no decoded text, key identifiers, or camera pixels may be recorded. */
interface QrScanMetrics {
    fun frame(sessionId: Long, width: Int, height: Int) {}
    fun decode(sessionId: Long, strategy: DecodeStrategy, elapsedNanos: Long, success: Boolean) {}
    fun collection(sessionId: Long, event: CollectionEvent) {}
    fun milestone(sessionId: Long, event: ScanMilestone, monotonicNanos: Long) {}

    companion object { val None: QrScanMetrics = object : QrScanMetrics {} }
}

enum class DecodeStrategy { REGION, FULL_FRAME, HARD_FULL_FRAME, HARD_UNROTATED }
enum class CollectionEvent { NEW_PART, DUPLICATE, RESTARTED, MALFORMED, COMPLETE }
enum class ScanMilestone { READY, FIRST_PART, COMPLETE, PREVIEW }

/** Carries metadata into import preview without retaining the key text or camera image. */
class QrPreviewTiming(private val sessionId: Long, private val metrics: QrScanMetrics) {
    private val shown = java.util.concurrent.atomic.AtomicBoolean(false)

    /** Called at the first frame opportunity after the preview enters composition; cancellation or parse failure never calls it. */
    fun previewShown() {
        if (shown.compareAndSet(false, true)) metrics.milestone(sessionId, ScanMilestone.PREVIEW, System.nanoTime())
    }
}
