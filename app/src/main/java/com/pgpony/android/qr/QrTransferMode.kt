package com.pgpony.android.qr

import com.pgpony.android.qr.v2.EnhancedQrEncoder

/** Enhanced sending is explicit: released receivers only understand COMPATIBLE. */
enum class QrTransferMode { COMPATIBLE, ENHANCED }

/** Builds immutable sequences off the main thread without changing certificate contents. */
object PublicKeyQrSequence {
    fun create(
        armored: String,
        mode: QrTransferMode,
        policy: QrEncodingPolicy,
    ): QrFrameStore? = when (mode) {
        QrTransferMode.COMPATIBLE -> QrFrameStore.create(armored, policy)
        QrTransferMode.ENHANCED -> QrFrameStore.fromFrames(EnhancedQrEncoder.encode(armored), QrEncodingPolicy.BALANCED)
    }
}
