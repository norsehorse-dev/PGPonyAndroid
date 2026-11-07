package com.pgpony.android.qr

import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** Explicit encoding experiments. BASELINE preserves the released 1,000/L default. */
enum class QrEncodingPolicy(val payloadChars: Int, val errorCorrection: ErrorCorrectionLevel) {
    BASELINE(1_000, ErrorCorrectionLevel.L),
    BALANCED(750, ErrorCorrectionLevel.M),
    ROBUST(600, ErrorCorrectionLevel.M),
}
