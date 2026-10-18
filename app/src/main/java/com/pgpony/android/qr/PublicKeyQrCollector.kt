package com.pgpony.android.qr

import com.pgpony.android.crypto.ArmorExtractor
import com.pgpony.android.qr.v2.EnhancedQrCollector
import com.pgpony.android.qr.v2.EnhancedQrResult

sealed interface PublicKeyQrResult {
    data class Complete(val text: String) : PublicKeyQrResult
    data class Progress(val have: Int, val required: Int, val enhanced: Boolean, val restarted: Boolean) : PublicKeyQrResult
    data object Duplicate : PublicKeyQrResult
    data object Malformed : PublicKeyQrResult
    data object Unsupported : PublicKeyQrResult
}

/**
 * Routes decoded text before import. The scanner serializes calls on its collection worker.
 * Switching supported transports discards the other transport's partial state. Unknown
 * versions do not complete scanning or destroy valid partial collection.
 */
class PublicKeyQrCollector(private val acceptOtherText: Boolean = false) {
    private val compatible = QrChunking.Collector()
    private val enhanced = EnhancedQrCollector()
    private var transport = 0
    private var enhancedHave = 0

    fun offer(text: String): PublicKeyQrResult {
        if (text.startsWith("PGPONY2:")) {
            val outcome = enhanced.offer(text)
            if (outcome is EnhancedQrResult.Malformed) return PublicKeyQrResult.Malformed
            val switched = transport != 0 && transport != 2
            if (transport != 2) { compatible.reset(); enhancedHave = 0; transport = 2 }
            return when (outcome) {
                is EnhancedQrResult.Complete -> PublicKeyQrResult.Complete(outcome.armoredPublicKey)
                is EnhancedQrResult.Progress -> {
                    val fresh = outcome.received != enhancedHave || outcome.restarted || switched
                    enhancedHave = outcome.received
                    if (fresh) PublicKeyQrResult.Progress(outcome.received, outcome.required, true,
                        switched || outcome.restarted) else PublicKeyQrResult.Duplicate
                }
                EnhancedQrResult.Malformed -> PublicKeyQrResult.Malformed
            }
        }
        if (QrChunking.isFrame(text)) {
            // Validate the envelope before dropping the other transport's valid progress.
            if (QrChunking.parse(text) == null) return PublicKeyQrResult.Malformed
            val switched = transport != 0 && transport != 1
            if (transport != 1) { enhanced.reset(); enhancedHave = 0; transport = 1 }
            return when (val outcome = compatible.offer(text)) {
                is QrChunking.Outcome.Complete -> PublicKeyQrResult.Complete(outcome.text)
                is QrChunking.Outcome.Progress -> PublicKeyQrResult.Progress(outcome.have, outcome.total, false, switched)
                is QrChunking.Outcome.Restarted -> PublicKeyQrResult.Progress(outcome.have, outcome.total, false, true)
                is QrChunking.Outcome.Duplicate -> PublicKeyQrResult.Duplicate
                else -> PublicKeyQrResult.Malformed
            }
        }
        if (text.startsWith("PGPONY")) return PublicKeyQrResult.Unsupported
        // Import preview extracts armor from surrounding text and supports private-key imports.
        // Preserve the original payload; parsing and confirmation remain the preview's job.
        return if (acceptOtherText || ArmorExtractor.extractForImport(text) != null) {
            PublicKeyQrResult.Complete(text)
        } else PublicKeyQrResult.Malformed
    }
}
