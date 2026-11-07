package com.pgpony.android.qr

import android.graphics.Bitmap
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.pgpony.android.qr.v2.EnhancedQrEncoder
import java.nio.ByteBuffer
import org.bouncycastle.openpgp.PGPUtil
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Full public-certificate transfers through Android bitmaps and the production decoder. */
@RunWith(AndroidJUnit4::class)
class QrExchangeRoundTripTest {
    private fun certificate(name: String): String =
        InstrumentationRegistry.getInstrumentation().context.assets.open("qr/$name.asc")
            .bufferedReader(Charsets.UTF_8).use { it.readText() }

    @Test fun compatiblePublicCertificatesSurviveRenderedReorderedAndDuplicateFrames() {
        for (name in listOf("rfc9580-v6", "rsa", "mlkem768", "mldsa65")) {
            val armor = certificate(name)
            for (policy in listOf(QrEncodingPolicy.BASELINE, QrEncodingPolicy.ROBUST)) {
                val store = QrFrameStore.create(armor, policy)!!
                var time = 0L
                val decoder = QrFrameDecoder(clockNanos = { time })
                val collector = PublicKeyQrCollector()
                var result: PublicKeyQrResult? = null
                try {
                    for (index in (0 until store.frameCount).reversed()) {
                        val text = decode(store.bitmap(index, 947), decoder, "$name/$policy/part=${index + 1}") {
                            time += 500_000_000L
                        }
                        if (store.frameCount == 1) {
                            assertEquals(armor, text)
                        } else {
                            assertTrue(text.startsWith("PGPONY1:"))
                        }
                        result = collector.offer(text)
                        if (result is PublicKeyQrResult.Progress) {
                            assertFalse(result.enhanced)
                            assertEquals(PublicKeyQrResult.Duplicate, collector.offer(text))
                        }
                    }
                    assertEquals("$name/$policy", PublicKeyQrResult.Complete(armor), result)
                } finally {
                    store.clear()
                }
            }
        }
    }

    @Test fun enhancedReceiverRecoversMissingDataFromRenderedReferenceFrames() {
        val armor = certificate("mldsa65")
        val binary = binary(armor)
        val dataCount = (binary.size + EnhancedQrEncoder.SHARD_BYTES - 1) / EnhancedQrEncoder.SHARD_BYTES
        val parityCount = (dataCount + 3) / 4
        val frames = EnhancedQrEncoder.encode(armor)
        // Remove as many systematic data frames as the parity budget allows.
        // Reverse every remaining frame so parity arrives before the surviving data.
        val received = frames.drop(parityCount).reversed()
        assertEquals(dataCount, received.size)
        val store = QrFrameStore.fromFrames(received, QrEncodingPolicy.BALANCED)
        var time = 0L
        val decoder = QrFrameDecoder(clockNanos = { time })
        val collector = PublicKeyQrCollector()
        var result: PublicKeyQrResult? = null
        try {
            for (index in received.indices) {
                val text = decode(store.bitmap(index, 947), decoder, "PGPONY2/part=${index + 1}") {
                    time += 500_000_000L
                }
                assertEquals(received[index], text)
                result = collector.offer(text)
                if (index < received.lastIndex) {
                    assertTrue(result is PublicKeyQrResult.Progress)
                    assertTrue((result as PublicKeyQrResult.Progress).enhanced)
                    assertEquals(PublicKeyQrResult.Duplicate, collector.offer(text))
                }
            }
            assertTrue(result is PublicKeyQrResult.Complete)
            assertArrayEquals(binary, binary((result as PublicKeyQrResult.Complete).text))
        } finally {
            store.clear()
        }
    }

    private fun binary(armor: String): ByteArray =
        PGPUtil.getDecoderStream(armor.byteInputStream(Charsets.US_ASCII)).use { it.readBytes() }

    private fun decode(bitmap: Bitmap, decoder: QrFrameDecoder, label: String, advanceClock: () -> Unit): String {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        val rowStride = bitmap.width + 13
        val offset = 7
        val plane = ByteArray(offset + rowStride * bitmap.height) { 0x7f }
        for (y in 0 until bitmap.height) for (x in 0 until bitmap.width) {
            plane[offset + y * rowStride + x] = (pixels[y * bitmap.width + x] and 0xff).toByte()
        }
        fun attempt() = decoder.decode(ByteBuffer.wrap(plane).apply { position(offset) },
            bitmap.width, bitmap.height, rowStride, 1)
        val decoded = attempt() ?: run {
            // Exercise the scanner's existing half-second retry budget without sleeping.
            advanceClock()
            println("Bounded decoder fallback used: $label")
            attempt()
        }
        assertNotNull("A rendered frame must decode before collection: $label", decoded)
        decoder.markProgress()
        return decoded!!
    }
}
