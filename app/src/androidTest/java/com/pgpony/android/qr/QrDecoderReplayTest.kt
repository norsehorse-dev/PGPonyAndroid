package com.pgpony.android.qr

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Public, synthetic Y planes only. This does not exercise a physical camera or display. */
@RunWith(AndroidJUnit4::class)
class QrDecoderReplayTest {
    private val assets get() = InstrumentationRegistry.getInstrumentation().context.assets
    private fun bytes(name: String) = assets.open("qr/$name").use { it.readBytes() }
    private fun sha256(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    @Test fun packagedCertificatesAreExactlyTheFourPinnedPublicFixtures() {
        val manifest = JSONObject(bytes("manifest.json").toString(Charsets.UTF_8))
        val certificates = manifest.getJSONArray("certificates")
        assertEquals(4, certificates.length())
        for (index in 0 until certificates.length()) {
            val fixture = certificates.getJSONObject(index)
            val value = bytes(fixture.getString("asset"))
            val text = value.toString(Charsets.UTF_8)
            assertTrue(text.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
            assertFalse(text.contains("PRIVATE KEY"))
            assertEquals(fixture.getString("sha256"), sha256(value))
            assertEquals(fixture.getInt("armorBytes"), value.size)
            assertEquals(fixture.getInt("armorChars"), text.length)
            val body = text.substringAfter("\n\n").lineSequence().filter {
                it.isNotEmpty() && !it.startsWith('=') && !it.startsWith("-----")
            }.joinToString("")
            assertEquals(fixture.getInt("binaryBytes"), Base64.getDecoder().decode(body).size)
        }
    }

    @Test fun productionDecoderReplaysPackagedLuminanceWithRecordedGeometry() {
        val manifest = JSONObject(bytes("manifest.json").toString(Charsets.UTF_8))
        val fixtures = manifest.getJSONArray("certificates")
        val sourceById = (0 until fixtures.length()).associate { index ->
            val fixture = fixtures.getJSONObject(index)
            fixture.getString("id") to bytes(fixture.getString("asset")).toString(Charsets.UTF_8)
        }
        val replays = manifest.getJSONArray("replays")
        assertEquals(12, replays.length())
        for (index in 0 until replays.length()) {
            val replay = replays.getJSONObject(index)
            val value = bytes(replay.getString("asset"))
            assertEquals(replay.getString("sha256"), sha256(value))
            val buffer = ByteBuffer.wrap(value).apply { position(replay.getInt("bufferPosition")) }
            val crop = replay.getJSONArray("crop")
            val decoded = QrFrameDecoder(clockNanos = { 0L }).decode(buffer,
                replay.getInt("width"), replay.getInt("height"), replay.getInt("rowStride"),
                replay.getInt("pixelStride"), PixelCrop(crop.getInt(0),crop.getInt(1),crop.getInt(2),crop.getInt(3)),
                replay.getInt("rotationDegrees"))
            val expected = QrChunking.split(sourceById.getValue(replay.getString("fixture")))!![replay.getInt("frameIndex")]
            if (replay.getString("expectedResult") == "decoded") {
                assertEquals(replay.getString("asset"), expected, decoded)
            } else {
                assertNull("Recorded first-attempt synthetic miss: ${replay.getString("asset")}", decoded)
            }
        }
    }
}
