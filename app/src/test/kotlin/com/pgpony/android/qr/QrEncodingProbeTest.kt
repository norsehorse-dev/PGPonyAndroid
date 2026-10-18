package com.pgpony.android.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

/** Deterministic encoding and synthetic luminance evidence, not a camera throughput benchmark. */
class QrEncodingProbeTest {
    @Test fun publicFixturesHavePinnedContentsAndStableProductionProfiles() {
        for (fixture in QrEncodingProbe.fixtures) {
            val bytes = javaClass.getResourceAsStream("/${fixture.source}")!!.readBytes()
            assertEquals(fixture.sha256, QrEncodingProbe.sha256(bytes))
            assertEquals(fixture.armorChars, bytes.toString(Charsets.UTF_8).length)
            assertEquals(fixture.binaryBytes, QrEncodingProbe.binaryLength(bytes.toString(Charsets.UTF_8)))
            val text = bytes.toString(Charsets.UTF_8)
            for (policy in QrEncodingPolicy.entries) {
                val frames = QrChunking.split(text, policy)!!
                val layout = QrSymbolLayout.forFrames(frames, policy)
                assertEquals(QrEncodingProbe.expectedFrames.getValue(fixture.id)[policy.ordinal], frames.size)
                assertEquals(QrEncodingProbe.expectedVersions.getValue(fixture.id)[policy.ordinal], layout.version)
                // The independent released parser validates current wire frames, including
                // the unchanged default slicing and the optional deterministic profiles.
                assertEquals(text, legacyCollect(frames.reversed()))
                println(QrEncodingProbe.reportRow(fixture, text, policy))
            }
        }
    }

    @Test fun capacityInputsKeepThePublishedCharacterLimit() {
        for (policy in QrEncodingPolicy.entries) {
            assertEquals(32, QrChunking.split("A".repeat(32_000), policy)!!.size)
            assertNull(QrChunking.split("A".repeat(32_001), policy))
        }
    }

    @Test fun publicSymbolReplayResultsMatchCleanBlurredAndPaddedEvidence() {
        for (fixture in QrEncodingProbe.fixtures) {
            val text = javaClass.getResource("/${fixture.source}")!!.readText()
            for (variant in QrEncodingProbe.variants) {
                val replay = QrEncodingProbe.replay(text, variant)
                val source = ByteBuffer.wrap(replay.bytes).apply { position(replay.bufferPosition) }
                val decoded = QrFrameDecoder(clockNanos = { 0L }).decode(source, replay.width, replay.height, replay.rowStride,
                    replay.pixelStride, rotationDegrees = replay.rotation)
                assertEquals("${fixture.id}/${variant.name}", QrEncodingProbe.expectedDecode(fixture, variant), decoded != null)
                if (decoded != null) assertEquals(replay.expected, decoded)
            }
        }
    }

    /** Independent PGPONY1 collector mirroring the released header grammar. */
    private fun legacyCollect(frames: List<String>): String {
        if (frames.size == 1 && !frames[0].startsWith("PGPONY1:")) return frames[0]
        val parts = mutableMapOf<Int, String>()
        var group: Pair<String, Int>? = null
        for (raw in frames) {
            val fields = raw.split(':', limit = 5)
            assertEquals("PGPONY1", fields[0])
            val sequence = fields[1].toInt()
            val total = fields[2].toInt()
            assertTrue(sequence in 1..total && total <= 32)
            assertTrue(fields[3].matches(Regex("[0-9a-f]{8}")))
            val candidate = fields[3] to total
            if (group != candidate) { group = candidate; parts.clear() }
            parts[sequence] = fields[4]
        }
        assertEquals(group!!.second, parts.size)
        return (1..group.second).joinToString("") { parts.getValue(it) }
    }
}

/** Also callable by tools/qr/run_encoding_probe.py without an Android runtime. */
object QrEncodingProbe {
    data class Fixture(val id: String, val source: String, val type: String,
        val armorChars: Int, val binaryBytes: Int, val sha256: String)
    val fixtures = listOf(
        Fixture("rfc9580-v6", "rfc9580/a3_cert.asc", "RFC 9580 A.3 version 6 certificate", 650, 424,
            "0e9fde2dcf7a10b8e2188cffd4091bbbeefb5e8c9e9dd18a40fe72403760dd7b"),
        Fixture("rsa", "keys/uid-selfsig-expiry-rsa.asc", "RSA certificate with UID self-signature expiry", 2468, 1762,
            "5b0339e98237592e7937ccebdadae6c9dcd1b74fe64ff952d603756070dd69b4"),
        Fixture("mlkem768", "pqc/rfc9980-a2-v4-ed25519-mlkem768-pub.asc", "RFC 9980 A.2 Ed25519 and ML-KEM-768 public certificate", 2348, 1680,
            "4ff0c22f4a9fd0c02fa64bb0faea1806743a030455225f1af4c9ee4e4981dc95"),
        Fixture("mldsa65", "pqc/rfc9980-a3-mldsa65-ed25519-cert.asc", "RFC 9980 A.3 ML-DSA-65 and Ed25519 public certificate", 18554, 13647,
            "4880dead81e043038df20e961ab74a7c61f14245371d6a229c1888be79813764"),
    )
    val expectedFrames = mapOf("rfc9580-v6" to listOf(1,1,1), "rsa" to listOf(3,4,5),
        "mlkem768" to listOf(3,4,4), "mldsa65" to listOf(19,25,31))
    // Filled from the production probe; tests pin changes to the actual QR encoding policy.
    val expectedVersions = mapOf("rfc9580-v6" to listOf(18,20,20), "rsa" to listOf(23,20,18),
        "mlkem768" to listOf(23,19,19), "mldsa65" to listOf(23,22,19))

    data class Variant(val name: String, val scale: Int, val blurRadius: Int, val pixelStride: Int, val rotation: Int)
    val variants = listOf(Variant("clean-4px",4,0,1,0), Variant("boxblur1-4px",4,1,1,0),
        Variant("rotated-padded-3px",3,0,2,90))
    // The dense first ML-DSA frame currently misses at rotated 3 px/module.
    // Preserve that observed synthetic limit instead of silently discarding it.
    fun expectedDecode(fixture: Fixture, variant: Variant): Boolean =
        fixture.id != "mldsa65" || variant.name != "rotated-padded-3px"

    data class Replay(val bytes: ByteArray, val expected: String, val width: Int, val height: Int,
        val rowStride: Int, val pixelStride: Int, val rotation: Int, val bufferPosition: Int)

    fun replay(text: String, variant: Variant): Replay {
        val expected = QrChunking.split(text)!!.first()
        val layout = QrSymbolLayout.forFrames(QrChunking.split(text)!!)
        val matrix = layout.encode(expected)
        val size = matrix.width * variant.scale
        val sharp = ByteArray(size * size) { i -> if(matrix[i % size / variant.scale, i / size / variant.scale]) 0 else -1 }
        val plane = if (variant.blurRadius == 0) sharp else ByteArray(sharp.size) { i ->
            val x = i % size; val y = i / size
            var sum = 0; var samples = 0
            for (dy in -variant.blurRadius..variant.blurRadius) for (dx in -variant.blurRadius..variant.blurRadius) {
                val sx = (x + dx).coerceIn(0, size-1); val sy = (y + dy).coerceIn(0, size-1)
                sum += sharp[sy * size + sx].toInt() and 255; samples++
            }
            (sum / samples).toByte()
        }
        val stride = size * variant.pixelStride + 13
        val position = 7
        val bytes = ByteArray(position + stride * size) { 0x7f }
        for (y in 0 until size) for (x in 0 until size) bytes[position + y*stride + x*variant.pixelStride] = plane[y*size+x]
        return Replay(bytes, expected, size, size, stride, variant.pixelStride, variant.rotation, position)
    }

    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
    fun binaryLength(text: String): Int = Base64.getDecoder().decode(text.substringAfter("\n\n").lineSequence()
        .filter { it.isNotEmpty() && !it.startsWith('=') && !it.startsWith("-----") }.joinToString("")).size

    const val CSV_HEADER = "fixture,profile,armor_chars,binary_bytes,frames,shared_version,symbol_modules,matrix_modules,min_frame_chars,max_frame_chars,frame_sequence_sha256,rc6_frames,rc6_min_version,rc6_max_version,rc6_quiet_zone_modules"
    fun reportRow(fixture: Fixture, text: String, policy: QrEncodingPolicy): String {
        val frames = QrChunking.split(text, policy)!!
        val layout = QrSymbolLayout.forFrames(frames, policy)
        val digest = MessageDigest.getInstance("SHA-256")
        frames.forEach { frame -> val bytes=frame.toByteArray(Charsets.UTF_8); digest.update("${bytes.size}:".toByteArray()); digest.update(bytes) }
        val sequenceHash = digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
        // RC6 QRCodeWriter used margin=1 and allowed individual frame versions.
        val legacy = QrChunking.split(text)!!.map {
            (QRCodeWriter().encode(it, BarcodeFormat.QR_CODE, 1, 1, mapOf(EncodeHintType.MARGIN to 1)).width - 2 - 17) / 4
        }
        return listOf(fixture.id,policy.name,text.length,binaryLength(text),frames.size,layout.version,
            layout.moduleCount-8,layout.moduleCount,frames.minOf{it.length},frames.maxOf{it.length},sequenceHash,
            legacy.size,legacy.min(),legacy.max(),1).joinToString(",")
    }

    @JvmStatic fun main(args: Array<String>) {
        val resources = File(args[0]); val output = File(args[1]).apply { mkdirs() }
        val assetDir = File(output,"assets/qr").apply { mkdirs() }
        val rows = mutableListOf(CSV_HEADER)
        val replayEntries = mutableListOf<String>()
        for (fixture in fixtures) {
            val bytes = File(resources,fixture.source).readBytes()
            check(sha256(bytes) == fixture.sha256)
            File(assetDir,"${fixture.id}.asc").writeBytes(bytes)
            val text = bytes.toString(Charsets.UTF_8)
            for (policy in QrEncodingPolicy.entries) rows += reportRow(fixture,text,policy)
            for (variant in variants) {
                val replay = replay(text,variant)
                val name = "${fixture.id}-${variant.name}.y"
                File(assetDir,name).writeBytes(replay.bytes)
                val buffer = ByteBuffer.wrap(replay.bytes).apply { position(replay.bufferPosition) }
                val decoded = QrFrameDecoder(clockNanos = { 0L }).decode(buffer,replay.width,replay.height,replay.rowStride,replay.pixelStride,
                    rotationDegrees=replay.rotation)
                check((decoded != null) == expectedDecode(fixture,variant)) { "Replay result changed: $name" }
                if (decoded != null) check(decoded == replay.expected)
                val expectedResult = if (decoded != null) "decoded" else "not-decoded"
                replayEntries += """{"asset":"$name","sha256":"${sha256(replay.bytes)}","origin":"synthetic-production-matrix","fixture":"${fixture.id}","profile":"BASELINE","frameIndex":0,"width":${replay.width},"height":${replay.height},"rowStride":${replay.rowStride},"pixelStride":${replay.pixelStride},"bufferPosition":${replay.bufferPosition},"rotationDegrees":${replay.rotation},"crop":[0,0,${replay.width},${replay.height}],"previewToAnalysis":[1,0,0,0,1,0,0,0,1],"modulePixels":${variant.scale},"boxBlurRadius":${variant.blurRadius},"expectedResult":"$expectedResult"}"""
            }
        }
        val certificates = fixtures.joinToString(",\n") {
            """{"id":"${it.id}","source":"app/src/test/resources/${it.source}","asset":"${it.id}.asc","type":"${it.type}","sha256":"${it.sha256}","armorChars":${it.armorChars},"armorBytes":${it.armorChars},"binaryBytes":${it.binaryBytes}}"""
        }
        File(assetDir,"manifest.json").writeText("""{
"schemaVersion":1,
"baselineCommit":"f04501acd56f74da190789bd32c2ceed90a75e8c",
"origin":"public repository certificates and deterministic synthetic QR luminance; no camera captures",
"certificates":[$certificates],
"capacityInputs":[{"generator":"ASCII A repeated","characters":32000,"expectedFrames":32},{"generator":"ASCII A repeated","characters":32001,"expectedResult":"rejected","scope":"protocol capacity only"}],
"replays":[${replayEntries.joinToString(",\n")}]
}
""")
        File(output,"encoding.csv").writeText(rows.joinToString("\n")+"\n")
        println(rows.joinToString("\n"))
        println("Verified ${replayEntries.size} synthetic public-symbol replays; output=$output")
    }
}
