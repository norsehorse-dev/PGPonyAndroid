package com.pgpony.android.qr.v2

import org.bouncycastle.openpgp.PGPUtil
import com.pgpony.android.qr.PublicKeyQrCollector
import com.pgpony.android.qr.PublicKeyQrResult
import com.pgpony.android.qr.QrScanSession
import org.junit.Assert.*
import org.junit.Test
import java.util.zip.CRC32

class EnhancedQrTransportTest {
    private val fixture = "/pqc/rfc9980-a3-mldsa65-ed25519-cert.asc"
    private fun armor(path: String = fixture) = javaClass.getResourceAsStream(path)!!.bufferedReader().readText()
    private fun binary(armored: String) = PGPUtil.getDecoderStream(armored.byteInputStream()).use { it.readBytes() }

    @Test fun completeCertificateBytesSurviveParityRecoveryReorderingAndDuplicates() {
        val raw = binary(armor())
        val frames = EnhancedQrEncoder.encode(armor())
        assertEquals((raw.size + 511) / 512 + (((raw.size + 511) / 512 + 3) / 4), frames.size)
        assertTrue(frames.all { Regex("[0-9A-Z $%*+./:\\-]+").matches(it) })
        assertTrue(frames.all { it.length <= EnhancedQrEncoder.MAX_FRAME_CHARACTERS })
        val k = fields(frames.first())[3].toInt()
        val collector = EnhancedQrCollector()
        var complete: EnhancedQrResult.Complete? = null
        for (frame in frames.takeLast(k).reversed()) {
            val result = collector.offer(frame)
            if (result is EnhancedQrResult.Complete) complete = result
            else assertEquals(result, collector.offer(frame))
        }
        assertNotNull(complete)
        assertArrayEquals(raw, binary(complete!!.armoredPublicKey))
        assertEquals(complete, collector.offer(frames.first()))
    }

    @Test fun malformedFramesCannotChangeValidCollectionAndMetadataRestartsAreExplicit() {
        val frames = EnhancedQrEncoder.encode(armor())
        val collector = EnhancedQrCollector()
        val first = collector.offer(frames.first()) as EnhancedQrResult.Progress
        assertEquals(1, first.received)
        val p = fields(frames[1])
        val malformed = listOf(
            "PGPONY2:", "PGPONY2:" + "A".repeat(2000),
            frames[1].replace("PGPONY2:", "PGPONY3:"),
            wire(p.toMutableList().also { it[1] = it[1].lowercase() }),
            wire(p.toMutableList().also { it[2] = "0" }),
            wire(p.toMutableList().also { it[2] = "65537" }),
            wire(p.toMutableList().also { it[2] = "0" + it[2] }),
            wire(p.toMutableList().also { it[3] = "129" }),
            wire(p.toMutableList().also { it[4] = "33" }),
            wire(p.toMutableList().also { it[5] = "160" }),
            wire(p.toMutableList().also { it[6] = "00000000" }),
            wire(p.toMutableList().also { it[7] = it[7].dropLast(1) }),
            frames[1] + " "
        )
        malformed.forEach { assertEquals(it.take(100), EnhancedQrResult.Malformed, collector.offer(it)) }
        assertEquals(first, collector.offer(frames.first()))
        val second = EnhancedQrEncoder.encode(armor("/keys/uid-selfsig-expiry-rsa.asc"))
        val restart = collector.offer(second.first()) as EnhancedQrResult.Progress
        assertTrue(restart.restarted)
        assertEquals(1, restart.received)
        var done: EnhancedQrResult? = null
        second.drop(1).forEach { if (done !is EnhancedQrResult.Complete) done = collector.offer(it) }
        assertTrue(done is EnhancedQrResult.Complete)
    }

    @Test fun insufficientShardsNeverCompleteAndResetForgetsCollection() {
        val frames = EnhancedQrEncoder.encode(armor())
        val k = fields(frames.first())[3].toInt()
        val collector = EnhancedQrCollector()
        frames.take(k - 1).forEach { assertTrue(collector.offer(it) is EnhancedQrResult.Progress) }
        collector.reset()
        assertEquals(1, (collector.offer(frames.last()) as EnhancedQrResult.Progress).received)
    }

    @Test fun checksumCoversCanonicalHeaderAndShardAndPayloadCanContainColons() {
        val frames = EnhancedQrEncoder.encode(armor())
        assertTrue(frames.any { fields(it)[7].contains(':') })
        val headerCorrupt = fields(frames.first()).toMutableList().also { it[5] = "1" }
        assertEquals(EnhancedQrResult.Malformed, EnhancedQrCollector().offer(wire(headerCorrupt)))
        val payloadCorrupt = fields(frames.first()).toMutableList().also {
            it[7] = (if (it[7][0] == '0') "1" else "0") + it[7].drop(1)
        }
        assertEquals(EnhancedQrResult.Malformed, EnhancedQrCollector().offer(wire(payloadCorrupt)))
    }

    @Test fun conflictingDuplicateAndFullDigestMismatchAreRejected() {
        val frames = EnhancedQrEncoder.encode(armor())
        val k = fields(frames.first())[3].toInt()
        val corrupt = fields(frames.first()).toMutableList()
        val bytes = Base45.decode(corrupt[7]).also { it[40] = (it[40].toInt() xor 1).toByte() }
        corrupt[7] = Base45.encode(bytes)
        val forged = recalculate(corrupt)
        val collector = EnhancedQrCollector()
        assertTrue(collector.offer(frames.first()) is EnhancedQrResult.Progress)
        assertEquals(EnhancedQrResult.Malformed, collector.offer(forged))
        assertEquals(1, (collector.offer(frames[1]) as EnhancedQrResult.Progress).received)
        collector.reset()
        assertTrue(collector.offer(forged) is EnhancedQrResult.Progress)
        frames.drop(1).take(k - 2).forEach { collector.offer(it) }
        assertEquals(EnhancedQrResult.Malformed, collector.offer(frames[k - 1]))
    }

    @Test fun nonzeroPaddingAndSecretPacketsAreNeverAccepted() {
        val raw = binary(armor())
        val frames = EnhancedQrEncoder.encodeBinary(raw)
        val k = fields(frames.first())[3].toInt()
        assertTrue(raw.size % 512 != 0)
        val padding = fields(frames[k - 1]).toMutableList()
        padding[7] = Base45.encode(Base45.decode(padding[7]).also { it[511] = 1 })
        val collector = EnhancedQrCollector()
        frames.take(k - 1).forEach { collector.offer(it) }
        assertEquals(EnhancedQrResult.Malformed, collector.offer(recalculate(padding)))
        for (secret in listOf("/subkeyadd/base-secret.pgp", "/subkeyadd/plus-one-secret.pgp")) {
            val bytes = javaClass.getResourceAsStream(secret)!!.readBytes()
            assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(bytes) }
            assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(raw + bytes) }
        }
        assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(ByteArray(65537)) }
        assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(byteArrayOf()) }
        assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encode("X".repeat(100001)) }
        assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(raw + byteArrayOf(0)) }
    }

    @Test fun completeBinaryIncludingPublicSubkeysSignaturesAndUserIdsIsPreserved() {
        for (resource in listOf("/subkeyadd/plus-two-public.pgp", "/subkeyadd/base-public.pgp")) {
            val raw = javaClass.getResourceAsStream(resource)!!.readBytes()
            val collector = EnhancedQrCollector()
            var complete: EnhancedQrResult.Complete? = null
            EnhancedQrEncoder.encodeBinary(raw).forEach { if (complete == null) complete = collector.offer(it) as? EnhancedQrResult.Complete }
            assertArrayEquals(raw, binary(complete!!.armoredPublicKey))
        }
    }

    @Test fun completeWireFramesMatchIndependentPythonReference() {
        val expected = javaClass.getResourceAsStream("/qr/v2/certificate-frames.txt")!!.bufferedReader().readLines()
        assertEquals(expected, EnhancedQrEncoder.encode(armor()))
    }

    @Test fun malformedKnownCompositePacketsAndEverySecretHeaderAreRejected() {
        val raw = binary(armor())
        val packets = packetBodies(raw)
        val primary = packets.first()
        assertEquals(6, primary.first)
        val wrongMaterialLength = primary.second.copyOf().also { it[9] = (it[9].toInt() xor 1).toByte() }
        val truncatedMaterial = primary.second.dropLast(1).toByteArray()
        for (body in listOf(wrongMaterialLength, truncatedMaterial)) {
            val malformed = packet(6, body) + packets.drop(1).fold(byteArrayOf()) { bytes, next -> bytes + packet(next.first, next.second) }
            assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(malformed) }
        }
        val signature = packets.first { it.first == 2 }.second
        for (body in listOf(signature.dropLast(1).toByteArray(), signature + byteArrayOf(0), signature.copyOf().also { it[4] = 127 })) {
            assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(packet(6, primary.second) + packet(2, body)) }
        }
        for (tag in listOf(5, 7)) for (old in listOf(false, true)) {
            assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(raw + packet(tag, byteArrayOf(4), old)) }
        }
        assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(raw + byteArrayOf(0xC5.toByte(), 224.toByte(), 0)) }
        assertThrows(IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(raw + byteArrayOf(0x97.toByte(), 4)) }
    }

    @Test fun receiverRejectsSecretCertificateEvenWithValidDigestAndChecksums() {
        val secret = javaClass.getResourceAsStream("/subkeyadd/base-secret.pgp")!!.readBytes()
        val k = (secret.size + 511) / 512
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(secret).joinToString("") { "%02X".format(it.toInt() and 255) }
        val collector = EnhancedQrCollector()
        var result: EnhancedQrResult? = null
        for (index in 0 until k) {
            val bytes = ByteArray(512)
            secret.copyInto(bytes, 0, index * 512, minOf((index + 1) * 512, secret.size))
            result = collector.offer(recalculate(mutableListOf("PGPONY2", digest, secret.size.toString(), k.toString(), ((k + 3) / 4).toString(), index.toString(), "", Base45.encode(bytes))))
        }
        assertEquals(EnhancedQrResult.Malformed, result)
    }

    @Test fun maximumCertificateBoundsAndLast128ShardsRecoverExactly() {
        val raw = binary(armor())
        val maximum = raw + packet(21, ByteArray(65536 - raw.size - 6))
        val frames = EnhancedQrEncoder.encodeBinary(maximum)
        assertEquals(160, frames.size)
        assertEquals(867, frames.last().length)
        assertEquals("128", fields(frames.last())[3])
        assertEquals("32", fields(frames.last())[4])
        val collector = EnhancedQrCollector()
        var complete: EnhancedQrResult.Complete? = null
        frames.takeLast(128).forEach { complete = collector.offer(it) as? EnhancedQrResult.Complete ?: complete }
        assertNotNull(complete)
        assertArrayEquals(maximum, binary(complete!!.armoredPublicKey))
    }

    @Test fun librePgpPublicCertificatesPreserveEveryBinaryPacket() {
        for (fixture in listOf("/pqc/librepgp-clean-pub.asc", "/pqc/gpg-bp384-ecdsa-pub.asc")) {
            val raw = PGPUtil.getDecoderStream(javaClass.getResourceAsStream(fixture)!!).use { it.readBytes() }
            val collector = EnhancedQrCollector()
            var complete: EnhancedQrResult.Complete? = null
            EnhancedQrEncoder.encodeBinary(raw).reversed().forEach {
                complete = collector.offer(it) as? EnhancedQrResult.Complete ?: complete
            }
            assertNotNull(fixture, complete)
            assertArrayEquals(fixture, raw, binary(complete!!.armoredPublicKey))
        }
    }

    @Test fun librePgpOpaquePublicMaterialRequiresKnownOidCanonicalMpiAndExactLengths() {
        val raw = PGPUtil.getDecoderStream(javaClass.getResourceAsStream("/pqc/librepgp-clean-pub.asc")!!).use { it.readBytes() }
        val packets = packetBodies(raw)
        val composite = packets.first { it.first == 14 && it.second[5] == 8.toByte() }.second
        val mutations = listOf<ByteArray>(
            composite.copyOf().also { it[6] = 1 }, // Material length exceeds its packet.
            composite.copyOf().also { it[13] = 0 }, // Unknown curve OID.
            composite.copyOf().also { it[14] = 127 }, // MPI claims a point beyond packet bounds.
            composite.copyOf().also { it[15] = 6 }, // MPI bit count disagrees with first octet.
            composite.copyOf().also { it[16] = 65 }, // Oversized native point has no legacy prefix.
            composite.copyOf().also { it[52] = (it[52].toInt() xor 1).toByte() }, // Kyber length disagrees with suite.
            composite + byteArrayOf(0) // Extra bytes cannot hide after the public material.
        )
        for ((index, badBody) in mutations.withIndex()) {
            val bad = packets.fold(byteArrayOf()) { bytes, next ->
                bytes + packet(next.first, if (next.second === composite) badBody else next.second)
            }
            assertThrows("Malformed LibrePGP vector $index", IllegalArgumentException::class.java) { EnhancedQrEncoder.encodeBinary(bad) }
        }
    }

    @Test fun everySupportedLibrePgpCurveAllowsBoundedMinimalAndLegacyPointForms() {
        val raw = PGPUtil.getDecoderStream(javaClass.getResourceAsStream("/pqc/librepgp-clean-pub.asc")!!).use { it.readBytes() }
        val primary = packetBodies(raw).first().second
        // These synthetic packets exercise public structure only; their binding/trust is not asserted.
        val suites = listOf(
            Triple("2B656E", 32, 1184), Triple("2B656F", 56, 1568),
            Triple("2B2403030208010107", 65, 1184), Triple("2B240303020801010B", 97, 1568)
        )
        for ((oidHex, width, kyberLength) in suites) {
            val oid = oidHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val native = width == 32 || width == 56
            val points = if (native) listOf(
                ByteArray(width).also { it[0] = 128.toByte() },
                byteArrayOf(1), byteArrayOf(64) + ByteArray(width)
            ) else listOf(ByteArray(width).also { it[0] = 4 })
            for (point in points) {
                val bits = (point.size - 1) * 8 + (32 - Integer.numberOfLeadingZeros(point[0].toInt() and 255))
                val material = byteArrayOf(oid.size.toByte()) + oid + byteArrayOf((bits shr 8).toByte(), bits.toByte()) + point +
                    java.nio.ByteBuffer.allocate(4).putInt(kyberLength).array() + ByteArray(kyberLength)
                val body = byteArrayOf(5, 0, 0, 0, 0, 8) + java.nio.ByteBuffer.allocate(4).putInt(material.size).array() + material
                PublicCertificate.validate(packet(6, primary) + packet(14, body))
                val wrongKyber = body.copyOf().also { it[it.size - kyberLength - 1] = (it[it.size - kyberLength - 1].toInt() xor 1).toByte() }
                assertThrows(IllegalArgumentException::class.java) { PublicCertificate.validate(packet(6, primary) + packet(14, wrongKyber)) }
            }
        }
    }

    @Test fun resumedScanReceivesCompletionAgainAfterPausedDeliveryWasDiscarded() {
        val frames = EnhancedQrEncoder.encode(armor())
        val k = fields(frames.first())[3].toInt()
        val collector = PublicKeyQrCollector()
        val session = QrScanSession()
        session.resume()
        val originalToken = session.token
        var original: PublicKeyQrResult? = null
        frames.take(k).forEach { original = collector.offer(it) }
        assertTrue(original is PublicKeyQrResult.Complete)
        // Model recovery finishing on the worker before pause invalidates main-thread delivery.
        session.pause()
        assertFalse(session.tryComplete(originalToken))
        session.resume()
        val resumedToken = session.token
        val retried = collector.offer(frames.last())
        assertEquals(original, retried)
        assertTrue(session.tryComplete(resumedToken))
        assertFalse(session.tryComplete(resumedToken))
    }

    @Test fun cachedCompletionRequiresValidFrameAndIsClearedByResetOrDifferentMetadata() {
        val frames = EnhancedQrEncoder.encode(armor())
        val k = fields(frames.first())[3].toInt()
        val collector = EnhancedQrCollector()
        frames.take(k).forEach(collector::offer)
        assertTrue(collector.offer(frames.last()) is EnhancedQrResult.Complete)
        val bad = fields(frames.last()).toMutableList().also { it[6] = "00000000" }
        assertEquals(EnhancedQrResult.Malformed, collector.offer(wire(bad)))
        assertTrue(collector.offer(frames.first()) is EnhancedQrResult.Complete)
        val other = EnhancedQrEncoder.encode(armor("/keys/uid-selfsig-expiry-rsa.asc"))
        val restarted = collector.offer(other.first()) as EnhancedQrResult.Progress
        assertTrue(restarted.restarted)
        assertEquals(1, restarted.received)
        assertTrue(collector.offer(frames.first()) is EnhancedQrResult.Progress)
        collector.reset()
        assertEquals(1, (collector.offer(frames.first()) as EnhancedQrResult.Progress).received)
    }

    private fun packet(tag: Int, body: ByteArray, old: Boolean = false): ByteArray {
        val length = java.nio.ByteBuffer.allocate(4).putInt(body.size).array()
        return (if (old) byteArrayOf((128 or (tag shl 2) or 2).toByte()) else byteArrayOf((192 or tag).toByte(), 255.toByte())) + length + body
    }

    private fun packetBodies(raw: ByteArray): List<Pair<Int, ByteArray>> {
        var offset = 0
        val packets = mutableListOf<Pair<Int, ByteArray>>()
        while (offset < raw.size) {
            val tag = raw[offset++].toInt() and 63
            val first = raw[offset++].toInt() and 255
            val length = when {
                first < 192 -> first
                first < 224 -> (first - 192) * 256 + (raw[offset++].toInt() and 255) + 192
                first == 255 -> java.nio.ByteBuffer.wrap(raw, offset, 4).int.also { offset += 4 }
                else -> error("Test fixture contains a partial packet")
            }
            packets += tag to raw.copyOfRange(offset, offset + length)
            offset += length
        }
        return packets
    }

    private fun fields(frame: String): List<String> = frame.split(':', limit = 8)
    private fun wire(fields: List<String>): String = fields.joinToString(":")
    private fun recalculate(fields: MutableList<String>): String {
        val header = fields.take(6).joinToString(":") + ":"
        val checksum = CRC32().also { it.update(header.toByteArray(Charsets.US_ASCII)); it.update(Base45.decode(fields[7])) }
        fields[6] = "%08X".format(java.util.Locale.ROOT, checksum.value)
        return wire(fields)
    }
}
