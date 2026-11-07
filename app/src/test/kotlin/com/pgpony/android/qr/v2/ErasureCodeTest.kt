package com.pgpony.android.qr.v2

import org.junit.Assert.*
import org.junit.Test
import java.util.Random

class ErasureCodeTest {
    @Test fun base45UsesRfc9285VectorsAndRejectsNoncanonicalInput() {
        for ((raw, encoded) in listOf("AB" to "BB8", "Hello!!" to "%69 VD92EX0", "base-45" to "UJCLQE7W581")) {
            assertEquals(encoded, Base45.encode(raw.toByteArray()))
            assertArrayEquals(raw.toByteArray(), Base45.decode(encoded))
        }
        for (text in listOf("A", ":::A", ":::", "::", "a0", "0000", "\n00")) {
            assertThrows(IllegalArgumentException::class.java) { Base45.decode(text) }
        }
        for (size in 0..512) {
            val bytes = ByteArray(size).also { Random(size.toLong()).nextBytes(it) }
            assertArrayEquals(bytes, Base45.decode(Base45.encode(bytes)))
        }
    }

    @Test fun smallCodeRecoversEveryAllowedErasurePattern() {
        val data = Array(4) { i -> ByteArray(19) { j -> (i * 83 + j * 31).toByte() } }
        val code = ErasureCode(4, 2)
        val encoded = code.encode(data)
        data.indices.forEach { assertArrayEquals(data[it], encoded[it]) }
        combinations(6, 4) { indexes ->
            val recovered = code.recover(indexes.associateWith { encoded[it] })
            data.indices.forEach { assertArrayEquals(data[it], recovered[it]) }
        }
        assertThrows(IllegalArgumentException::class.java) { code.recover(mapOf(0 to encoded[0], 1 to encoded[1], 2 to encoded[2])) }
    }

    @Test fun rs24_20RecoversEveryFourErasurePattern() {
        val data = Array(20) { byteArrayOf((it * 37).toByte()) }
        val code = ErasureCode(20, 4)
        val encoded = code.encode(data)
        combinations(24, 20) { indexes ->
            val recovered = code.recover(indexes.associateWith { encoded[it] })
            data.indices.forEach { assertArrayEquals(data[it], recovered[it]) }
        }
    }

    @Test fun largeCodeRecoversRandomPatternsAtMaximumBounds() {
        val random = Random(45845)
        for (k in listOf(1, 2, 7, 20, 64, 128)) {
            val r = (k + 3) / 4
            val code = ErasureCode(k, r)
            val data = Array(k) { ByteArray(512).also(random::nextBytes) }
            val shards = code.encode(data)
            repeat(8) {
                val indexes = shards.indices.shuffled(kotlin.random.Random(random.nextLong())).take(k)
                val recovered = code.recover(indexes.associateWith { shards[it] })
                data.indices.forEach { assertArrayEquals(data[it], recovered[it]) }
            }
            assertThrows(IllegalArgumentException::class.java) { code.recover((0 until k - 1).associateWith { shards[it] }) }
        }
    }

    @Test fun independentPythonVectorsMatchEveryEncodedByte() {
        val lines = javaClass.getResourceAsStream("/qr/v2/erasure-vectors.txt")!!.bufferedReader().readLines()
        for (line in lines.filter { it.isNotBlank() && !it.startsWith("#") }) {
            val parts = line.split('|')
            val k = parts[0].toInt()
            val r = parts[1].toInt()
            val data = parts[2].split(',').map(::hex).toTypedArray()
            val expected = parts[3].split(',').map(::hex)
            val actual = ErasureCode(k, r).encode(data)
            expected.indices.forEach { assertArrayEquals("k=$k r=$r shard=$it", expected[it], actual[it]) }
        }
    }

    private fun hex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun combinations(n: Int, k: Int, block: (List<Int>) -> Unit) {
        val selected = IntArray(k) { it }
        while (true) {
            block(selected.toList())
            var i = k - 1
            while (i >= 0 && selected[i] == n - k + i) i--
            if (i < 0) return
            selected[i]++
            for (j in i + 1 until k) selected[j] = selected[j - 1] + 1
        }
    }
}
