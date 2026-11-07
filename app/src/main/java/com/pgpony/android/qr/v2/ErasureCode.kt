package com.pgpony.android.qr.v2

/**
 * Systematic Vandermonde Reed–Solomon erasure code over GF(256), polynomial 0x11D.
 * Rows evaluate at the integer field elements 0..n-1; the first k rows become identity.
 * This is a transport erasure code, independent of QR symbol error correction.
 * No decoder guesses corrupt shards: the caller must verify each shard's checksum first.
 */
internal class ErasureCode(val dataCount: Int, val parityCount: Int) {
    private val total = dataCount + parityCount
    private val generator: Array<IntArray>

    init {
        require(dataCount in 1..128 && parityCount in 1..32 && total <= 160)
        val vandermonde = Array(total) { row ->
            IntArray(dataCount).also { values ->
                values[0] = 1
                for (column in 1 until dataCount) values[column] = Field.multiply(values[column - 1], row)
            }
        }
        val topInverse = invert(Array(dataCount) { vandermonde[it].copyOf() })
        generator = Array(total) { row ->
            IntArray(dataCount) { column ->
                var value = 0
                for (i in 0 until dataCount) value = value xor Field.multiply(vandermonde[row][i], topInverse[i][column])
                value
            }
        }
    }

    /** Returns owned arrays: data first, followed by parity. Inputs are never mutated. */
    fun encode(data: Array<ByteArray>): Array<ByteArray> {
        require(data.size == dataCount)
        val width = data[0].size
        require(width in 1..512 && data.all { it.size == width })
        return Array(total) { row ->
            if (row < dataCount) data[row].copyOf() else combine(generator[row], data, width)
        }
    }

    /** Recovers all k data shards from any k distinct, valid indexes in 0 until n. */
    fun recover(shards: Map<Int, ByteArray>): Array<ByteArray> {
        require(shards.size >= dataCount && shards.size <= total)
        require(shards.keys.all { it in 0 until total })
        val width = shards.values.first().size
        require(width in 1..512 && shards.values.all { it.size == width })
        val indexes = shards.keys.sorted().take(dataCount)
        val inverse = invert(Array(dataCount) { generator[indexes[it]].copyOf() })
        val selected = Array(dataCount) { shards.getValue(indexes[it]) }
        return Array(dataCount) { row ->
            shards[row]?.copyOf() ?: combine(inverse[row], selected, width)
        }
    }

    private fun combine(coefficients: IntArray, inputs: Array<ByteArray>, width: Int): ByteArray {
        val output = ByteArray(width)
        for (i in inputs.indices) {
            val coefficient = coefficients[i]
            if (coefficient == 0) continue
            for (j in 0 until width) {
                output[j] = (output[j].toInt() xor Field.multiply(coefficient, inputs[i][j].toInt() and 255)).toByte()
            }
        }
        return output
    }

    private fun invert(matrix: Array<IntArray>): Array<IntArray> {
        val size = matrix.size
        val augmented = Array(size) { row -> IntArray(size * 2) { col ->
            if (col < size) matrix[row][col] else if (col - size == row) 1 else 0
        } }
        for (column in 0 until size) {
            val pivot = (column until size).firstOrNull { augmented[it][column] != 0 }
                ?: throw IllegalArgumentException("Singular erasure matrix")
            val swap = augmented[column]
            augmented[column] = augmented[pivot]
            augmented[pivot] = swap
            val scale = Field.inverse(augmented[column][column])
            if (scale != 1) for (j in column until size * 2) augmented[column][j] = Field.multiply(augmented[column][j], scale)
            for (row in 0 until size) {
                if (row == column) continue
                val factor = augmented[row][column]
                if (factor == 0) continue
                for (j in column until size * 2) augmented[row][j] = augmented[row][j] xor Field.multiply(factor, augmented[column][j])
            }
        }
        return Array(size) { augmented[it].copyOfRange(size, size * 2) }
    }

    /** Integer bytes denote polynomial coefficients, with XOR addition and generator 2. */
    private object Field {
        private val exponent = IntArray(510)
        private val logarithm = IntArray(256)
        init {
            var value = 1
            for (i in 0 until 255) {
                exponent[i] = value
                logarithm[value] = i
                value = value shl 1
                if (value and 256 != 0) value = value xor 0x11D
            }
            for (i in 255 until exponent.size) exponent[i] = exponent[i - 255]
        }
        fun multiply(a: Int, b: Int): Int = if (a == 0 || b == 0) 0 else exponent[logarithm[a] + logarithm[b]]
        fun inverse(a: Int): Int {
            require(a != 0)
            return exponent[255 - logarithm[a]]
        }
    }
}
