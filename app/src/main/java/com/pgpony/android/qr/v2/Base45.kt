package com.pgpony.android.qr.v2

/** RFC 9285 Base45, preserving spaces and colons; neither is a field separator here. */
internal object Base45 {
    private const val ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

    fun encode(bytes: ByteArray): String = buildString((bytes.size * 3 + 1) / 2) {
        var i = 0
        while (i < bytes.size) {
            val paired = i + 1 < bytes.size
            var value = bytes[i].toInt() and 255
            if (paired) value = value * 256 + (bytes[i + 1].toInt() and 255)
            append(ALPHABET[value % 45])
            value /= 45
            append(ALPHABET[value % 45])
            if (paired) append(ALPHABET[value / 45])
            i += if (paired) 2 else 1
        }
    }

    fun decode(text: String): ByteArray {
        require(text.length % 3 != 1) { "Invalid Base45 length" }
        val output = ByteArray(text.length / 3 * 2 + if (text.length % 3 == 2) 1 else 0)
        var source = 0
        var destination = 0
        fun digit(index: Int): Int = ALPHABET.indexOf(text[index]).also { require(it >= 0) { "Invalid Base45 character" } }
        while (source < text.length) {
            val paired = source + 2 < text.length
            val value = digit(source) + digit(source + 1) * 45 + if (paired) digit(source + 2) * 2025 else 0
            require(value <= if (paired) 65535 else 255) { "Noncanonical Base45 value" }
            if (paired) output[destination++] = (value / 256).toByte()
            output[destination++] = value.toByte()
            source += if (paired) 3 else 2
        }
        return output
    }
}
