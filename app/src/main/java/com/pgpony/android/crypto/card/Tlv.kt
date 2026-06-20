// Tlv.kt
// PGPony Android — HW Phase 0
//
// Minimal BER-TLV parser for OpenPGP card data objects. The card returns
// nested TLV structures (e.g. Application Related Data 0x6E contains a
// Discretionary DO 0x73 which contains C0/C1/.../C5, and the public key
// template 0x7F49 contains 0x81/0x82 or 0x86). This parser handles:
//
//   • 1- and 2-byte tags (multi-byte when low 5 bits of the first tag
//     byte are 0b11111, continuing while the high bit is set)
//   • definite short-form lengths (0x00..0x7F) and long-form lengths
//     (0x81 → 1 length byte, 0x82 → 2 length bytes, 0x83 → 3 length bytes)
//
// Indefinite lengths (0x80) do not occur in OpenPGP card DOs and are
// rejected. No Android dependencies — pure JVM, unit-testable.

package com.pgpony.android.crypto.card

/**
 * A parsed Tag-Length-Value element. [tag] is the full (possibly
 * multi-byte) tag collapsed into an Int; [value] is the raw content
 * bytes (not including tag/length).
 */
data class Tlv(val tag: Int, val value: ByteArray) {

    /** Parse [value] as a sequence of child TLVs (for constructed DOs). */
    fun children(): List<Tlv> = parse(value)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Tlv) return false
        return tag == other.tag && value.contentEquals(other.value)
    }

    override fun hashCode(): Int = 31 * tag + value.contentHashCode()

    companion object {

        /** Parse a flat sequence of TLVs from [bytes]. */
        fun parse(bytes: ByteArray): List<Tlv> {
            val out = ArrayList<Tlv>()
            var i = 0
            while (i < bytes.size) {
                // ── Tag ──
                var tag = bytes[i].toInt() and 0xFF
                i++
                if (tag and 0x1F == 0x1F) {
                    // Multi-byte tag: continue while high bit set.
                    do {
                        if (i >= bytes.size) throw TlvException("Truncated multi-byte tag")
                        val next = bytes[i].toInt() and 0xFF
                        tag = (tag shl 8) or next
                        i++
                    } while (next0x80Set(tag))
                }

                // ── Length ──
                if (i >= bytes.size) throw TlvException("Missing length for tag 0x%X".format(tag))
                var len = bytes[i].toInt() and 0xFF
                i++
                if (len == 0x80) {
                    throw TlvException("Indefinite length not supported (tag 0x%X)".format(tag))
                }
                if (len > 0x80) {
                    val numLenBytes = len and 0x7F
                    if (numLenBytes > 4) throw TlvException("Length field too large")
                    if (i + numLenBytes > bytes.size) throw TlvException("Truncated length field")
                    var l = 0
                    repeat(numLenBytes) {
                        l = (l shl 8) or (bytes[i].toInt() and 0xFF)
                        i++
                    }
                    len = l
                }

                // ── Value ──
                if (i + len > bytes.size) {
                    throw TlvException(
                        "Truncated value for tag 0x%X (need %d, have %d)".format(tag, len, bytes.size - i)
                    )
                }
                val value = bytes.copyOfRange(i, i + len)
                i += len
                out.add(Tlv(tag, value))
            }
            return out
        }

        /**
         * Depth-first search for the first TLV with [tag] anywhere in the
         * parsed tree of [bytes]. Only recurses into the OpenPGP card's
         * known *constructed* DOs (0x6E, 0x73, 0x65, 0x7F49) so a
         * primitive value whose bytes happen to look like TLV can't
         * produce a false match. This finds C1/C5/etc. regardless of
         * whether a card nests them under 0x73 or places them directly
         * under 0x6E.
         */
        fun findRecursive(bytes: ByteArray, tag: Int): Tlv? {
            for (tlv in parse(bytes)) {
                if (tlv.tag == tag) return tlv
                if (tlv.tag in CONSTRUCTED_TAGS) {
                    val nested = runCatching { findRecursive(tlv.value, tag) }.getOrNull()
                    if (nested != null) return nested
                }
            }
            return null
        }

        private val CONSTRUCTED_TAGS = setOf(
            OpenPgpCard.DO_APPLICATION_RELATED_DATA, // 0x6E
            OpenPgpCard.DO_DISCRETIONARY,            // 0x73
            OpenPgpCard.DO_CARDHOLDER_RELATED_DATA,  // 0x65
            OpenPgpCard.DO_PUBLIC_KEY_TEMPLATE       // 0x7F49
        )

        // The last tag byte we appended had its high bit set → another
        // tag byte follows. We track via the low byte of the running tag.
        private fun next0x80Set(runningTag: Int): Boolean = (runningTag and 0x80) != 0
    }
}

class TlvException(message: String) : Exception(message)
