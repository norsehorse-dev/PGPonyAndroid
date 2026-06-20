// CommandApdu.kt
// PGPony Android — HW Phase 0 (extended-length added in Phase AR-1)
//
// ISO 7816-4 command APDU builder. By default we emit SHORT-FORM APDUs and
// let OpenPgpCardSession handle 0x61xx (GET RESPONSE) and 0x6Cxx (wrong Le)
// chaining — the universally-compatible approach that avoids depending on a
// given card's extended-length support over NFC.
//
// Short-form encoding:
//   Case 1 (no data, no Le):        CLA INS P1 P2
//   Case 2 (no data, Le):           CLA INS P1 P2 Le
//   Case 3 (data, no Le):           CLA INS P1 P2 Lc <data>
//   Case 4 (data + Le):             CLA INS P1 P2 Lc <data> Le
//
// Le == 256 is encoded as a single 0x00 byte (the ISO convention for
// "send up to 256 bytes"). No Android dependencies — unit-testable.
//
// ── Phase AR-1: extended-length APDUs ──────────────────────────────────
// RSA card decryption (PSO:DECIPHER) sends a data field of 1 + modulus
// bytes — 513 bytes for RSA-4096 — which the short form cannot encode
// (Lc is a single byte). Setting [extended] = true switches toBytes() to
// the ISO 7816-4 extended form:
//   Case 3E (data, no Le):          CLA INS P1 P2 00 Lc(2) <data>
//   Case 4E (data + Le):            CLA INS P1 P2 00 Lc(2) <data> Le(2)
//   Case 2E (no data, Le):          CLA INS P1 P2 00 Le(2)
// One leading 0x00 marker, then 2-byte Lc, the data, then 2-byte Le when
// present. An extended Le of 0x0000 means "up to 65536"; 65536 maps to it.
// The short-form path is unchanged and stays the default, so ECDH
// decipher, sign, PIN, and info reads do not regress. YubiKey 5 NFC and
// Token2 PIN+ both advertise extended-length support over NFC, and
// IsoDep.transceive passes extended APDUs straight through. (If a target
// card ever rejects an extended APDU — 0x6700 / 0x6A87 / 0x6D00 — the
// documented fallback is ISO 7816-4 command chaining: split the data into
// <=255-byte blocks with CLA 0x10 on all but the last.)

package com.pgpony.android.crypto.card

data class CommandApdu(
    val cla: Int = 0x00,
    val ins: Int,
    val p1: Int,
    val p2: Int,
    val data: ByteArray = ByteArray(0),
    /** Expected response length. null = no Le byte; 256 encodes as 0x00. */
    val le: Int? = null,
    /**
     * When true, encode in ISO 7816-4 extended form (2-byte Lc / Le with a
     * leading 0x00 marker). Required for command data larger than 255 bytes
     * (RSA PSO:DECIPHER). Defaults to false — every existing caller keeps
     * the short-form encoding and its size guard unchanged.
     */
    val extended: Boolean = false
) {
    fun toBytes(): ByteArray {
        if (extended) return toBytesExtended()

        require(data.size <= 255) {
            "Short-form APDU data limited to 255 bytes (was ${data.size}). " +
                "Use command chaining or set extended = true for larger payloads."
        }
        require(le == null || le in 0..256) { "Le out of short-form range: $le" }

        val out = ArrayList<Byte>(5 + data.size + 1)
        out.add((cla and 0xFF).toByte())
        out.add((ins and 0xFF).toByte())
        out.add((p1 and 0xFF).toByte())
        out.add((p2 and 0xFF).toByte())
        if (data.isNotEmpty()) {
            out.add((data.size and 0xFF).toByte())   // Lc
            for (b in data) out.add(b)
        }
        if (le != null) {
            // 256 → 0x00 short-form "max"
            out.add((if (le == 256) 0x00 else le and 0xFF).toByte())
        }
        return out.toByteArray()
    }

    /**
     * ISO 7816-4 extended-length encoding. The single 0x00 marker doubles
     * as the high byte of the 3-byte Lc field when data is present, or of
     * the 3-byte Le field when there is no data. Lc and Le are big-endian.
     * An [le] of 65536 (or 0) is written as 0x0000 = "up to 65536".
     */
    private fun toBytesExtended(): ByteArray {
        require(data.size <= 65535) {
            "Extended-form APDU data limited to 65535 bytes (was ${data.size})."
        }
        require(le == null || le in 0..65536) { "Le out of extended-form range: $le" }

        val out = ArrayList<Byte>(7 + data.size + 2)
        out.add((cla and 0xFF).toByte())
        out.add((ins and 0xFF).toByte())
        out.add((p1 and 0xFF).toByte())
        out.add((p2 and 0xFF).toByte())
        // Extended-length marker (also the high byte of the Lc/Le field).
        out.add(0x00)
        if (data.isNotEmpty()) {
            // 2-byte Lc
            out.add(((data.size ushr 8) and 0xFF).toByte())
            out.add((data.size and 0xFF).toByte())
            for (b in data) out.add(b)
        }
        if (le != null) {
            // 2-byte Le; 65536 → 0x0000 ("max").
            val leVal = if (le == 65536) 0 else le
            out.add(((leVal ushr 8) and 0xFF).toByte())
            out.add((leVal and 0xFF).toByte())
        }
        return out.toByteArray()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CommandApdu) return false
        return cla == other.cla && ins == other.ins && p1 == other.p1 &&
            p2 == other.p2 && le == other.le && extended == other.extended &&
            data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = cla
        result = 31 * result + ins
        result = 31 * result + p1
        result = 31 * result + p2
        result = 31 * result + (le ?: -1)
        result = 31 * result + extended.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}
