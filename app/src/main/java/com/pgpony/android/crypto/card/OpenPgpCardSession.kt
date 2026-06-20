// OpenPgpCardSession.kt
// PGPony Android — HW Phase 0
//
// High-level read operations against an OpenPGP card, built on the
// transport-agnostic CardTransport. This is the API the NFC layer and
// UI call. Phase 0/1 implements discovery only: SELECT the application,
// read the Application Related Data, and assemble a CardInfo summary.
//
// transmit() handles the two standard chaining cases so callers never
// see them:
//   • SW1 = 0x61 xx → more data available → issue GET RESPONSE
//   • SW1 = 0x6C xx → wrong Le → resend the command with Le = xx
//
// No PIN/sign/decrypt here — that's Phase 2/3. readPublicKeyMaterial is
// provided for later use but is NOT called on the discovery path, so a
// quirk in one card's public-key encoding can't break a scan.

package com.pgpony.android.crypto.card

/**
 * Cap on wrong-PIN attempts when forcing a PIN to its blocked state during a
 * factory reset. OpenPGP-card retry counters are small (default 3, max 15 in
 * the spec), so 15 covers every real card while preventing an unbounded loop.
 */
private const val MAX_BLOCK_ATTEMPTS = 15

class OpenPgpCardSession(private val transport: CardTransport) {

    /** SELECT the OpenPGP application by its AID prefix. */
    fun select() {
        val cmd = CommandApdu(
            cla = 0x00,
            ins = OpenPgpCard.INS_SELECT,
            p1 = OpenPgpCard.P1_SELECT_BY_NAME,
            p2 = OpenPgpCard.P2_SELECT_FIRST_OR_ONLY,
            data = OpenPgpCard.AID_PREFIX,
            le = 256
        )
        val resp = transmit(cmd, throwOnError = false)
        if (!resp.isSuccess) {
            throw OpenPgpCardException.NotAnOpenPgpCard(
                "SELECT OpenPGP application failed (${resp.swHex()})"
            )
        }
    }

    /** GET DATA 0x6E and parse it into Application Related Data. */
    fun getApplicationRelatedData(): ApplicationRelatedData {
        val resp = transmit(
            CommandApdu(
                cla = 0x00,
                ins = OpenPgpCard.INS_GET_DATA,
                p1 = (OpenPgpCard.DO_APPLICATION_RELATED_DATA ushr 8) and 0xFF,
                p2 = OpenPgpCard.DO_APPLICATION_RELATED_DATA and 0xFF,
                le = 256
            )
        )
        return try {
            ApplicationRelatedData.parse(resp.data)
        } catch (e: TlvException) {
            throw OpenPgpCardException.Malformed("Could not parse card data: ${e.message}", e)
        }
    }

    /**
     * Full discovery: SELECT, read application data, build the CardInfo
     * summary the UI and repository consume. This is the Phase 1 entry
     * point invoked from the NFC reader callback.
     */
    fun readCardInfo(): CardInfo {
        select()
        val ard = getApplicationRelatedData()

        val slots = listOf(
            CardSlotInfo(
                slot = CardSlot.SIGNATURE,
                algorithm = ard.sigAlgorithm?.mappedAlgorithm,
                displayAlgorithm = ard.sigAlgorithm?.displayName ?: "—",
                fingerprint = ard.sigFingerprint,
                generationTime = ard.sigGenTimeMs
            ),
            CardSlotInfo(
                slot = CardSlot.DECRYPTION,
                algorithm = ard.decAlgorithm?.mappedAlgorithm,
                displayAlgorithm = ard.decAlgorithm?.displayName ?: "—",
                fingerprint = ard.decFingerprint,
                generationTime = ard.decGenTimeMs
            ),
            CardSlotInfo(
                slot = CardSlot.AUTHENTICATION,
                algorithm = ard.authAlgorithm?.mappedAlgorithm,
                displayAlgorithm = ard.authAlgorithm?.displayName ?: "—",
                fingerprint = ard.authFingerprint,
                generationTime = ard.authGenTimeMs
            )
        )

        return CardInfo(
            aidHex = ard.aidHex,
            manufacturerName = ard.manufacturerName,
            serialHex = ard.serialHex,
            slots = slots,
            pw1TriesRemaining = ard.pw1TriesRemaining,
            pw3TriesRemaining = ard.pw3TriesRemaining
        )
    }

    /**
     * Read the raw public-key material for [slot] via GENERATE ASYMMETRIC
     * KEY PAIR (P1 = 0x81, read mode). Returns the parsed 0x7F49 template.
     * Not used on the discovery path — wired for Phase 2/3 when PGPony
     * needs the actual public key to verify a card signature or build a
     * recipient. Throws if the slot has no key.
     */
    fun readPublicKeyMaterial(slot: CardSlot): CardPublicKeyMaterial {
        // CRT body is the slot tag with zero length, e.g. B6 00.
        val crt = byteArrayOf((slot.crtTag and 0xFF).toByte(), 0x00)
        val resp = transmit(
            CommandApdu(
                cla = 0x00,
                ins = OpenPgpCard.INS_GENERATE_ASYMMETRIC_KEY_PAIR,
                p1 = OpenPgpCard.P1_READ_PUBLIC_KEY,
                p2 = 0x00,
                data = crt,
                le = 256
            )
        )
        val template = Tlv.findRecursive(resp.data, OpenPgpCard.DO_PUBLIC_KEY_TEMPLATE)
            ?: throw OpenPgpCardException.Malformed("No public key template (0x7F49) in response")
        val modulus = Tlv.findRecursive(template.value, OpenPgpCard.DO_PK_RSA_MODULUS)?.value
        val exponent = Tlv.findRecursive(template.value, OpenPgpCard.DO_PK_RSA_EXPONENT)?.value
        val ecPoint = Tlv.findRecursive(template.value, OpenPgpCard.DO_PK_EC_POINT)?.value
        return CardPublicKeyMaterial(slot, modulus, exponent, ecPoint)
    }

    // ── Phase B1: on-card key generation (card I/O half) ───────────────
    //
    // The OpenPGP-packet construction + fingerprint computation that consumes
    // these is built in B1b against the iOS OpenPGPPacketBuilder reference, so
    // the bytes stay byte-identical to the gpg-verified iOS implementation.

    /**
     * GENERATE ASYMMETRIC KEY PAIR in *generate* mode (P1 = 0x80) for [slot].
     * The card creates a fresh key pair internally and returns only the public
     * key — the private key never leaves the card (and can never be backed up).
     * Requires PW3 (admin) verified in this session. Set the slot's algorithm
     * attributes first via [setAlgorithmAttributes] if a non-default algorithm
     * is wanted. Returns the parsed public material (EC point for Ed25519 /
     * cv25519, modulus+exponent for RSA).
     */
    fun generateKeyOnCard(slot: CardSlot): CardPublicKeyMaterial {
        val crt = byteArrayOf((slot.crtTag and 0xFF).toByte(), 0x00)
        val resp = transmit(
            CommandApdu(
                cla = 0x00,
                ins = OpenPgpCard.INS_GENERATE_ASYMMETRIC_KEY_PAIR,
                p1 = OpenPgpCard.P1_GENERATE,
                p2 = 0x00,
                data = crt,
                le = 256
            )
        )
        val template = Tlv.findRecursive(resp.data, OpenPgpCard.DO_PUBLIC_KEY_TEMPLATE)
            ?: throw OpenPgpCardException.Malformed("No public key template (0x7F49) in GENERATE response")
        val modulus = Tlv.findRecursive(template.value, OpenPgpCard.DO_PK_RSA_MODULUS)?.value
        val exponent = Tlv.findRecursive(template.value, OpenPgpCard.DO_PK_RSA_EXPONENT)?.value
        val ecPoint = Tlv.findRecursive(template.value, OpenPgpCard.DO_PK_EC_POINT)?.value
        return CardPublicKeyMaterial(slot, modulus, exponent, ecPoint)
    }

    /**
     * PUT DATA (INS 0xDA) — write [value] into the data object [tag]. [tag] may
     * be one byte (P1 = 0x00) or two (P1 = high byte). Requires PW3 (admin)
     * verified. Used to register the host-computed fingerprint + creation time
     * after on-card generation, and to set algorithm attributes.
     */
    fun putData(tag: Int, value: ByteArray) {
        transmit(
            CommandApdu(
                cla = 0x00,
                ins = OpenPgpCard.INS_PUT_DATA,
                p1 = (tag shr 8) and 0xFF,
                p2 = tag and 0xFF,
                data = value
            )
        )
    }

    /** Set the algorithm-attributes DO for [slot] (PUT DATA 0xC1/0xC2/0xC3). */
    fun setAlgorithmAttributes(slot: CardSlot, attributes: ByteArray) {
        val tag = when (slot) {
            CardSlot.SIGNATURE -> OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_SIG
            CardSlot.DECRYPTION -> OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_DEC
            CardSlot.AUTHENTICATION -> OpenPgpCard.DO_ALGORITHM_ATTRIBUTES_AUTH
        }
        putData(tag, attributes)
    }

    /**
     * Write the 20-byte v4 fingerprint for [slot] (DO 0xC7/0xC8/0xC9). The card
     * surfaces this verbatim in `gpg --card-status`; it MUST be computed from
     * the same public-key packet body + creation time as the OpenPGP key, or
     * the card and the keyring will disagree.
     */
    fun writeFingerprint(slot: CardSlot, fingerprint: ByteArray) {
        require(fingerprint.size == 20) { "v4 fingerprint must be 20 bytes" }
        val tag = when (slot) {
            CardSlot.SIGNATURE -> OpenPgpCard.DO_FINGERPRINT_SIG
            CardSlot.DECRYPTION -> OpenPgpCard.DO_FINGERPRINT_DEC
            CardSlot.AUTHENTICATION -> OpenPgpCard.DO_FINGERPRINT_AUTH
        }
        putData(tag, fingerprint)
    }

    /**
     * Write the key creation time for [slot] (DO 0xCE/0xCF/0xD0) as 4-byte
     * big-endian Unix seconds. This MUST be the exact same timestamp baked into
     * the fingerprint and the OpenPGP key packet — a mismatch produces a card
     * whose fingerprint differs from the exported public key (the divergence we
     * debugged on the iOS side).
     */
    fun writeGenerationTime(slot: CardSlot, epochSeconds: Long) {
        val t = epochSeconds.toInt()
        val be = byteArrayOf(
            ((t ushr 24) and 0xFF).toByte(),
            ((t ushr 16) and 0xFF).toByte(),
            ((t ushr 8) and 0xFF).toByte(),
            (t and 0xFF).toByte()
        )
        val tag = when (slot) {
            CardSlot.SIGNATURE -> OpenPgpCard.DO_GENTIME_SIG
            CardSlot.DECRYPTION -> OpenPgpCard.DO_GENTIME_DEC
            CardSlot.AUTHENTICATION -> OpenPgpCard.DO_GENTIME_AUTH
        }
        putData(tag, be)
    }

    // ── HW Phase 2: PIN verification + signing primitives ──────────────

    /**
     * VERIFY a PIN against the given reference (PW1_SIGN 0x81 authorizes
     * PSO:CDS, PW1_OTHER 0x82 authorizes decrypt, PW3_ADMIN 0x83 is the
     * admin PIN). [pin] is the raw PIN bytes (UTF-8 of the digits/chars).
     * Throws [OpenPgpCardException.WrongPin] (with tries remaining) on a
     * bad PIN, or CardStatus on other failures.
     *
     * Note the card's "Signature PIN: forced" mode: PW1/0x81 access is
     * consumed after a single PSO:CDS, so a sign flow must VERIFY again
     * before each signature.
     */
    fun verify(pinReference: Int, pin: ByteArray) {
        transmit(
            CommandApdu(
                cla = 0x00,
                ins = OpenPgpCard.INS_VERIFY,
                p1 = 0x00,
                p2 = pinReference,
                data = pin
            )
        )
    }

    /**
     * PSO:COMPUTE DIGITAL SIGNATURE (INS 0x2A, P1P2 0x9E 0x9A). [input] is
     * the already-prepared value the card signs: a PKCS#1 DigestInfo for
     * RSA, or the raw hash for ECDSA/EdDSA — the caller (the OpenPGP
     * signature bridge in Phase 2b) is responsible for that formatting.
     * Returns the raw signature value from the card. Requires PW1/0x81 to
     * have been verified immediately beforehand.
     */
    fun signDigest(input: ByteArray): ByteArray {
        val resp = transmit(
            CommandApdu(
                cla = 0x00,
                ins = OpenPgpCard.INS_PERFORM_SECURITY_OPERATION,
                p1 = OpenPgpCard.P1_PSO_CDS,
                p2 = OpenPgpCard.P2_PSO_CDS,
                data = input,
                le = 256
            )
        )
        return resp.data
    }

    /**
     * CHANGE REFERENCE DATA (INS 0x24). The card splits the concatenated
     * [oldPin]||[newPin] using its stored length of the current PIN, so
     * the caller just supplies both. [pinReference] is CRD_PW1 (0x81) for
     * the user PIN or CRD_PW3 (0x83) for the admin PIN. Throws WrongPin
     * (tries remaining) if the current PIN is wrong.
     */
    fun changeReferenceData(pinReference: Int, oldPin: ByteArray, newPin: ByteArray) {
        transmit(
            CommandApdu(
                cla = 0x00,
                ins = OpenPgpCard.INS_CHANGE_REFERENCE_DATA,
                p1 = 0x00,
                p2 = pinReference,
                data = oldPin + newPin
            )
        )
    }

    /**
     * PSO:DECIPHER (INS 0x2A, P1P2 0x80 0x86). [cipherData] is the full
     * Cipher DO the card deciphers — for ECDH that's
     * A6 { 7F49 { 86 <ephemeral public point> } } (see EcdhCipherData).
     * Returns the card's output: for X25519 ECDH, the 32-byte shared
     * secret (the host then runs the RFC 6637 KDF + key unwrap). Requires
     * PW1/0x82 (PW1_OTHER) to have been verified beforehand.
     */
    fun decipher(cipherData: ByteArray): ByteArray {
        val resp = transmit(
            CommandApdu(
                cla = 0x00,
                ins = OpenPgpCard.INS_PERFORM_SECURITY_OPERATION,
                p1 = OpenPgpCard.P1_PSO_DECIPHER,
                p2 = OpenPgpCard.P2_PSO_DECIPHER,
                data = cipherData,
                le = 256
            )
        )
        return resp.data
    }

    /**
     * PSO:DECIPHER for an RSA encryption key (HW Phase AR-2). Unlike the
     * ECDH path, the OpenPGP card spec §7.2.11 RSA padding indicator format
     * is just:
     *
     *   00 <cryptogram>
     *
     * — a single 0x00 byte followed by the RSA cryptogram, with no A6/7F49
     * Cipher DO wrapping. The card performs the RSA private operation AND
     * strips the PKCS#1 v1.5 (EME) padding, returning the OpenPGP session
     * key block directly (symAlgoID ‖ key ‖ 2-byte checksum). There is no
     * host-side KDF or AES key unwrap — the caller returns the card output
     * verbatim and BC verifies the checksum.
     *
     * [cryptogram] is the RSA-encrypted value parsed from the PKESK MPI
     * (leading zero bytes already stripped, as MPIs are minimal). It is
     * left-padded with zeros to [modulusBytes] here, because the card
     * expects the cryptogram at the full modulus length (the ~1/256 case
     * where the high byte is zero must be restored). For RSA-4096 the data
     * field is 1 + 512 = 513 bytes, which requires the extended-length
     * APDU encoding from Phase AR-1.
     *
     * Requires PW1/0x82 (PW1_OTHER) to have been verified beforehand.
     */
    fun decipherRsa(cryptogram: ByteArray, modulusBytes: Int): ByteArray {
        // Left-pad the cryptogram to the modulus length. Trim only if a
        // stray leading zero pushed it one byte over (defensive; a valid
        // cryptogram is < n, so it never exceeds modulusBytes once minimal).
        val padded = when {
            cryptogram.size == modulusBytes -> cryptogram
            cryptogram.size < modulusBytes ->
                ByteArray(modulusBytes - cryptogram.size) + cryptogram
            else -> {
                val extra = cryptogram.size - modulusBytes
                require(cryptogram.take(extra).all { it.toInt() == 0 }) {
                    "RSA cryptogram (${cryptogram.size}) longer than modulus ($modulusBytes)"
                }
                cryptogram.copyOfRange(extra, cryptogram.size)
            }
        }

        // 00 padding indicator || cryptogram. The 513-byte field exceeds the
        // short-APDU limit, so transmit() sends it via command chaining (see
        // sendCommand) — extended-length is rejected by the card with 0x6982.
        val data = ByteArray(1 + padded.size)
        data[0] = 0x00
        System.arraycopy(padded, 0, data, 1, padded.size)

        val resp = transmit(
            CommandApdu(
                cla = 0x00,
                ins = OpenPgpCard.INS_PERFORM_SECURITY_OPERATION,
                p1 = OpenPgpCard.P1_PSO_DECIPHER,
                p2 = OpenPgpCard.P2_PSO_DECIPHER,
                data = data,
                le = 256
            )
        )
        return resp.data
    }

    /**
     * High-level: SELECT the application and change the user PIN (PW1).
     * Self-contained like readCardInfo — this is what the NFC reader's
     * operation lambda invokes on tap. No admin PIN, no key material:
     * the low-risk "nicety" from the v6.0 plan.
     */
    fun changeUserPin(oldPin: String, newPin: String) {
        select()
        changeReferenceData(
            OpenPgpCard.CRD_PW1,
            oldPin.toByteArray(Charsets.UTF_8),
            newPin.toByteArray(Charsets.UTF_8)
        )
    }

    // ── Phase B2: admin-PIN lifecycle ──────────────────────────────────

    /**
     * High-level: SELECT + change the admin PIN (PW3). Same CHANGE REFERENCE
     * DATA path as the user PIN, just the PW3 reference. Throws WrongPin
     * (tries remaining) if [oldPin] is wrong; PW3 blocks at 0 tries and then
     * only a factory reset recovers the card.
     */
    fun changeAdminPin(oldPin: String, newPin: String) {
        select()
        changeReferenceData(
            OpenPgpCard.CRD_PW3,
            oldPin.toByteArray(Charsets.UTF_8),
            newPin.toByteArray(Charsets.UTF_8)
        )
    }

    /**
     * Unblock the user PIN (PW1) with RESET RETRY COUNTER (INS 0x2C) after
     * verifying the admin PIN (PW3). P1 = 0x02 (admin-authenticated), P2 =
     * CRD_PW1 (0x81); the data field is the NEW user PIN. The card restores
     * PW1's retry counter to full and sets it to [newUserPin]. Requires the
     * admin PIN — this is the recover-a-blocked-user-PIN path, not a reset of
     * a forgotten admin PIN (that needs factory reset).
     */
    fun unblockUserPin(adminPin: String, newUserPin: String) {
        select()
        verify(OpenPgpCard.PW3_ADMIN, adminPin.toByteArray(Charsets.UTF_8))
        transmit(
            CommandApdu(
                cla = 0x00,
                ins = OpenPgpCard.INS_RESET_RETRY_COUNTER,
                p1 = 0x02,
                p2 = OpenPgpCard.CRD_PW1,
                data = newUserPin.toByteArray(Charsets.UTF_8)
            )
        )
    }

    /**
     * Factory-reset the card to defaults (PW1 = 123456, PW3 = 12345678, all
     * key slots cleared). Blocks PW1 and PW3 by exhausting their retry
     * counters with wrong values, then TERMINATE DF (allowed once both are
     * blocked) + ACTIVATE FILE. This is GnuPG's `factory-reset` approach: it
     * needs no PIN, so it recovers a card you are locked out of — and it
     * destroys everything on the card. The UI gates this behind an explicit
     * two-step confirmation.
     */
    fun factoryReset() {
        select()
        blockPin(OpenPgpCard.PW1_SIGN)
        blockPin(OpenPgpCard.PW3_ADMIN)
        transmit(
            CommandApdu(cla = 0x00, ins = OpenPgpCard.INS_TERMINATE_DF, p1 = 0x00, p2 = 0x00)
        )
        transmit(
            CommandApdu(cla = 0x00, ins = OpenPgpCard.INS_ACTIVATE_FILE, p1 = 0x00, p2 = 0x00)
        )
        // Re-SELECT so the card is left in a usable (freshly initialized) state.
        select()
    }

    /**
     * Exhaust a PIN's retry counter with deliberately wrong values until the
     * card reports it blocked (0x6983) or zero tries (0x63C0). Capped so a
     * card that never reports blocked can't loop forever — if it isn't
     * actually blocked afterwards, the following TERMINATE DF fails safely
     * and the card is left unchanged.
     */
    private fun blockPin(reference: Int) {
        // 8 zero digits: a valid length for both PW1 (min 6) and PW3 (min 8),
        // and astronomically unlikely to be the real PIN.
        val wrong = "00000000".toByteArray(Charsets.UTF_8)
        repeat(MAX_BLOCK_ATTEMPTS) {
            val resp = transmit(
                CommandApdu(
                    cla = 0x00,
                    ins = OpenPgpCard.INS_VERIFY,
                    p1 = 0x00,
                    p2 = reference,
                    data = wrong
                ),
                throwOnError = false
            )
            // 0x6983 = blocked; 0x63C0 = wrong, zero tries remaining.
            if (resp.sw == OpenPgpCard.SW_AUTH_METHOD_BLOCKED || resp.sw == 0x63C0) return
        }
    }

    // ── Internal: transmit with GET RESPONSE / wrong-Le chaining ───────

    private fun transmit(command: CommandApdu, throwOnError: Boolean = true): ResponseApdu {
        var resp = sendCommand(command)

        // Accumulate response data across GET RESPONSE continuations.
        val buffer = ArrayList<Byte>()
        buffer.addAll(resp.data.toList())

        while (true) {
            when {
                resp.hasMoreData -> {
                    val le = if (resp.sw2 == 0) 256 else resp.sw2
                    resp = sendRaw(
                        CommandApdu(
                            cla = 0x00,
                            ins = OpenPgpCard.INS_GET_RESPONSE,
                            p1 = 0x00,
                            p2 = 0x00,
                            le = le
                        )
                    )
                    buffer.addAll(resp.data.toList())
                }
                resp.wrongLe -> {
                    // Resend the original command with the corrected Le.
                    buffer.clear()
                    resp = sendCommand(command.copy(le = if (resp.sw2 == 0) 256 else resp.sw2))
                    buffer.addAll(resp.data.toList())
                }
                else -> break
            }
        }

        val combined = ResponseApdu(buffer.toByteArray(), resp.sw1, resp.sw2)
        if (throwOnError && !combined.isSuccess) {
            throw OpenPgpCardException.CardStatus.of(combined.sw)
        }
        return combined
    }

    /**
     * Send a command, using ISO 7816-4 command chaining when the data field
     * exceeds the 255-byte short-APDU limit (the RSA-4096 PSO:DECIPHER carries
     * a 513-byte field).
     *
     * Phase AR-3c — extended-length APDUs are optional in the OpenPGP card
     * spec and are NOT reliably accepted over NFC: cards reject the large
     * DECIPHER with 0x6982 ("security status not satisfied", no PIN-counter
     * decrement) even after a successful VERIFY. Command chaining is mandated
     * by the spec ("Command chaining should be supported") and works on
     * YubiKey 5 NFC and Token2. Each chunk but the last carries the chaining
     * bit (CLA | 0x10) and no Le; the card accumulates the data and performs
     * the operation on the final command, where the real Le is sent. The card
     * acknowledges each non-final chunk with 0x9000.
     */
    private fun sendCommand(command: CommandApdu): ResponseApdu {
        if (command.data.size <= 255) return sendRaw(command)

        // 0x10 is the ISO 7816-4 command-chaining bit in the CLA byte.
        val chainBit = 0x10
        val chunks = command.data.asList().chunked(255)
        var resp = ResponseApdu(ByteArray(0), 0x90, 0x00)
        for ((index, chunk) in chunks.withIndex()) {
            val isLast = index == chunks.lastIndex
            resp = sendRaw(
                CommandApdu(
                    cla = if (isLast) command.cla else command.cla or chainBit,
                    ins = command.ins,
                    p1 = command.p1,
                    p2 = command.p2,
                    data = chunk.toByteArray(),
                    le = if (isLast) command.le else null
                )
            )
            // A non-final chunk must be acknowledged with 0x9000. If the card
            // rejects mid-chain, stop and surface that status to transmit().
            if (!isLast && !resp.isSuccess) return resp
        }
        return resp
    }

    private fun sendRaw(command: CommandApdu): ResponseApdu {
        val raw = try {
            transport.transceive(command.toBytes())
        } catch (e: OpenPgpCardException) {
            throw e
        } catch (e: Exception) {
            throw OpenPgpCardException.Communication("Card communication failed: ${e.message}", e)
        }
        return ResponseApdu.parse(raw)
    }
}

/**
 * Raw public-key material read from a card slot. RSA populates
 * [modulus]/[exponent]; ECC populates [ecPoint]. Phase 2/3 will turn
 * this into a Bouncy Castle public key.
 */
data class CardPublicKeyMaterial(
    val slot: CardSlot,
    val modulus: ByteArray?,
    val exponent: ByteArray?,
    val ecPoint: ByteArray?
) {
    val isRsa: Boolean get() = modulus != null && exponent != null
    val isEc: Boolean get() = ecPoint != null

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CardPublicKeyMaterial) return false
        return slot == other.slot &&
            (modulus?.contentEquals(other.modulus ?: ByteArray(0)) ?: (other.modulus == null)) &&
            (exponent?.contentEquals(other.exponent ?: ByteArray(0)) ?: (other.exponent == null)) &&
            (ecPoint?.contentEquals(other.ecPoint ?: ByteArray(0)) ?: (other.ecPoint == null))
    }

    override fun hashCode(): Int {
        var result = slot.hashCode()
        result = 31 * result + (modulus?.contentHashCode() ?: 0)
        result = 31 * result + (exponent?.contentHashCode() ?: 0)
        result = 31 * result + (ecPoint?.contentHashCode() ?: 0)
        return result
    }
}
