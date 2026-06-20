// OpenPgpCard.kt
// PGPony Android — HW Phase 0
//
// Constants for the OpenPGP card application (ISO 7816-4 APDUs).
// References: OpenPGP card spec v3.4.1 (gnupg.org) and the YubiKey /
// Token2 PIN+ implementations of it. These are the raw protocol values
// the APDU layer and OpenPgpCardSession build on — no Android
// dependencies here, so everything in this file is unit-testable on the
// JVM without a device.
//
// Scope note: Phase 0/1 only exercises SELECT, GET DATA, and (optionally)
// the read-public-key form of GENERATE ASYMMETRIC KEY PAIR. The PSO /
// VERIFY / CHANGE REFERENCE DATA constants are defined here now so the
// Phase 2/3 sign + decrypt + PIN work doesn't have to re-derive them,
// but they are not used yet.

package com.pgpony.android.crypto.card

object OpenPgpCard {

    // ── Application identifier ─────────────────────────────────────────
    //
    // The full AID is 16 bytes:
    //   D2 76 00 01 24 01   RID(5) + application(1) = OpenPGP application
    //   VV VV               spec version (e.g. 03 04)
    //   MM MM               manufacturer id
    //   SS SS SS SS         serial number
    //   00 00               RFU
    // Selecting by the 6-byte prefix performs a partial AID select, which
    // matches the OpenPGP application regardless of version/mfr/serial.
    val AID_PREFIX = byteArrayOf(
        0xD2.toByte(), 0x76, 0x00, 0x01, 0x24, 0x01
    )

    /** Length of the full AID stored in DO 0x4F. */
    const val AID_LENGTH = 16

    /** Byte offsets within the 16-byte AID. */
    const val AID_OFFSET_MANUFACTURER = 8   // 2 bytes
    const val AID_OFFSET_SERIAL = 10        // 4 bytes

    // ── Instruction bytes (INS) ────────────────────────────────────────
    const val INS_SELECT: Int = 0xA4
    const val INS_GET_DATA: Int = 0xCA
    const val INS_GET_RESPONSE: Int = 0xC0
    const val INS_VERIFY: Int = 0x20                       // Phase 2/3
    const val INS_CHANGE_REFERENCE_DATA: Int = 0x24        // Phase 2 (PW1 change)
    const val INS_PERFORM_SECURITY_OPERATION: Int = 0x2A   // Phase 2/3 (PSO)
    const val INS_INTERNAL_AUTHENTICATE: Int = 0x88        // deferred (auth slot)
    const val INS_GENERATE_ASYMMETRIC_KEY_PAIR: Int = 0x47
    const val INS_PUT_DATA: Int = 0xDA                     // Phase B1: write DOs
    // ── Phase B2: admin-PIN lifecycle ──────────────────────────────────
    const val INS_RESET_RETRY_COUNTER: Int = 0x2C   // unblock PW1
    const val INS_TERMINATE_DF: Int = 0xE6          // factory reset (step 1)
    const val INS_ACTIVATE_FILE: Int = 0x44         // factory reset (step 2)

    // ── SELECT parameters ──────────────────────────────────────────────
    const val P1_SELECT_BY_NAME: Int = 0x04
    const val P2_SELECT_FIRST_OR_ONLY: Int = 0x00

    // ── GENERATE ASYMMETRIC KEY PAIR parameters ────────────────────────
    const val P1_GENERATE: Int = 0x80       // generate fresh keypair (deferred)
    const val P1_READ_PUBLIC_KEY: Int = 0x81 // read existing public key

    // CRT (Control Reference Template) tags identifying which slot a
    // GENERATE / PSO operation targets.
    const val CRT_SIGNATURE: Int = 0xB6
    const val CRT_DECRYPTION: Int = 0xB8
    const val CRT_AUTHENTICATION: Int = 0xA4

    // ── PSO parameters (Phase 2/3 — defined, not yet used) ─────────────
    const val P1_PSO_CDS: Int = 0x9E        // compute digital signature
    const val P2_PSO_CDS: Int = 0x9A
    const val P1_PSO_DECIPHER: Int = 0x80
    const val P2_PSO_DECIPHER: Int = 0x86

    // ── VERIFY / CHANGE REFERENCE DATA reference values (Phase 2/3) ─────
    const val PW1_SIGN: Int = 0x81          // authorizes PSO:CDS
    const val PW1_OTHER: Int = 0x82         // authorizes PSO:DEC etc.
    const val PW3_ADMIN: Int = 0x83         // admin PIN

    // CHANGE REFERENCE DATA P2 references: PW1 = 0x81, PW3 = 0x83. (There
    // is no sign/other distinction here — that only applies to VERIFY.)
    const val CRD_PW1: Int = 0x81
    const val CRD_PW3: Int = 0x83

    // ── Data Object tags ───────────────────────────────────────────────
    const val DO_APPLICATION_RELATED_DATA: Int = 0x6E
    const val DO_AID: Int = 0x4F
    const val DO_HISTORICAL_BYTES: Int = 0x5F52
    const val DO_DISCRETIONARY: Int = 0x73
    const val DO_EXTENDED_CAPABILITIES: Int = 0xC0
    const val DO_ALGORITHM_ATTRIBUTES_SIG: Int = 0xC1
    const val DO_ALGORITHM_ATTRIBUTES_DEC: Int = 0xC2
    const val DO_ALGORITHM_ATTRIBUTES_AUTH: Int = 0xC3
    const val DO_PW_STATUS_BYTES: Int = 0xC4
    const val DO_FINGERPRINTS: Int = 0xC5
    const val DO_CA_FINGERPRINTS: Int = 0xC6
    // ── Phase B1: per-slot fingerprint + generation-time DOs (PUT DATA) ──
    // Written after on-card key generation so the card carries the OpenPGP
    // fingerprint + creation time for each slot. Per OpenPGP card spec §4.4.1.
    const val DO_FINGERPRINT_SIG: Int = 0xC7
    const val DO_FINGERPRINT_DEC: Int = 0xC8
    const val DO_FINGERPRINT_AUTH: Int = 0xC9
    const val DO_GENTIME_SIG: Int = 0xCE
    const val DO_GENTIME_DEC: Int = 0xCF
    const val DO_GENTIME_AUTH: Int = 0xD0
    const val DO_GENERATION_TIMES: Int = 0xCD
    const val DO_PUBLIC_KEY_TEMPLATE: Int = 0x7F49
    const val DO_CARDHOLDER_RELATED_DATA: Int = 0x65

    // Public key template sub-tags (inside 0x7F49)
    const val DO_PK_RSA_MODULUS: Int = 0x81
    const val DO_PK_RSA_EXPONENT: Int = 0x82
    const val DO_PK_EC_POINT: Int = 0x86

    // Cipher DO (Phase 3) — wraps the ephemeral public key in the
    // PSO:DECIPHER command data: A6 { 7F49 { 86 <ephemeral point> } }.
    const val DO_CIPHER: Int = 0xA6

    // ── Algorithm IDs as they appear in the algorithm-attributes DO ────
    // These match the OpenPGP public-key algorithm IDs.
    const val ALGO_RSA: Int = 0x01
    const val ALGO_ECDH: Int = 0x12   // 18
    const val ALGO_ECDSA: Int = 0x13  // 19
    const val ALGO_EDDSA: Int = 0x16  // 22

    // ── Status words ───────────────────────────────────────────────────
    const val SW_SUCCESS: Int = 0x9000
    const val SW1_MORE_DATA: Int = 0x61          // SW1; SW2 = bytes still available
    const val SW1_WRONG_LE: Int = 0x6C           // SW1; SW2 = correct Le
    const val SW1_VERIFY_REMAINING: Int = 0x63   // SW1; low nibble of SW2 = PIN tries left
    const val SW_SECURITY_NOT_SATISFIED: Int = 0x6982
    const val SW_AUTH_METHOD_BLOCKED: Int = 0x6983
    const val SW_CONDITIONS_NOT_SATISFIED: Int = 0x6985
    const val SW_FILE_NOT_FOUND: Int = 0x6A82
    const val SW_INCORRECT_PARAMS: Int = 0x6A80
    const val SW_WRONG_PARAMS_P1P2: Int = 0x6B00
    const val SW_INS_NOT_SUPPORTED: Int = 0x6D00
    const val SW_CLASS_NOT_SUPPORTED: Int = 0x6E00

    // ── Known manufacturer IDs (best-effort friendly names) ────────────
    // Source: FSFE OpenPGP-card vendor registry. 0x0000 and 0xFFFF are
    // reserved for testing / randomly-assigned serials.
    fun manufacturerName(id: Int): String = when (id) {
        0x0000 -> "Test card"
        0x0001 -> "PPC Card Systems"
        0x0002 -> "Prism Payment Technologies"
        0x0003 -> "OpenFortress"
        0x0004 -> "Wewid"
        0x0005 -> "ZeitControl"
        0x0006 -> "Yubico"
        0x0007 -> "OpenKMS"
        0x0008 -> "LogoEmail"
        0x0009 -> "Fidesmo"
        0x000A -> "VivoKey"
        0x000B -> "Feitian Technologies"
        0x000D -> "Dangerous Things"
        0x000E -> "Excelsecu"
        0x000F -> "Nitrokey"
        0x0010 -> "NeoPGP"
        0x0011 -> "Token2"
        0x002A -> "Magrathea"
        0x0042 -> "GnuPG e.V."
        0x1337 -> "Warsaw Hackerspace"
        0x63AF -> "Trustica"
        0xFFFF -> "Test card"
        else -> "Manufacturer 0x%04X".format(id)
    }
}
