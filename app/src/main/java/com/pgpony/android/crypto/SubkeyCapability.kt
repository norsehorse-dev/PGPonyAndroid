// SubkeyCapability.kt
// PGPony Android
//
// Cross-platform-parity enum of subkey capabilities. Bit flag values
// MATCH iOS PGPony SubkeyCapabilitySet on purpose so subkey rows
// migrate cleanly if we ever sync the keyring across platforms:
//
//   Certify      = 0x01
//   Sign         = 0x02
//   Encrypt      = 0x04
//   Authenticate = 0x08
//
// Note: these values DIFFER from the OpenPGP wire-protocol KeyFlags
// values (where encrypt-comms is 0x04, encrypt-storage is 0x08, and
// authenticate is 0x20). iOS chose to fold encrypt-comms and
// encrypt-storage into a single Encrypt bit, and to compact
// Authenticate down from 0x20 to 0x08. We preserve that scheme here.
// Conversions happen at the BC boundary in `fromBcKeyFlags()` below.
//
// Added in Phase A1 (Subkey Model Refactor). Used by:
// - PgpSubkeyEntity.capabilities column
// - Phase A2 SigningService when picking a signing-capable subkey
// - Phase A6 SigningService when picking the certify-capable primary
//   for revocation signatures

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.sig.KeyFlags as BcKeyFlags
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature

enum class SubkeyCapability(val flag: Int, val displayName: String) {
    Certify(0x01, "Certify"),
    Sign(0x02, "Sign"),
    Encrypt(0x04, "Encrypt"),
    Authenticate(0x08, "Authenticate");

    companion object {

        // ── Bit-set helpers ───────────────────────────────────────────

        /** True iff `bits` contains this capability. */
        fun hasCapability(bits: Int, cap: SubkeyCapability): Boolean =
            (bits and cap.flag) != 0

        /** Expand a packed bit-set into the matching enum values. */
        fun fromBits(bits: Int): List<SubkeyCapability> =
            values().filter { hasCapability(bits, it) }

        /** Pack a list of capabilities back into a bit-set. */
        fun toBits(caps: List<SubkeyCapability>): Int =
            caps.fold(0) { acc, c -> acc or c.flag }

        /** Short comma-joined display string, e.g. "Certify, Sign". */
        fun displayString(bits: Int): String =
            fromBits(bits).joinToString(", ") { it.displayName }
                .ifEmpty { "None" }

        // ── BC interop ────────────────────────────────────────────────

        /**
         * Convert a Bouncy Castle (= OpenPGP wire) KeyFlags bit-set to
         * the PGPony scheme used in this enum.
         *
         * Wire-protocol flags (RFC 4880 §5.2.3.21):
         *   0x01 CERTIFY_OTHER     -> our Certify
         *   0x02 SIGN_DATA         -> our Sign
         *   0x04 ENCRYPT_COMMS     -> our Encrypt
         *   0x08 ENCRYPT_STORAGE   -> our Encrypt (folded)
         *   0x10 SPLIT             -> dropped (not a capability)
         *   0x20 AUTHENTICATION    -> our Authenticate
         *   0x80 SHARED            -> dropped (not a capability)
         */
        fun fromBcKeyFlags(bcKeyFlags: Int): Int {
            var ours = 0
            if (bcKeyFlags and BcKeyFlags.CERTIFY_OTHER != 0) ours = ours or Certify.flag
            if (bcKeyFlags and BcKeyFlags.SIGN_DATA != 0) ours = ours or Sign.flag
            if (bcKeyFlags and (BcKeyFlags.ENCRYPT_COMMS or BcKeyFlags.ENCRYPT_STORAGE) != 0) {
                ours = ours or Encrypt.flag
            }
            if (bcKeyFlags and BcKeyFlags.AUTHENTICATION != 0) ours = ours or Authenticate.flag
            return ours
        }

        // ── Heuristic fallback ────────────────────────────────────────

        /**
         * When the key has no usable self-signature (rare in v4 — but
         * possible for stripped public-key exports), guess capabilities
         * from algorithm + primary-vs-subkey position.
         *
         * Heuristic table:
         *   primary RSA            -> Certify | Sign | Encrypt
         *   primary Ed25519        -> Certify
         *   primary v6 Ed25519/Ed448 -> Certify
         *   subkey  RSA            -> Sign | Encrypt
         *   subkey  Ed25519/Ed448  -> Sign
         *   subkey  Cv25519/X25519/X448 -> Encrypt
         */
        fun heuristic(algorithm: KeyAlgorithm, isPrimary: Boolean): Int {
            return when (algorithm) {
                KeyAlgorithm.RSA_2048,
                KeyAlgorithm.RSA_4096 ->
                    if (isPrimary) Certify.flag or Sign.flag or Encrypt.flag
                    else Sign.flag or Encrypt.flag

                KeyAlgorithm.ED25519_CV25519 ->
                    if (isPrimary) Certify.flag else Encrypt.flag

                KeyAlgorithm.V6_ED25519,
                KeyAlgorithm.V6_ED448 ->
                    if (isPrimary) Certify.flag else Sign.flag

                KeyAlgorithm.V6_X25519,
                KeyAlgorithm.V6_X448 ->
                    if (isPrimary) Certify.flag else Encrypt.flag
            }
        }

        /**
         * Best-effort capability extraction from a Bouncy Castle public
         * key. Reads the most recent self-signature's KeyFlags subpacket
         * if present; falls back to the heuristic table when no flags
         * subpacket can be found.
         *
         * `algorithm` and `isPrimary` are passed by the caller because
         * they're already computed at the migration site — saves a
         * second `detectAlgorithm(pubKey)` call.
         */
        @JvmStatic
        fun fromPgpPublicKey(
            pubKey: PGPPublicKey,
            algorithm: KeyAlgorithm,
            isPrimary: Boolean
        ): Int {
            val flagsFromSig = readKeyFlagsFromSelfSig(pubKey)
            return flagsFromSig ?: heuristic(algorithm, isPrimary)
        }

        private fun readKeyFlagsFromSelfSig(pubKey: PGPPublicKey): Int? {
            try {
                val sigIter = pubKey.signatures ?: return null
                var newestTime = Long.MIN_VALUE
                var newestFlags: Int? = null
                while (sigIter.hasNext()) {
                    val sig = sigIter.next() as? PGPSignature ?: continue
                    val hashed = sig.hashedSubPackets ?: continue
                    if (!hashed.hasSubpacket(SignatureSubpacketTags.KEY_FLAGS)) continue
                    val flagsValue = hashed.keyFlags  // BC packs flags in an Int
                    // Prefer the most recent self-sig in case multiple
                    // self-sigs are present (re-bind on key edit, etc.)
                    val sigTime = sig.creationTime?.time ?: 0L
                    if (sigTime >= newestTime) {
                        newestTime = sigTime
                        newestFlags = flagsValue
                    }
                }
                return newestFlags?.let { fromBcKeyFlags(it) }
            } catch (_: Exception) {
                return null
            }
        }
    }
}
