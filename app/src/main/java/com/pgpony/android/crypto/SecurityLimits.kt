// SecurityLimits.kt
// PGPony Android — 4.5.0 (Cipher review, Finding A/B)
//
// One place for every resource ceiling used by the decrypt hardening guards.
// Bounds are policy: each sits above real GnuPG / Sequoia / PGPony values and
// below the abuse band, so a legitimate message is never rejected while a
// crafted one fails closed with PGPCryptoError.ResourceLimitExceeded.

package com.pgpony.android.crypto

object SecurityLimits {
    // Argon2 memory is 2^m KiB. PGPony's own messages and keys use 64 MiB
    // (m = 16). Reject anything above 2^22 KiB (4 GiB) outright.
    const val ARGON2_MAX_MEM_EXP = 22

    // Always allow up to our own encrypt parameters regardless of the device
    // heap, so no legitimate PGPony / GnuPG / Sequoia message is turned away by
    // the device-relative check.
    const val ARGON2_SELF_MEM_EXP = 16

    const val ARGON2_MAX_PASSES = 64
    const val ARGON2_MAX_PARALLELISM = 64

    // Above ARGON2_SELF_MEM_EXP, also refuse anything that would not fit this
    // fraction of the JVM max heap.
    const val KDF_HEAP_FRACTION = 0.5

    // Finding B (11B): decompression-bomb caps.
    // Compression nesting depth. Legitimate messages nest 0-2; deep nesting
    // overflows the recursion stack.
    const val MAX_DECOMPRESSION_DEPTH = 8
    // Total decrypted plaintext buffered IN MEMORY (the message decrypt path).
    // Large files use the streaming path instead.
    const val MAX_MESSAGE_PLAINTEXT_BYTES = 128L * 1024 * 1024
    // Total decrypted plaintext written by the STREAMING path (files). Generous;
    // stops a runaway zlib bomb without rejecting a real large attachment.
    const val MAX_STREAM_PLAINTEXT_BYTES = 8L * 1024 * 1024 * 1024

    // 4.6.0 (item 17.7): the most an OpenPGP API caller may hand the provider
    // as input in one call. The provider buffers input whole (it sniffs the
    // message shape first), so this bounds the :remote_api process's memory.
    const val MAX_PROVIDER_INPUT_BYTES = 256L * 1024 * 1024

    // 4.6.0: a .zip that wraps a message. The payload is ciphertext, so it gets
    // the streaming path's bound; the entry count stops an archive of millions
    // of tiny entries from spinning the scan.
    const val MAX_ZIP_PAYLOAD_BYTES = MAX_STREAM_PLAINTEXT_BYTES
    const val MAX_ZIP_ENTRIES = 1000
}
