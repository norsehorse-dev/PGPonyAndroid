// QrMissingParts.kt
// PGPony Android, 4.8.0 RC8 (#100): what the scanner shows about the parts of
// a multi-part code it has not read yet.
//
// A tester sat at 31 of 32 parts with no way to tell which part the camera
// kept missing, so he could not wait for it. The scanner now lists the missing
// part numbers once only a few are left, and draws a strip of every part
// (filled when received) the whole time. The strip wraps into rows so a
// 512-part code stays a compact block instead of a line too thin to read.
// Pure Kotlin so the thresholds and the layout are unit-tested.

package com.pgpony.android.qr

object QrMissingParts {

    /** The most part numbers listed by name; above this only the strip shows them. */
    const val LIST_LIMIT = 8

    /** One row holds every part of a normal (32 or fewer) code. */
    private const val ROW_PARTS = 32

    /** A long code packs twice as many parts per row so the block stays short. */
    private const val LONG_ROW_PARTS = 64

    /** The part numbers to list by name, or null when none are missing or too many to list. */
    fun toList(missing: List<Int>): List<Int>? =
        missing.takeIf { it.isNotEmpty() && it.size <= LIST_LIMIT }?.sorted()

    /** How many parts one row of the strip holds for a code of [total] parts. */
    fun columns(total: Int): Int = when {
        total <= ROW_PARTS -> maxOf(total, 1)
        total <= 2 * ROW_PARTS -> ROW_PARTS
        else -> LONG_ROW_PARTS
    }

    /** Rows the strip needs for [total] parts. */
    fun rows(total: Int): Int = if (total <= 0) 0 else (total + columns(total) - 1) / columns(total)
}
