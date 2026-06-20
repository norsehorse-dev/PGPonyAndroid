// KeyServerDto.kt
// PGPony Android
//
// Strongly-typed request and response shapes for the Hagrid VKS v1 API
// at keys.openpgp.org.
//
// Added in Phase A0 (Foundations) to replace the prior hand-rolled
// JSON string interpolation in KeyServerRepository. The interpolation
// was fragile (no escaping of quotes/backslashes in the armored key)
// and the response was never parsed, so the `token` field needed by
// `request-verify` was unreachable.
//
// API reference: https://keys.openpgp.org/about/api

package com.pgpony.android.network.dto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// ── VKS Upload ────────────────────────────────────────────────────────

/**
 * Body for POST /vks/v1/upload.
 * Hagrid wants `application/json` with a single `keytext` field.
 */
@Serializable
data class VksUploadRequest(
    val keytext: String
)

/**
 * Response body for POST /vks/v1/upload.
 *
 * - `keyFpr` (key_fpr in the wire format) is the v4 hex fingerprint
 *   Hagrid recorded for the uploaded key.
 * - `token` is an opaque string the client passes back to
 *   /vks/v1/request-verify to trigger verification emails.
 * - `status` maps each email address found in the uploaded key to its
 *   current state: "unpublished" | "pending" | "published" | "revoked".
 *
 * All fields are nullable because Hagrid may omit them in unusual
 * upload outcomes (e.g. a key with no user IDs).
 */
@Serializable
data class VksUploadResponse(
    @SerialName("key_fpr") val keyFpr: String? = null,
    val token: String? = null,
    val status: Map<String, String>? = null
)

// ── VKS Request-Verify ────────────────────────────────────────────────

/**
 * Body for POST /vks/v1/request-verify.
 * The `token` value comes from a prior upload response.
 */
@Serializable
data class VksRequestVerifyRequest(
    val token: String,
    val addresses: List<String>
)

/**
 * Response body for POST /vks/v1/request-verify.
 * Status values match the upload response: "unpublished" | "pending"
 * | "published" | "revoked".
 */
@Serializable
data class VksRequestVerifyResponse(
    @SerialName("key_fpr") val keyFpr: String? = null,
    val status: Map<String, String>? = null
)
