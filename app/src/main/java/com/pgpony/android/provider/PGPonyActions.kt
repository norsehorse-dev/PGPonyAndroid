// PGPonyActions.kt
// PGPony Android 4.8.2 (item 1): PGPony's own actions on the OpenPGP provider.
//
// These ride on the standard IOpenPgpService2 binding, after the same API
// version gate and the same signature-pinned allow-list as every OpenPGP
// action. A client finds them with GET_CAPABILITIES; PGPony 4.8.1 and older
// answer it with GENERIC_ERROR "Unknown OpenPGP API action". The names and
// extras here are a published contract (docs/PROVIDER_PGPONY_ACTIONS.md):
// add to them, never rename or change the meaning of one.

package com.pgpony.android.provider

object PGPonyActions {

    /** Bumped when an action is added or an extra gains a meaning. */
    const val API_LEVEL = 1

    const val ACTION_GET_CAPABILITIES = "com.pgpony.android.action.GET_CAPABILITIES"
    const val ACTION_X25519_KEYS = "com.pgpony.android.action.X25519_KEYS"
    const val ACTION_X25519_AGREE = "com.pgpony.android.action.X25519_AGREE"

    // GET_CAPABILITIES results.
    /** String[]: the PGPony actions this build answers. */
    const val EXTRA_CAPABILITIES = "com.pgpony.android.extra.CAPABILITIES"
    /** int: [API_LEVEL]. */
    const val EXTRA_API_LEVEL = "com.pgpony.android.extra.API_LEVEL"
    /** int: the most points one X25519_AGREE call takes. */
    const val EXTRA_X25519_MAX_POINTS = "com.pgpony.android.extra.X25519_MAX_POINTS"

    // X25519_KEYS results, parallel arrays, one entry per subkey.
    /** String[]: subkey fingerprints, upper-case hex (40 or 64 digits). */
    const val EXTRA_X25519_SUBKEY_FINGERPRINTS = "com.pgpony.android.extra.X25519_SUBKEY_FINGERPRINTS"
    /** String[]: the primary key fingerprint of each subkey. */
    const val EXTRA_X25519_PRIMARY_FINGERPRINTS = "com.pgpony.android.extra.X25519_PRIMARY_FINGERPRINTS"
    /** byte[]: the 32-byte public u-coordinates, concatenated in order. */
    const val EXTRA_X25519_PUBLIC_POINTS = "com.pgpony.android.extra.X25519_PUBLIC_POINTS"
    /** String[]: the primary User ID of each key, for showing to the user. */
    const val EXTRA_X25519_LABELS = "com.pgpony.android.extra.X25519_LABELS"
    /** boolean[]: whether each subkey is on a security key. */
    const val EXTRA_X25519_ON_CARD = "com.pgpony.android.extra.X25519_ON_CARD"

    // X25519_AGREE request and result.
    /** String: the subkey to agree with (as X25519_KEYS lists it). */
    const val EXTRA_X25519_SUBKEY_FINGERPRINT = "com.pgpony.android.extra.X25519_SUBKEY_FINGERPRINT"
    /** byte[]: 1 to EXTRA_X25519_MAX_POINTS points of 32 bytes, concatenated. */
    const val EXTRA_X25519_POINTS = "com.pgpony.android.extra.X25519_POINTS"
    /** byte[]: one 32-byte shared secret per point, concatenated in order. */
    const val EXTRA_X25519_SECRETS = "com.pgpony.android.extra.X25519_SECRETS"

    /** String on an error result of a PGPony action: a stable reason
     *  (X25519Agreement.Refusal.code) next to the OpenPgpError text. */
    const val EXTRA_ERROR_REASON = "com.pgpony.android.extra.ERROR_REASON"

    val CAPABILITIES: Array<String> = arrayOf(ACTION_X25519_KEYS, ACTION_X25519_AGREE)
}
