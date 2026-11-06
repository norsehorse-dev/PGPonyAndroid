// KeyServerCheck.kt
// PGPony Android 4.8.0 (#90): Check on Key Details asks the key servers the
// user marked for lookup, in the user's order, instead of keys.openpgp.org
// only.
//
// A key published only on keys.pgpony.app or on a server the user added read
// "not on keys.openpgp.org", which was true and not what the user asked. The
// check now stops at the first server that has the key and names it. A server
// that cannot be reached is skipped; the check fails only when every server
// failed, so one server being down does not hide an answer from the others.
// The iteration is kept apart from the network so it can be unit-tested.

package com.pgpony.android.keyserver

import kotlinx.coroutines.CancellationException

object KeyServerCheck {

    sealed class Outcome {
        /** [server] (its display name) has the key. */
        data class Found(val server: String) : Outcome()

        /** No server had the key. [asked] are the servers that answered, in
         *  order; one that could not be reached is not listed, since it did
         *  not say the key is missing. */
        data class NotFound(val asked: List<String>) : Outcome()

        /** Every server failed; [error] is the last failure. */
        data class Failed(val error: Exception) : Outcome()
    }

    /**
     * The servers Check asks: those marked "Use for lookup", in the order the
     * user set in Settings. With none marked, keys.openpgp.org, which is what
     * Check asked before 4.8.0 and what the other lookups fall back to.
     */
    fun serversToAsk(directory: List<KeyServer>): List<KeyServer> =
        directory.filter { it.lookupEnabled }.ifEmpty {
            KeyServerDirectory.DEFAULTS.filter { it.id == KeyServerDirectory.ID_OPENPGP }
        }

    /**
     * Ask [servers] in order with [fetch] (armored key, null when the server
     * does not have it, throws when the server cannot be reached) and stop at
     * the first that has the key.
     */
    suspend fun <S> askInOrder(
        servers: List<S>,
        name: (S) -> String,
        fetch: suspend (S) -> String?
    ): Outcome {
        val answered = mutableListOf<String>()
        var lastError: Exception? = null
        for (server in servers) {
            var hit: String? = null
            var failed = false
            try {
                hit = fetch(server)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                lastError = e
                failed = true
            }
            if (failed) continue
            if (!hit.isNullOrBlank()) return Outcome.Found(name(server))
            answered += name(server)
        }
        val error = lastError
        if (answered.isEmpty() && error != null) return Outcome.Failed(error)
        return Outcome.NotFound(answered)
    }
}
