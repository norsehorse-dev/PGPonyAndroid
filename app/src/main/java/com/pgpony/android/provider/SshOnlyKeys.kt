// SshOnlyKeys.kt
// PGPony Android, 4.8.0 RC7 (item 1): the pure part of serving SSH-only
// ssh-mldsa44-ed25519 keys (data/ssh/SshKeyStore) through the SSH
// authentication API.
//
// SshAuthenticationService routes every request by its key id first: an id in
// the SSH-only scheme ("ssh:SHA256:...") goes to SshKeyStore and never reaches
// the OpenPGP lookup (findEntity), and every other id takes the OpenPGP path
// exactly as before. What the service answers for an SSH-only key (the
// description, the .pub line, the signature) is built here, with no Android
// dependency, so the JVM tests cover the same code the service runs.

package com.pgpony.android.provider

import com.pgpony.android.crypto.ssh.MlDsaEd25519Ssh
import com.pgpony.android.data.ssh.SshKeyEntry
import com.pgpony.android.data.ssh.SshKeyError
import com.pgpony.android.data.ssh.SshKeyStore

object SshOnlyKeys {

    /** Which key store a request's key id names. */
    enum class Route {
        /** No key id in the request. */
        NONE,
        /** An SSH-only key: SshKeyStore. */
        SSH_ONLY,
        /** Anything else: an OpenPGP fingerprint or key id, looked up as before. */
        OPENPGP
    }

    /** The route for the API's key_id extra as the client sent it. */
    fun route(rawId: String?): Route {
        val id = rawId?.trim()
        return when {
            id.isNullOrEmpty() -> Route.NONE
            SshKeyStore.isSshKeyId(id) -> Route.SSH_ONLY
            else -> Route.OPENPGP
        }
    }

    /** The trimmed SSH-only key id in [rawId], or null when it names no SSH-only key. */
    fun sshOnlyId(rawId: String?): String? =
        rawId?.trim()?.takeIf { route(it) == Route.SSH_ONLY }

    /**
     * The key_description SELECT_KEY returns, which the agent shows as the
     * key's comment (ssh-add -L). Same shape as an OpenPGP key's
     * "user id (subkey id)": the label, then the key type in brackets. A key
     * with no label shows its fingerprint instead.
     */
    fun description(entry: SshKeyEntry): String =
        "${entry.label.ifBlank { entry.fingerprint }} (${entry.keyType})"

    /**
     * The GET_SSH_PUBLIC_KEY answer: "type base64" with no comment, as for
     * OpenPGP keys. The clients take everything after the first space and
     * decode it as base64, so a comment would break them.
     */
    fun sshPublicKey(entry: SshKeyEntry): String = MlDsaEd25519Ssh.publicKeyLine(entry.publicKey, "")

    /** What [sign] did. */
    sealed class SignResult {
        /** The full SSH signature blob: string(type) + string(signature). */
        class Ok(val blob: ByteArray) : SignResult()
        /** No such key: deleted after the client stored its id. */
        object NoSuchKey : SignResult()
        /** The key is listed but its secret can no longer be read on this device. */
        object Unreadable : SignResult()
    }

    /**
     * [challenge] signed with SSH-only key [id]. [hashAlgorithm] is the API's
     * hash_algorithm extra; the OkcAgent fork passes the raw ssh-agent flags,
     * which are 0 for this type. It is ignored, as for Ed25519: the composite
     * always hashes with SHA-512, and there is no RSA hash choice to make.
     */
    @Suppress("UNUSED_PARAMETER")
    fun sign(store: SshKeyStore, id: String, challenge: ByteArray, hashAlgorithm: Int): SignResult = try {
        SignResult.Ok(store.sign(id, challenge))
    } catch (e: SshKeyError.NotFound) {
        SignResult.NoSuchKey
    } catch (e: SshKeyError.Unreadable) {
        SignResult.Unreadable
    }
}
