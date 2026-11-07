// SshAuthenticationService.kt
// PGPony Android, 4.6.0 (item 16, issue #68): the SSH authentication API.
//
// The service an ssh-agent bridge binds to so `ssh` in Termux can sign in with
// a key held in PGPony, the way OkcAgent does with OpenKeychain. The private
// key never leaves PGPony (or the card): the client sends a challenge, PGPony
// returns the SSH signature.
//
// Contract: org.openintents.ssh.authentication (API version 1), the interface
// OpenKeychain implements. One AIDL call, execute(Intent), with four actions:
//
//   SELECT_KEY          no key id: a PendingIntent to PGPony's key picker
//                       (keys with a usable authentication subkey only); with
//                       a key id (the picker's answer): the id and a
//                       description the agent shows as the key's comment.
//   GET_SSH_PUBLIC_KEY  the key in OpenSSH .pub form ("type base64").
//   GET_PUBLIC_KEY      X.509 SubjectPublicKeyInfo and an algorithm code.
//   SIGN                the challenge signed with the authentication subkey,
//                       as an SSH signature blob. For RSA the hash follows the
//                       request (ssh-rsa, rsa-sha2-256, rsa-sha2-512).
//
// The key id PGPony hands out is the primary key's fingerprint (hex). A
// decimal 64-bit key id, which OpenKeychain hands out, is also accepted, so an
// agent set up against OpenKeychain keeps working once the same key is in
// PGPony.
//
// Consent and unlock follow the OpenPGP provider: the calling app is allowed
// once (the same signature-pinned allow-list, Settings > Connected apps, but
// its own SSH scope: an app allowed for OpenPGP gets no SSH signatures, and an
// app allowed for SSH gets no OpenPGP operations), a
// protected key asks for its passphrase once per unlock session
// (ProviderPassphraseCache), and a card key asks for a tap and PIN on every
// signature (INTERNAL AUTHENTICATE on the authentication slot). Every prompt
// is a PendingIntent the client launches; each hands the client's request
// back so the client re-executes it.
//
// 4.6.0: each app is bound to the key the user picked for it in the SSH key
// picker (ApiClientAuthorizer.bindSshKey, written only by the picker). A
// request naming any other key gets the picker again, showing only that key,
// so the user approves it explicitly; nothing is signed with a key the user
// did not choose for that app.
//
// 4.6.3 (#68): an app keeps every key the user approved for it, not only the
// last one. An agent with several keys asks for all their public keys on each
// connection, and with a single binding every approval undid the previous
// one, so the picker came back on every connection. Each key is now approved
// once.
//
// 4.8.0 RC7 (item 1): SSH-only ssh-mldsa44-ed25519 keys (OpenSSH 10.6)
// (data/ssh/SshKeyStore), which no OpenPGP subkey or card can hold. Their key
// id is "ssh:SHA256:..." (SshKeyStore.isSshKeyId), and every action routes on
// it before any OpenPGP lookup, so findEntity never sees one and the OpenPGP
// path is unchanged. Such a key is approved per app like an OpenPGP key (the
// picker lists both), has no passphrase and no card, and answers SELECT_KEY,
// GET_SSH_PUBLIC_KEY and SIGN. GET_PUBLIC_KEY has no algorithm code for it and
// returns INVALID_ALGORITHM; neither OkcAgent nor okc-agents calls it.

package com.pgpony.android.provider

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.ssh.SshAuth
import com.pgpony.android.crypto.ssh.SshSigningKey
import com.pgpony.android.data.ApiClientEntity
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.data.ssh.SshKeyEntry
import com.pgpony.android.data.ssh.SshKeyStore
import com.pgpony.android.i18n.ErrorText
import kotlinx.coroutines.runBlocking
import org.openintents.ssh.authentication.ISshAuthenticationService
import org.openintents.ssh.authentication.SshAuthenticationApiError

class SshAuthenticationService : Service() {

    companion object {
        const val SERVICE_INTENT = "org.openintents.ssh.authentication.ISshAuthenticationService"
        const val API_VERSION = 1

        const val EXTRA_API_VERSION = "api_version"
        const val EXTRA_RESULT_CODE = "result_code"
        const val RESULT_CODE_ERROR = 0
        const val RESULT_CODE_SUCCESS = 1
        const val RESULT_CODE_USER_INTERACTION_REQUIRED = 2
        const val EXTRA_ERROR = "error"
        const val EXTRA_PENDING_INTENT = "intent"

        const val ACTION_SIGN = "org.openintents.ssh.action.SIGN"
        const val ACTION_SELECT_KEY = "org.openintents.ssh.action.SELECT_KEY"
        const val ACTION_GET_PUBLIC_KEY = "org.openintents.ssh.action.GET_PUBLIC_KEY"
        const val ACTION_GET_SSH_PUBLIC_KEY = "org.openintents.ssh.action.GET_SSH_PUBLIC_KEY"

        const val EXTRA_KEY_ID = "key_id"
        const val EXTRA_KEY_DESCRIPTION = "key_description"
        const val EXTRA_CHALLENGE = "challenge"
        const val EXTRA_HASH_ALGORITHM = "hash_algorithm"
        const val EXTRA_SIGNATURE = "signature"
        const val EXTRA_PUBLIC_KEY = "public_key"
        const val EXTRA_PUBLIC_KEY_ALGORITHM = "public_key_algorithm"
        const val EXTRA_SSH_PUBLIC_KEY = "ssh_public_key"

        /** A single challenge larger than this is not an SSH session hash. */
        private const val MAX_CHALLENGE = 64 * 1024
    }

    private val repo: KeyRepository
        get() = (application as PGPonyApp).keyRepository

    // 4.8.0 RC7 (item 1): it caches nothing, so a key made in the main process
    // is seen here on the next request, without a restart of :remote_api.
    private val sshKeys: SshKeyStore
        get() = (application as PGPonyApp).sshKeyStore

    private val authorizer: ApiClientAuthorizer by lazy {
        ApiClientAuthorizer(
            dao = (application as PGPonyApp).database.apiClientDao(),
            signatureSha256Of = ApiClientAuthorizer.platformSignatureLookup(packageManager)
        )
    }

    private val binder = object : ISshAuthenticationService.Stub() {
        override fun execute(intent: Intent?): Intent {
            if (intent == null) return error(SshAuthenticationApiError.GENERIC_ERROR, "No request")
            intent.setExtrasClassLoader(this@SshAuthenticationService.classLoader)
            return try {
                executeInternal(intent, Binder.getCallingUid())
            } catch (t: Throwable) {
                // Nothing may cross the binder as an exception (see the
                // OpenPGP provider): report it as ours, text intact.
                error(SshAuthenticationApiError.INTERNAL_ERROR, t.message ?: t.javaClass.simpleName)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private fun executeInternal(data: Intent, callingUid: Int): Intent {
        val version = data.getIntExtra(EXTRA_API_VERSION, -1)
        if (version != API_VERSION) {
            return error(
                SshAuthenticationApiError.INCOMPATIBLE_API_VERSIONS,
                "PGPony supports SSH authentication API version $API_VERSION, client sent $version"
            )
        }
        val callingPackage = packageManager.getPackagesForUid(callingUid)?.firstOrNull()
            ?: return error(SshAuthenticationApiError.GENERIC_ERROR, "Could not resolve the calling app")

        when (runBlocking { authorizer.authorize(callingPackage, ApiClientEntity.SCOPE_SSH) }) {
            ApiClientAuthorizer.Decision.AUTHORIZED -> Unit
            ApiClientAuthorizer.Decision.UNKNOWN -> return consentRequired(callingPackage, data)
            ApiClientAuthorizer.Decision.SIGNATURE_MISMATCH -> return error(
                SshAuthenticationApiError.GENERIC_ERROR,
                "The signature of $callingPackage does not match the one allowed in PGPony. " +
                    "Remove it under PGPony Settings > Connected apps and connect again."
            )
            ApiClientAuthorizer.Decision.UNRESOLVABLE -> return error(
                SshAuthenticationApiError.GENERIC_ERROR,
                "Could not read the signing certificate of $callingPackage"
            )
        }

        return when (data.action) {
            ACTION_SELECT_KEY -> selectKey(data, callingPackage)
            ACTION_GET_SSH_PUBLIC_KEY -> publicKey(data, callingPackage, sshFormat = true)
            ACTION_GET_PUBLIC_KEY -> publicKey(data, callingPackage, sshFormat = false)
            ACTION_SIGN -> sign(data, callingPackage)
            else -> error(SshAuthenticationApiError.UNKNOWN_ACTION, "Unknown action: ${data.action}")
        }
    }

    // ── Key resolution ─────────────────────────────────────────────────

    private class Resolved(
        val entity: PGPKeyEntity,
        val sub: CertificateBindings.SubkeyState,
        val material: SshAuth.Material
    )

    private sealed class Lookup {
        class Ok(val r: Resolved) : Lookup()
        class Fail(val response: Intent) : Lookup()
    }

    /** The key a request names, or an error result. */
    private fun resolve(data: Intent): Lookup {
        val id = data.getStringExtra(EXTRA_KEY_ID)?.trim()
        if (id.isNullOrEmpty()) {
            return Lookup.Fail(error(SshAuthenticationApiError.NO_KEY_ID, "No key id in request"))
        }
        // 4.8.0 RC7 (item 1): every action routes SSH-only ids away before
        // this; the guard keeps findEntity from ever seeing one.
        if (SshKeyStore.isSshKeyId(id)) {
            return Lookup.Fail(error(SshAuthenticationApiError.NO_SUCH_KEY, "Key not found in PGPony"))
        }
        val entity = runBlocking { findEntity(id) }
            ?: return Lookup.Fail(error(SshAuthenticationApiError.NO_SUCH_KEY, "Key not found in PGPony"))
        if (entity.isRevoked) {
            return Lookup.Fail(error(SshAuthenticationApiError.NO_SUCH_KEY, "This key is revoked"))
        }
        val cert = repo.sshAuthCertificate(entity.fingerprint)
            ?: return Lookup.Fail(error(SshAuthenticationApiError.NO_SUCH_KEY, "Key not found in PGPony"))
        val sub = SshAuth.authSubkey(cert)
            ?: return Lookup.Fail(
                error(
                    SshAuthenticationApiError.NO_AUTH_KEY,
                    if (SshAuth.onlyDualUseAuthSubkeys(cert)) {
                        getString(R.string.ssh_error_dual_use_auth)
                    } else {
                        "${entity.userID} has no usable authentication subkey. " +
                            "Add an Authenticate subkey in PGPony's Key Detail."
                    }
                )
            )
        val material = SshAuth.material(sub.publicBody)
            ?: return Lookup.Fail(error(SshAuthenticationApiError.INVALID_ALGORITHM, "Algorithm not supported for SSH"))
        return Lookup.Ok(Resolved(entity, sub, material))
    }

    /** By primary fingerprint (hex), or by a decimal 64-bit key id. */
    private suspend fun findEntity(id: String): PGPKeyEntity? {
        val hex = id.removePrefix("0x").removePrefix("0X").filter { !it.isWhitespace() && it != ':' }
        if ((hex.length == 40 || hex.length == 64) && hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            return repo.getAllKeys().firstOrNull { it.fingerprint.equals(hex, ignoreCase = true) }
        }
        val keyId = id.toLongOrNull() ?: return null
        return repo.getAllKeys().firstOrNull { entity ->
            runCatching { java.lang.Long.parseUnsignedLong(entity.longKeyId, 16) }.getOrNull() == keyId
        }
    }

    /**
     * The key named by [data] if it is the one bound to [callingPackage];
     * otherwise the picker, limited to that key, for the user to approve.
     */
    private fun resolveBound(data: Intent, callingPackage: String): Lookup {
        val l = resolve(data)
        if (l !is Lookup.Ok) return l
        if (runBlocking { authorizer.sshKeyAllowed(callingPackage, l.r.entity.fingerprint) }) return l
        return Lookup.Fail(keyPicker(data, callingPackage, onlyFingerprint = l.r.entity.fingerprint))
    }

    private fun keyPicker(data: Intent, callingPackage: String, onlyFingerprint: String?): Intent {
        // 4.8.0 RC7 (item 1): [onlyFingerprint] may be an SSH-only key id,
        // whose base64 must keep its case (normalizeSshKey uppercases only
        // OpenPGP fingerprints) and holds '/' and '+', so it is encoded for
        // the URI (a hex fingerprint encodes to itself).
        val only = onlyFingerprint?.let { ApiClientEntity.normalizeSshKey(it) }
        val picker = Intent(this, ProviderKeyPickerActivity::class.java).apply {
            putExtra(ProviderKeyPickerActivity.EXTRA_API_DATA, data)
            putExtra(ProviderKeyPickerActivity.EXTRA_FOR_SSH, true)
            putExtra(ProviderKeyPickerActivity.EXTRA_SSH_CLIENT_PACKAGE, callingPackage)
            if (only != null) {
                putExtra(ProviderKeyPickerActivity.EXTRA_SSH_ONLY_FINGERPRINT, only)
            }
            setData(
                android.net.Uri.parse(
                    "pgpony-ssh-selectkey://$callingPackage/${only?.let { android.net.Uri.encode(it) } ?: "any"}"
                )
            )
        }
        return interaction(PendingIntent.getActivity(this, 10, picker, pendingFlags()))
    }

    private fun description(r: Resolved): String =
        "${r.entity.userID.ifBlank { r.entity.shortFingerprint }} (${String.format("%016X", r.sub.keyId)})"

    // ── Actions ────────────────────────────────────────────────────────

    private fun selectKey(data: Intent, callingPackage: String): Intent {
        if (data.getStringExtra(EXTRA_KEY_ID).isNullOrEmpty()) {
            return keyPicker(data, callingPackage, onlyFingerprint = null)
        }
        SshOnlyKeys.sshOnlyId(data.getStringExtra(EXTRA_KEY_ID))?.let { id ->
            return when (val l = resolveSshOnlyBound(id, data, callingPackage)) {
                is SshOnlyLookup.Fail -> l.response
                is SshOnlyLookup.Ok -> success().apply {
                    putExtra(EXTRA_KEY_ID, l.entry.id)
                    putExtra(EXTRA_KEY_DESCRIPTION, SshOnlyKeys.description(l.entry))
                }
            }
        }
        return when (val l = resolveBound(data, callingPackage)) {
            is Lookup.Fail -> l.response
            is Lookup.Ok -> success().apply {
                putExtra(EXTRA_KEY_ID, l.r.entity.fingerprint.uppercase())
                putExtra(EXTRA_KEY_DESCRIPTION, description(l.r))
            }
        }
    }

    private fun publicKey(data: Intent, callingPackage: String, sshFormat: Boolean): Intent {
        SshOnlyKeys.sshOnlyId(data.getStringExtra(EXTRA_KEY_ID))?.let { id ->
            return sshOnlyPublicKey(id, data, callingPackage, sshFormat)
        }
        return when (val l = resolveBound(data, callingPackage)) {
            is Lookup.Fail -> l.response
            is Lookup.Ok -> if (sshFormat) {
                success().apply {
                    putExtra(EXTRA_SSH_PUBLIC_KEY, SshAuth.authorizedKeysLine(l.r.material, ""))
                }
            } else {
                val (spki, alg) = SshAuth.subjectPublicKeyInfo(l.r.material)
                success().apply {
                    putExtra(EXTRA_PUBLIC_KEY, spki)
                    putExtra(EXTRA_PUBLIC_KEY_ALGORITHM, alg)
                }
            }
        }
    }

    private fun sign(data: Intent, callingPackage: String): Intent {
        val challenge = data.getByteArrayExtra(EXTRA_CHALLENGE)
        if (challenge == null || challenge.isEmpty()) {
            return error(SshAuthenticationApiError.GENERIC_ERROR, "No challenge given")
        }
        if (challenge.size > MAX_CHALLENGE) {
            return error(SshAuthenticationApiError.GENERIC_ERROR, "Challenge too large")
        }
        val hash = data.getIntExtra(EXTRA_HASH_ALGORITHM, SshAuthenticationApiError.INVALID_HASH_ALGORITHM)
        SshOnlyKeys.sshOnlyId(data.getStringExtra(EXTRA_KEY_ID))?.let { id ->
            return sshOnlySign(id, data, callingPackage, challenge, hash)
        }
        val r = when (val l = resolveBound(data, callingPackage)) {
            is Lookup.Fail -> return l.response
            is Lookup.Ok -> l.r
        }
        if (r.material is SshAuth.Material.Rsa &&
            hash !in setOf(SshAuth.HASH_SHA1, SshAuth.HASH_SHA256, SshAuth.HASH_SHA512)
        ) {
            return error(SshAuthenticationApiError.INVALID_HASH_ALGORITHM, "Unsupported hash algorithm for RSA")
        }

        if (r.entity.isCardBacked) return cardSign(data, r, challenge, hash)

        val primaryKeyId = runCatching { java.lang.Long.parseUnsignedLong(r.entity.longKeyId, 16) }.getOrDefault(r.sub.keyId)
        val ring = repo.loadSshAuthSecretRing(r.entity.fingerprint)
            ?: return error(
                SshAuthenticationApiError.NO_AUTH_KEY,
                storageFailureMessage() ?: "The private key for ${r.entity.userID} is not on this device"
            )
        val passphrase = ProviderPassphraseCache.get(primaryKeyId)
        return when (val u = SshSigningKey.unlock(ring, r.sub.keyId, passphrase)) {
            is SshSigningKey.Unlock.Ok -> try {
                success().apply { putExtra(EXTRA_SIGNATURE, SshAuth.sign(r.material, u.key, challenge, hash)) }
            } catch (e: SshAuth.UnsupportedHash) {
                error(SshAuthenticationApiError.INVALID_HASH_ALGORITHM, e.message ?: "Unsupported hash algorithm")
            }
            SshSigningKey.Unlock.NeedsPassphrase ->
                passphraseRequired(data, primaryKeyId, r.entity.userID, wasWrong = false)
            SshSigningKey.Unlock.WrongPassphrase -> {
                ProviderPassphraseCache.clear(primaryKeyId)
                passphraseRequired(data, primaryKeyId, r.entity.userID, wasWrong = true)
            }
            is SshSigningKey.Unlock.Missing -> error(SshAuthenticationApiError.NO_AUTH_KEY, u.reason)
        }
    }

    /** A card key: tap and PIN in ProviderCardOpActivity, then the client's
     *  re-execute collects the signature. */
    private fun cardSign(data: Intent, r: Resolved, challenge: ByteArray, hash: Int): Intent {
        val opKey = ProviderCardOpStore.opKey(
            ACTION_SIGN, r.sub.keyId, false, hash.toString(), emptyList(), challenge
        )
        val done = ProviderCardOpStore.consumeCompleted(opKey)
        if (done is ProviderCardOpStore.CompletedOp.SshSignature) {
            return success().apply { putExtra(EXTRA_SIGNATURE, done.blob) }
        }
        ProviderCardOpStore.putPending(
            ProviderCardOpStore.PendingOp(
                opKey = opKey,
                action = ACTION_SIGN,
                input = challenge,
                cardEntityFingerprint = r.entity.fingerprint,
                armor = false,
                filename = null,
                recipientFingerprints = emptyList(),
                senderAddress = null,
                sshHash = hash
            )
        )
        val cardIntent = Intent(this, ProviderCardOpActivity::class.java).apply {
            putExtra(ProviderCardOpActivity.EXTRA_OP_KEY, opKey)
            putExtra(ProviderCardOpActivity.EXTRA_API_DATA, data)
            setData(android.net.Uri.parse("pgpony-ssh-cardop://$opKey"))
        }
        return interaction(PendingIntent.getActivity(this, 13, cardIntent, pendingFlags()))
    }

    // ── SSH-only keys (4.8.0 RC7, item 1) ──────────────────────────────

    private sealed class SshOnlyLookup {
        class Ok(val entry: SshKeyEntry) : SshOnlyLookup()
        class Fail(val response: Intent) : SshOnlyLookup()
    }

    /**
     * The SSH-only key [id] if [callingPackage] is approved for it; otherwise
     * the picker, limited to that key, as for an OpenPGP key. A key deleted
     * after the client stored its id is NO_SUCH_KEY.
     */
    private fun resolveSshOnlyBound(id: String, data: Intent, callingPackage: String): SshOnlyLookup {
        val entry = sshKeys.get(id)
            ?: return SshOnlyLookup.Fail(error(SshAuthenticationApiError.NO_SUCH_KEY, "Key not found in PGPony"))
        if (runBlocking { authorizer.sshKeyAllowed(callingPackage, entry.id) }) return SshOnlyLookup.Ok(entry)
        return SshOnlyLookup.Fail(keyPicker(data, callingPackage, onlyFingerprint = entry.id))
    }

    private fun sshOnlyPublicKey(id: String, data: Intent, callingPackage: String, sshFormat: Boolean): Intent {
        // GET_PUBLIC_KEY's algorithm codes (RSA, ECDSA, EdDSA, DSA) have none
        // for this type. Answered before any lookup, so it says nothing about
        // which keys exist and opens no picker for a request that cannot work.
        if (!sshFormat) {
            return error(SshAuthenticationApiError.INVALID_ALGORITHM, "Algorithm not supported for SSH")
        }
        return when (val l = resolveSshOnlyBound(id, data, callingPackage)) {
            is SshOnlyLookup.Fail -> l.response
            is SshOnlyLookup.Ok -> success().apply { putExtra(EXTRA_SSH_PUBLIC_KEY, SshOnlyKeys.sshPublicKey(l.entry)) }
        }
    }

    /**
     * No passphrase and no card: once the app is approved for the key, the
     * signature is made at once, the same as an OpenPGP SSH key with no
     * passphrase. The hash argument is ignored (SshOnlyKeys.sign).
     */
    private fun sshOnlySign(id: String, data: Intent, callingPackage: String, challenge: ByteArray, hash: Int): Intent {
        val entry = when (val l = resolveSshOnlyBound(id, data, callingPackage)) {
            is SshOnlyLookup.Fail -> return l.response
            is SshOnlyLookup.Ok -> l.entry
        }
        return when (val r = SshOnlyKeys.sign(sshKeys, entry.id, challenge, hash)) {
            is SshOnlyKeys.SignResult.Ok -> success().apply { putExtra(EXTRA_SIGNATURE, r.blob) }
            SshOnlyKeys.SignResult.NoSuchKey ->
                error(SshAuthenticationApiError.NO_SUCH_KEY, "Key not found in PGPony")
            SshOnlyKeys.SignResult.Unreadable ->
                error(SshAuthenticationApiError.NO_AUTH_KEY, getString(R.string.ssh_error_sshkey_unreadable))
        }
    }

    // ── Interaction results ────────────────────────────────────────────

    private fun consentRequired(callingPackage: String, data: Intent): Intent {
        val consent = Intent(this, ApiConsentActivity::class.java).apply {
            putExtra(ApiConsentActivity.EXTRA_PACKAGE_NAME, callingPackage)
            putExtra(ApiConsentActivity.EXTRA_API_DATA, data)
            setData(android.net.Uri.parse("${ApiConsentActivity.SSH_CONSENT_SCHEME}://$callingPackage"))
        }
        return interaction(PendingIntent.getActivity(this, 11, consent, pendingFlags()))
    }

    private fun passphraseRequired(data: Intent, keyId: Long, label: String, wasWrong: Boolean): Intent {
        val prompt = Intent(this, ProviderPassphraseActivity::class.java).apply {
            putExtra(ProviderPassphraseActivity.EXTRA_KEY_ID, keyId)
            putExtra(ProviderPassphraseActivity.EXTRA_KEY_LABEL, label)
            putExtra(ProviderPassphraseActivity.EXTRA_WRONG, wasWrong)
            putExtra(ProviderPassphraseActivity.EXTRA_API_DATA, data)
            putExtra(ProviderPassphraseActivity.EXTRA_NO_KEY_CHANGE, true)
            setData(android.net.Uri.parse("pgpony-ssh-passphrase://$keyId/$wasWrong"))
        }
        return interaction(PendingIntent.getActivity(this, 12, prompt, pendingFlags()))
    }

    private fun pendingFlags(): Int = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE

    private fun storageFailureMessage(): String? = when {
        repo.keyMaterialRecoverable() -> getString(R.string.ssh_error_storage_recoverable)
        repo.keyMaterialUnreadable() -> getString(R.string.ssh_error_storage_unreadable)
        else -> null
    }

    private fun interaction(pi: PendingIntent): Intent = Intent().apply {
        putExtra(EXTRA_RESULT_CODE, RESULT_CODE_USER_INTERACTION_REQUIRED)
        putExtra(EXTRA_PENDING_INTENT, pi)
    }

    private fun success(): Intent = Intent().apply {
        putExtra(EXTRA_RESULT_CODE, RESULT_CODE_SUCCESS)
    }

    // 4.6.2: the one place the text for the SSH client is built, so every
    // error (including e.message passthroughs) reaches it in the user's language.
    private fun error(code: Int, message: String): Intent = Intent().apply {
        putExtra(EXTRA_RESULT_CODE, RESULT_CODE_ERROR)
        putExtra(EXTRA_ERROR, SshAuthenticationApiError(code, ErrorText.localize(message) ?: message))
    }
}
