// PGPonyOpenPgpService.kt
// PGPony Android — 4.0.0 Succession Phase 1 (OpenPGP API provider)
//
// The exported OpenPGP API provider service — the headline surface of
// the 4.0.0 release. Client apps (Thunderbird for Android, K-9 Mail,
// Password Store, Conversations) discover providers by resolving the
// "org.openintents.openpgp.IOpenPgpService2" intent action, bind, and
// drive everything through IOpenPgpService2.execute(Intent, PFD, pipeId).
//
// Phase 1 scope — handshake + identity only:
//   • API-version negotiation (versions 7–11, matching OpenKeychain)
//   • signature-pinned per-package authorization with a first-use
//     consent flow (RESULT_CODE_USER_INTERACTION_REQUIRED + a
//     PendingIntent to ApiConsentActivity — the API's standard pattern)
//   • ACTION_CHECK_PERMISSION (the client "am I connected?" probe)
//   • ACTION_GET_KEY_IDS (public-key lookup by email user id)
//   • every crypto action (ENCRYPT / SIGN_AND_ENCRYPT / DECRYPT_VERIFY /
//     DETACHED_SIGN / CLEARTEXT_SIGN / GET_KEY / GET_SIGN_KEY_ID / …)
//     returns a descriptive not-yet-implemented OpenPgpError — wired to
//     the real crypto layer in Phase 2.
//
// Security posture (plan §5 — largest new attack surface in the app):
//   • no default-allow: every package hits the consent flow once, and
//     the signature pin is re-checked on EVERY call
//   • unauthorized callers learn nothing: no key material, no key
//     counts, not even "wrong API version" before authorization runs
//     (version check is the one exception — it leaks only that PGPony
//     speaks versions 7–11, which the manifest already advertises)
//   • the binder identity (Binder.getCallingUid) is the source of truth
//     for WHO is calling — never an Intent extra
//
// Threading: execute() runs on a binder pool thread, never the main
// thread. The Room DAO calls are wrapped in runBlocking — acceptable
// because binder threads are made for exactly this kind of synchronous
// remote call, and every DB op here is a single-row lookup.

package com.pgpony.android.provider

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SigningError
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.autocrypt.AutocryptPeerStore
import com.pgpony.android.autocrypt.AutocryptRecommendation
import com.pgpony.android.data.repository.KeyRepository
import kotlinx.coroutines.runBlocking
import org.openintents.openpgp.AutocryptPeerUpdate
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.OpenPgpDecryptionResult
import org.openintents.openpgp.OpenPgpError
import org.openintents.openpgp.OpenPgpMetadata
import org.openintents.openpgp.OpenPgpSignatureResult
import org.openintents.openpgp.util.OpenPgpApi
import java.util.concurrent.ConcurrentHashMap

class PGPonyOpenPgpService : Service() {

    /**
     * API versions this provider accepts. Clients send
     * EXTRA_API_VERSION on every call; anything outside this set gets
     * OpenPgpError.INCOMPATIBLE_API_VERSIONS.
     *
     * P1 Fix1: 7..11 → 7..12. The plan doc said "versions 7–11 as
     * implemented by OpenKeychain", but that described the 2024-frozen
     * 6.0.4 release; Thunderbird for Android's openpgp-api fork sends
     * API_VERSION = 12 (verified in thunderbird-android source), and
     * OpenKeychain master accepts Arrays.asList(7..12) with 12 =
     * API_VERSION_WITH_AUTOCRYPT. Version 12 adds the Autocrypt
     * actions — new actions, not changed semantics — and those are
     * honestly stubbed here until Phase P4, so accepting 12 is
     * correct. Without this, Thunderbird's compose screen shows
     * "Crypto provider uses incompatible version."
     */
    private val supportedApiVersions = 7..12

    /**
     * P2c Fix4: hard ceiling on payload size for HARDWARE-CARD operations
     * through the provider. The card is only tapped at the END of an
     * encrypt/sign (the signature is the last packet), so it sits
     * CONNECTED BUT IDLE for the whole time BC processes the payload —
     * and an NFC link with no traffic goes stale ("Tag is out of date")
     * on a large file. This is an architectural limit of the card flow
     * (the in-app card path has it too), not something streaming fixes:
     * the real answer is a two-phase hash-then-tap-to-sign flow, tracked
     * as a follow-up. Until then, above this size the provider returns a
     * clear "use a software key" error instead of hanging. Software keys
     * stream unbounded (P2d), so large attachments have a working path.
     */
    private val cardOpMaxBytes = 8L * 1024 * 1024

    private val repo: KeyRepository
        get() = (application as PGPonyApp).keyRepository

    private val crypto: PGPCryptoService
        get() = PGPCryptoService.shared

    private val autocryptStore: AutocryptPeerStore
        get() = (application as PGPonyApp).autocryptPeerStore

    // SigningService (not crypto.sign) for the sign-only actions:
    // its buildSignatureGenerator throws TYPED SigningErrors
    // (PassphraseRequired / InvalidPassphrase) which drive the
    // passphrase-prompt flow, whereas crypto.sign() wraps everything
    // into a generic SigningFailed.
    private val signing: SigningService
        get() = SigningService.shared

    private val verifier: VerifyService
        get() = VerifyService.shared

    private val authorizer: ApiClientAuthorizer by lazy {
        ApiClientAuthorizer(
            dao = (application as PGPonyApp).database.apiClientDao(),
            signatureSha256Of = ApiClientAuthorizer.platformSignatureLookup(packageManager)
        )
    }

    /**
     * Output pipes created by createOutputPipe, keyed by
     * "callingUid/pipeId" so concurrent clients can't collide or steal
     * each other's pipes. The WRITE end is held here for the matching
     * execute() call; the READ end is returned to the client.
     * Phase 1's implemented actions produce no stream output, but the
     * plumbing is contract-complete so Phase 2 only adds crypto.
     */
    private val outputPipes = ConcurrentHashMap<String, ParcelFileDescriptor>()

    private val binder = object : IOpenPgpService2.Stub() {

        override fun createOutputPipe(pipeId: Int): ParcelFileDescriptor {
            val pipe = ParcelFileDescriptor.createReliablePipe()
            outputPipes["${Binder.getCallingUid()}/$pipeId"] = pipe[1]
            return pipe[0]
        }

        override fun execute(data: Intent, input: ParcelFileDescriptor?, pipeId: Int): Intent {
            // 4.1.0, issue #9 (yuyuchen2) — set the class loader BEFORE
            // anything reads an extra.
            //
            // An Intent that arrives over Binder carries its extras as an
            // unparsed blob and unparcels them lazily using the FRAMEWORK
            // class loader. Every framework type resolves; no app type does.
            // `org.openintents.openpgp.AutocryptPeerUpdate` is an app type on
            // both sides of this boundary, so reading it in
            // updateAutocryptPeer threw, ON OUR SIDE:
            //
            //   BadParcelableException: ClassNotFoundException when
            //   unmarshalling: org.openintents.openpgp.AutocryptPeerUpdate
            //
            // That crossed back as a Binder exception, the client's OpenPgpApi
            // wrapper caught it, and the user saw "OpenPgp error -1:
            // ClassNotFoundException when unmarshalling…". Error -1 is
            // CLIENT_SIDE_ERROR, so the report reads as the mail app's fault.
            // It is not.
            //
            // This is NOT the 4.0.4 R8 bug wearing the same exception text.
            // That one renamed our class names on the way OUT; keep rules
            // fixed it. Here the name is intact and nothing told the Bundle
            // where to look for it, so debug builds fail identically and no
            // amount of keep rules helps. FairEmail is the client that
            // surfaces it because it sends ACTION_UPDATE_AUTOCRYPT_PEER around
            // a decrypt; OpenKeychain works because it sets this exact loader
            // at the top of its own dispatcher.
            data.setExtrasClassLoader(this@PGPonyOpenPgpService.classLoader)

            val pipeKey = "${Binder.getCallingUid()}/$pipeId"
            val output = outputPipes.remove(pipeKey)
            try {
                return executeInternal(data, input, output, Binder.getCallingUid())
            } catch (t: Throwable) {
                // Nothing may cross the Binder as an exception. What escapes
                // here is reported by the client as CLIENT_SIDE_ERROR (-1),
                // which points the user at their mail app for a fault in
                // ours — exactly how issue #9 was misfiled for a week. Report
                // it as ours, with the text intact so a log still identifies
                // it. OutOfMemoryError included: a 45 MB attachment must fail
                // as an error, not as a dead binder call.
                return errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    t.message ?: t.javaClass.simpleName
                )
            } finally {
                // Phase 1 actions never write stream output; close both
                // ends so the client's read sees EOF instead of a hang.
                try { input?.close() } catch (ignored: Exception) {}
                try { output?.close() } catch (ignored: Exception) {}
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    // ── Dispatch ───────────────────────────────────────────────────────

    private fun executeInternal(
        data: Intent,
        input: ParcelFileDescriptor?,
        output: ParcelFileDescriptor?,
        callingUid: Int
    ): Intent {
        // 1) API version gate.
        val version = data.getIntExtra(OpenPgpApi.EXTRA_API_VERSION, -1)
        if (version !in supportedApiVersions) {
            return errorResult(
                OpenPgpError.INCOMPATIBLE_API_VERSIONS,
                "PGPony supports OpenPGP API versions " +
                    "${supportedApiVersions.first}–${supportedApiVersions.last}, " +
                    "client sent $version"
            )
        }

        // 2) Resolve the calling package from the binder uid — the only
        //    caller identity that can't be spoofed by an extra.
        val callingPackage = packageManager.getPackagesForUid(callingUid)?.firstOrNull()
            ?: return errorResult(
                OpenPgpError.GENERIC_ERROR,
                "Could not resolve calling package for uid $callingUid"
            )

        // 3) Authorization (signature-pinned, re-checked every call).
        when (runBlocking { authorizer.authorize(callingPackage) }) {
            ApiClientAuthorizer.Decision.AUTHORIZED -> Unit // fall through

            ApiClientAuthorizer.Decision.UNKNOWN ->
                return consentRequiredResult(callingPackage)

            ApiClientAuthorizer.Decision.SIGNATURE_MISMATCH ->
                return errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    "The signature of $callingPackage does not match the one " +
                        "authorized in PGPony. If you reinstalled or updated this " +
                        "app from a different source, remove it under PGPony " +
                        "Settings → Connected apps and connect again."
                )

            ApiClientAuthorizer.Decision.UNRESOLVABLE ->
                return errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    "Could not read the signing certificate of $callingPackage"
                )
        }

        // #51: pick the signing key when the choice is real. Two of the
        // user's own signing keys can share one address (e.g. a modern Ed25519
        // key and a legacy RSA key on the same email); signing one of them
        // silently, locked to the client's cached key, was the reported bug.
        // When the address is ambiguous we ask once and remember the pick for
        // that address, so later sends from it are silent (RandomNam3). The
        // "ask which key to sign with" toggle forces the prompt every send,
        // which is also how the user changes a remembered pick. Skipped once
        // the picker has resumed the op (EXTRA_SIGN_CHOICE_MADE) — that resume
        // is where the pick is persisted.
        val signActions = setOf(
            OpenPgpApi.ACTION_SIGN_AND_ENCRYPT,
            OpenPgpApi.ACTION_CLEARTEXT_SIGN,
            OpenPgpApi.ACTION_SIGN,
            OpenPgpApi.ACTION_DETACHED_SIGN
        )
        if (data.action in signActions) {
            if (data.getBooleanExtra(ProviderKeyPickerActivity.EXTRA_SIGN_CHOICE_MADE, false)) {
                // Resumed after a pick. In auto-ask mode (the toggle off) the pick
                // becomes this address's pinned key, so later sends are silent. In
                // "ask every time" mode the pick is for this one send only and is
                // NOT pinned — otherwise the first pick would end the asking.
                if (!askSignKeyEachSend()) {
                    val chosen = data.getLongExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, 0L)
                    val email = sendIdentityEmail(data)
                    if (chosen != 0L && !email.isNullOrBlank()) rememberSignKeyFor(email, chosen)
                }
            } else {
                val email = sendIdentityEmail(data)
                // An explicit per-address key — pinned in Connected apps, or
                // remembered from an earlier auto-ask — wins, even over the "ask
                // which key to sign with" toggle. So that toggle only prompts for
                // addresses the user has not pinned.
                val pinned = email?.let { validatedRememberedKey(it) }
                when {
                    pinned != null -> data.putExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, pinned)
                    askSignKeyEachSend() && signingCandidateCount() > 1 ->
                        // Always-ask: show ALL signing keys, unscoped, so a
                        // single identity with several addresses (catch-all) can
                        // still reach every key (RandomNam3, #51).
                        return perSendSignKeyInteraction(data, callingPackage, scopeToAddress = false)
                    email != null && countSigningKeysForEmail(email) > 1 ->
                        return perSendSignKeyInteraction(data, callingPackage)
                }
            }
        }

        // 4) Action dispatch.
        return when (data.action) {
            OpenPgpApi.ACTION_CHECK_PERMISSION -> successResult()

            OpenPgpApi.ACTION_GET_KEY_IDS -> getKeyIds(data)

            // P2a-1 — signing-key selection (Thunderbird's "Configure
            // end-to-end key").
            OpenPgpApi.ACTION_GET_SIGN_KEY_ID -> getSignKeyId(data, callingPackage)

            // P2a-2 — the send path.
            OpenPgpApi.ACTION_ENCRYPT -> encryptOp(data, input, output, withSignature = false)
            OpenPgpApi.ACTION_SIGN_AND_ENCRYPT -> encryptOp(data, input, output, withSignature = true)
            OpenPgpApi.ACTION_CLEARTEXT_SIGN -> cleartextSign(data, input, output)
            // ACTION_SIGN is the deprecated alias for cleartext sign
            // (see OpenPgpApi.java) — same handler.
            OpenPgpApi.ACTION_SIGN -> cleartextSign(data, input, output)
            OpenPgpApi.ACTION_DETACHED_SIGN -> detachedSign(data, input)

            // P2a-2 Fix1 — recipient crypto-capability probe. Without
            // this, Thunderbird's compose lock says "recipients don't
            // support this feature" for EVERY recipient and encryption
            // can never be enabled.
            OpenPgpApi.ACTION_QUERY_AUTOCRYPT_STATUS -> queryAutocryptStatus(data)

            // P2b-1 — the receive path.
            OpenPgpApi.ACTION_DECRYPT_VERIFY ->
                decryptVerify(data, input, output, metadataOnly = false)
            OpenPgpApi.ACTION_DECRYPT_METADATA ->
                decryptVerify(data, input, output, metadataOnly = true)

            // P2b-2 — public-key export (clients' "show/fetch signer key").
            OpenPgpApi.ACTION_GET_KEY -> getKey(data, output)

            // ── Remaining Phase 2 actions — contract-visible, stubbed ──
            OpenPgpApi.ACTION_UPDATE_AUTOCRYPT_PEER -> updateAutocryptPeer(data)

            OpenPgpApi.ACTION_GET_SIGN_KEY_ID_LEGACY,
            OpenPgpApi.ACTION_BACKUP ->
                errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    "PGPony does not implement ${data.action} yet — crypto " +
                        "operations arrive in the next release phase."
                )

            else -> errorResult(
                OpenPgpError.GENERIC_ERROR,
                "Unknown OpenPGP API action: ${data.action}"
            )
        }
    }

    // ── Actions ────────────────────────────────────────────────────────

    /**
     * ACTION_GET_KEY_IDS — map email user ids (EXTRA_USER_IDS) to the
     * 64-bit key ids of held public keys. Key-id derivation is
     * version-aware via PGPKeyEntity.longKeyId (v4 trailing 16 hex
     * chars, v6 leading 16 — never slice the fingerprint here).
     *
     * Phase 1 returns exact userEmail matches only. The Phase 2 pass
     * adds the OpenKeychain "download missing key / select ambiguous
     * key" PendingIntent flows on top (plan Phase 2 + §6 Q7 route the
     * lookups through the Phase 5a multi-server directory).
     */
    private fun getKeyIds(data: Intent): Intent {
        val userIds = data.getStringArrayExtra(OpenPgpApi.EXTRA_USER_IDS) ?: emptyArray()
        val keyIds = runBlocking {
            userIds
                .mapNotNull { raw ->
                    val email = raw.substringAfterLast('<').substringBefore('>').trim()
                        .ifEmpty { raw.trim() }
                    // 4.2.1 (#27): match ANY user id, not just the primary,
                    // so a secondary identity (4.2.0 #29) resolves here and
                    // the client is offered encryption to it.
                    repo.getByAnyUserEmail(email).firstOrNull()
                }
                .map { entity -> java.lang.Long.parseUnsignedLong(entity.longKeyId, 16) }
                .toLongArray()
        }
        return successResult().putExtra(OpenPgpApi.RESULT_KEY_IDS, keyIds)
    }

    /**
     * ACTION_GET_SIGN_KEY_ID — P2a-1. Semantics ported from
     * OpenKeychain's getSignKeyIdImpl (verified against master source),
     * because OpenPgpKeyPreference-based clients depend on the exact
     * shape:
     *
     *   • a key-picker PendingIntent is attached to EVERY response
     *     (success included) — it's how the client's widget re-opens
     *     the picker to CHANGE an existing selection;
     *   • request carrying RESULT_SIGN_KEY_ID ("sign_key_id" — the
     *     re-execution after our picker returned) → SUCCESS echoing it;
     *   • otherwise → USER_INTERACTION_REQUIRED, with
     *     EXTRA_PRESELECT_KEY_ID as the currently-displayed key;
     *   • a non-zero key id additionally returns RESULT_PRIMARY_USER_ID
     *     and RESULT_KEY_CREATION_TIME (epoch ms; createdAt already is);
     *   • a non-zero key id that is NOT in the keyring is a hard error
     *     ("Signing key not found"), matching the reference.
     */
    private fun getSignKeyId(data: Intent, callingPackage: String): Intent {
        val result = Intent()

        val pickerIntent = Intent(this, ProviderKeyPickerActivity::class.java).apply {
            putExtra(ProviderKeyPickerActivity.EXTRA_API_DATA, data)
            putExtra(
                ProviderKeyPickerActivity.EXTRA_PRESELECT_USER_ID,
                data.getStringExtra(OpenPgpApi.EXTRA_USER_ID)
            )
            setData(android.net.Uri.parse("pgpony-api-signkey://$callingPackage"))
        }
        val pickerPendingIntent = PendingIntent.getActivity(
            this,
            1,
            pickerIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        result.putExtra(OpenPgpApi.RESULT_INTENT, pickerPendingIntent)

        val signKeyId: Long
        if (data.hasExtra(OpenPgpApi.RESULT_SIGN_KEY_ID)) {
            signKeyId = data.getLongExtra(
                OpenPgpApi.RESULT_SIGN_KEY_ID, ProviderKeyPickerActivity.KEY_ID_NONE
            )
            result.putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_SUCCESS)
        } else {
            signKeyId = data.getLongExtra(
                OpenPgpApi.EXTRA_PRESELECT_KEY_ID, ProviderKeyPickerActivity.KEY_ID_NONE
            )
            result.putExtra(
                OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED
            )
        }
        result.putExtra(OpenPgpApi.RESULT_SIGN_KEY_ID, signKeyId)

        if (signKeyId != ProviderKeyPickerActivity.KEY_ID_NONE) {
            val entity = runBlocking { findEntityByKeyId(signKeyId) }
                ?: return errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    "Signing key not found in the PGPony keyring"
                )
            result.putExtra(OpenPgpApi.RESULT_PRIMARY_USER_ID, entity.userID)
            result.putExtra(OpenPgpApi.RESULT_KEY_CREATION_TIME, entity.createdAt)
        }
        return result
    }

    private suspend fun findEntityByKeyId(keyId: Long) =
        repo.getAllKeys().firstOrNull { entity ->
            runCatching {
                java.lang.Long.parseUnsignedLong(entity.longKeyId, 16)
            }.getOrNull() == keyId
        }

    // ── P2a-2: the send path ───────────────────────────────────────────
    //
    // Buffered, not yet streamed: input is read fully, crypto runs on
    // byte arrays (the shape PGPCryptoService exposes today), output is
    // written in one pass. Fine for mail bodies and normal attachments;
    // the large-attachment streaming refactor (plan §5, "the main
    // unknown") converts these to stream-through when PGPCryptoService
    // grows streaming entry points — the provider signatures already
    // take PFDs, so only the middle changes.
    //
    // Signing-key unlock errors map to the API's interaction pattern:
    // PassphraseRequired / InvalidPassphrase → USER_INTERACTION_REQUIRED
    // + a PendingIntent to ProviderPassphraseActivity, which stores the
    // passphrase in the in-process ProviderPassphraseCache; the client
    // retries and the operation finds it. Wrong passphrase clears the
    // cached entry first so a stale value can't loop.

    /** ACTION_ENCRYPT / ACTION_SIGN_AND_ENCRYPT. */
    private fun encryptOp(
        data: Intent,
        input: ParcelFileDescriptor?,
        output: ParcelFileDescriptor?,
        withSignature: Boolean
    ): Intent {
        // P2d: input is no longer read up front — the software path
        // streams it straight into the encryptor; only the card path
        // buffers (its request is parked for the NFC tap).
        if (input == null) {
            return errorResult(OpenPgpError.GENERIC_ERROR, "No input data provided")
        }
        val armor = data.getBooleanExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, false)
        val filename = data.getStringExtra(OpenPgpApi.EXTRA_ORIGINAL_FILENAME)

        // Recipients: EXTRA_KEY_IDS (already-resolved ids) and/or
        // EXTRA_USER_IDS (email addresses), deduped by fingerprint.
        val requestedKeyIds = data.getLongArrayExtra(OpenPgpApi.EXTRA_KEY_IDS)
        val requestedUserIds = data.getStringArrayExtra(OpenPgpApi.EXTRA_USER_IDS)
        if ((requestedKeyIds == null || requestedKeyIds.isEmpty()) &&
            (requestedUserIds == null || requestedUserIds.isEmpty())
        ) {
            return errorResult(OpenPgpError.NO_USER_IDS, "No recipients provided")
        }

        val rings = LinkedHashMap<String, org.bouncycastle.openpgp.PGPPublicKeyRing>()
        val missing = mutableListOf<String>()
        runBlocking {
            requestedKeyIds?.forEach { id ->
                val entity = findEntityByKeyId(id)?.takeIf { !it.isRevoked }
                val ring = entity?.let { repo.loadPublicKeyRing(it.fingerprint) }
                if (ring != null) rings[entity.fingerprint] = ring
                else missing += String.format("0x%016X", id)
            }
            requestedUserIds?.forEach { raw ->
                val email = raw.substringAfterLast('<').substringBefore('>').trim()
                    .ifEmpty { raw.trim() }
                // P2c Fix2: encrypt to ALL non-revoked keys held for the
                // address, not firstOrNull(). With both a software and a
                // card-backed key for the same address (Kevin's own setup),
                // taking the first key silently encrypted to whichever row
                // happened to sort first — a phone-to-phone mail signed by
                // the card ended up readable only by the software key.
                // Encrypting to every held key makes the message openable
                // by whichever is convenient (receive prefers software —
                // no NFC tap — but the card can always open it too).
                // 4.2.1 (#27): resolve across all user ids so encrypt to a
                // secondary identity actually finds the key — without this,
                // the getKeyIds fix above would offer encryption that then
                // failed here at send time.
                val matches = repo.getByAnyUserEmail(email).filter { !it.isRevoked }
                var added = false
                matches.forEach { entity ->
                    repo.loadPublicKeyRing(entity.fingerprint)?.let { ring ->
                        rings[entity.fingerprint] = ring
                        added = true
                    }
                }
                if (!added) missing += raw
            }
        }
        if (missing.isNotEmpty()) {
            // Opportunistic mode (Autocrypt-style "encrypt if possible")
            // gets its dedicated error id so clients silently fall back
            // to plaintext; the normal path gets a readable list. The
            // OpenKeychain download-missing-key PendingIntent flow lands
            // with the Phase 5a multi-server directory (plan §6 Q7).
            return if (data.getBooleanExtra(OpenPgpApi.EXTRA_OPPORTUNISTIC_ENCRYPTION, false)) {
                errorResult(
                    OpenPgpError.OPPORTUNISTIC_MISSING_KEYS,
                    "Missing keys for: ${missing.joinToString()}"
                )
            } else {
                errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    "No PGPony key found for: ${missing.joinToString()}. " +
                        "Import the recipient's public key in PGPony first."
                )
            }
        }

        // Signing leg (SIGN_AND_ENCRYPT only).
        var signingRing: org.bouncycastle.openpgp.PGPSecretKeyRing? = null
        var signPassphrase: String? = null
        var signKeyId = 0L
        var signKeyLabel = ""
        if (withSignature) {
            when (val resolved = resolveSigningMaterial(data, rings.values)) {
                is SignResolve.Fail -> return resolved.response
                is SignResolve.Card -> {
                    // P2c: the entire sign+encrypt runs during the NFC
                    // tap (the card must be present while BC signs), so
                    // park the request and round-trip via the card
                    // activity; a completed op is served on retry.
                    // (Card path buffers by design — P2d streaming is
                    // for the software leg only.)
                    val plaintext = readAll(input)
                        ?: return errorResult(OpenPgpError.GENERIC_ERROR, "No input data provided")
                    if (plaintext.size > cardOpMaxBytes) return cardTooLargeError()
                    val opKey = ProviderCardOpStore.opKey(
                        OpenPgpApi.ACTION_SIGN_AND_ENCRYPT, resolved.keyId, armor,
                        filename, rings.keys.toList(), plaintext
                    )
                    ProviderCardOpStore.consumeCompleted(opKey)?.let { done ->
                        streamCardResult(done, output)
                        return successResult()
                    }
                    ProviderCardOpStore.putPending(
                        ProviderCardOpStore.PendingOp(
                            opKey = opKey,
                            action = OpenPgpApi.ACTION_SIGN_AND_ENCRYPT,
                            input = plaintext,
                            cardEntityFingerprint = resolved.entity.fingerprint,
                            armor = armor,
                            filename = filename,
                            recipientFingerprints = rings.keys.toList(),
                            senderAddress = null,
                            // Card ops: compress only if the client asked
                            // AND it's not a big attachment (keeps the NFC
                            // tag from going stale mid-ZLIB).
                            enableCompression = data.getBooleanExtra(
                                OpenPgpApi.EXTRA_ENABLE_COMPRESSION, false
                            ) && plaintext.size < 1 shl 20
                        )
                    )
                    return cardInteractionResult(opKey, data)
                }
                is SignResolve.Ok -> {
                    signingRing = resolved.ring
                    signPassphrase = resolved.passphrase
                    signKeyId = resolved.keyId
                    signKeyLabel = resolved.label
                    // RC5 P1 (#34, EmanuelLoos — his diagnosis): the
                    // client sends ONE sign+encrypt covering outbound AND
                    // encrypt-to-self, so the client's configured key
                    // rides along as a recipient. If the signing default
                    // just substituted that key away (e.g. v6 → v4 for a
                    // classical recipient), leaving its ring in the
                    // recipient set embeds a composite PKESK that pre-v6
                    // clients cannot parse past — the recipient loses the
                    // WHOLE message even though their own packet is fine.
                    // So encrypt-to-self follows the substitution,
                    // unconditionally: the self-copy becomes readable by
                    // the substitute key instead. No toggle — a
                    // backwards-compatible message carrying a v6 PKESK
                    // defeats the slot's entire purpose.
                    if (resolved.entity.fingerprint != resolved.clientEntity.fingerprint &&
                        rings.containsKey(resolved.clientEntity.fingerprint)
                    ) {
                        repo.loadPublicKeyRing(resolved.entity.fingerprint)?.let { subRing ->
                            rings.remove(resolved.clientEntity.fingerprint)
                            rings[resolved.entity.fingerprint] = subRing
                        }
                    }
                }
            }
        }

        // P2d: software path streams end to end. encryptStream unlocks
        // the signing key BEFORE writing any output byte, so the
        // passphrase-interaction catches below always fire with a clean
        // output pipe.
        if (output == null) {
            return errorResult(OpenPgpError.GENERIC_ERROR, "No output pipe provided")
        }
        return try {
            ParcelFileDescriptor.AutoCloseInputStream(input).use { ins ->
                ParcelFileDescriptor.AutoCloseOutputStream(output).use { outs ->
                    crypto.encryptStream(
                        input = ins,
                        output = outs,
                        recipientPublicKeys = rings.values.toList(),
                        signingSecretKey = signingRing,
                        passphrase = signPassphrase,
                        filename = filename,
                        armor = armor
                    )
                }
            }
            successResult()
        } catch (e: SigningError.PassphraseRequired) {
            passphraseRequiredResult(data, signKeyId, signKeyLabel, wasWrong = false)
        } catch (e: SigningError.InvalidPassphrase) {
            ProviderPassphraseCache.clear(signKeyId)
            passphraseRequiredResult(data, signKeyId, signKeyLabel, wasWrong = true)
        } catch (e: Exception) {
            errorResult(OpenPgpError.GENERIC_ERROR, e.message ?: "Encryption failed")
        }
    }

    /** ACTION_CLEARTEXT_SIGN (and the deprecated ACTION_SIGN alias). */
    private fun cleartextSign(
        data: Intent,
        input: ParcelFileDescriptor?,
        output: ParcelFileDescriptor?
    ): Intent {
        val text = readAll(input)?.toString(Charsets.UTF_8)
            ?: return errorResult(OpenPgpError.GENERIC_ERROR, "No input data provided")
        val resolved = resolveSigningMaterial(data)
        if (resolved is SignResolve.Fail) return resolved.response
        if (resolved is SignResolve.Card) {
            return cardOpRoundTrip(
                data = data,
                action = OpenPgpApi.ACTION_CLEARTEXT_SIGN,
                resolved = resolved,
                input = text.toByteArray(Charsets.UTF_8),
                armor = true,
                output = output
            )
        }
        val ok = resolved as SignResolve.Ok

        return try {
            val signed = signing.signClear(
                text = text,
                secretKeyRing = ok.ring,
                passphrase = ok.passphrase
            )
            writeAll(output, signed.toByteArray(Charsets.UTF_8))
            successResult()
        } catch (e: SigningError.PassphraseRequired) {
            passphraseRequiredResult(data, ok.keyId, ok.label, wasWrong = false)
        } catch (e: SigningError.InvalidPassphrase) {
            ProviderPassphraseCache.clear(ok.keyId)
            passphraseRequiredResult(data, ok.keyId, ok.label, wasWrong = true)
        } catch (e: Exception) {
            errorResult(OpenPgpError.GENERIC_ERROR, e.message ?: "Signing failed")
        }
    }

    /**
     * ACTION_DETACHED_SIGN. The signature travels back as the
     * RESULT_DETACHED_SIGNATURE byte-array extra (NOT the output pipe —
     * that's the API contract; K-9/Thunderbird build multipart/signed
     * from the extra). RESULT_SIGNATURE_MICALG carries the OpenPGP
     * micalg token for the multipart/signed content-type header; all
     * PGPony signatures are SHA-256, hence "pgp-sha256".
     */
    private fun detachedSign(data: Intent, input: ParcelFileDescriptor?): Intent {
        if (input == null) {
            return errorResult(OpenPgpError.GENERIC_ERROR, "No input data provided")
        }
        val armor = data.getBooleanExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, false)
        val resolved = resolveSigningMaterial(data)
        if (resolved is SignResolve.Fail) return resolved.response
        if (resolved is SignResolve.Card) {
            // Card path buffers by design (P2c op store).
            val payload = readAll(input)
                ?: return errorResult(OpenPgpError.GENERIC_ERROR, "No input data provided")
            if (payload.size > cardOpMaxBytes) return cardTooLargeError()
            val opKey = ProviderCardOpStore.opKey(
                OpenPgpApi.ACTION_DETACHED_SIGN, resolved.keyId, armor, null,
                emptyList(), payload
            )
            ProviderCardOpStore.consumeCompleted(opKey)?.let { done ->
                val detached = done as ProviderCardOpStore.CompletedOp.Detached
                return successResult().apply {
                    putExtra(OpenPgpApi.RESULT_DETACHED_SIGNATURE, detached.signature)
                    putExtra(OpenPgpApi.RESULT_SIGNATURE_MICALG, detached.micalg)
                }
            }
            ProviderCardOpStore.putPending(
                ProviderCardOpStore.PendingOp(
                    opKey = opKey,
                    action = OpenPgpApi.ACTION_DETACHED_SIGN,
                    input = payload,
                    cardEntityFingerprint = resolved.entity.fingerprint,
                    armor = armor,
                    filename = null,
                    recipientFingerprints = emptyList(),
                    senderAddress = null
                )
            )
            return cardInteractionResult(opKey, data)
        }
        val ok = resolved as SignResolve.Ok

        // P2d: software path streams the payload into the hash — a
        // multipart/signed message with a large attachment never lands
        // in memory whole.
        return try {
            val signature = ParcelFileDescriptor.AutoCloseInputStream(input).use { ins ->
                signing.signDetachedStream(
                    input = ins,
                    secretKeyRing = ok.ring,
                    passphrase = ok.passphrase,
                    armor = armor
                )
            }
            successResult().apply {
                putExtra(OpenPgpApi.RESULT_DETACHED_SIGNATURE, signature)
                putExtra(OpenPgpApi.RESULT_SIGNATURE_MICALG, "pgp-sha256")
            }
        } catch (e: SigningError.PassphraseRequired) {
            passphraseRequiredResult(data, ok.keyId, ok.label, wasWrong = false)
        } catch (e: SigningError.InvalidPassphrase) {
            ProviderPassphraseCache.clear(ok.keyId)
            passphraseRequiredResult(data, ok.keyId, ok.label, wasWrong = true)
        } catch (e: Exception) {
            errorResult(OpenPgpError.GENERIC_ERROR, e.message ?: "Signing failed")
        }
    }

    /**
     * ACTION_QUERY_AUTOCRYPT_STATUS — P2a-2 Fix1. The compose screen's
     * per-recipient "can I encrypt to these people?" probe (API 12).
     * Response contract mirrored from OpenKeychain's autocryptQueryImpl
     * (verified in master source):
     *
     *   • any recipient without a usable key → AUTOCRYPT_STATUS_UNAVAILABLE
     *     (client shows "recipient doesn't support this feature")
     *   • keys held for everyone, but no Autocrypt peer state →
     *     AUTOCRYPT_STATUS_DISCOURAGE — the reference returns exactly
     *     this for manually-imported keys (its "case OK"), and clients
     *     treat anything except UNAVAILABLE as encryptable. A fresh
     *     OpenKeychain behaves identically, so this is full parity.
     *   • RESULT_KEYS_CONFIRMED = every resolved key is user-verified
     *     (PGPony trust level VERIFIED / ULTIMATE).
     *
     * AVAILABLE / MUTUAL become reachable when Phase P4 adds the
     * autocrypt_peers store fed by UPDATE_AUTOCRYPT_PEER.
     */
    /**
     * ACTION_UPDATE_AUTOCRYPT_PEER — 4.0.0 Phase 4. The email client parsed
     * an incoming message's Autocrypt (+ Autocrypt-Gossip) headers and hands
     * us the per-peer update. Persist the peer state (timestamps +
     * prefer-encrypt) and import the key so encrypt-by-email finds it;
     * QUERY_AUTOCRYPT_STATUS reads it back as a recommendation.
     */
    private fun updateAutocryptPeer(data: Intent): Intent {
        val peerId = data.getStringExtra(OpenPgpApi.EXTRA_AUTOCRYPT_PEER_ID)
            ?: return errorResult(OpenPgpError.GENERIC_ERROR, "Missing Autocrypt peer id")
        // Best-effort, matching the gossip loop below. The class loader is
        // set at the Binder boundary now, so this should not fail — but an
        // Autocrypt peer hint is an optimisation for a later encrypt, and a
        // malformed one must never be able to fail the decrypt the client is
        // actually in the middle of.
        val update: AutocryptPeerUpdate? = runCatching {
            @Suppress("DEPRECATION")
            data.getParcelableExtra<AutocryptPeerUpdate>(
                OpenPgpApi.EXTRA_AUTOCRYPT_PEER_UPDATE
            )
        }.getOrNull()
        val now = System.currentTimeMillis()
        runBlocking {
            if (update != null) {
                val effective = update.effectiveDate?.time ?: now
                if (update.hasKeyData()) {
                    autocryptStore.updateKey(
                        peerId, effective, update.keyData,
                        update.preferEncrypt == AutocryptPeerUpdate.PreferEncrypt.MUTUAL
                    )
                } else {
                    autocryptStore.updateLastSeen(peerId, effective)
                }
            }
            // Autocrypt-Gossip (address -> AutocryptPeerUpdate), passed as a
            // Bundle. Best-effort: skip anything malformed.
            val gossip = data.getBundleExtra(OpenPgpApi.EXTRA_AUTOCRYPT_PEER_GOSSIP_UPDATES)
            if (gossip != null) {
                // A nested Bundle carries its own class-loader reference, so
                // the one set on the Intent at the Binder boundary does not
                // necessarily reach in here. Say it again where it is read.
                gossip.classLoader = AutocryptPeerUpdate::class.java.classLoader
                for (addr in gossip.keySet()) {
                    val gu = runCatching {
                        @Suppress("DEPRECATION")
                        gossip.getParcelable<AutocryptPeerUpdate>(addr)
                    }.getOrNull() ?: continue
                    if (gu.hasKeyData()) {
                        autocryptStore.updateGossipKey(addr, gu.effectiveDate?.time ?: now, gu.keyData)
                    }
                }
            }
        }
        return successResult()
    }

    private fun queryAutocryptStatus(data: Intent): Intent {
        val userIds = data.getStringArrayExtra(OpenPgpApi.EXTRA_USER_IDS) ?: emptyArray()
        var anyMissing = false
        var allConfirmed = true
        // Overall recommendation = the WEAKEST across recipients (any
        // discourage -> discourage; mutual only if every peer is mutual).
        var overall: AutocryptRecommendation? = null
        runBlocking {
            userIds.forEach { raw ->
                val email = raw.substringAfterLast('<').substringBefore('>').trim()
                    .ifEmpty { raw.trim() }
                // 4.2.1 (#27): secondary identities count for the
                // Autocrypt recommendation too.
                val matches = repo.getByAnyUserEmail(email).filter { !it.isRevoked }
                if (matches.isEmpty()) {
                    anyMissing = true
                    allConfirmed = false
                } else {
                    if (!matches.all {
                            it.trustLevel == com.pgpony.android.data.TrustLevel.VERIFIED ||
                                it.trustLevel == com.pgpony.android.data.TrustLevel.ULTIMATE
                        }
                    ) {
                        allConfirmed = false
                    }
                    val rec = autocryptStore.recommendation(email)
                    overall = if (overall == null) rec else minOf(overall!!, rec)
                }
            }
        }
        val status = when {
            anyMissing -> OpenPgpApi.AUTOCRYPT_STATUS_UNAVAILABLE
            overall == AutocryptRecommendation.MUTUAL -> OpenPgpApi.AUTOCRYPT_STATUS_MUTUAL
            overall == AutocryptRecommendation.AVAILABLE -> OpenPgpApi.AUTOCRYPT_STATUS_AVAILABLE
            else -> OpenPgpApi.AUTOCRYPT_STATUS_DISCOURAGE
        }
        return successResult().apply {
            putExtra(OpenPgpApi.RESULT_AUTOCRYPT_STATUS, status)
            putExtra(OpenPgpApi.RESULT_KEYS_CONFIRMED, allConfirmed)
        }
    }

    // ── P2b-1: the receive path ────────────────────────────────────────

    /**
     * ACTION_DECRYPT_VERIFY / ACTION_DECRYPT_METADATA. Three input
     * shapes, matching what mail clients actually send:
     *
     *   1. EXTRA_DETACHED_SIGNATURE present → multipart/signed verify:
     *      input = the signed MIME part, no decryption. Output (when a
     *      pipe exists) echoes the input through.
     *   2. Clear-signed text ("BEGIN PGP SIGNED MESSAGE") → verify via
     *      VerifyService, output = the inner text.
     *   3. Encrypted message (armored or binary) → decrypt via
     *      PGPCryptoService with ALL held public rings as verification
     *      keys — processDecryptedContent already recurses into
     *      Compressed Data before looking for signatures (the R5
     *      decompress-first gotcha) and now reports signature presence
     *      + raw key id even for unheld signers.
     *
     * R5 message-targeted unlock: the PKESK recipient key ids are
     * parsed FIRST and only matching secret rings are offered to the
     * decryptor; when no held key matches, the caller gets a readable
     * error — never a passphrase prompt for a message we can't open.
     *
     * OpenPgpSignatureResult population (§6 Q12): NO_SIGNATURE /
     * KEY_MISSING (with key id) / VALID_KEY_CONFIRMED (trust Verified
     * or Ultimate) / VALID_KEY_UNCONFIRMED / INVALID_KEY_REVOKED /
     * INVALID_KEY_EXPIRED / INVALID_SIGNATURE.
     */
    private fun decryptVerify(
        data: Intent,
        input: ParcelFileDescriptor?,
        output: ParcelFileDescriptor?,
        metadataOnly: Boolean
    ): Intent {
        val inputBytes = readAll(input)
            ?: return errorResult(OpenPgpError.GENERIC_ERROR, "No input data provided")

        val allEntities = runBlocking { repo.getAllKeys() }
        val publicRings = allEntities.mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }

        // P2b-2: the sender address rides on every client decrypt call
        // and drives the SenderStatusResult (Thunderbird's full
        // "verified" display + its sender-mismatch warning).
        val senderAddress = data.getStringExtra(OpenPgpApi.EXTRA_SENDER_ADDRESS)

        // ── Shape 1: detached-signature verify (multipart/signed) ──────
        val detachedSignature = data.getByteArrayExtra(OpenPgpApi.EXTRA_DETACHED_SIGNATURE)
        if (detachedSignature != null) {
            val verification = verifier.verifyDetached(
                signatureBytes = detachedSignature,
                signedBytes = inputBytes,
                publicKeyRings = publicRings
            )
            if (!metadataOnly) writeAll(output, inputBytes)
            return successResult().apply {
                putExtra(
                    OpenPgpApi.RESULT_SIGNATURE,
                    mapVerification(verification, allEntities, senderAddress)
                )
                putExtra(
                    OpenPgpApi.RESULT_DECRYPTION,
                    OpenPgpDecryptionResult(
                        OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED
                    )
                )
            }
        }

        // ── Shape 2: clear-signed text ──────────────────────────────────
        val asText = inputBytes.toString(Charsets.UTF_8)
        if (asText.contains("-----BEGIN PGP SIGNED MESSAGE-----")) {
            val verification = verifier.verifyClearSigned(asText, publicRings)
            val content = when (verification) {
                is VerificationResult.Verified -> verification.signedContent
                is VerificationResult.Invalid -> verification.signedContent
                is VerificationResult.UnknownSigner -> verification.signedContent
                is VerificationResult.Unsigned -> verification.content
            } ?: ""
            if (!metadataOnly) writeAll(output, content.toByteArray(Charsets.UTF_8))
            return successResult().apply {
                putExtra(
                    OpenPgpApi.RESULT_SIGNATURE,
                    mapVerification(verification, allEntities, senderAddress)
                )
                putExtra(
                    OpenPgpApi.RESULT_DECRYPTION,
                    OpenPgpDecryptionResult(
                        OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED
                    )
                )
            }
        }

        // ── Shape 3: encrypted message ──────────────────────────────────
        // Message-targeted key selection (R5): PKESK recipient ids first.
        val allRecipientIds = try {
            crypto.recipientKeyIDs(inputBytes)
        } catch (e: Exception) {
            emptyList()
        }
        // 4.1.0 - hidden recipients (`gpg -R`). A wildcard PKESK carries the
        // all-zero key ID, which matches nothing on any ring. Narrowing by it
        // left `targeted` empty and the card lookup below empty-handed too, so
        // Thunderbird and FairEmail were told "None of your PGPony keys can
        // decrypt this message" about a message PGPony could in fact open.
        //
        // Treated the same way the in-app path treats it: match on the
        // ADDRESSED ids only, and when a wildcard is present offer every
        // candidate rather than none - the crypto layer's resolvePkesk trials
        // the software keys itself, and the card is the fallback after that.
        val hiddenRecipient = allRecipientIds.contains(0L)
        val recipientIds = allRecipientIds.filter { it != 0L }
        val softwarePairs = allEntities.filter { it.isKeyPair && !it.isCardBacked }
        val ringsByEntity = softwarePairs.mapNotNull { entity ->
            repo.loadSecretKeyRing(entity.fingerprint)?.let { entity to it }
        }
        val addressed = if (recipientIds.isNotEmpty()) {
            ringsByEntity.filter { (_, ring) ->
                recipientIds.any { ring.getSecretKey(it) != null }
            }
        } else {
            ringsByEntity
        }
        // A hidden-recipient message with no addressed match: trial the
        // software keys HERE, before the client's output pipe is committed to
        // decryptStream. Doing it inside decryptStream would work too, but the
        // pipe is single-use, so a failure there could not fall through to the
        // card - and the card is exactly what a `gpg -R` message addressed to
        // a hardware key needs. See PGPCryptoService.canOpenWithSecretKeys.
        val targeted = if (addressed.isEmpty() && hiddenRecipient) {
            ringsByEntity.filter { (entity, ring) ->
                val kid = runCatching {
                    java.lang.Long.parseUnsignedLong(entity.longKeyId, 16)
                }.getOrDefault(0L)
                val pp = data.getStringExtra(OpenPgpApi.EXTRA_PASSPHRASE)
                    ?: ProviderPassphraseCache.get(kid)
                crypto.canOpenWithSecretKeys(inputBytes, listOf(ring), pp)
            }
        } else {
            addressed
        }
        if (targeted.isEmpty()) {
            // P2c: a card-backed match routes through the NFC card flow —
            // the whole decrypt runs during the tap, result served on the
            // client's retry.
            // 4.1.0 - a hidden-recipient message names no card either, so
            // fall back to the first paired card with an encryption-capable
            // key. The tap is justified by then: control only reaches here
            // when the software keys have already been trialled and lost, and
            // a card key cannot be trialled without one (no local private
            // material, which is the point of it).
            // Addressed first, hidden second - a message can carry both an
            // addressed PKESK we cannot match and a wildcard we can.
            val addressedCard = if (recipientIds.isEmpty()) null else allEntities.firstOrNull { entity ->
                entity.isCardBacked && runCatching {
                    repo.loadPublicKeyRing(entity.fingerprint)
                        ?.let { ring -> recipientIds.any { ring.getPublicKey(it) != null } }
                }.getOrNull() == true
            }
            val hiddenCard = if (!hiddenRecipient) null else allEntities.firstOrNull { entity ->
                entity.isCardBacked && runCatching {
                    repo.loadPublicKeyRing(entity.fingerprint)
                        ?.let { ring -> ring.publicKeys.asSequence().any { it.isEncryptionKey } }
                }.getOrNull() == true
            }
            val cardEntity = addressedCard ?: hiddenCard
            if (cardEntity != null) {
                if (inputBytes.size > cardOpMaxBytes) return cardTooLargeError()
                val action = if (metadataOnly) OpenPgpApi.ACTION_DECRYPT_METADATA
                else OpenPgpApi.ACTION_DECRYPT_VERIFY
                val opKey = ProviderCardOpStore.opKey(
                    action, 0L, false, null, emptyList(), inputBytes
                )
                ProviderCardOpStore.consumeCompleted(opKey)?.let { done ->
                    val dec = done as ProviderCardOpStore.CompletedOp.Decrypted
                    runBlocking { repo.incrementDecryptUseCount(cardEntity.fingerprint) }
                    if (!metadataOnly) writeAll(output, dec.data)
                    return successResult().apply {
                        putExtra(
                            OpenPgpApi.RESULT_SIGNATURE,
                            signatureResultFromCardDecrypt(dec, allEntities, senderAddress)
                        )
                        putExtra(
                            OpenPgpApi.RESULT_DECRYPTION,
                            OpenPgpDecryptionResult(OpenPgpDecryptionResult.RESULT_ENCRYPTED)
                        )
                        putExtra(
                            OpenPgpApi.RESULT_METADATA,
                            OpenPgpMetadata(dec.filename, null, 0L, dec.data.size.toLong())
                        )
                    }
                }
                ProviderCardOpStore.putPending(
                    ProviderCardOpStore.PendingOp(
                        opKey = opKey,
                        action = action,
                        input = inputBytes,
                        cardEntityFingerprint = cardEntity.fingerprint,
                        armor = false,
                        filename = null,
                        recipientFingerprints = emptyList(),
                        senderAddress = senderAddress
                    )
                )
                return cardInteractionResult(opKey, data)
            }
            return errorResult(
                OpenPgpError.GENERIC_ERROR,
                "None of your PGPony keys can decrypt this message."
            )
        }

        val matchedEntity = targeted.first().first
        val matchedKeyId = runCatching {
            java.lang.Long.parseUnsignedLong(matchedEntity.longKeyId, 16)
        }.getOrDefault(0L)
        val passphrase = data.getStringExtra(OpenPgpApi.EXTRA_PASSPHRASE)
            ?: ProviderPassphraseCache.get(matchedKeyId)

        // P2d: stream the plaintext straight to the output pipe (or a
        // counting sink for metadata-only) so a large encrypted
        // attachment's plaintext never lands in memory whole. The
        // ciphertext is still buffered (needed above for shape sniffing
        // and PKESK-target selection), but that halves peak memory
        // versus buffering plaintext too — and the integrity gate inside
        // decryptStream still runs before we report success.
        val sink: java.io.OutputStream = if (metadataOnly) {
            object : java.io.OutputStream() {
                override fun write(b: Int) {}
                override fun write(b: ByteArray, off: Int, len: Int) {}
            }
        } else {
            output?.let { ParcelFileDescriptor.AutoCloseOutputStream(it) }
                ?: return errorResult(OpenPgpError.GENERIC_ERROR, "No output pipe provided")
        }

        val streamResult = try {
            sink.use { outs ->
                crypto.decryptStream(
                    input = java.io.ByteArrayInputStream(inputBytes),
                    output = outs,
                    secretKeyRings = targeted.map { it.second },
                    passphrase = passphrase,
                    verificationKeys = publicRings
                )
            }
        } catch (e: PGPCryptoError.PassphraseRequired) {
            return passphraseRequiredResult(data, matchedKeyId, matchedEntity.userID, wasWrong = false)
        } catch (e: PGPCryptoError.InvalidPassphrase) {
            ProviderPassphraseCache.clear(matchedKeyId)
            return passphraseRequiredResult(data, matchedKeyId, matchedEntity.userID, wasWrong = true)
        } catch (e: Exception) {
            return errorResult(OpenPgpError.GENERIC_ERROR, e.message ?: "Decryption failed")
        }

        runBlocking { repo.incrementDecryptUseCount(matchedEntity.fingerprint) }

        return successResult().apply {
            putExtra(
                OpenPgpApi.RESULT_SIGNATURE,
                signatureResultFromDecryptStream(streamResult, allEntities, senderAddress)
            )
            putExtra(
                OpenPgpApi.RESULT_DECRYPTION,
                OpenPgpDecryptionResult(
                    OpenPgpDecryptionResult.RESULT_ENCRYPTED
                )
            )
            putExtra(
                OpenPgpApi.RESULT_METADATA,
                OpenPgpMetadata(
                    streamResult.filename,
                    null,
                    0L,
                    streamResult.bytesWritten
                )
            )
        }
    }

    /**
     * P2d — signature mapping for a streamed decrypt. Same rules as
     * signatureResultFromDecrypt but reads DecryptStreamResult's fields.
     */
    private fun signatureResultFromDecryptStream(
        result: com.pgpony.android.crypto.DecryptStreamResult,
        allEntities: List<com.pgpony.android.data.PGPKeyEntity>,
        senderAddress: String?
    ): OpenPgpSignatureResult {
        if (!result.hasSignature) {
            return OpenPgpSignatureResult.createWithNoSignature()
        }
        val keyIdRaw = result.signatureKeyIDRaw ?: 0L
        if (result.signerKeyID == null) {
            return OpenPgpSignatureResult.createWithKeyMissing(keyIdRaw, null)
        }
        if (!result.signatureVerified) {
            return OpenPgpSignatureResult.createWithInvalidSignature()
        }
        val entity = allEntities.firstOrNull { candidate ->
            runCatching {
                repo.loadPublicKeyRing(candidate.fingerprint)?.getPublicKey(keyIdRaw) != null
            }.getOrNull() == true
        }
        return buildValidSignatureResult(entity, keyIdRaw, senderAddress)
    }

    /** Map a VerifyService result to the API's OpenPgpSignatureResult. */
    private fun mapVerification(
        verification: VerificationResult,
        allEntities: List<com.pgpony.android.data.PGPKeyEntity>,
        senderAddress: String?
    ): OpenPgpSignatureResult {
        return when (verification) {
            is VerificationResult.Unsigned ->
                OpenPgpSignatureResult.createWithNoSignature()

            is VerificationResult.UnknownSigner ->
                OpenPgpSignatureResult.createWithKeyMissing(
                    runCatching {
                        java.lang.Long.parseUnsignedLong(verification.signerKeyID, 16)
                    }.getOrDefault(0L),
                    null
                )

            is VerificationResult.Invalid ->
                OpenPgpSignatureResult.createWithInvalidSignature()

            is VerificationResult.Verified -> {
                val entity = allEntities.firstOrNull {
                    it.fingerprint.equals(verification.signerFingerprint, ignoreCase = true)
                } ?: allEntities.firstOrNull {
                    it.longKeyId.equals(verification.signerKeyID, ignoreCase = true)
                }
                buildValidSignatureResult(
                    entity = entity,
                    keyIdRaw = runCatching {
                        java.lang.Long.parseUnsignedLong(verification.signerKeyID, 16)
                    }.getOrDefault(0L),
                    senderAddress = senderAddress
                )
            }
        }
    }

    /** Map an (already decrypted) DecryptResult's signature state. */
    private fun signatureResultFromDecrypt(
        result: com.pgpony.android.crypto.DecryptResult,
        allEntities: List<com.pgpony.android.data.PGPKeyEntity>,
        senderAddress: String?
    ): OpenPgpSignatureResult {
        if (!result.hasSignature) {
            return OpenPgpSignatureResult.createWithNoSignature()
        }
        val keyIdRaw = result.signatureKeyIDRaw ?: 0L
        // Signer held? (signerKeyID is only populated when the key was
        // found for verification.)
        if (result.signerKeyID == null) {
            return OpenPgpSignatureResult.createWithKeyMissing(
                keyIdRaw, null
            )
        }
        if (!result.signatureVerified) {
            return OpenPgpSignatureResult.createWithInvalidSignature()
        }
        // Resolve the signer entity: the sig key id may belong to a
        // signing SUBKEY, so match against each held ring's keys.
        val entity = allEntities.firstOrNull { candidate ->
            runCatching {
                repo.loadPublicKeyRing(candidate.fingerprint)
                    ?.getPublicKey(keyIdRaw) != null
            }.getOrNull() == true
        }
        return buildValidSignatureResult(entity, keyIdRaw, senderAddress)
    }

    private fun buildValidSignatureResult(
        entity: com.pgpony.android.data.PGPKeyEntity?,
        keyIdRaw: Long,
        senderAddress: String?
    ): OpenPgpSignatureResult {
        if (entity == null) {
            return OpenPgpSignatureResult.createWithKeyMissing(
                keyIdRaw, null
            )
        }
        // Revocation / expiry override validity, matching the reference
        // provider's semantics (and PGPony's own banner rules).
        val status = when {
            entity.isRevoked ->
                OpenPgpSignatureResult.RESULT_INVALID_KEY_REVOKED
            entity.isExpired ->
                OpenPgpSignatureResult.RESULT_INVALID_KEY_EXPIRED
            entity.trustLevel == com.pgpony.android.data.TrustLevel.VERIFIED ||
                entity.trustLevel == com.pgpony.android.data.TrustLevel.ULTIMATE ->
                OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED
            else ->
                OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED
        }
        val confirmed = status ==
            OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED

        // P2b-2 — sender-status matching. All user ids on the signer's
        // RING (not just the entity's primary) are candidates: a key
        // with alice@work + alice@home must match mail from either.
        // Mapping mirrors OpenKeychain's builder semantics, and drives
        // Thunderbird's display: match+confirmed → the full "verified"
        // state; match+unconfirmed → unverified; NO match → the
        // sender-mismatch warning (the "signed by someone other than
        // the sender" spoof signal); no sender supplied → UNKNOWN
        // (treated as unverified).
        val ringUserIds: List<String> =
            runCatching {
                repo.loadPublicKeyRing(entity.fingerprint)
                    ?.publicKey?.userIDs?.asSequence()?.toList()
            }.getOrNull() ?: listOf(entity.userID)
        val senderEmail = senderAddress
            ?.substringAfterLast('<')?.substringBefore('>')?.trim()
            ?.ifEmpty { senderAddress.trim() }
        val senderMatches = !senderEmail.isNullOrEmpty() && ringUserIds.any { uid ->
            val uidEmail = uid.substringAfterLast('<').substringBefore('>').trim()
                .ifEmpty { uid.trim() }
            uidEmail.equals(senderEmail, ignoreCase = true)
        }
        val senderStatus = when {
            senderEmail.isNullOrEmpty() ->
                OpenPgpSignatureResult.SenderStatusResult.UNKNOWN
            senderMatches && confirmed ->
                OpenPgpSignatureResult.SenderStatusResult.USER_ID_CONFIRMED
            senderMatches ->
                OpenPgpSignatureResult.SenderStatusResult.USER_ID_UNCONFIRMED
            else ->
                OpenPgpSignatureResult.SenderStatusResult.USER_ID_MISSING
        }

        return OpenPgpSignatureResult.createWithValidSignature(
            status,
            entity.userID,
            keyIdRaw,
            ringUserIds,
            if (confirmed) ringUserIds else emptyList(),
            senderStatus,
            null
        )
    }

    // ── P2c: card-flow helpers ─────────────────────────────────────────

    /** Shared card round-trip for the simple sign-only stream ops. */
    private fun cardOpRoundTrip(
        data: Intent,
        action: String,
        resolved: SignResolve.Card,
        input: ByteArray,
        armor: Boolean,
        output: ParcelFileDescriptor?
    ): Intent {
        if (input.size > cardOpMaxBytes) return cardTooLargeError()
        val opKey = ProviderCardOpStore.opKey(action, resolved.keyId, armor, null, emptyList(), input)
        ProviderCardOpStore.consumeCompleted(opKey)?.let { done ->
            streamCardResult(done, output)
            return successResult()
        }
        ProviderCardOpStore.putPending(
            ProviderCardOpStore.PendingOp(
                opKey = opKey,
                action = action,
                input = input,
                cardEntityFingerprint = resolved.entity.fingerprint,
                armor = armor,
                filename = null,
                recipientFingerprints = emptyList(),
                senderAddress = null
            )
        )
        return cardInteractionResult(opKey, data)
    }

    private fun cardTooLargeError(): Intent = errorResult(
        OpenPgpError.GENERIC_ERROR,
        "This attachment is too large to process with a hardware key over " +
            "NFC. Choose a software key for large attachments, or encrypt it " +
            "in the PGPony app."
    )

    /**
     * Write a completed card result to the client's output pipe. A
     * StreamFile (large sign+encrypt / decrypt output) is streamed and
     * its temp file deleted; a Stream is written directly.
     */
    private fun streamCardResult(done: ProviderCardOpStore.CompletedOp, output: ParcelFileDescriptor?) {
        when (done) {
            is ProviderCardOpStore.CompletedOp.StreamFile -> {
                try {
                    output?.let { pfd ->
                        ParcelFileDescriptor.AutoCloseOutputStream(pfd).use { outs ->
                            java.io.FileInputStream(done.file).use { it.copyTo(outs) }
                        }
                    }
                } finally {
                    runCatching { done.file.delete() }
                }
            }
            is ProviderCardOpStore.CompletedOp.Stream -> writeAll(output, done.bytes)
            else -> {}
        }
    }

    private fun cardInteractionResult(opKey: String, apiData: Intent): Intent {
        val cardIntent = Intent(this, ProviderCardOpActivity::class.java).apply {
            putExtra(ProviderCardOpActivity.EXTRA_OP_KEY, opKey)
            // #61 (DorianRudolph): echo the client's original API request so the
            // activity hands it back on RESULT_OK and the client re-calls the
            // service to collect the completed card op (same as the passphrase and
            // key-picker paths). Without it FairEmail gets a bare RESULT_OK, never
            // re-calls, and the signed message never sends.
            putExtra(ProviderCardOpActivity.EXTRA_API_DATA, apiData)
            setData(android.net.Uri.parse("pgpony-api-cardop://$opKey"))
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            3,
            cardIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Intent().apply {
            putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpApi.RESULT_INTENT, pendingIntent)
        }
    }

    /** Map a card decrypt's signature state (CardDecryptResult fields). */
    private fun signatureResultFromCardDecrypt(
        dec: ProviderCardOpStore.CompletedOp.Decrypted,
        allEntities: List<com.pgpony.android.data.PGPKeyEntity>,
        senderAddress: String?
    ): OpenPgpSignatureResult {
        if (!dec.hadSignature) {
            return OpenPgpSignatureResult.createWithNoSignature()
        }
        val keyIdRaw = dec.signerKeyIdRaw ?: 0L
        if (!dec.signerKnown) {
            return OpenPgpSignatureResult.createWithKeyMissing(keyIdRaw, null)
        }
        if (!dec.signatureVerified) {
            return OpenPgpSignatureResult.createWithInvalidSignature()
        }
        val entity = allEntities.firstOrNull { candidate ->
            runCatching {
                repo.loadPublicKeyRing(candidate.fingerprint)
                    ?.getPublicKey(keyIdRaw) != null
            }.getOrNull() == true
        }
        return buildValidSignatureResult(entity, keyIdRaw, senderAddress)
    }

    // ── P2b-2: GET_KEY — public-key export ─────────────────────────────

    /**
     * ACTION_GET_KEY: hand the client a held public key, addressed by
     * EXTRA_KEY_ID or EXTRA_USER_ID (email), written to the output pipe
     * — armored when EXTRA_REQUEST_ASCII_ARMOR, binary otherwise.
     * Matches OpenKeychain's getKeyImpl shape. Two deliberate interim
     * gaps, both noted for later phases: EXTRA_MINIMIZE (minimal export
     * for Autocrypt keydata) lands with Phase P4's minimal-export path;
     * the missing-key "download from keyserver" PendingIntent lands
     * with the Phase 5a multi-server directory — until then a missing
     * key is a readable error.
     */
    private fun getKey(data: Intent, output: ParcelFileDescriptor?): Intent {
        val entity = runBlocking {
            when {
                data.hasExtra(OpenPgpApi.EXTRA_KEY_ID) ->
                    findEntityByKeyId(data.getLongExtra(OpenPgpApi.EXTRA_KEY_ID, 0L))
                data.hasExtra(OpenPgpApi.EXTRA_USER_ID) -> {
                    val raw = data.getStringExtra(OpenPgpApi.EXTRA_USER_ID) ?: ""
                    val email = raw.substringAfterLast('<').substringBefore('>').trim()
                        .ifEmpty { raw.trim() }
                    // 4.2.1 (#27): a client asking for a key by a secondary
                    // identity address should get it, same as the resolve
                    // sites above.
                    repo.getByAnyUserEmail(email).firstOrNull { !it.isRevoked }
                }
                else -> null
            }
        }
        if (!data.hasExtra(OpenPgpApi.EXTRA_KEY_ID) && !data.hasExtra(OpenPgpApi.EXTRA_USER_ID)) {
            return errorResult(OpenPgpError.GENERIC_ERROR, "Missing argument key_id or user_id")
        }
        if (entity == null) {
            return errorResult(
                OpenPgpError.GENERIC_ERROR,
                "Key not found in the PGPony keyring. Keyserver download " +
                    "through the provider arrives in a later release phase — " +
                    "import the key in PGPony for now."
            )
        }

        val keyBytes: ByteArray = if (
            data.getBooleanExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, false)
        ) {
            repo.exportArmoredPublicKey(entity.fingerprint)
                ?.toByteArray(Charsets.UTF_8)
                ?: return errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    "Could not export key material for ${entity.userEmail}"
                )
        } else {
            repo.loadPublicKeyRing(entity.fingerprint)?.encoded
                ?: return errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    "Could not export key material for ${entity.userEmail}"
                )
        }
        writeAll(output, keyBytes)
        return successResult()
    }

    // ── Signing-material resolution ────────────────────────────────────

    private sealed class SignResolve {
        class Ok(
            val ring: org.bouncycastle.openpgp.PGPSecretKeyRing,
            val passphrase: String?,
            val keyId: Long,
            val label: String,
            // RC5 P1 (#34): encryptOp needs both to swap the
            // encrypt-to-self recipient when a substitution happened.
            val entity: com.pgpony.android.data.PGPKeyEntity,
            val clientEntity: com.pgpony.android.data.PGPKeyEntity
        ) : SignResolve()

        /** P2c: the signing key lives on a hardware card. */
        class Card(
            val entity: com.pgpony.android.data.PGPKeyEntity,
            val keyId: Long
        ) : SignResolve()

        class Fail(val response: Intent) : SignResolve()
    }

    /**
     * RC4 O4 (#34): [recipientRings] carries the encrypt-side recipient
     * context so the per-key signing defaults (signing_defaults table)
     * apply on the provider path exactly as they do in-app: null =
     * sign-only action (the sign-without-encrypting picker); all
     * recipients composite = the PQC picker; any classical recipient =
     * the classical picker. The substitution runs BEFORE ring load and
     * REPLACES keyId/label, so the passphrase cache, the unlock prompt,
     * and the retry round-trip all coherently target the key that will
     * actually sign. Same guardrails as the in-app resolver: the
     * substitute must be an unrevoked software key pair, else the
     * client's chosen key stands.
     */
    private fun resolveSigningMaterial(
        data: Intent,
        recipientRings: Collection<org.bouncycastle.openpgp.PGPPublicKeyRing>? = null
    ): SignResolve {
        val keyId = data.getLongExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, 0L)
        if (keyId == 0L) {
            return SignResolve.Fail(
                errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    "No signing key configured — set an end-to-end key in " +
                        "your mail app's encryption settings."
                )
            )
        }
        val clientEntity = runBlocking { findEntityByKeyId(keyId) }
            ?: return SignResolve.Fail(
                errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    "Signing key not found in the PGPony keyring"
                )
            )
        // RC4 O4 (#34): apply the per-key signing defaults.
        val entity = resolveProviderSigner(clientEntity, recipientRings)
        val effectiveKeyId = if (entity === clientEntity) keyId else {
            try {
                java.lang.Long.parseUnsignedLong(entity.longKeyId, 16)
            } catch (e: Exception) {
                keyId
            }
        }
        if (entity.isCardBacked) {
            // P2c: card-backed signing goes through the NFC interaction
            // flow — the caller branches on this variant.
            return SignResolve.Card(entity, effectiveKeyId)
        }
        val ring = repo.loadSecretKeyRing(entity.fingerprint)
            ?: return SignResolve.Fail(
                errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    "Private key material for ${entity.userEmail} is missing"
                )
            )
        // Client-supplied passphrase (EXTRA_PASSPHRASE) wins; otherwise
        // whatever our own prompt cached; otherwise null (correct for
        // PGPony's default passphrase-less keys).
        val passphrase = data.getStringExtra(OpenPgpApi.EXTRA_PASSPHRASE)
            ?: ProviderPassphraseCache.get(effectiveKeyId)
        return SignResolve.Ok(ring, passphrase, effectiveKeyId, entity.userID, entity, clientEntity)
    }

    /**
     * RC4 O4 (#34): the provider-side twin of
     * EncryptDecryptViewModel.resolveEffectiveSigner. Consults the
     * signing_defaults row of the key the client chose and substitutes
     * per context; falls back to the client's key when the row is
     * absent, the slot is null, or the pick is not an unrevoked
     * software key pair.
     */
    private fun resolveProviderSigner(
        base: com.pgpony.android.data.PGPKeyEntity,
        recipientRings: Collection<org.bouncycastle.openpgp.PGPPublicKeyRing>?
    ): com.pgpony.android.data.PGPKeyEntity {
        val row = runBlocking { repo.signingDefaultsFor(base.fingerprint) } ?: return base
        val allRecipientsComposite = recipientRings != null && recipientRings.isNotEmpty() &&
            recipientRings.all { ring ->
                ring.publicKeys.asSequence().any { it.algorithm == 35 || it.algorithm == 36 } ||
                    ring.publicKeys.asSequence().any {
                        it.algorithm == com.pgpony.android.crypto.pqc.CompositeLibrePGPKeyMaterial.ALGORITHM_ID
                    }
            }
        val pickedFp = when {
            recipientRings == null -> row.signOnlySignerFingerprint
            allRecipientsComposite -> row.pqcSignerFingerprint
            else -> row.classicalSignerFingerprint
        } ?: return base
        if (pickedFp == base.fingerprint) return base
        val picked = runBlocking { repo.getByFingerprint(pickedFp) }
        return if (picked != null && picked.isKeyPair && !picked.isCardBacked && !picked.isRevoked) {
            picked
        } else {
            base
        }
    }

    private fun passphraseRequiredResult(
        data: Intent,
        keyId: Long,
        keyLabel: String,
        wasWrong: Boolean
    ): Intent {
        val promptIntent = Intent(this, ProviderPassphraseActivity::class.java).apply {
            putExtra(ProviderPassphraseActivity.EXTRA_KEY_ID, keyId)
            putExtra(ProviderPassphraseActivity.EXTRA_KEY_LABEL, keyLabel)
            putExtra(ProviderPassphraseActivity.EXTRA_WRONG, wasWrong)
            // 4.0.4: the client re-executes the original request with the
            // intent this PendingIntent returns, exactly as it does for the
            // key picker. Returning a bare RESULT_OK left clients (FairEmail)
            // with nothing to retry, so the message only appeared after the
            // user pressed Unlock a second time. Echo the request back.
            putExtra(ProviderPassphraseActivity.EXTRA_API_DATA, data)
            setData(
                android.net.Uri.parse(
                    "pgpony-api-passphrase://$keyId/$wasWrong/${data.action}"
                )
            )
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            2,
            promptIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Intent().apply {
            putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpApi.RESULT_INTENT, pendingIntent)
        }
    }

    // ── #51: per-send signing-key selection ─────────────────────────────

    /** Whether the user asked to be prompted for the signing key on each send. */
    private fun askSignKeyEachSend(): Boolean =
        getSharedPreferences("pgpony_prefs", android.content.Context.MODE_MULTI_PROCESS)
            .getBoolean("provider_ask_sign_key_each_send", false)

    /** Count of keys that can sign (software pairs and card-backed, unrevoked). */
    private fun signingCandidateCount(): Int =
        runBlocking {
            repo.getAllKeys().count { (it.isKeyPair || it.isCardBacked) && !it.isRevoked }
        }

    /**
     * How many of the user's signing keys share an address. More than one means
     * that address is ambiguous (e.g. a modern and a legacy key on the same
     * email), so the user must choose rather than have one picked for them.
     */
    private fun countSigningKeysForEmail(email: String): Int = runBlocking {
        repo.getAllKeys().count {
            (it.isKeyPair || it.isCardBacked) && !it.isRevoked &&
                it.userEmail.equals(email, ignoreCase = true)
        }
    }

    private fun signChoicePrefKey(email: String) = "sign_key_choice::" + email.lowercase()

    /** Persist the user's per-address signing-key pick (#51). */
    private fun rememberSignKeyFor(email: String, keyId: Long) {
        getSharedPreferences("pgpony_prefs", android.content.Context.MODE_MULTI_PROCESS)
            .edit().putLong(signChoicePrefKey(email), keyId).apply()
    }

    /**
     * The remembered per-address pick, but only if it still resolves to an
     * unrevoked signing key on that address; otherwise null so we ask again.
     */
    private fun validatedRememberedKey(email: String): Long? {
        val rid = getSharedPreferences("pgpony_prefs", android.content.Context.MODE_MULTI_PROCESS)
            .getLong(signChoicePrefKey(email), 0L)
        if (rid == 0L) return null
        val entity = runBlocking { findEntityByKeyId(rid) } ?: return null
        return if (!entity.isRevoked && (entity.isKeyPair || entity.isCardBacked) &&
            entity.userEmail.equals(email, ignoreCase = true)
        ) rid else null
    }

    /**
     * The send's from-address: the email of the client's chosen sign key
     * (EXTRA_SIGN_KEY_ID, always present on a sign op), falling back to
     * EXTRA_USER_ID. Null when neither yields an address.
     */
    private fun sendIdentityEmail(data: Intent): String? = runBlocking {
        val keyId = data.getLongExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, 0L)
        (if (keyId != 0L) findEntityByKeyId(keyId)?.userEmail else null)
            ?.takeIf { it.isNotBlank() }
            ?: data.getStringExtra(OpenPgpApi.EXTRA_USER_ID)
                ?.substringAfterLast('<')?.substringBefore('>')?.trim()
                ?.ifEmpty { null }
    }

    /**
     * Return a USER_INTERACTION_REQUIRED response that opens PGPony's key
     * picker in per-send mode. On pick the picker re-runs the same sign op
     * with the chosen EXTRA_SIGN_KEY_ID and the resume marker, so the client's
     * cached sign key is overridden for this one send.
     */
    private fun perSendSignKeyInteraction(
        data: Intent,
        callingPackage: String,
        scopeToAddress: Boolean = true
    ): Intent {
        val pickerIntent = Intent(this, ProviderKeyPickerActivity::class.java).apply {
            putExtra(ProviderKeyPickerActivity.EXTRA_API_DATA, data)
            putExtra(ProviderKeyPickerActivity.EXTRA_FOR_OP, true)
            val sendEmail = sendIdentityEmail(data)
            // Scope the list to the sending address only in the automatic
            // ambiguity case. Always-ask (and the passphrase-prompt switch) show
            // every key, so catch-all identities can reach keys on other
            // addresses.
            if (scopeToAddress) {
                putExtra(
                    ProviderKeyPickerActivity.EXTRA_PRESELECT_USER_ID,
                    data.getStringExtra(OpenPgpApi.EXTRA_USER_ID)
                )
                putExtra(ProviderKeyPickerActivity.EXTRA_PRESELECT_EMAIL, sendEmail)
            }
            // "In use" reflects what actually signs: the remembered pick if we
            // have one, otherwise the client's cached key.
            putExtra(
                ProviderKeyPickerActivity.EXTRA_CURRENT_KEY_ID,
                (sendEmail?.let { validatedRememberedKey(it) })
                    ?: data.getLongExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, 0L)
            )
            setData(android.net.Uri.parse("pgpony-api-signpick://$callingPackage/${data.action}"))
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            3,
            pickerIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Intent().apply {
            putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpApi.RESULT_INTENT, pendingIntent)
        }
    }

    // ── Stream helpers ─────────────────────────────────────────────────

    private fun readAll(input: ParcelFileDescriptor?): ByteArray? =
        input?.let { pfd ->
            try {
                ParcelFileDescriptor.AutoCloseInputStream(pfd).use { it.readBytes() }
            } catch (e: Exception) {
                null
            }
        }

    private fun writeAll(output: ParcelFileDescriptor?, bytes: ByteArray) {
        output?.let { pfd ->
            ParcelFileDescriptor.AutoCloseOutputStream(pfd).use { it.write(bytes) }
        }
    }

    // ── Consent flow ───────────────────────────────────────────────────

    /**
     * The API's standard interaction pattern: RESULT_CODE_USER_INTERACTION_REQUIRED
     * plus a PendingIntent the client fires with startIntentSenderForResult.
     * The PendingIntent opens ApiConsentActivity; after the user allows,
     * the client retries its call and sails through.
     */
    private fun consentRequiredResult(callingPackage: String): Intent {
        val consentIntent = Intent(this, ApiConsentActivity::class.java).apply {
            putExtra(ApiConsentActivity.EXTRA_PACKAGE_NAME, callingPackage)
            // Distinct data URI so PendingIntents for different clients
            // never collapse into one another.
            data = android.net.Uri.parse("pgpony-api-consent://$callingPackage")
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            consentIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Intent().apply {
            putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpApi.RESULT_INTENT, pendingIntent)
        }
    }

    // ── Result helpers ─────────────────────────────────────────────────

    private fun successResult(): Intent = Intent().apply {
        putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_SUCCESS)
    }

    private fun errorResult(errorId: Int, message: String): Intent = Intent().apply {
        putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)
        putExtra(OpenPgpApi.RESULT_ERROR, OpenPgpError(errorId, message))
    }
}
