// AgentBridgeService.kt
// PGPony Android, 4.6.0 (item 16b): the Android side of the SSHPony ssh-agent
// bridge (see AgentBridge for the flow and the pairing handshake).
//
// AgentBridgeReceiver gets the broadcast sshpony-agent sends for each
// connection from ssh and starts this service with the localhost port to call
// back. The service runs in the :remote_api process with the OpenPGP provider,
// so it shares the provider's unlock session (ProviderPassphraseCache), its
// passphrase prompt and its hardware-key activity.
//
// It is a foreground service ("specialUse": a terminal's ssh-agent) for as
// long as a connection is open. Android lets an app start one from the
// background only when it is exempt from battery optimization, so the SSH
// agent settings ask for that; without it the receiver posts a notification
// explaining what to change.
//
// Prompts: PGPony cannot open a screen from the background, so a sign request
// that needs the user (a passphrase, or a card tap and PIN) posts a
// notification; tapping it opens the same prompt the OpenPGP provider uses.
// The connection waits up to PROMPT_TIMEOUT_MS for the answer, then refuses
// the signature, and ssh moves on.

package com.pgpony.android.provider.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.ssh.SshAuth
import com.pgpony.android.crypto.ssh.SshSigningKey
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.provider.ProviderCardOpActivity
import com.pgpony.android.provider.ProviderCardOpStore
import com.pgpony.android.provider.ProviderPassphraseActivity
import com.pgpony.android.provider.ProviderPassphraseCache
import com.pgpony.android.provider.SshAuthenticationService
import kotlinx.coroutines.runBlocking
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class AgentBridgeService : Service() {

    companion object {
        private const val TAG = "AgentBridge"

        const val CHANNEL_STATUS = "ssh_agent_status"
        const val CHANNEL_PROMPTS = "ssh_agent_prompts"
        private const val STATUS_ID = 7101
        private const val PROMPT_ID_BASE = 7200

        private const val CONNECT_TIMEOUT_MS = 5_000
        private const val HANDSHAKE_TIMEOUT_MS = 15_000
        const val PROMPT_TIMEOUT_MS = 120_000L
        private const val POLL_MS = 300L
        private const val MAX_WRONG_PASSPHRASE = 3

        fun createChannels(context: Context) {
            val nm = context.getSystemService(NotificationManager::class.java) ?: return
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_STATUS,
                    context.getString(R.string.agent_channel_status_name),
                    NotificationManager.IMPORTANCE_LOW
                )
            )
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_PROMPTS,
                    context.getString(R.string.agent_channel_prompts_name),
                    NotificationManager.IMPORTANCE_HIGH
                )
            )
        }
    }

    private val active = AtomicInteger(0)
    @Volatile private var lastStartId = 0
    private val promptIds = AtomicInteger(0)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        createChannels(this)
        val status = NotificationCompat.Builder(this, CHANNEL_STATUS)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.agent_status_title))
            .setContentText(getString(R.string.agent_status_text))
            .setOngoing(true)
            .build()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(STATUS_ID, status, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(STATUS_ID, status)
            }
        } catch (e: Exception) {
            Log.w(TAG, "could not enter the foreground: ${e.message}")
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val port = intent?.getIntExtra(AgentBridge.EXTRA_PORT, -1) ?: -1
        if (port !in 1..65535) {
            finishIfIdle()
            return START_NOT_STICKY
        }
        active.incrementAndGet()
        Thread({
            try {
                serve(port)
            } catch (t: Throwable) {
                Log.w(TAG, "connection ended: ${t.message}")
            } finally {
                active.decrementAndGet()
                finishIfIdle()
            }
        }, "sshpony-$port").start()
        return START_NOT_STICKY
    }

    private fun finishIfIdle() {
        if (active.get() == 0) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf(lastStartId)
        }
    }

    private fun serve(port: Int) {
        val secret = AgentBridgePrefs.secret(this) ?: return
        if (!AgentBridgePrefs.isEnabled(this)) return
        Socket().use { socket ->
            socket.connect(InetSocketAddress("127.0.0.1", port), CONNECT_TIMEOUT_MS)
            socket.soTimeout = HANDSHAKE_TIMEOUT_MS
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            AgentBridge.serverHandshake(input, output, secret)
            socket.soTimeout = 0
            SshAgentSession(KeySource()).serve(input, output)
        }
    }

    // ── Keys and signing ───────────────────────────────────────────────

    private inner class KeySource : SshAgentSession.KeySource {
        private var cached: List<SshAgentSession.AgentKey>? = null

        override fun keys(): List<SshAgentSession.AgentKey> =
            cached ?: offeredKeys(this@AgentBridgeService).also { cached = it }

        override fun sign(key: SshAgentSession.AgentKey, data: ByteArray, flags: Int): ByteArray? {
            val o = key.ref as? OfferedKey ?: return null
            val hash = SshAgentSession.hashFor(flags)
            return if (o.entity.isCardBacked) signWithCard(o, data, hash) else signWithSoftwareKey(o, data, hash)
        }
    }

    private fun primaryKeyId(e: PGPKeyEntity, fallback: Long): Long =
        runCatching { java.lang.Long.parseUnsignedLong(e.longKeyId, 16) }.getOrDefault(fallback)

    private fun signWithSoftwareKey(o: OfferedKey, data: ByteArray, hash: Int): ByteArray? {
        val repo = PGPonyApp.instance.keyRepository
        val ring = repo.loadSshAuthSecretRing(o.entity.fingerprint) ?: return null
        val keyId = primaryKeyId(o.entity, o.sub.keyId)
        var wrong = 0
        var wasWrong = false
        while (true) {
            when (val u = SshSigningKey.unlock(ring, o.sub.keyId, ProviderPassphraseCache.get(keyId))) {
                is SshSigningKey.Unlock.Ok ->
                    return runCatching { SshAuth.sign(o.material, u.key, data, hash) }.getOrNull()
                SshSigningKey.Unlock.NeedsPassphrase -> Unit
                SshSigningKey.Unlock.WrongPassphrase -> {
                    ProviderPassphraseCache.clear(keyId)
                    wasWrong = true
                    if (++wrong >= MAX_WRONG_PASSPHRASE) return null
                }
                is SshSigningKey.Unlock.Missing -> return null
            }
            if (!awaitPassphrase(keyId, o.entity.userID, wasWrong)) return null
        }
    }

    /** Post the unlock prompt and wait for the passphrase to reach the cache. */
    private fun awaitPassphrase(keyId: Long, label: String, wasWrong: Boolean): Boolean {
        val waitId = AgentWaits.newId()
        val prompt = Intent(this, ProviderPassphraseActivity::class.java).apply {
            putExtra(ProviderPassphraseActivity.EXTRA_KEY_ID, keyId)
            putExtra(ProviderPassphraseActivity.EXTRA_KEY_LABEL, label)
            putExtra(ProviderPassphraseActivity.EXTRA_WRONG, wasWrong)
            putExtra(ProviderPassphraseActivity.EXTRA_NO_KEY_CHANGE, true)
            putExtra(ProviderPassphraseActivity.EXTRA_AGENT_WAIT_ID, waitId)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            data = android.net.Uri.parse("pgpony-agent-passphrase://$waitId")
        }
        val notifId = PROMPT_ID_BASE + (promptIds.incrementAndGet() and 0xFF)
        postPrompt(
            notifId,
            getString(R.string.agent_prompt_unlock_title, label),
            getString(R.string.agent_prompt_unlock_text),
            prompt
        )
        try {
            val deadline = System.currentTimeMillis() + PROMPT_TIMEOUT_MS
            while (System.currentTimeMillis() < deadline) {
                if (ProviderPassphraseCache.get(keyId) != null) return true
                if (AgentWaits.isCancelled(waitId)) return false
                Thread.sleep(POLL_MS)
            }
            return false
        } finally {
            AgentWaits.forget(waitId)
            NotificationManagerCompat.from(this).cancel(notifId)
        }
    }

    private fun signWithCard(o: OfferedKey, data: ByteArray, hash: Int): ByteArray? {
        val opKey = ProviderCardOpStore.opKey(
            SshAuthenticationService.ACTION_SIGN, o.sub.keyId, false, "agent:$hash", emptyList(), data
        )
        ProviderCardOpStore.putPending(
            ProviderCardOpStore.PendingOp(
                opKey = opKey,
                action = SshAuthenticationService.ACTION_SIGN,
                input = data,
                cardEntityFingerprint = o.entity.fingerprint,
                armor = false,
                filename = null,
                recipientFingerprints = emptyList(),
                senderAddress = null,
                sshHash = hash
            )
        )
        val cardIntent = Intent(this, ProviderCardOpActivity::class.java).apply {
            putExtra(ProviderCardOpActivity.EXTRA_OP_KEY, opKey)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            setData(android.net.Uri.parse("pgpony-agent-cardop://$opKey"))
        }
        val notifId = PROMPT_ID_BASE + (promptIds.incrementAndGet() and 0xFF)
        postPrompt(
            notifId,
            getString(R.string.agent_prompt_card_title),
            getString(R.string.agent_prompt_card_text, o.entity.userID),
            cardIntent
        )
        try {
            val deadline = System.currentTimeMillis() + PROMPT_TIMEOUT_MS
            while (System.currentTimeMillis() < deadline) {
                val done = ProviderCardOpStore.consumeCompleted(opKey)
                if (done is ProviderCardOpStore.CompletedOp.SshSignature) return done.blob
                // The card activity drops the pending op when the user cancels.
                if (done == null && ProviderCardOpStore.getPending(opKey) == null) return null
                Thread.sleep(POLL_MS)
            }
            ProviderCardOpStore.abandon(opKey)
            return null
        } finally {
            NotificationManagerCompat.from(this).cancel(notifId)
        }
    }

    private fun postPrompt(id: Int, title: String, text: String, target: Intent) {
        val pi = PendingIntent.getActivity(
            this, id, target, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val n = NotificationCompat.Builder(this, CHANNEL_PROMPTS)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(Notification.CATEGORY_STATUS)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .setTimeoutAfter(PROMPT_TIMEOUT_MS)
            .build()
        try {
            NotificationManagerCompat.from(this).notify(id, n)
        } catch (e: SecurityException) {
            Log.w(TAG, "notifications are not allowed; the prompt cannot be shown")
        }
    }
}

/**
 * The keys the agent offers: key pairs and card keys that are not revoked,
 * have a usable SSH authentication subkey, and are not switched off in the
 * SSH agent settings.
 */
internal fun offeredKeys(context: Context): List<SshAgentSession.AgentKey> {
    val repo = PGPonyApp.instance.keyRepository
    val excluded = AgentBridgePrefs.excluded(context)
    return runBlocking { repo.getAllKeys() }
        .filter { (it.isKeyPair || it.isCardBacked) && !it.isRevoked && it.fingerprint.uppercase() !in excluded }
        .mapNotNull { e ->
            val cert = repo.sshAuthCertificate(e.fingerprint) ?: return@mapNotNull null
            val sub = SshAuth.authSubkey(cert) ?: return@mapNotNull null
            val m = SshAuth.material(sub.publicBody) ?: return@mapNotNull null
            SshAgentSession.AgentKey(SshAuth.publicBlob(m), e.userID.ifBlank { e.shortFingerprint }, OfferedKey(e, sub, m))
        }
}

/** An offered key: the entity, its authentication subkey and SSH material. */
internal class OfferedKey(
    val entity: PGPKeyEntity,
    val sub: CertificateBindings.SubkeyState,
    val material: SshAuth.Material
)

/** Waits the service is running, and which ones the user cancelled. */
object AgentWaits {
    private val cancelled = ConcurrentHashMap.newKeySet<String>()
    fun newId(): String = java.util.UUID.randomUUID().toString()
    fun cancel(id: String) { cancelled.add(id) }
    fun isCancelled(id: String): Boolean = cancelled.contains(id)
    fun forget(id: String) { cancelled.remove(id) }
}
