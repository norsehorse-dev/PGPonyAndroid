// PairController.kt
// PGPony Android 4.6.3 (4.7.0 item 21): pair with PGPony Desktop or another
// phone and move keys over the local network. Everything between the pairing
// protocol (com.pgpony.android.pair, docs/PAIRING_PROTOCOL.md) and the screen,
// ported from desktop 3.0's PairController: open and join pairing windows, turn
// the user's picks into offered items, check what arrives against what was
// offered (section 6), and import it through the same code a file import or a
// backup restore uses, once the user accepted the preview. No Compose here.
//
// Phone specifics: the host listens only on Wi-Fi, Ethernet, tethering and USB
// interfaces (never cellular), and lists those addresses only.

package com.pgpony.android.ui.pair

import com.pgpony.android.PGPonyApp
import com.pgpony.android.R
import com.pgpony.android.backup.BackupService
import com.pgpony.android.backup.CrockfordBase32
import com.pgpony.android.data.repository.ImportPreview
import com.pgpony.android.data.repository.ImportResolution
import com.pgpony.android.data.repository.KeyRepository
import com.pgpony.android.pair.PairAttempt
import com.pgpony.android.pair.PairCrypto
import com.pgpony.android.pair.PairException
import com.pgpony.android.pair.PairFailure
import com.pgpony.android.pair.PairInvite
import com.pgpony.android.pair.PairItem
import com.pgpony.android.pair.PairPeer
import com.pgpony.android.pair.PairProtocol
import com.pgpony.android.pair.PairSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.NoRouteToHostException
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException

class PairController(private val repo: KeyRepository) {

    /** Something the user can send. */
    sealed class Outgoing {
        abstract val name: String

        data class PublicKey(val fingerprint: String, override val name: String) : Outgoing()
        data class KeyPair(val fingerprint: String, override val name: String, val protected: Boolean) : Outgoing()
        data class Backup(override val name: String) : Outgoing()
    }

    /** Offered items with their bytes, and the backup's recovery code when a backup is among them. */
    class Prepared(val items: List<PairItem>, val payloads: Map<Int, ByteArray>, val recoveryCode: String?)

    /** What this keyring could send. Card-backed keys go as public keys only. */
    suspend fun candidates(): List<Outgoing> = withContext(Dispatchers.IO) {
        val keys = repo.getAllKeys()
        val out = ArrayList<Outgoing>()
        for (k in keys) {
            if (k.isKeyPair && !k.isCardBacked) {
                val protected = runCatching { repo.isPrivateKeyPassphraseProtected(k.fingerprint) }.getOrDefault(false)
                out += Outgoing.KeyPair(k.fingerprint, k.userID.ifBlank { k.fingerprint }, protected)
            }
        }
        for (k in keys) out += Outgoing.PublicKey(k.fingerprint, k.userID.ifBlank { k.fingerprint })
        if (keys.isNotEmpty()) out += Outgoing.Backup(str(R.string.pair_item_backup))
        out
    }

    /**
     * Builds the items for [picked]. [transferPassphrase] protects key pairs that have no
     * passphrase of their own; without it such a pick fails with [PairPrepareException]. A key
     * pair goes out only when every secret part is under a passphrase.
     */
    suspend fun prepare(picked: List<Outgoing>, transferPassphrase: String?): Prepared = withContext(Dispatchers.IO) {
        val items = ArrayList<PairItem>()
        val payloads = HashMap<Int, ByteArray>()
        var recovery: String? = null
        picked.forEachIndexed { i, o ->
            val id = i + 1
            val kind: String
            val fingerprint: String?
            val bytes: ByteArray
            when (o) {
                is Outgoing.PublicKey -> {
                    kind = PairItem.PUBLIC_KEY
                    fingerprint = o.fingerprint
                    bytes = (repo.exportArmoredPublicKeyForSharing(o.fingerprint)
                        ?: throw PairPrepareException(str(R.string.pair_err_export, o.name)))
                        .toByteArray(Charsets.UTF_8)
                }
                is Outgoing.KeyPair -> {
                    kind = PairItem.KEY_PAIR
                    fingerprint = o.fingerprint
                    if (!o.protected && transferPassphrase.isNullOrEmpty()) {
                        throw PairPrepareException(str(R.string.pair_err_needs_passphrase, o.name))
                    }
                    val armored = (if (o.protected) repo.exportArmoredPrivateKey(o.fingerprint)
                    else repo.exportArmoredPrivateKey(o.fingerprint, transferPassphrase))
                        ?: throw PairPrepareException(str(R.string.pair_err_export, o.name))
                    bytes = armored.toByteArray(Charsets.UTF_8)
                    // Never send a secret in the clear, whatever the export path did.
                    if (!PairKeyProtection.isFullyPassphraseProtected(bytes)) {
                        throw PairPrepareException(str(R.string.pair_err_export, o.name))
                    }
                }
                is Outgoing.Backup -> {
                    kind = PairItem.BACKUP
                    fingerprint = null
                    val code = CrockfordBase32.generate()
                    recovery = code.grouped
                    bytes = BackupService(repo).exportBackup(code.canonical)
                }
            }
            if (bytes.size > PairSession.MAX_ITEM_BYTES) throw PairPrepareException(str(R.string.pair_err_too_large, o.name))
            items += PairItem(id, kind, o.name, fingerprint, bytes.size.toLong())
            payloads[id] = bytes
        }
        Prepared(items, payloads, recovery)
    }

    /**
     * A received item that passed [check], as read from its own bytes: what the preview shows
     * before anything is written. [preview] is the key of a key item, null for a backup.
     */
    class Received(val item: PairItem, val bytes: ByteArray, val preview: ImportPreview?)

    /**
     * Checks a received item against what its offer said (docs/PAIRING_PROTOCOL.md, section 6),
     * writing nothing. A public key is one armored block holding one certificate with no secret
     * material and the offered fingerprint; a key pair is one block holding one secret key with
     * the offered fingerprint, every secret part under a passphrase; a backup is one armored
     * message. Throws [PairPrepareException] with a readable reason otherwise.
     */
    suspend fun check(item: PairItem, bytes: ByteArray): Received = withContext(Dispatchers.IO) {
        when (item.kind) {
            PairItem.PUBLIC_KEY, PairItem.KEY_PAIR -> {
                val offered = item.fingerprint?.trim()?.takeIf { it.isNotEmpty() }
                    ?: throw PairPrepareException(str(R.string.pair_err_no_fingerprint, item.name))
                val text = bytes.toString(Charsets.UTF_8)
                val preview = if (ARMOR_BEGIN.findAll(text).count() == 1) repo.previewArmoredKey(text) else null
                if (preview == null || preview.additionalKeys.isNotEmpty()) {
                    throw PairPrepareException(str(R.string.pair_err_not_one_key, item.name))
                }
                if (!preview.fingerprint.equals(offered, ignoreCase = true)) {
                    throw PairPrepareException(str(R.string.pair_err_wrong_key, item.name))
                }
                if (item.kind == PairItem.PUBLIC_KEY && preview.hasPrivateKey) {
                    throw PairPrepareException(str(R.string.pair_err_secret_in_public, item.name))
                }
                if (item.kind == PairItem.KEY_PAIR) {
                    if (!preview.hasPrivateKey) throw PairPrepareException(str(R.string.pair_err_no_secret, item.name))
                    if (!PairKeyProtection.isFullyPassphraseProtected(bytes)) {
                        throw PairPrepareException(str(R.string.pair_err_unprotected, item.name))
                    }
                }
                Received(item, bytes, preview)
            }
            PairItem.BACKUP -> {
                val text = bytes.toString(Charsets.ISO_8859_1)
                if (!text.trimStart().startsWith("-----BEGIN PGP MESSAGE-----") || ARMOR_BEGIN.findAll(text).count() != 1) {
                    throw PairPrepareException(str(R.string.pair_err_not_backup, item.name))
                }
                Received(item, bytes, null)
            }
            else -> throw PairPrepareException(str(R.string.pair_err_import, item.name))
        }
    }

    /**
     * Imports one received item, which the user accepted after its preview, and says what
     * happened. It runs [check] again first. A backup needs [backupCode], the recovery code the
     * sending screen shows; restoring takes no trust levels and applies no settings from it.
     * Throws with a readable message on failure.
     */
    suspend fun apply(item: PairItem, bytes: ByteArray, backupCode: String?): String {
        check(item, bytes)
        return withContext(Dispatchers.IO) {
            when (item.kind) {
                PairItem.PUBLIC_KEY, PairItem.KEY_PAIR -> {
                    val outcome = try {
                        repo.importArmoredKeyDetailed(bytes.toString(Charsets.UTF_8))
                    } catch (e: Exception) {
                        throw PairPrepareException(str(R.string.pair_err_import, item.name))
                    }
                    when (outcome.resolution) {
                        ImportResolution.ALREADY_IN_KEYRING -> str(R.string.pair_import_already)
                        ImportResolution.INSERTED -> str(R.string.pair_import_added)
                        else -> str(R.string.pair_import_updated)
                    }
                }
                PairItem.BACKUP -> {
                    val code = backupCode?.takeIf { it.isNotBlank() }
                        ?: throw PairPrepareException(str(R.string.pair_err_backup_code))
                    val report = BackupService(repo).restoreBackup(bytes, code)
                    val n = report.added.size + report.upgraded.size + report.updated.size
                    PGPonyApp.instance.resources.getQuantityString(R.plurals.pair_restore_summary, n, n)
                }
                else -> throw PairPrepareException(str(R.string.pair_err_import, item.name))
            }
        }
    }

    companion object {
        /** How long a pairing window stays open (docs/PAIRING_PROTOCOL.md, section 1). */
        const val WINDOW_MS = 10 * 60 * 1000

        /** How many wrong typed codes the host takes before the attempt counts as refused. */
        const val TYPED_CODE_TRIES = 3

        private val ARMOR_BEGIN = Regex("-----BEGIN PGP ")

        /**
         * Interfaces a phone may pair on: Wi-Fi, Wi-Fi hotspot and Wi-Fi Direct, Ethernet, and
         * USB or Bluetooth tethering. Cellular (rmnet, ccmni and the like) and VPN tunnels never.
         */
        private val LOCAL_INTERFACE_PREFIXES = listOf("wlan", "swlan", "ap", "p2p", "eth", "en", "rndis", "usb", "ncm", "bt-pan")

        internal fun isLocalInterface(name: String): Boolean {
            val n = name.lowercase()
            return LOCAL_INTERFACE_PREFIXES.any { n.startsWith(it) }
        }

        private fun str(id: Int, vararg args: Any): String =
            if (args.isEmpty()) PGPonyApp.instance.getString(id) else PGPonyApp.instance.getString(id, *args)

        private fun localInterfaces(): List<NetworkInterface> = runCatching {
            NetworkInterface.getNetworkInterfaces().toList()
                .filter { it.isUp && !it.isLoopback && !it.isVirtual && !it.isPointToPoint && isLocalInterface(it.name) }
        }.getOrDefault(emptyList())

        /** The addresses another device on this network can reach, IPv4 first. */
        fun localAddresses(): List<InetAddress> =
            localInterfaces()
                .flatMap { it.inetAddresses.toList() }
                .filter { !it.isLoopbackAddress && !it.isLinkLocalAddress && !it.isMulticastAddress }
                .sortedBy { if (it is Inet4Address) 0 else 1 }

        /**
         * What the host screen lists, the first one shown large: IPv4 addresses, or the IPv6
         * ones only when there is no IPv4 address at all (a phone holds several rotating IPv6
         * privacy addresses, and a local network pairs over IPv4).
         */
        fun hostAddresses(): List<InetAddress> {
            val all = localAddresses()
            val v4 = all.filterIsInstance<Inet4Address>()
            return if (v4.isNotEmpty()) v4 else all
        }

        /** The subnets of the listed addresses: besides the always-local ranges, a peer in one may pair. */
        fun hostSubnets(): List<PairPeer.Subnet> {
            val listed = hostAddresses().toSet()
            return localInterfaces()
                .flatMap { it.interfaceAddresses }
                .filter { it.address in listed }
                .mapNotNull { runCatching { PairPeer.Subnet(it.address.address, it.networkPrefixLength.toInt()) }.getOrNull() }
        }

        /** [a]'s bytes, an IPv4-mapped IPv6 address (::ffff:a.b.c.d) as its IPv4 address. */
        internal fun plain(a: InetAddress): ByteArray {
            val b = a.address
            if (b.size == 16 && (0 until 10).all { b[it].toInt() == 0 } &&
                b[10].toInt() == -1 && b[11].toInt() == -1
            ) return b.copyOfRange(12, 16)
            return b
        }

        /** A peer's address as the compare screens show it (no zone). */
        fun peerText(address: InetAddress): String =
            if (address is Inet4Address) address.hostAddress.orEmpty() else address.hostAddress.orEmpty().substringBefore('%')

        /**
         * True when a join failed in a way that fits another device having taken the window: the
         * host refused the connection, reset it, or closed it during the handshake.
         */
        fun windowMayBeTaken(e: Throwable): Boolean = when (e) {
            is ConnectException -> true
            is NoRouteToHostException -> false
            is SocketException -> true
            is PairException -> e.failure == PairFailure.CLOSED
            else -> false
        }

        /** `192.168.1.20:49152` or `[fd00::1]:49152` as the host screen shows it. */
        fun display(address: InetAddress, port: Int): String =
            if (address is Inet4Address) "${address.hostAddress}:$port"
            else "[${address.hostAddress.orEmpty().substringBefore('%')}]:$port"

        /**
         * What the join field or a scan holds: an invite (docs/PAIRING_PROTOCOL.md, section 8),
         * whose host key hash the join then checks, or a typed address. Null when it is neither.
         */
        fun target(text: String): JoinTarget? = try {
            PairInvite.parse(text)?.let { invite ->
                JoinTarget(invite.addresses.map { it.socketAddress() }, invite.hostKeyHash)
            } ?: if (looksLikeInvite(text)) null else parse(text)?.let { JoinTarget(listOf(it), null) }
        } catch (e: RuntimeException) {
            null
        }

        /** Starts like an invite, so a failed [target] should say the invite is unreadable. */
        fun looksLikeInvite(text: String): Boolean = text.trim().startsWith("pgpony-pair:", ignoreCase = true)

        /** Reads a typed address; null when it is not one. */
        fun parse(text: String): InetSocketAddress? {
            val t = text.trim()
            val (host, portText) = when {
                t.startsWith("[") -> t.substringAfter('[').substringBefore(']') to t.substringAfter("]:", "")
                t.count { it == ':' } == 1 -> t.substringBefore(':') to t.substringAfter(':')
                else -> return null
            }
            val port = portText.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            if (host.isBlank()) return null
            return runCatching { InetSocketAddress(InetAddress.getByName(host), port) }.getOrNull()
        }
    }

    /**
     * An open pairing window: a listener on an ephemeral port. [awaitConnection] waits for one
     * connection from the local network (others are closed at once and do not use up the
     * window), then closes the listener; [handshake] runs phase 1 on it.
     */
    class HostWindow : AutoCloseable {
        private val server = ServerSocket(0)
        val hostKey: PairCrypto.KeyPair = PairCrypto.keyPair()
        val port: Int get() = server.localPort
        val openedAt = System.currentTimeMillis()
        private val addresses: List<InetAddress> = hostAddresses()
        private val subnets: List<PairPeer.Subnet> = hostSubnets()
        @Volatile private var socket: Socket? = null
        @Volatile private var closed = false

        /** The invite the host screen shows as a QR code: the listed addresses and this window's key hash. */
        fun invite(): PairInvite? {
            val list = addresses.mapNotNull { PairInvite.parseAddress(display(it, port)) }
            if (list.isEmpty()) return null
            return PairInvite.forHostKey(hostKey.public, list.take(PairInvite.MAX_ADDRESSES))
        }

        /** The listed addresses, formatted with this window's port, the first one shown large. */
        fun addressTexts(): List<String> = addresses.map { display(it, port) }

        /**
         * Waits until the window closes for a connection from the local network on a local
         * interface, and returns the peer's address. Anything else is closed before a byte is
         * read, and the window keeps waiting. The listener is closed once one is taken.
         */
        fun awaitConnection(): String {
            try {
                while (true) {
                    val left = openedAt + WINDOW_MS - System.currentTimeMillis()
                    if (left <= 0) throw PairException(PairFailure.TIMEOUT, WINDOW_EXPIRED)
                    server.soTimeout = left.toInt().coerceAtLeast(1)
                    val s = try {
                        server.accept()
                    } catch (e: SocketTimeoutException) {
                        throw PairException(PairFailure.TIMEOUT, WINDOW_EXPIRED)
                    }
                    // Only a peer on the local network, reaching this phone on one of the
                    // addresses it lists (never the cellular one).
                    val local = plain(s.localAddress)
                    val onListed = addresses.any { plain(it).contentEquals(local) }
                    if (!onListed || !PairPeer.isAllowed(s.inetAddress, subnets)) {
                        runCatching { s.close() }
                        continue
                    }
                    socket = s
                    if (closed) {
                        runCatching { s.close() }
                        throw PairException(PairFailure.CLOSED, "the pairing window was closed")
                    }
                    return peerText(s.inetAddress)
                }
            } finally {
                runCatching { server.close() }
            }
        }

        /** Phase 1 on the connection [awaitConnection] took. */
        fun handshake(): PairAttempt {
            val s = socket ?: throw PairException(PairFailure.CLOSED, "no connection")
            s.tcpNoDelay = true
            return PairProtocol.host(s.getInputStream(), s.getOutputStream(), { s.soTimeout = it }, { s.close() }, hostKey)
        }

        /** Closes the listener and, while the window owns it, the connection it took. Never blocks. */
        override fun close() {
            closed = true
            runCatching { server.close() }
            runCatching { socket?.close() }
        }

        companion object {
            /** The message of a window that expired; the screen shows its own text for it. */
            const val WINDOW_EXPIRED = "window expired"
        }
    }

    /** Where a join connects: one typed address, or an invite's addresses and host key hash. */
    class JoinTarget(val addresses: List<InetSocketAddress>, val hostKeyHash: ByteArray?)

    /** A joined attempt and the host's address as the compare screen shows it. */
    class Connection(val attempt: PairAttempt, val peer: String)

    /**
     * Connects to the first of [target]'s addresses that answers and runs phase 1, checking the
     * host key against the invite's hash when there is one.
     */
    fun connect(target: JoinTarget): Connection {
        val timeout = if (target.addresses.size > 1) PairInvite.CONNECT_TIMEOUT_MS else 10_000
        var last: Exception? = null
        for (address in target.addresses) {
            val socket = Socket()
            try {
                socket.connect(address, timeout)
            } catch (e: Exception) {
                runCatching { socket.close() }
                last = e
                continue
            }
            socket.tcpNoDelay = true
            val peer = peerText(socket.inetAddress)
            return Connection(
                PairProtocol.join(
                    socket.getInputStream(), socket.getOutputStream(), { socket.soTimeout = it }, { socket.close() }, target.hostKeyHash
                ),
                peer
            )
        }
        throw last ?: PairException(PairFailure.CLOSED, "no address to connect to")
    }
}

class PairPrepareException(message: String) : Exception(message)
