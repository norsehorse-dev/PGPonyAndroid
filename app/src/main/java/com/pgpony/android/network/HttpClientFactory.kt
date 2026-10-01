// HttpClientFactory.kt
// PGPony Android — 4.0.0 Phase 6 (SOCKS/Tor proxy)
//
// The single source of HTTP clients for the whole network layer
// (KeyServerRepository, WkdService, MultiKeyServerService). Replaces
// each service's private HttpClient(Android) so proxy configuration is
// applied uniformly — turn the proxy on once and keyserver lookup,
// publish, WKD, and the background refresh worker all route through it.
//
// The client is cached and rebuilt only when the proxy config changes
// (compared by Config.signature), so per-request retrieval is cheap.
// When a proxy is set, the Ktor Android engine routes through it and a
// dead proxy makes requests FAIL — fail-closed, no direct fallback
// (plan §6). Context comes from PGPonyApp.instance so the shared,
// context-less service singletons can use it.

package com.pgpony.android.network

import android.content.Context
import com.pgpony.android.PGPonyApp
import io.ktor.client.HttpClient
import io.ktor.client.engine.android.Android
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin

/** Thrown when a request is attempted while offline mode is on. The network
 *  call sites already catch IOException and degrade to a null/failed result,
 *  so no request escapes and nothing crashes. */
class OfflineModeException : java.io.IOException(
    "PGPony offline mode is on; no network request was made"
)

object HttpClientFactory {

    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val SOCKET_TIMEOUT_MS = 15_000
    // Hard per-request ceiling so a stalled call can never hang the UI
    // forever (the old per-service clients had this via HttpTimeout; the
    // shared client dropped it). WKD overrides this with a tight 8s
    // per-request timeout so it fast-fails and falls through to Hagrid.
    private const val REQUEST_TIMEOUT_MS = 20_000L
    // Tor adds latency; give proxied requests more headroom.
    private const val TOR_CONNECT_TIMEOUT_MS = 30_000
    private const val TOR_SOCKET_TIMEOUT_MS = 30_000
    private const val TOR_REQUEST_TIMEOUT_MS = 45_000L

    @Volatile private var cached: HttpClient? = null
    @Volatile private var cachedSignature: String? = null

    // RC1 offline switch: fail every request fast, before any socket, when
    // offline mode is on. This is the single choke point the whole network
    // layer routes through (keyserver lookup/search/publish, WKD, the update
    // check, the background refresh worker), so one guard here covers them
    // all. Checked per request, not per client build, so a mid-session toggle
    // takes effect immediately even though the client is cached.
    private val offlineGuard = createClientPlugin("PGPonyOfflineGuard") {
        onRequest { _, _ ->
            if (OfflineMode.isEnabled()) throw OfflineModeException()
        }
    }

    // The loopback bridge that carries proxied requests over SOCKS5 with the
    // host name resolved by the proxy (see SocksBridge). One per proxied
    // client; replaced with the client when the proxy config changes. It also
    // does the SOCKS5 sign-in itself: the user/pass pair when one is set
    // (a distinct pair puts PGPony on its own Tor circuit, Orbot
    // IsolateSOCKSAuth), otherwise no authentication.
    @Volatile private var bridge: SocksBridge? = null

    private fun closeBridge() {
        bridge?.close()
        bridge = null
    }

    // An .onion address only exists inside Tor. With no proxy set, refuse it
    // before any socket so the name is never handed to the local resolver or
    // tried in the clear.
    private val onionGuard = createClientPlugin("PGPonyOnionGuard") {
        onRequest { request, _ ->
            if (request.url.host.trimEnd('.').lowercase().endsWith(".onion")) {
                throw java.io.IOException("An .onion address can only be reached through Tor, and no proxy is set, so nothing was sent")
            }
        }
    }

    /** The shared client for the current proxy config (context-less). */
    fun client(): HttpClient = client(PGPonyApp.instance)

    @Synchronized
    fun client(context: Context): HttpClient {
        val cfg = ProxyPrefs.config(context)
        val sig = cfg.signature
        val existing = cached
        if (existing != null && cachedSignature == sig) return existing

        // Config changed — close the old client and build a fresh one.
        existing?.close()
        val built = build(cfg)
        cached = built
        cachedSignature = sig
        return built
    }

    // 4.6.0 (item 17.8): ask every server for an unencoded body. The platform
    // HTTP stack otherwise requests gzip and inflates it transparently, which
    // lets a hostile key server or WKD host turn a small response into a large
    // one before any size cap sees it.
    private val identityEncoding = createClientPlugin("PGPonyIdentityEncoding") {
        onRequest { request, _ ->
            request.headers.remove("Accept-Encoding")
            request.headers.append("Accept-Encoding", "identity")
        }
    }

    private fun build(cfg: ProxyPrefs.Config): HttpClient {
        // 4.6.0 (item 17.8): a proxy mode with no usable host (Custom picked
        // before a host was typed, the host cleared, or a restored backup with
        // a blank host) used to build a DIRECT client while Settings showed a
        // proxy. Fail closed instead: every request errors, nothing leaves.
        closeBridge()
        if (cfg.enabled && cfg.host.isNullOrBlank()) {
            return failClosedClient("A proxy is turned on but no proxy host is set, so nothing was sent")
        }
        val proxied = cfg.enabled && cfg.host != null
        val via = if (proxied) {
            try {
                SocksBridge(cfg.host!!, cfg.port, cfg.username, cfg.password, TOR_CONNECT_TIMEOUT_MS)
            } catch (e: java.io.IOException) {
                return failClosedClient("The proxy connection could not be set up, so nothing was sent")
            }
        } else {
            null
        }
        bridge = via
        return HttpClient(Android) {
            // RC1 offline switch: block outright when offline mode is on,
            // before any other plugin or the socket.
            install(offlineGuard)
            if (!proxied) install(onionGuard)
            install(identityEncoding)
            // A hard request ceiling so a stalled lookup (common over Tor)
            // can never leave the search spinner running forever. Per-call
            // sites (WKD) tighten this with a request-scoped timeout {}.
            install(HttpTimeout) {
                requestTimeoutMillis =
                    if (proxied) TOR_REQUEST_TIMEOUT_MS else REQUEST_TIMEOUT_MS
                connectTimeoutMillis =
                    (if (proxied) TOR_CONNECT_TIMEOUT_MS else CONNECT_TIMEOUT_MS).toLong()
                socketTimeoutMillis =
                    (if (proxied) TOR_SOCKET_TIMEOUT_MS else SOCKET_TIMEOUT_MS).toLong()
            }
            engine {
                if (via != null) {
                    // SOCKS5 through Orbot / custom, by way of the loopback
                    // bridge so host names reach the proxy unresolved. A dead
                    // proxy → the request fails; there is no direct fallback.
                    proxy = via.proxy
                    connectTimeout = TOR_CONNECT_TIMEOUT_MS
                    socketTimeout = TOR_SOCKET_TIMEOUT_MS
                } else {
                    connectTimeout = CONNECT_TIMEOUT_MS
                    socketTimeout = SOCKET_TIMEOUT_MS
                }
            }
        }
    }

    // A client that sends nothing: every request fails with [reason].
    private fun failClosedClient(reason: String): HttpClient = HttpClient(Android) {
        install(offlineGuard)
        install(createClientPlugin("PGPonyProxyMissing") {
            onRequest { _, _ ->
                throw java.io.IOException(reason)
            }
        })
    }

    /** Force a rebuild on the next client() (call after a settings change). */
    @Synchronized
    fun invalidate() {
        closeBridge()
        cached?.close()
        cached = null
        cachedSignature = null
    }
}
