// ProxyPrefs.kt
// PGPony Android — 4.0.0 Phase 6 (SOCKS/Tor proxy)
//
// The user's proxy configuration, backed by SharedPreferences (the
// self-contained pattern the rest of the network layer uses). Read by
// HttpClientFactory to build the shared proxy-aware client, and by
// MultiKeyServerService to swap keys.pgpony.app for its onion under an
// active proxy.
//
// Modes:
//   OFF     — direct connections (default).
//   ORBOT   — SOCKS5 127.0.0.1:9050 (Orbot's default listener).
//   CUSTOM  — user-supplied host:port SOCKS5.
//
// Fail-closed: when a proxy is enabled and unreachable, requests FAIL —
// the client never silently falls back to a direct connection (plan §6
// "no silent direct fallback"). This is inherent to setting the engine
// proxy; there is deliberately no direct-retry path anywhere.

package com.pgpony.android.network

import android.content.Context
import android.content.pm.PackageManager

object ProxyPrefs {

    const val PREFS = "pgpony_prefs"
    const val KEY_MODE = "proxy_mode"                 // "off" | "orbot" | "custom"
    const val KEY_CUSTOM_HOST = "proxy_custom_host"
    const val KEY_CUSTOM_PORT = "proxy_custom_port"
    const val KEY_ONION_MIRROR = "proxy_onion_mirror" // default ON under a proxy
    // #proxy stream isolation: optional SOCKS5 user/pass. Blank = no auth.
    // Applies to whichever proxy is active (Orbot or Custom). A distinct
    // user/pass pair puts PGPony on its own Tor circuit (IsolateSOCKSAuth).
    const val KEY_PROXY_USER = "proxy_socks_user"
    const val KEY_PROXY_PASS = "proxy_socks_pass"

    const val MODE_OFF = "off"
    const val MODE_ORBOT = "orbot"
    const val MODE_CUSTOM = "custom"

    const val ORBOT_HOST = "127.0.0.1"
    const val ORBOT_PORT = 9050
    const val ORBOT_PACKAGE = "org.torproject.android"

    /** keys.pgpony.app's onion (plan §6 [R2]); /pks and /vks live under it. */
    const val PGPONY_ONION_BASE =
        "http://pgponyisur7gxcrfw5ofpjr2sepqul3zgbs66rrd3ughk5qvi4a3t5id.onion"
    const val PGPONY_CLEARNET_HOST = "keys.pgpony.app"

    data class Config(
        val mode: String,
        val host: String?,
        val port: Int,
        val onionMirror: Boolean,
        val username: String? = null,
        val password: String? = null
    ) {
        val enabled: Boolean get() = mode != MODE_OFF
        /** True when SOCKS5 user/pass auth should be offered to the proxy. */
        val hasAuth: Boolean get() = !username.isNullOrEmpty() && !password.isNullOrEmpty()
        /** A stable signature so HttpClientFactory rebuilds only on change.
         *  Credentials are folded in so a user/pass change rebuilds the client
         *  (and re-scopes the SOCKS Authenticator). In-memory only, never logged. */
        val signature: String get() = "$mode|$host|$port|$username|${password?.length ?: 0}"
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun config(context: Context): Config {
        val p = prefs(context)
        val mode = p.getString(KEY_MODE, MODE_OFF) ?: MODE_OFF
        val user = p.getString(KEY_PROXY_USER, "")?.ifBlank { null }
        val pass = p.getString(KEY_PROXY_PASS, "")?.ifBlank { null }
        return when (mode) {
            MODE_ORBOT -> Config(mode, ORBOT_HOST, ORBOT_PORT, onionMirror(context), user, pass)
            MODE_CUSTOM -> Config(
                mode,
                p.getString(KEY_CUSTOM_HOST, "")?.ifBlank { null },
                p.getInt(KEY_CUSTOM_PORT, ORBOT_PORT),
                onionMirror(context),
                user,
                pass
            )
            else -> Config(MODE_OFF, null, 0, false)
        }
    }

    fun onionMirror(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ONION_MIRROR, true)

    fun setMode(context: Context, mode: String) =
        prefs(context).edit().putString(KEY_MODE, mode).apply()

    fun setCustom(context: Context, host: String, port: Int) =
        prefs(context).edit()
            .putString(KEY_CUSTOM_HOST, host)
            .putInt(KEY_CUSTOM_PORT, port)
            .apply()

    fun setOnionMirror(context: Context, enabled: Boolean) =
        prefs(context).edit().putBoolean(KEY_ONION_MIRROR, enabled).apply()

    /** Set the SOCKS5 user/pass (blank clears). Caller should invalidate the
     *  shared client so the change takes effect immediately. */
    fun setCredentials(context: Context, username: String, password: String) =
        prefs(context).edit()
            .putString(KEY_PROXY_USER, username)
            .putString(KEY_PROXY_PASS, password)
            .apply()

    fun username(context: Context): String = prefs(context).getString(KEY_PROXY_USER, "") ?: ""
    fun password(context: Context): String = prefs(context).getString(KEY_PROXY_PASS, "") ?: ""

    /** Convenience toggle: is Orbot installed? (drives the one-tap UI). */
    fun isOrbotInstalled(context: Context): Boolean = try {
        context.packageManager.getPackageInfo(ORBOT_PACKAGE, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    /**
     * Rewrite a server base URL to its onion when a proxy is active and
     * the onion mirror is on — only for the first-party keys.pgpony.app
     * (keys.openpgp.org via clearnet-through-proxy unless it later gets
     * a cheap onion). Leaves everything else untouched.
     */
    fun effectiveBaseUrl(context: Context, baseUrl: String): String {
        val cfg = config(context)
        if (!cfg.enabled || !cfg.onionMirror) return baseUrl
        return if (baseUrl.contains(PGPONY_CLEARNET_HOST)) PGPONY_ONION_BASE else baseUrl
    }
}
