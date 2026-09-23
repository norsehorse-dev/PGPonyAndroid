// AgentBridgePrefs.kt
// PGPony Android, 4.6.0 (item 16b): the SSH agent bridge settings.
//
// Kept in their own private preferences file, read with MODE_MULTI_PROCESS
// because the Settings screen writes them in the main process and the bridge
// reads them in :remote_api. App backup is off for PGPony, so the pairing
// secret never leaves the device.

package com.pgpony.android.provider.agent

import android.content.Context

object AgentBridgePrefs {
    private const val FILE = "ssh_agent_bridge"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_SECRET = "pairing_secret"
    private const val KEY_EXCLUDED = "excluded_keys"

    @Suppress("DEPRECATION")
    private fun prefs(context: Context) =
        context.getSharedPreferences(FILE, Context.MODE_MULTI_PROCESS)

    fun isEnabled(context: Context): Boolean = prefs(context).getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, on: Boolean) {
        prefs(context).edit().putBoolean(KEY_ENABLED, on).commit()
    }

    fun secret(context: Context): ByteArray? =
        prefs(context).getString(KEY_SECRET, null)?.let { AgentBridge.fromHex(it) }
            ?.takeIf { it.size == AgentBridge.SECRET_LEN }

    fun isPaired(context: Context): Boolean = secret(context) != null

    /** A fresh pairing secret; any earlier pairing stops working. */
    fun pair(context: Context): ByteArray {
        val s = AgentBridge.newSecret()
        prefs(context).edit().putString(KEY_SECRET, AgentBridge.toHex(s)).commit()
        return s
    }

    fun unpair(context: Context) {
        prefs(context).edit().remove(KEY_SECRET).commit()
    }

    /** Primary fingerprints (uppercase) the user switched off for the agent. */
    fun excluded(context: Context): Set<String> =
        prefs(context).getStringSet(KEY_EXCLUDED, emptySet())?.toSet() ?: emptySet()

    fun setOffered(context: Context, fingerprint: String, offered: Boolean) {
        val fp = fingerprint.uppercase()
        val next = excluded(context).toMutableSet().apply { if (offered) remove(fp) else add(fp) }
        prefs(context).edit().putStringSet(KEY_EXCLUDED, next).commit()
    }
}
