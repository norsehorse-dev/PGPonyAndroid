// ProviderCacheClearReceiver.kt
// PGPony Android, #2.1
//
// ProviderPassphraseCache is a per-process in-memory object. Once the OpenPGP
// provider (PGPonyOpenPgpService and its provider activities) runs in the
// dedicated :remote_api process, the main process can no longer reach the
// passphrases cached there. This receiver is registered ONLY in the provider
// process (PGPonyApp.onCreate) and applies clear requests the main process
// fires when the user clears the cache or when a key changes. Device lock is
// handled separately: the provider process also registers its own
// SessionLockReceiver so it self-clears on lock even if the main process was
// killed by an aggressive ROM, which is the exact condition #2.1 is about.

package com.pgpony.android.provider

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.pgpony.android.PGPonyApp

class ProviderCacheClearReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_CLEAR) return
        val ids = intent.getLongArrayExtra(EXTRA_KEY_IDS)
        if (ids == null) {
            ProviderPassphraseCache.clearAll()
        } else {
            ProviderPassphraseCache.clearKeys(ids.toList())
        }
    }

    companion object {
        const val ACTION_CLEAR =
            "com.pgpony.android.provider.action.CLEAR_PASSPHRASE_CACHE"
        const val EXTRA_KEY_IDS =
            "com.pgpony.android.provider.extra.KEY_IDS"

        // Package-scoped so it never leaves the app; the receiver is
        // RECEIVER_NOT_EXPORTED, so only our own UID can deliver it. A no-op
        // when the provider process is not running: there is no dynamic
        // receiver to catch it and no manifest receiver to start one, so a
        // dead provider process (which holds no cache) is simply skipped.
        private fun send(intent: Intent) {
            val ctx = PGPonyApp.instance.applicationContext
            ctx.sendBroadcast(intent.setPackage(ctx.packageName))
        }

        fun requestClearAll() {
            send(Intent(ACTION_CLEAR))
        }

        fun requestClearKeys(keyIds: Collection<Long>) {
            send(Intent(ACTION_CLEAR).putExtra(EXTRA_KEY_IDS, keyIds.toLongArray()))
        }
    }
}
