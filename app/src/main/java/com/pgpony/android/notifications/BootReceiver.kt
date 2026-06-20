// BootReceiver.kt
// PGPony Android — Phase A12
//
// BroadcastReceiver for BOOT_COMPLETED. Android wipes all scheduled
// alarms during the boot sequence (security model: nothing from a
// previous session should be able to wake the device without
// re-establishing its claim to do so), so an app that wants
// persistent scheduled work has to re-schedule at boot.
//
// Behavior:
//   • Triggers on action android.intent.action.BOOT_COMPLETED
//   • Reads the "key_expiration_reminders" SharedPreferences flag
//   • If false, no-op
//   • If true, queues a coroutine to:
//       - fetch all keys from KeyRepository
//       - call KeyExpirationService.scheduleReminders with the result
//
// Receiver runtime budget on Android is ~10 seconds before the
// system kills the process. Because we have to hit the database
// (which Room may need to open from cold), we use goAsync() to
// get up to ~30 seconds. The work is still bounded — keyring is
// small (<100 keys typically), repository fetch is fast.
//
// Permission required: RECEIVE_BOOT_COMPLETED (declared in
// AndroidManifest.xml). The system grants this at install time —
// no runtime permission needed.

package com.pgpony.android.notifications

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.pgpony.android.PGPonyApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != "android.intent.action.QUICKBOOT_POWERON" &&
            intent.action != "com.htc.intent.action.QUICKBOOT_POWERON"
        ) {
            // QUICKBOOT_POWERON variants exist on some OEM ROMs (Huawei,
            // HTC) — receive them too so users on those devices don't
            // silently lose reminders after a fast-boot.
            return
        }

        val prefs = context.getSharedPreferences("pgpony_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("key_expiration_reminders", false)) return

        // goAsync extends our runtime budget. PendingResult.finish()
        // must be called when work completes — wrapped in try/finally
        // so a thrown exception doesn't leave the receiver hung.
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Defensive — channel might not exist if the app
                // process hasn't run yet (rare: Application.onCreate
                // normally fires before receivers do, but BootReceiver
                // can race). Idempotent so calling here is safe.
                KeyExpirationService.createNotificationChannel(context)
                val keys = PGPonyApp.instance.keyRepository.getAllKeys()
                KeyExpirationService.scheduleReminders(context, keys)
            } catch (e: Exception) {
                // best-effort — alarms will re-schedule on next launch
                // via PGPonyApp.onCreate's own re-schedule pass
            } finally {
                pending.finish()
            }
        }
    }
}
