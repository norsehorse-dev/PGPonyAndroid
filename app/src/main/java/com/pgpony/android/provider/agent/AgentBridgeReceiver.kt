// AgentBridgeReceiver.kt
// PGPony Android, 4.6.0 (item 16b): receives sshpony-agent's broadcast
// (one per ssh connection) and starts AgentBridgeService with the port to call
// back. Exported so Termux can reach it; the pairing handshake in the service
// decides whether the caller is served (see AgentBridge).

package com.pgpony.android.provider.agent

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.pgpony.android.R

class AgentBridgeReceiver : BroadcastReceiver() {

    companion object {
        private const val NOTICE_ID = 7102
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.getIntExtra(AgentBridge.EXTRA_PROTOCOL, -1) != AgentBridge.PROTOCOL) return
        val port = intent.getIntExtra(AgentBridge.EXTRA_PORT, -1)
        if (port !in 1..65535) return
        if (!AgentBridgePrefs.isEnabled(context) || !AgentBridgePrefs.isPaired(context)) {
            notice(
                context,
                context.getString(R.string.agent_notice_off_title),
                context.getString(R.string.agent_notice_off_text),
                context.packageManager.getLaunchIntentForPackage(context.packageName)
            )
            return
        }
        val service = Intent(context, AgentBridgeService::class.java).putExtra(AgentBridge.EXTRA_PORT, port)
        try {
            ContextCompat.startForegroundService(context, service)
        } catch (e: Exception) {
            // Android 12+: a background app may start a foreground service only
            // when it is exempt from battery optimization.
            Log.w("AgentBridge", "could not start the bridge: ${e.message}")
            notice(
                context,
                context.getString(R.string.agent_notice_background_title),
                context.getString(R.string.agent_notice_background_text),
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(android.net.Uri.parse("package:${context.packageName}"))
            )
        }
    }

    private fun notice(context: Context, title: String, text: String, target: Intent?) {
        AgentBridgeService.createChannels(context)
        val pi = target?.let {
            PendingIntent.getActivity(
                context, NOTICE_ID, it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        }
        val n = NotificationCompat.Builder(context, AgentBridgeService.CHANNEL_PROMPTS)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .apply { if (pi != null) setContentIntent(pi) }
            .build()
        try {
            NotificationManagerCompat.from(context).notify(NOTICE_ID, n)
        } catch (_: SecurityException) {
        }
    }
}
