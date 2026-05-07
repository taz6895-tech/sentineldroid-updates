package com.sentineldroid.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.sentineldroid.MainActivity
import com.sentineldroid.R
import com.sentineldroid.scanner.AppScanner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Persistent foreground service that keeps SentinelDroid watching the device
 * after the user closes the app or reboots the phone.
 *
 * Behaviour:
 *  - Posts a low-priority sticky notification (required by Android 8+ to stay alive)
 *  - Runs a periodic light scan (apps + accessibility services) on a coroutine
 *  - Updates the notification text with the current threat snapshot
 *  - Survives app swipe-away via START_STICKY and a low-importance channel
 */
class SentinelMonitorService : Service() {

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private var monitorJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        createChannelIfNeeded()
        startForeground(NOTIFICATION_ID, buildNotification("SentinelDroid is watching your device", null))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (monitorJob?.isActive != true) {
            monitorJob = scope.launch { monitorLoop() }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        monitorJob?.cancel()
        scope.cancel()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // User swiped the app away — restart ourselves so monitoring stays on.
        val restart = Intent(applicationContext, SentinelMonitorService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            applicationContext.startForegroundService(restart)
        } else {
            applicationContext.startService(restart)
        }
        super.onTaskRemoved(rootIntent)
    }

    private suspend fun monitorLoop() {
        val scanner = AppScanner(applicationContext)
        while (scope.isActive) {
            val statusLine = try {
                val summary = scanner.buildSecuritySummary()
                val high = summary.highRiskApps
                val sus = summary.suspiciousApps
                when {
                    high > 0 -> "⚠ $high high-risk app(s) — tap to review"
                    summary.keyloggerRisk -> "⚠ Possible keylogger active — tap to review"
                    sus > 0  -> "$sus app(s) flagged for review"
                    else     -> "All clear — no threats detected"
                } to (high > 0 || summary.keyloggerRisk)
            } catch (t: Throwable) {
                "Monitoring active" to false
            }

            val (text, alert) = statusLine
            updateNotification(text, alert)

            delay(SCAN_INTERVAL_MS)
        }
    }

    private fun updateNotification(text: String, alert: Boolean) {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        mgr.notify(NOTIFICATION_ID, buildNotification(text, alert))
    }

    private fun buildNotification(text: String, alert: Boolean?): Notification {
        val tapIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        else PendingIntent.FLAG_UPDATE_CURRENT
        val pi = PendingIntent.getActivity(this, 0, tapIntent, flags)

        val channel = if (alert == true) CHANNEL_ALERT_ID else CHANNEL_STATUS_ID

        return NotificationCompat.Builder(this, channel)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("SentinelDroid")
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setPriority(
                if (alert == true) NotificationCompat.PRIORITY_DEFAULT
                else NotificationCompat.PRIORITY_MIN
            )
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(pi)
            .build()
    }

    private fun createChannelIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (mgr.getNotificationChannel(CHANNEL_STATUS_ID) == null) {
            val status = NotificationChannel(
                CHANNEL_STATUS_ID,
                "Background Monitoring",
                NotificationManager.IMPORTANCE_MIN
            ).apply {
                description = "Persistent low-priority status while SentinelDroid is watching."
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            }
            mgr.createNotificationChannel(status)
        }
        if (mgr.getNotificationChannel(CHANNEL_ALERT_ID) == null) {
            val alert = NotificationChannel(
                CHANNEL_ALERT_ID,
                "Threat Alerts",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Alerts when SentinelDroid finds a high-risk app or keylogger."
                setShowBadge(true)
            }
            mgr.createNotificationChannel(alert)
        }
    }

    companion object {
        const val NOTIFICATION_ID    = 53001
        const val CHANNEL_STATUS_ID  = "sentineldroid_status"
        const val CHANNEL_ALERT_ID   = "sentineldroid_alert"
        const val ACTION_STOP        = "com.sentineldroid.action.STOP_MONITOR"

        private const val SCAN_INTERVAL_MS = 30L * 60L * 1000L  // 30 min light rescan

        private const val PREFS = "sentineldroid_service"
        private const val KEY_ENABLED = "background_enabled"

        fun isEnabled(context: Context): Boolean =
            prefs(context).getBoolean(KEY_ENABLED, true)

        fun setEnabled(context: Context, enabled: Boolean) {
            prefs(context).edit().putBoolean(KEY_ENABLED, enabled).apply()
            if (enabled) start(context) else stop(context)
        }

        fun start(context: Context) {
            if (!isEnabled(context)) return
            val intent = Intent(context, SentinelMonitorService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, SentinelMonitorService::class.java).apply {
                action = ACTION_STOP
            }
            try { context.startService(intent) } catch (_: Exception) { }
            context.stopService(Intent(context, SentinelMonitorService::class.java))
        }

        private fun prefs(context: Context): SharedPreferences =
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }
}
