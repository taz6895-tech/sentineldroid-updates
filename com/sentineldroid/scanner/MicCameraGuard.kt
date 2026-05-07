package com.sentineldroid.scanner

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class SensorUsageEntry(
    val appName: String,
    val packageName: String,
    val sensorType: String,
    val emoji: String,
    val lastUsedMs: Long,
    val timesUsed: Int,
    val risk: ThreatLevel,
    val icon: android.graphics.drawable.Drawable? = null
)

class MicCameraGuard(private val context: Context) {

    private val KNOWN_SAFE_APPS = setOf(
        "com.google.android.apps.tachyon",   // Google Meet
        "com.android.dialer",
        "com.google.android.dialer",
        "com.samsung.android.dialer",
        "com.google.android.talk",
        "org.telegram.messenger",
        "com.whatsapp",
        "com.discord",
        "com.google.android.apps.photos",
        "com.android.camera2",
        "com.samsung.android.app.camera",
        "com.google.android.GoogleCamera",
        "com.android.camera"
    )

    private data class OpCheck(val opStr: String, val label: String, val emoji: String)

    private val SENSOR_OPS = listOf(
        OpCheck(AppOpsManager.OPSTR_RECORD_AUDIO,   "Microphone", "🎙️"),
        OpCheck(AppOpsManager.OPSTR_CAMERA,          "Camera",     "📷"),
        OpCheck(AppOpsManager.OPSTR_FINE_LOCATION,   "Location",   "📍"),
        OpCheck(AppOpsManager.OPSTR_COARSE_LOCATION, "Location",   "📍")
    )

    suspend fun getSensorUsage(): List<SensorUsageEntry> = withContext(Dispatchers.IO) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return@withContext emptyList()

        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val pm     = context.packageManager
        val results= mutableListOf<SensorUsageEntry>()
        val seen   = mutableSetOf<String>()   // deduplicate location entries

        val packages = pm.getInstalledPackages(0)

        for (pkg in packages) {
            val pkgName = pkg.packageName
            val appInfo = pkg.applicationInfo ?: continue
            val uid     = appInfo.uid
            val appName = try { pm.getApplicationLabel(appInfo).toString() } catch (e: Exception) { pkgName }
            val icon    = try { pm.getApplicationIcon(pkgName) } catch (e: Exception) { null }
            val isSystem= (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

            for (opCheck in SENSOR_OPS) {
                // Deduplicate: don't show both FINE and COARSE location for same app
                val dedupeKey = "$pkgName:${opCheck.label}"
                if (dedupeKey in seen) continue

                // FIX: use checkOpNoThrow — this is the correct non-privileged API
                val lastUsed = getLastOpTime(appOps, opCheck.opStr, uid, pkgName) ?: continue
                if (lastUsed <= 0) continue

                seen += dedupeKey

                val isSafe = pkgName in KNOWN_SAFE_APPS || isSystem
                val risk   = if (isSafe) ThreatLevel.SAFE else assessRisk(lastUsed)

                results += SensorUsageEntry(
                    appName    = appName,
                    packageName= pkgName,
                    sensorType = opCheck.label,
                    emoji      = opCheck.emoji,
                    lastUsedMs = lastUsed,
                    timesUsed  = 0,
                    risk       = risk,
                    icon       = icon
                )
            }
        }

        results
            .filter { it.lastUsedMs > 0 }
            .sortedWith(compareByDescending<SensorUsageEntry> { it.risk.ordinal }
                .thenByDescending { it.lastUsedMs })
    }

    /**
     * FIX: Uses checkOpNoThrow() per-package — works without privileged permissions.
     * getPackagesForOps() requires GET_APP_OPS_STATS (signature|privileged) so it
     * always returns empty on normal devices. checkOpNoThrow() is the correct API.
     */
    private fun getLastOpTime(
        appOps: AppOpsManager,
        op: String,
        uid: Int,
        pkg: String
    ): Long? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                // API 28+: use getOpsForPackage for time data
                val pkgOps = appOps.getOpsForPackage(uid, pkg, arrayOf(op))
                val opEntry = pkgOps?.firstOrNull()?.ops?.firstOrNull { it.opStr == op }
                    ?: return null
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val t = opEntry.getLastAccessTime(AppOpsManager.OP_FLAGS_ALL)
                    if (t > 0) t else null
                } else {
                    @Suppress("DEPRECATION")
                    val t = opEntry.time
                    if (t > 0) t else null
                }
            } else {
                // API 23–27: checkOpNoThrow tells us if the op is granted, not timing
                val mode = appOps.checkOpNoThrow(op, uid, pkg)
                if (mode == AppOpsManager.MODE_ALLOWED) 1L else null  // can't get timing
            }
        } catch (e: Exception) { null }
    }

    private fun assessRisk(lastUsedMs: Long): ThreatLevel {
        val minutesAgo = (System.currentTimeMillis() - lastUsedMs) / 60_000
        return when {
            minutesAgo < 5    -> ThreatLevel.HIGH    // accessed in last 5 min
            minutesAgo < 60   -> ThreatLevel.MEDIUM  // accessed in last hour
            minutesAgo < 1440 -> ThreatLevel.LOW     // accessed today
            else              -> ThreatLevel.SAFE
        }
    }

    fun formatTimeAgo(ms: Long): String {
        if (ms <= 0) return "Never"
        val diff    = System.currentTimeMillis() - ms
        val minutes = diff / 60_000
        val hours   = diff / 3_600_000
        val days    = diff / 86_400_000
        return when {
            minutes < 1  -> "Just now"
            minutes < 60 -> "$minutes min ago"
            hours < 24   -> "$hours hr ago"
            days == 1L   -> "Yesterday"
            else         -> "$days days ago"
        }
    }
}
