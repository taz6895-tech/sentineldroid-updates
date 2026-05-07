package com.sentineldroid.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

enum class PrivacyCategory(val label: String, val emoji: String) {
    LOCATION("Location Tracking", "📍"),
    MICROPHONE("Microphone Access", "🎙️"),
    CAMERA("Camera Access", "📷"),
    CONTACTS("Contacts & Calls", "📞"),
    MESSAGES("Messages & SMS", "💬"),
    STORAGE("Files & Storage", "📁"),
    SENSORS("Sensors & Motion", "📡"),
    IDENTITY("Phone Identity", "🪪"),
    BACKGROUND("Background Activity", "⚙️"),
    NETWORK("Network & Internet", "🌐")
}

data class PermissionEntry(
    val appName: String,
    val packageName: String,
    val permission: String,
    val permissionLabel: String,
    val category: PrivacyCategory,
    val riskLevel: ThreatLevel,
    val icon: android.graphics.drawable.Drawable? = null
)

data class PrivacyAuditResult(
    val byCategory: Map<PrivacyCategory, List<PermissionEntry>>,
    val totalAppsWithSensitiveAccess: Int,
    val mostInvasiveApp: Pair<String, Int>?  // appName to permission count
)

class PrivacyAuditScanner(private val context: Context) {

    private val permissionMap = mapOf(
        // Location
        "android.permission.ACCESS_FINE_LOCATION" to Pair(PrivacyCategory.LOCATION, "Precise GPS Location"),
        "android.permission.ACCESS_COARSE_LOCATION" to Pair(PrivacyCategory.LOCATION, "Approximate Location"),
        "android.permission.ACCESS_BACKGROUND_LOCATION" to Pair(PrivacyCategory.LOCATION, "Background Location (always-on)"),
        // Microphone
        "android.permission.RECORD_AUDIO" to Pair(PrivacyCategory.MICROPHONE, "Record Audio / Microphone"),
        "android.permission.CAPTURE_AUDIO_OUTPUT" to Pair(PrivacyCategory.MICROPHONE, "Capture System Audio"),
        // Camera
        "android.permission.CAMERA" to Pair(PrivacyCategory.CAMERA, "Camera"),
        "android.permission.CAPTURE_VIDEO_OUTPUT" to Pair(PrivacyCategory.CAMERA, "Capture Screen Video"),
        // Contacts & Calls
        "android.permission.READ_CONTACTS" to Pair(PrivacyCategory.CONTACTS, "Read Contacts"),
        "android.permission.WRITE_CONTACTS" to Pair(PrivacyCategory.CONTACTS, "Modify Contacts"),
        "android.permission.READ_CALL_LOG" to Pair(PrivacyCategory.CONTACTS, "Read Call History"),
        "android.permission.WRITE_CALL_LOG" to Pair(PrivacyCategory.CONTACTS, "Modify Call History"),
        "android.permission.PROCESS_OUTGOING_CALLS" to Pair(PrivacyCategory.CONTACTS, "Intercept Outgoing Calls"),
        "android.permission.ANSWER_PHONE_CALLS" to Pair(PrivacyCategory.CONTACTS, "Answer Phone Calls"),
        // Messages
        "android.permission.READ_SMS" to Pair(PrivacyCategory.MESSAGES, "Read SMS Messages"),
        "android.permission.SEND_SMS" to Pair(PrivacyCategory.MESSAGES, "Send SMS Messages"),
        "android.permission.RECEIVE_SMS" to Pair(PrivacyCategory.MESSAGES, "Receive / Intercept SMS"),
        "android.permission.READ_MMS" to Pair(PrivacyCategory.MESSAGES, "Read MMS Messages"),
        // Storage
        "android.permission.READ_EXTERNAL_STORAGE" to Pair(PrivacyCategory.STORAGE, "Read Files & Photos"),
        "android.permission.WRITE_EXTERNAL_STORAGE" to Pair(PrivacyCategory.STORAGE, "Write/Modify Files"),
        "android.permission.MANAGE_EXTERNAL_STORAGE" to Pair(PrivacyCategory.STORAGE, "Full File System Access"),
        "android.permission.READ_MEDIA_IMAGES" to Pair(PrivacyCategory.STORAGE, "Access Photos"),
        "android.permission.READ_MEDIA_VIDEO" to Pair(PrivacyCategory.STORAGE, "Access Videos"),
        "android.permission.READ_MEDIA_AUDIO" to Pair(PrivacyCategory.STORAGE, "Access Audio Files"),
        // Identity
        "android.permission.READ_PHONE_STATE" to Pair(PrivacyCategory.IDENTITY, "Read Phone Identity (IMEI)"),
        "android.permission.READ_PHONE_NUMBERS" to Pair(PrivacyCategory.IDENTITY, "Read Phone Number"),
        "android.permission.USE_BIOMETRIC" to Pair(PrivacyCategory.IDENTITY, "Use Biometric/Fingerprint"),
        "android.permission.USE_FINGERPRINT" to Pair(PrivacyCategory.IDENTITY, "Use Fingerprint Sensor"),
        "android.permission.GET_ACCOUNTS" to Pair(PrivacyCategory.IDENTITY, "Read Google/Device Accounts"),
        // Background
        "android.permission.RECEIVE_BOOT_COMPLETED" to Pair(PrivacyCategory.BACKGROUND, "Auto-Start on Boot"),
        "android.permission.FOREGROUND_SERVICE" to Pair(PrivacyCategory.BACKGROUND, "Run Persistent Background Service"),
        "android.permission.SCHEDULE_EXACT_ALARM" to Pair(PrivacyCategory.BACKGROUND, "Schedule Exact Alarms (wake device)"),
        "android.permission.REQUEST_INSTALL_PACKAGES" to Pair(PrivacyCategory.BACKGROUND, "Install Other Apps"),
        "android.permission.SYSTEM_ALERT_WINDOW" to Pair(PrivacyCategory.BACKGROUND, "Draw Over Other Apps"),
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to Pair(PrivacyCategory.BACKGROUND, "Full Accessibility Service"),
        // Sensors
        "android.permission.BODY_SENSORS" to Pair(PrivacyCategory.SENSORS, "Body/Health Sensors"),
        "android.permission.ACTIVITY_RECOGNITION" to Pair(PrivacyCategory.SENSORS, "Physical Activity Recognition"),
        "android.permission.HIGH_SAMPLING_RATE_SENSORS" to Pair(PrivacyCategory.SENSORS, "High-Rate Sensor Data"),
        // Network
        "android.permission.INTERNET" to Pair(PrivacyCategory.NETWORK, "Internet Access"),
        "android.permission.ACCESS_WIFI_STATE" to Pair(PrivacyCategory.NETWORK, "Read Wi-Fi Networks"),
        "android.permission.CHANGE_WIFI_STATE" to Pair(PrivacyCategory.NETWORK, "Change Wi-Fi Settings"),
        "android.permission.ACCESS_NETWORK_STATE" to Pair(PrivacyCategory.NETWORK, "Read Network State"),
        "android.permission.CHANGE_NETWORK_STATE" to Pair(PrivacyCategory.NETWORK, "Change Network State"),
        "android.permission.NFC" to Pair(PrivacyCategory.NETWORK, "NFC Access"),
        "android.permission.BLUETOOTH" to Pair(PrivacyCategory.NETWORK, "Bluetooth Access"),
        "android.permission.BLUETOOTH_SCAN" to Pair(PrivacyCategory.NETWORK, "Scan for Bluetooth Devices"),
        "android.permission.BLUETOOTH_CONNECT" to Pair(PrivacyCategory.NETWORK, "Connect to Bluetooth Devices")
    )

    // Higher-risk permissions that warrant extra attention
    private val HIGH_RISK_PERMS = setOf(
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW"
    )

    private val SAFE_PREFIXES = setOf(
        "com.google.", "com.android.", "com.samsung.", "android."
    )

    suspend fun audit(): PrivacyAuditResult = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val allEntries = mutableListOf<PermissionEntry>()
        val appPermCounts = mutableMapOf<String, Int>()

        for (pkg in packages) {
            val pkgName = pkg.packageName
            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (isSystem && SAFE_PREFIXES.any { pkgName.startsWith(it) }) continue

            val requested = pkg.requestedPermissions ?: continue
            val flags = pkg.requestedPermissionsFlags ?: continue
            val appName = try { pm.getApplicationLabel(appInfo).toString() } catch (e: Exception) { pkgName }
            val icon = try { pm.getApplicationIcon(pkgName) } catch (e: Exception) { null }

            var sensitiveCount = 0

            for (i in requested.indices) {
                val perm = requested[i]
                val isGranted = (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                if (!isGranted) continue

                val mapping = permissionMap[perm] ?: continue
                val (category, label) = mapping

                // Skip low-sensitivity network perms for cleaner output unless it's a non-system app with lots
                if (category == PrivacyCategory.NETWORK &&
                    (perm == "android.permission.INTERNET" || perm == "android.permission.ACCESS_NETWORK_STATE")) continue

                val risk = when {
                    perm in HIGH_RISK_PERMS -> ThreatLevel.HIGH
                    category == PrivacyCategory.LOCATION || category == PrivacyCategory.MICROPHONE
                        || category == PrivacyCategory.CAMERA -> ThreatLevel.MEDIUM
                    else -> ThreatLevel.LOW
                }

                allEntries.add(PermissionEntry(appName, pkgName, perm, label, category, risk, icon))
                sensitiveCount++
            }

            if (sensitiveCount > 0) appPermCounts[appName] = sensitiveCount
        }

        // Group by category, sort each group by risk
        val byCategory = allEntries
            .groupBy { it.category }
            .mapValues { (_, v) -> v.sortedByDescending { it.riskLevel.ordinal }.distinctBy { it.packageName + it.permission } }
            .toSortedMap(compareBy { it.ordinal })

        val mostInvasive = appPermCounts.maxByOrNull { it.value }?.toPair()
        val totalApps = appPermCounts.size

        PrivacyAuditResult(byCategory, totalApps, mostInvasive)
    }
}
