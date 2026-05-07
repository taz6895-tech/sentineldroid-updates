package com.sentineldroid.scanner

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.view.accessibility.AccessibilityManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class AppScanner(private val context: Context) {

    // Dangerous permissions that spyware/stalkerware typically request
    private val SPYWARE_PERMISSIONS = mapOf(
        "android.permission.READ_SMS" to "Read your SMS messages",
        "android.permission.RECEIVE_SMS" to "Intercept incoming SMS",
        "android.permission.READ_CALL_LOG" to "Read your call history",
        "android.permission.PROCESS_OUTGOING_CALLS" to "Intercept outgoing calls",
        "android.permission.RECORD_AUDIO" to "Record microphone/calls",
        "android.permission.CAMERA" to "Access camera",
        "android.permission.ACCESS_FINE_LOCATION" to "Precise GPS location",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "Background GPS tracking",
        "android.permission.READ_CONTACTS" to "Read your contacts",
        "android.permission.READ_CALL_LOG" to "Access call logs",
        "android.permission.ACCESS_COARSE_LOCATION" to "Approximate location",
        "android.permission.RECEIVE_BOOT_COMPLETED" to "Auto-start on boot",
        "android.permission.FOREGROUND_SERVICE" to "Run persistently in background",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "Install apps silently",
        "android.permission.WRITE_SECURE_SETTINGS" to "Modify system settings",
        "android.permission.READ_PHONE_STATE" to "Read phone identity/IMEI",
        "android.permission.READ_PHONE_NUMBERS" to "Read your phone number"
    )

    // High-risk combos: if an app has ALL permissions in a group, it's very suspicious
    private val SPYWARE_COMBOS = listOf(
        listOf("android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION", "android.permission.RECEIVE_BOOT_COMPLETED"),
        listOf("android.permission.CAMERA", "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.FOREGROUND_SERVICE"),
        listOf("android.permission.READ_SMS", "android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG"),
    )

    // Known safe system packages to exclude
    private val SYSTEM_ALLOWLIST = setOf(
        "com.android.phone", "com.android.systemui", "com.android.settings",
        "com.google.android.gms", "com.google.android.gsf", "com.android.dialer",
        "com.android.contacts", "com.google.android.apps.messaging", "com.android.camera2"
    )

    suspend fun scanAllApps(): List<ThreatItem> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val threats = mutableListOf<ThreatItem>()

        val packages: List<PackageInfo> = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        for (pkg in packages) {
            if (pkg.packageName in SYSTEM_ALLOWLIST) continue

            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

            val grantedDangerous = getGrantedDangerousPermissions(pm, pkg)
            if (grantedDangerous.isEmpty()) continue

            val threatLevel = assessThreatLevel(pkg.packageName, grantedDangerous, isSystem)
            if (threatLevel == ThreatLevel.SAFE) continue

            val appName = try { pm.getApplicationLabel(appInfo).toString() } catch (e: Exception) { pkg.packageName }
            val icon = try { pm.getApplicationIcon(pkg.packageName) } catch (e: Exception) { null }
            val description = buildThreatDescription(grantedDangerous, isSystem, threatLevel)

            threats.add(ThreatItem(
                appName = appName,
                packageName = pkg.packageName,
                threatLevel = threatLevel,
                description = description,
                permissions = grantedDangerous.map { SPYWARE_PERMISSIONS[it] ?: it },
                icon = icon
            ))
        }

        threats.sortedByDescending { it.threatLevel.ordinal }
    }

    private fun getGrantedDangerousPermissions(pm: PackageManager, pkg: PackageInfo): List<String> {
        val requested = pkg.requestedPermissions ?: return emptyList()
        val flags = pkg.requestedPermissionsFlags ?: return emptyList()

        return requested.filterIndexed { i, perm ->
            perm in SPYWARE_PERMISSIONS &&
            (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        }
    }

    private fun assessThreatLevel(packageName: String, permissions: List<String>, isSystem: Boolean): ThreatLevel {
        val count = permissions.size

        // Check for dangerous combos (classic spyware pattern)
        val hasSpywareCombo = SPYWARE_COMBOS.any { combo -> combo.all { it in permissions } }
        if (hasSpywareCombo) return if (isSystem) ThreatLevel.MEDIUM else ThreatLevel.CRITICAL

        // Background location + microphone + boot = stalkerware
        val hasBackgroundLocation = "android.permission.ACCESS_BACKGROUND_LOCATION" in permissions
        val hasMic = "android.permission.RECORD_AUDIO" in permissions
        val hasBootReceiver = "android.permission.RECEIVE_BOOT_COMPLETED" in permissions
        val hasCamera = "android.permission.CAMERA" in permissions

        if (!isSystem) {
            if (hasBackgroundLocation && hasMic) return ThreatLevel.HIGH
            if (hasBackgroundLocation && hasCamera) return ThreatLevel.HIGH
            if (hasMic && hasBootReceiver && count >= 4) return ThreatLevel.HIGH
        }

        val hasSmsRead = "android.permission.READ_SMS" in permissions
        val hasCallLog = "android.permission.READ_CALL_LOG" in permissions
        val hasFineLocation = "android.permission.ACCESS_FINE_LOCATION" in permissions

        if (!isSystem && hasSmsRead && hasCallLog) return ThreatLevel.HIGH
        if (count >= 6 && hasFineLocation) return if (isSystem) ThreatLevel.LOW else ThreatLevel.MEDIUM
        if (count >= 4) return ThreatLevel.LOW
        if (count >= 2) return ThreatLevel.LOW

        return ThreatLevel.SAFE
    }

    private fun buildThreatDescription(permissions: List<String>, isSystem: Boolean, level: ThreatLevel): String {
        val prefix = if (isSystem) "System app — " else ""
        return when (level) {
            ThreatLevel.CRITICAL -> "${prefix}Has multiple spyware-like permission combinations. Strongly review this app."
            ThreatLevel.HIGH -> "${prefix}Has dangerous permission combos typical of stalkerware or trackers."
            ThreatLevel.MEDIUM -> "${prefix}Has several sensitive permissions that could enable tracking."
            ThreatLevel.LOW -> "${prefix}Has some sensitive permissions. Review if you trust this app."
            ThreatLevel.SAFE -> "Safe"
        }
    }

    // ─── Keylogger / Accessibility Scanner ─────────────────────────────────────

    fun getAccessibilityThreats(): List<ThreatItem> {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val pm = context.packageManager
        val threats = mutableListOf<ThreatItem>()

        val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)

        for (service in enabledServices) {
            val resolveInfo = service.resolveInfo ?: continue
            val serviceInfo = resolveInfo.serviceInfo
            val pkgName = serviceInfo.packageName

            if (pkgName == context.packageName) continue // Skip ourselves

            val appName = try { pm.getApplicationLabel(pm.getApplicationInfo(pkgName, 0)).toString() }
            catch (e: Exception) { pkgName }

            val icon = try { pm.getApplicationIcon(pkgName) } catch (e: Exception) { null }

            val canReadText = service.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0
            val label = service.loadSummary(pm)?.toString() ?: ""

            val isKnownSafe = isKnownSafeAccessibilityApp(pkgName)
            val level = when {
                isKnownSafe -> ThreatLevel.LOW
                canReadText -> ThreatLevel.HIGH
                else -> ThreatLevel.MEDIUM
            }

            threats.add(ThreatItem(
                appName = appName,
                packageName = pkgName,
                threatLevel = level,
                description = buildAccessibilityDescription(canReadText, isKnownSafe, label),
                icon = icon
            ))
        }
        return threats
    }

    private fun isKnownSafeAccessibilityApp(pkg: String): Boolean {
        val safePrefixes = listOf(
            "com.google.android.marvin", "com.samsung.accessibility",
            "com.android.talkback", "com.google.android.accessibility",
            "com.samsung.android.app.talkback", "com.huawei.accessibility"
        )
        return safePrefixes.any { pkg.startsWith(it) }
    }

    private fun buildAccessibilityDescription(canReadText: Boolean, isKnownSafe: Boolean, label: String): String {
        return buildString {
            if (isKnownSafe) append("Known safe accessibility app. ")
            else {
                append("Accessibility service active. ")
                if (canReadText) append("⚠️ Can READ all text on your screen — keylogger risk! ")
                else append("Has screen interaction access. ")
            }
            if (label.isNotEmpty()) append("Purpose: $label")
        }
    }

    // ─── Device Admin Scanner ──────────────────────────────────────────────────

    fun getDeviceAdminThreats(): List<ThreatItem> {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val pm = context.packageManager
        val threats = mutableListOf<ThreatItem>()

        val admins = dpm.activeAdmins ?: return threats

        for (admin in admins) {
            val pkgName = admin.packageName
            val appName = try { pm.getApplicationLabel(pm.getApplicationInfo(pkgName, 0)).toString() }
            catch (e: Exception) { pkgName }
            val icon = try { pm.getApplicationIcon(pkgName) } catch (e: Exception) { null }

            val isKnownSafe = isKnownSafeAdminApp(pkgName)
            val level = if (isKnownSafe) ThreatLevel.LOW else ThreatLevel.HIGH

            threats.add(ThreatItem(
                appName = appName,
                packageName = pkgName,
                threatLevel = level,
                description = if (isKnownSafe)
                    "This is a known legitimate MDM/work profile app with device admin rights."
                else
                    "⚠️ This app has Device Administrator rights. Spyware uses this to prevent uninstallation!",
                icon = icon
            ))
        }
        return threats
    }

    private fun isKnownSafeAdminApp(pkg: String): Boolean {
        val safePrefixes = listOf(
            "com.google.android.apps.work", "com.android.managedprovisioning",
            "com.samsung.android.mdm", "com.microsoft.intune", "com.airwatch"
        )
        return safePrefixes.any { pkg.startsWith(it) }
    }

    // ─── Location Tracker Scanner ──────────────────────────────────────────────

    suspend fun getLocationTrackers(): List<ThreatItem> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val trackers = mutableListOf<ThreatItem>()
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        for (pkg in packages) {
            val requested = pkg.requestedPermissions ?: continue
            val flags = pkg.requestedPermissionsFlags ?: continue

            val hasBackground = requested.filterIndexed { i, perm ->
                perm == "android.permission.ACCESS_BACKGROUND_LOCATION" &&
                (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            }.isNotEmpty()

            val hasFine = requested.filterIndexed { i, perm ->
                perm == "android.permission.ACCESS_FINE_LOCATION" &&
                (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            }.isNotEmpty()

            if (!hasBackground && !hasFine) continue

            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val appName = try { pm.getApplicationLabel(appInfo).toString() } catch (e: Exception) { pkg.packageName }
            val icon = try { pm.getApplicationIcon(pkg.packageName) } catch (e: Exception) { null }

            val level = when {
                hasBackground && !isSystem -> ThreatLevel.HIGH
                hasBackground -> ThreatLevel.MEDIUM
                hasFine && !isSystem -> ThreatLevel.LOW
                else -> ThreatLevel.SAFE
            }

            if (level == ThreatLevel.SAFE) continue

            trackers.add(ThreatItem(
                appName = appName,
                packageName = pkg.packageName,
                threatLevel = level,
                description = if (hasBackground)
                    "Tracks your location in the background even when app is closed."
                else
                    "Has access to your precise GPS location.",
                icon = icon
            ))
        }
        trackers.sortedByDescending { it.threatLevel.ordinal }
    }

    // ─── Security Summary ──────────────────────────────────────────────────────

    suspend fun buildSecuritySummary(): SecuritySummary = withContext(Dispatchers.IO) {
        val allApps = scanAllApps()
        val accessibilityThreats = getAccessibilityThreats()
        val adminThreats = getDeviceAdminThreats()
        val locationTrackers = getLocationTrackers()

        val highRisk = allApps.count { it.threatLevel >= ThreatLevel.HIGH }
        val suspicious = allApps.count { it.threatLevel == ThreatLevel.MEDIUM }
        val keyloggerRisk = accessibilityThreats.any {
            it.threatLevel >= ThreatLevel.HIGH && !isKnownSafeAccessibilityApp(it.packageName)
        }

        var score = 100
        score -= highRisk * 15
        score -= suspicious * 5
        score -= adminThreats.count { it.threatLevel >= ThreatLevel.HIGH } * 10
        if (keyloggerRisk) score -= 20
        score -= locationTrackers.count { it.threatLevel == ThreatLevel.HIGH } * 8
        score = score.coerceIn(0, 100)

        SecuritySummary(
            score = score,
            highRiskApps = highRisk,
            suspiciousApps = suspicious,
            keyloggerRisk = keyloggerRisk,
            networkSafe = true, // set by NetworkScanner
            locationTrackers = locationTrackers.count { it.threatLevel >= ThreatLevel.HIGH }
        )
    }
}
