package com.sentineldroid.scanner

import android.content.Intent

enum class FixType {
    OPEN_SETTINGS,      // Deep-link to a Settings screen
    REVOKE_ADMIN,       // Open Device Admin settings
    UNINSTALL_APP,      // Open app info to uninstall
    NONE                // No automated fix available
}

data class VulnItem(
    val id: String,
    val title: String,
    val description: String,
    val detail: String,
    val severity: ThreatLevel,
    val fixLabel: String,
    val fixType: FixType,
    val fixIntent: Intent? = null,
    val fixPackage: String? = null,   // for UNINSTALL_APP / REVOKE_ADMIN
    var isFixed: Boolean = false
)

data class VirusItem(
    val appName: String,
    val packageName: String,
    val reason: String,
    val severity: ThreatLevel,
    val icon: android.graphics.drawable.Drawable? = null
)
