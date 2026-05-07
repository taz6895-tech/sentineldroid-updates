package com.sentineldroid.scanner

enum class ThreatLevel {
    SAFE, LOW, MEDIUM, HIGH, CRITICAL
}

data class ThreatItem(
    val appName: String,
    val packageName: String,
    val threatLevel: ThreatLevel,
    val description: String,
    val permissions: List<String> = emptyList(),
    val icon: android.graphics.drawable.Drawable? = null
)

data class NetworkThreat(
    val ssid: String,
    val threatLevel: ThreatLevel,
    val description: String,
    val details: List<String>
)

data class SecuritySummary(
    val score: Int,           // 0-100 (100 = safest)
    val highRiskApps: Int,
    val suspiciousApps: Int,
    val keyloggerRisk: Boolean,
    val networkSafe: Boolean,
    val locationTrackers: Int
)
