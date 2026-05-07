package com.sentineldroid.scanner

import android.content.Context
import android.content.SharedPreferences
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

data class WifiHistoryEntry(
    val ssid: String,
    val bssid: String,
    val signalStrength: Int,
    val capabilities: String,    // encryption type string
    val encryptionType: String,  // "Open", "WEP", "WPA2", "WPA3"
    val firstSeenMs: Long,
    val lastSeenMs: Long,
    val timesDetected: Int,
    val riskLevel: ThreatLevel,
    val riskReason: String
)

class WifiHistoryScanner(private val context: Context) {

    private val prefs: SharedPreferences by lazy {
        try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
            EncryptedSharedPreferences.create(
                context, "sentineldroid_wifihistory_enc", masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            context.getSharedPreferences("sentineldroid_wifihistory", Context.MODE_PRIVATE)
        }
    }

    // Known malicious / honeypot SSIDs
    private val SUSPICIOUS_SSIDS = setOf(
        "free wifi", "free internet", "free public wifi", "airport free wifi",
        "_nomap", "free", "public wifi", "wifi free", "free_wifi",
        "linksys", "netgear", "dlink", "default", "tp-link",
        "xfinitywifi", "attwifi", "google starbucks"
    )

    suspend fun scanAndRecord(): List<WifiHistoryEntry> = withContext(Dispatchers.IO) {
        val wm = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val scanResults: List<ScanResult> = try { wm.scanResults ?: emptyList() }
                                            catch (e: Exception) { emptyList() }

        val nowMs = System.currentTimeMillis()
        val stored = loadHistory().toMutableMap()

        for (result in scanResults) {
            val ssid = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                result.wifiSsid?.toString()?.removeSurrounding("\"") ?: continue
            else @Suppress("DEPRECATION") result.SSID?.removeSurrounding("\"") ?: continue

            if (ssid.isBlank()) continue
            val bssid = result.BSSID ?: ""
            val key   = "${ssid}|${bssid}"

            val existing = stored[key]
            stored[key] = JSONObject().apply {
                put("ssid",        ssid)
                put("bssid",       bssid)
                put("signal",      result.level)
                put("caps",        result.capabilities ?: "")
                put("firstSeen",   existing?.optLong("firstSeen") ?: nowMs)
                put("lastSeen",    nowMs)
                put("count",       (existing?.optInt("count") ?: 0) + 1)
            }
        }

        saveHistory(stored)
        buildEntries(stored.values.toList())
            .sortedByDescending { it.riskLevel.ordinal }
    }

    fun getFullHistory(): List<WifiHistoryEntry> {
        val stored = loadHistory()
        return buildEntries(stored.values.toList())
            .sortedByDescending { it.lastSeenMs }
    }

    fun clearHistory() = prefs.edit().remove("wifi_history").apply()

    private fun buildEntries(objects: List<JSONObject>): List<WifiHistoryEntry> {
        return objects.mapNotNull { obj ->
            try {
                val ssid  = obj.getString("ssid")
                val caps  = obj.optString("caps", "")
                val enc   = parseEncryption(caps)
                val (risk, reason) = assessRisk(ssid, enc, caps)

                WifiHistoryEntry(
                    ssid            = ssid,
                    bssid           = obj.optString("bssid", ""),
                    signalStrength  = obj.optInt("signal", -100),
                    capabilities    = caps,
                    encryptionType  = enc,
                    firstSeenMs     = obj.optLong("firstSeen", 0),
                    lastSeenMs      = obj.optLong("lastSeen", 0),
                    timesDetected   = obj.optInt("count", 1),
                    riskLevel       = risk,
                    riskReason      = reason
                )
            } catch (e: Exception) { null }
        }
    }

    private fun parseEncryption(caps: String): String {
        val c = caps.uppercase()
        return when {
            c.contains("WPA3") || c.contains("SAE") -> "WPA3"
            c.contains("WPA2") || c.contains("RSN") -> "WPA2"
            c.contains("WPA")                       -> "WPA"
            c.contains("WEP")                       -> "WEP"
            !c.contains("PSK") && !c.contains("EAP")-> "Open"
            else                                    -> "Unknown"
        }
    }

    private fun assessRisk(ssid: String, enc: String, caps: String): Pair<ThreatLevel, String> {
        val lower = ssid.lowercase()

        // Check for known suspicious SSID names
        if (SUSPICIOUS_SSIDS.any { lower == it || lower.contains(it) }) {
            return Pair(ThreatLevel.HIGH,
                "⚠️ Network name matches known honeypot or default router name")
        }

        // Check encryption
        return when (enc) {
            "Open"    -> Pair(ThreatLevel.HIGH,
                "🔴 Open network — no encryption, all traffic visible to nearby attackers")
            "WEP"     -> Pair(ThreatLevel.HIGH,
                "🔴 WEP encryption — crackable in minutes, functionally unencrypted")
            "WPA"     -> Pair(ThreatLevel.MEDIUM,
                "🟠 WPA (original) — vulnerable to dictionary attacks")
            "WPA2"    -> Pair(ThreatLevel.LOW,
                "🟡 WPA2 — acceptable but has known KRACK vulnerability")
            "WPA3"    -> Pair(ThreatLevel.SAFE,
                "✅ WPA3 — best available Wi-Fi security")
            else      -> Pair(ThreatLevel.LOW, "ℹ️ Encryption type unclear")
        }
    }

    private fun loadHistory(): MutableMap<String, JSONObject> {
        val json = prefs.getString("wifi_history", "{}") ?: "{}"
        return try {
            val obj = JSONObject(json)
            obj.keys().asSequence().associateWith { obj.getJSONObject(it) }.toMutableMap()
        } catch (e: Exception) { mutableMapOf() }
    }

    private fun saveHistory(map: Map<String, JSONObject>) {
        // Keep only the last 200 entries
        val trimmed = map.entries
            .sortedByDescending { it.value.optLong("lastSeen") }
            .take(200)
            .associate { it.key to it.value }

        val obj = JSONObject()
        trimmed.forEach { (k, v) -> obj.put(k, v) }
        prefs.edit().putString("wifi_history", obj.toString()).apply()
    }

    fun formatDate(ms: Long): String {
        if (ms == 0L) return "Unknown"
        val sdf = java.text.SimpleDateFormat("MMM d, yyyy", java.util.Locale.getDefault())
        return sdf.format(java.util.Date(ms))
    }
}
