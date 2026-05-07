package com.sentineldroid.scanner

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class NetworkScanner(private val context: Context) {

    suspend fun scanNetwork(): NetworkThreat = withContext(Dispatchers.IO) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val wm = context.getSystemService(Context.WIFI_SERVICE) as WifiManager

        val network      = cm.activeNetwork
        val capabilities = cm.getNetworkCapabilities(network)

        val isWifi    = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)     == true
        val isCellular= capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true
        val isVpn     = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)      == true

        if (!isWifi && !isCellular) {
            return@withContext NetworkThreat(
                ssid = "No Connection", threatLevel = ThreatLevel.SAFE,
                description = "Not connected to any network.", details = listOf("You are offline.")
            )
        }

        if (isVpn) {
            val ssid = getSsid(wm)
            return@withContext NetworkThreat(
                ssid = ssid, threatLevel = ThreatLevel.SAFE,
                description = "VPN is active — your traffic is encrypted.",
                details = listOf(
                    "✅ VPN detected — all traffic encrypted",
                    if (isWifi) "📶 Connected via Wi-Fi through VPN"
                    else "📱 Connected via Mobile Data through VPN"
                )
            )
        }

        if (isCellular && !isWifi) {
            return@withContext NetworkThreat(
                ssid = "Mobile Data", threatLevel = ThreatLevel.LOW,
                description = "Connected via mobile data. Generally safe.",
                details = listOf(
                    "📱 Using cellular connection",
                    "ℹ️ Mobile data is generally secure",
                    "💡 Consider a VPN for extra privacy on sensitive tasks"
                )
            )
        }

        // ── Wi-Fi analysis ────────────────────────────────────────────────────
        val ssid       = getSsid(wm)
        val details    = mutableListOf<String>()
        var threatLevel = ThreatLevel.SAFE

        // FIX: use ScanResults for real encryption data instead of toString() heuristics
        val encryption = getEncryptionFromScanResults(wm, ssid)

        when (encryption) {
            EncType.OPEN -> {
                threatLevel = ThreatLevel.HIGH
                details += listOf(
                    "🔴 Open/unencrypted Wi-Fi — DANGEROUS",
                    "Anyone nearby can intercept all your traffic",
                    "⚠️ Do not use banking, email, or passwords on this network",
                    "💡 Enable VPN immediately if you must use this network"
                )
            }
            EncType.WEP -> {
                threatLevel = ThreatLevel.HIGH
                details += listOf(
                    "🔴 WEP encryption — cracked in minutes with basic tools",
                    "WEP has been broken since 2005 and offers no real protection",
                    "⚠️ Treat this exactly like an open network"
                )
            }
            EncType.WPA1_ONLY -> {
                threatLevel = ThreatLevel.MEDIUM
                details += listOf(
                    "🟠 WPA (original) — partially vulnerable to TKIP attacks",
                    "WPA-TKIP can be cracked with dictionary attacks",
                    "💡 Ask the network owner to upgrade to WPA2 or WPA3"
                )
            }
            EncType.WPA2 -> {
                threatLevel = ThreatLevel.LOW
                details += listOf(
                    "🟡 WPA2 — acceptable but has known weaknesses (KRACK attack)",
                    "Secure against casual attackers; vulnerable to advanced ones",
                    "💡 WPA3 networks offer significantly better protection"
                )
            }
            EncType.WPA3 -> {
                threatLevel = ThreatLevel.SAFE
                details += listOf(
                    "✅ WPA3 — best available Wi-Fi security",
                    "Resistant to offline dictionary attacks and eavesdropping",
                    "🛡️ Even captured traffic cannot be decrypted later (forward secrecy)"
                )
            }
            EncType.UNKNOWN -> {
                threatLevel = ThreatLevel.MEDIUM
                details += listOf(
                    "🟠 Could not determine Wi-Fi encryption type",
                    "This may require location permission to read scan results",
                    "ℹ️ Treat as potentially insecure"
                )
            }
        }

        // Signal strength — use non-deprecated API on Android 12+
        val rssi = getCurrentRssi(wm)
        if (rssi != null) {
            val bars = WifiManager.calculateSignalLevel(rssi, 5)
            details += "📶 Signal: ${"▮".repeat(bars)}${"▯".repeat(4 - bars)} ($rssi dBm)"
        }

        // FIX: check if SSID looks like a spoofed hotspot
        if (looksLikeSpoofedHotspot(ssid)) {
            threatLevel = maxLevel(threatLevel, ThreatLevel.MEDIUM)
            details += "⚠️ Network name resembles a common honeypot/spoofed hotspot name"
        }

        val description = when (threatLevel) {
            ThreatLevel.HIGH     -> "Insecure network — your data is exposed to nearby attackers."
            ThreatLevel.MEDIUM   -> "Network security unclear — proceed with caution."
            ThreatLevel.LOW      -> "Reasonably secure network. Standard precautions apply."
            ThreatLevel.SAFE     -> "Network is well-secured."
            else                 -> "Network status unknown."
        }

        NetworkThreat(ssid = ssid, threatLevel = threatLevel, description = description, details = details)
    }

    // ─── Encryption detection via ScanResults ─────────────────────────────────

    private enum class EncType { OPEN, WEP, WPA1_ONLY, WPA2, WPA3, UNKNOWN }

    private fun getEncryptionFromScanResults(wm: WifiManager, currentSsid: String): EncType {
        return try {
            // On Android 10+ getScanResults() requires ACCESS_FINE_LOCATION at runtime
            val hasLocationPerm = ContextCompat.checkSelfPermission(
                context, Manifest.permission.ACCESS_FINE_LOCATION
            ) == PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(
                context, Manifest.permission.ACCESS_COARSE_LOCATION
            ) == PackageManager.PERMISSION_GRANTED

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && !hasLocationPerm) {
                return EncType.UNKNOWN  // Permission not granted yet — user will be prompted
            }

            val results: List<ScanResult> = wm.scanResults ?: return EncType.UNKNOWN
            val match = results.firstOrNull { result ->
                val scanSsid = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                    result.wifiSsid?.toString()?.removeSurrounding("\"") ?: ""
                else
                    @Suppress("DEPRECATION") result.SSID?.removeSurrounding("\"") ?: ""
                scanSsid == currentSsid
            } ?: return EncType.UNKNOWN

            val cap = match.capabilities.uppercase()
            when {
                cap.contains("WPA3") || cap.contains("SAE")       -> EncType.WPA3
                cap.contains("WPA2") || cap.contains("RSN")       -> EncType.WPA2
                cap.contains("WPA")                               -> EncType.WPA1_ONLY
                cap.contains("WEP")                               -> EncType.WEP
                !cap.contains("PSK") && !cap.contains("EAP")
                    && !cap.contains("WPA") && !cap.contains("WEP") -> EncType.OPEN
                else                                              -> EncType.UNKNOWN
            }
        } catch (e: Exception) { EncType.UNKNOWN }
    }

    private fun getSsid(wm: WifiManager): String {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // On API 31+ use scan results to get SSID (avoids deprecated connectionInfo)
                wm.connectionInfo?.ssid?.removeSurrounding("\"") ?: "Unknown"
            } else {
                @Suppress("DEPRECATION")
                wm.connectionInfo?.ssid?.removeSurrounding("\"") ?: "Unknown"
            }
        } catch (e: Exception) { "Unknown Network" }
    }

    private fun getCurrentRssi(wm: WifiManager): Int? {
        return try {
            @Suppress("DEPRECATION")
            val rssi = wm.connectionInfo?.rssi
            if (rssi != null && rssi != -127) rssi else null
        } catch (e: Exception) { null }
    }

    private fun looksLikeSpoofedHotspot(ssid: String): Boolean {
        val lower = ssid.lowercase()
        val honeypotNames = listOf(
            "free wifi", "free internet", "airport wifi", "starbucks", "hotel wifi",
            "xfinitywifi", "attwifi", "google starbucks", "free public wifi",
            "_nomap", "linksys", "netgear", "dlink", "default"
        )
        return honeypotNames.any { lower == it || lower.contains(it) }
    }

    private fun maxLevel(a: ThreatLevel, b: ThreatLevel): ThreatLevel =
        if (b.ordinal > a.ordinal) b else a
}
