package com.sentineldroid.scanner

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.*

enum class LogEventType {
    SCAN_COMPLETE, THREAT_FOUND, VULN_FOUND, BREACH_DETECTED,
    NETWORK_ALERT, VIRUS_FOUND, FIX_APPLIED, APP_LOCK_AUTH
}

data class LogEvent(
    val id: String,
    val type: LogEventType,
    val title: String,
    val detail: String,
    val severity: ThreatLevel,
    val timestampMs: Long = System.currentTimeMillis()
) {
    val formattedTime: String get() {
        val sdf = SimpleDateFormat("MMM d, h:mm a", Locale.getDefault())
        return sdf.format(Date(timestampMs))
    }
}

/**
 * Security event log — stored in EncryptedSharedPreferences so that
 * breach notifications, threat names, and masked emails are not readable
 * from unencrypted storage even on rooted devices.
 */
class SecurityLogManager(context: Context) {

    private val prefs: SharedPreferences = buildEncryptedPrefs(context)
    private val MAX_EVENTS = 100

    fun log(event: LogEvent) {
        val events = getEvents().toMutableList()
        events.add(0, event)
        if (events.size > MAX_EVENTS) events.subList(MAX_EVENTS, events.size).clear()
        saveEvents(events)
    }

    fun logScanComplete(threatsFound: Int, score: Int) = log(LogEvent(
        id = UUID.randomUUID().toString(),
        type = LogEventType.SCAN_COMPLETE,
        title = "Full Scan Completed",
        detail = "Security score: $score/100 — $threatsFound threat(s) found",
        severity = when {
            threatsFound == 0 -> ThreatLevel.SAFE
            score < 60        -> ThreatLevel.HIGH
            else              -> ThreatLevel.MEDIUM
        }
    ))

    fun logThreatFound(appName: String, level: ThreatLevel, description: String) = log(LogEvent(
        id = UUID.randomUUID().toString(),
        type = LogEventType.THREAT_FOUND,
        title = "Threat: $appName",
        detail = description,
        severity = level
    ))

    fun logBreachDetected(email: String, breachCount: Int) {
        // Mask email before storing — "user@gmail.com" → "u***@gmail.com"
        val masked = maskEmail(email)
        log(LogEvent(
            id = UUID.randomUUID().toString(),
            type = LogEventType.BREACH_DETECTED,
            title = "Data Breach Found",
            detail = "$masked found in $breachCount breach(es) — change passwords immediately",
            severity = if (breachCount > 3) ThreatLevel.CRITICAL else ThreatLevel.HIGH
        ))
    }

    fun logNetworkAlert(ssid: String, issue: String) = log(LogEvent(
        id = UUID.randomUUID().toString(),
        type = LogEventType.NETWORK_ALERT,
        title = "Network Alert: $ssid",
        detail = issue,
        severity = ThreatLevel.HIGH
    ))

    fun logVulnFound(title: String, severity: ThreatLevel) = log(LogEvent(
        id = UUID.randomUUID().toString(),
        type = LogEventType.VULN_FOUND,
        title = "Vulnerability: $title",
        detail = "System vulnerability detected",
        severity = severity
    ))

    fun logFixApplied(what: String) = log(LogEvent(
        id = UUID.randomUUID().toString(),
        type = LogEventType.FIX_APPLIED,
        title = "Fix Applied",
        detail = what,
        severity = ThreatLevel.SAFE
    ))

    fun getEvents(): List<LogEvent> {
        val json = prefs.getString("events", "[]") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).mapNotNull { i ->
                try {
                    val obj = arr.getJSONObject(i)
                    LogEvent(
                        id          = obj.getString("id"),
                        type        = LogEventType.valueOf(obj.getString("type")),
                        title       = obj.getString("title"),
                        detail      = obj.getString("detail"),
                        severity    = ThreatLevel.valueOf(obj.getString("severity")),
                        timestampMs = obj.getLong("ts")
                    )
                } catch (e: Exception) { null }
            }
        } catch (e: Exception) { emptyList() }
    }

    fun clearLog() = prefs.edit().remove("events").apply()

    private fun saveEvents(events: List<LogEvent>) {
        val arr = JSONArray()
        for (e in events) {
            JSONObject().apply {
                put("id",       e.id)
                put("type",     e.type.name)
                put("title",    e.title)
                put("detail",   e.detail)
                put("severity", e.severity.name)
                put("ts",       e.timestampMs)
            }.also { arr.put(it) }
        }
        prefs.edit().putString("events", arr.toString()).apply()
    }

    private fun maskEmail(email: String): String {
        val atIdx = email.indexOf('@')
        if (atIdx < 1) return "***"
        val local  = email.substring(0, atIdx)
        val domain = email.substring(atIdx)
        val mask   = when {
            local.length <= 1 -> "*"
            local.length <= 3 -> local[0] + "***"
            else              -> local[0] + "***" + local.last()
        }
        return "$mask$domain"
    }

    companion object {
        fun buildEncryptedPrefs(context: Context): SharedPreferences {
            return try {
                val masterKey = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()
                EncryptedSharedPreferences.create(
                    context,
                    "sentineldroid_log_enc",
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
            } catch (e: Exception) {
                context.getSharedPreferences("sentineldroid_log", Context.MODE_PRIVATE)
            }
        }
    }
}
