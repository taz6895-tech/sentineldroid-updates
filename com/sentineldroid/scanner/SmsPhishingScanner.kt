package com.sentineldroid.scanner

import android.content.Context
import android.database.Cursor
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class SmsPhishingResult(
    val messageId: String,
    val sender: String,
    val preview: String,           // first 120 chars
    val timestampMs: Long,
    val riskLevel: ThreatLevel,
    val detectedThreats: List<String>,
    val suspiciousUrls: List<String>
)

class SmsPhishingScanner(private val context: Context) {

    private val phishingChecker = PhishingChecker()

    // Smishing (SMS phishing) keyword patterns
    private val SCAM_PATTERNS = listOf(
        // Urgency + action triggers
        "your account has been suspended" to ThreatLevel.HIGH,
        "verify your account" to ThreatLevel.HIGH,
        "unusual activity detected" to ThreatLevel.HIGH,
        "your package could not be delivered" to ThreatLevel.MEDIUM,
        "click to claim your prize" to ThreatLevel.HIGH,
        "you have won" to ThreatLevel.HIGH,
        "congratulations you were selected" to ThreatLevel.HIGH,
        "limited time offer" to ThreatLevel.LOW,
        "act now" to ThreatLevel.LOW,
        "your card has been charged" to ThreatLevel.MEDIUM,
        "IRS" to ThreatLevel.MEDIUM,
        "HMRC" to ThreatLevel.MEDIUM,
        "tax refund" to ThreatLevel.HIGH,
        "social security" to ThreatLevel.MEDIUM,
        // Banking scams
        "bank account locked" to ThreatLevel.HIGH,
        "confirm your payment" to ThreatLevel.MEDIUM,
        "unauthorized transaction" to ThreatLevel.HIGH,
        "wire transfer" to ThreatLevel.MEDIUM,
        // Gift card scams
        "send gift card" to ThreatLevel.HIGH,
        "buy itunes" to ThreatLevel.HIGH,
        "google play card" to ThreatLevel.HIGH,
        // Crypto scams
        "bitcoin investment" to ThreatLevel.HIGH,
        "crypto opportunity" to ThreatLevel.HIGH,
        "double your investment" to ThreatLevel.HIGH,
        // Delivery scams
        "usps.com" to ThreatLevel.LOW,         // legit but cloned often
        "reschedule delivery" to ThreatLevel.MEDIUM,
        "customs fee" to ThreatLevel.MEDIUM
    )

    // URL shorteners used heavily in smishing
    private val SHORTENER_DOMAINS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "cutt.ly",
        "rb.gy", "is.gd", "short.link", "tiny.cc", "clck.ru"
    )

    suspend fun scanInbox(limit: Int = 100): List<SmsPhishingResult> = withContext(Dispatchers.IO) {
        val results = mutableListOf<SmsPhishingResult>()

        try {
            val cursor: Cursor? = context.contentResolver.query(
                Uri.parse("content://sms/inbox"),
                arrayOf("_id", "address", "body", "date"),
                null, null,
                "date DESC LIMIT $limit"
            )

            cursor?.use { c ->
                val idIdx   = c.getColumnIndex("_id")
                val addrIdx = c.getColumnIndex("address")
                val bodyIdx = c.getColumnIndex("body")
                val dateIdx = c.getColumnIndex("date")

                while (c.moveToNext()) {
                    val id      = c.getString(idIdx.coerceAtLeast(0)) ?: continue
                    val sender  = c.getString(addrIdx.coerceAtLeast(0)) ?: "Unknown"
                    val body    = c.getString(bodyIdx.coerceAtLeast(0)) ?: continue
                    val dateMs  = c.getLong(dateIdx.coerceAtLeast(0))

                    val (risk, threats, urls) = analyzeMessage(body)
                    if (risk != ThreatLevel.SAFE) {
                        results.add(SmsPhishingResult(
                            messageId       = id,
                            sender          = sender,
                            preview         = body.take(120),
                            timestampMs     = dateMs,
                            riskLevel       = risk,
                            detectedThreats = threats,
                            suspiciousUrls  = urls
                        ))
                    }
                }
            }
        } catch (e: SecurityException) {
            // READ_SMS permission not granted — caller handles this
            throw e
        } catch (e: Exception) {
            // Inbox not accessible on this device
        }

        results.sortedByDescending { it.riskLevel.ordinal }
    }

    private suspend fun analyzeMessage(body: String): Triple<ThreatLevel, List<String>, List<String>> {
        val threats = mutableListOf<String>()
        val suspiciousUrls = mutableListOf<String>()
        var maxRisk = ThreatLevel.SAFE

        val lower = body.lowercase()

        // Check scam keyword patterns
        for ((pattern, risk) in SCAM_PATTERNS) {
            if (lower.contains(pattern.lowercase())) {
                threats += "Scam phrase detected: \"$pattern\""
                if (risk.ordinal > maxRisk.ordinal) maxRisk = risk
            }
        }

        // Extract and check URLs
        val urlRegex = Regex("""https?://[^\s<>"]+|www\.[^\s<>"]+""")
        val urls = urlRegex.findAll(body).map { it.value }.toList()

        for (url in urls) {
            // Check URL shorteners
            val domain = url.removePrefix("https://").removePrefix("http://")
                .removePrefix("www.").substringBefore("/").substringBefore("?")
            val baseDomain = domain.split(".").takeLast(2).joinToString(".")

            if (baseDomain in SHORTENER_DOMAINS) {
                threats += "URL shortener hides destination: $url"
                suspiciousUrls += url
                if (ThreatLevel.MEDIUM.ordinal > maxRisk.ordinal) maxRisk = ThreatLevel.MEDIUM
            } else {
                // Run phishing check
                val result = phishingChecker.checkUrl(url)
                if (result.risk == UrlRisk.DANGEROUS || result.risk == UrlRisk.SUSPICIOUS) {
                    suspiciousUrls += url
                    threats += "Suspicious URL: $url"
                    val risk = if (result.risk == UrlRisk.DANGEROUS) ThreatLevel.HIGH else ThreatLevel.MEDIUM
                    if (risk.ordinal > maxRisk.ordinal) maxRisk = risk
                }
            }
        }

        return Triple(maxRisk, threats, suspiciousUrls)
    }

    fun formatDate(ms: Long): String {
        val sdf = java.text.SimpleDateFormat("MMM d, h:mm a", java.util.Locale.getDefault())
        return sdf.format(java.util.Date(ms))
    }
}
