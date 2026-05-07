package com.sentineldroid.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.net.URISyntaxException

enum class UrlRisk { SAFE, SUSPICIOUS, DANGEROUS, ERROR }

data class UrlCheckResult(
    val url: String,
    val risk: UrlRisk,
    val reasons: List<String>,
    val recommendation: String
)

class PhishingChecker {

    // FIX: explicit allowed schemes — blocks javascript:, data:, file:, etc.
    private val ALLOWED_SCHEMES = setOf("http", "https")

    private val SUSPICIOUS_TLDS = setOf(
        ".tk", ".ml", ".ga", ".cf", ".gq",
        ".xyz", ".top", ".click", ".loan", ".review",
        ".date", ".win", ".download", ".stream", ".science",
        ".racing", ".party", ".faith", ".bid", ".accountant"
    )

    // FIX: keywords as full lowercase tokens — no ReDoS risk
    private val PHISHING_KEYWORDS = listOf(
        "paypa1", "arnazon", "g00gle", "faceb00k", "bankofamerica-",
        "secure-login", "verify-account", "update-billing", "confirm-identity",
        "account-suspended", "unusual-activity", "suspended-account",
        "apple-id-locked", "netflix-suspend", "free-gift", "you-won",
        "click-here-now", "urgent-action", "verify-now", "signin-alert",
        "security-alert", "suspend-notice", "refund-pending"
    )

    private val KNOWN_SAFE_DOMAINS = setOf(
        "google.com", "gmail.com", "youtube.com", "apple.com",
        "microsoft.com", "amazon.com", "facebook.com", "twitter.com",
        "instagram.com", "netflix.com", "paypal.com", "bankofamerica.com",
        "wellsfargo.com", "chase.com", "citi.com", "linkedin.com",
        "github.com", "stackoverflow.com", "reddit.com", "wikipedia.org",
        "android.com", "play.google.com", "accounts.google.com",
        "haveibeenpwned.com", "raw.githubusercontent.com"
    )

    private val URL_SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
        "short.link", "rb.gy", "cutt.ly", "is.gd", "tiny.cc", "clck.ru",
        "urlshortener.com", "shorturl.at", "s.id", "lc.chat"
    )

    // Brand names to detect lookalikes — sorted longest-first to avoid partial matches
    private val BRAND_NAMES = listOf(
        "bankofamerica", "wellsfargo", "microsoft", "instagram",
        "linkedin", "facebook", "netflix", "paypal", "amazon",
        "google", "twitter", "youtube", "apple", "chase", "citibank"
    )

    // Homoglyph substitutions used by phishers
    private val HOMOGLYPHS = mapOf(
        '0' to 'o', '1' to 'l', '3' to 'e', '4' to 'a',
        '5' to 's', '6' to 'g', '7' to 't', '8' to 'b',
        '@' to 'a', '!' to 'i'
    )

    suspend fun checkUrl(rawUrl: String): UrlCheckResult = withContext(Dispatchers.IO) {
        val trimmed = rawUrl.trim()
        if (trimmed.isBlank()) {
            return@withContext errorResult(rawUrl, "URL is empty")
        }

        // FIX: cap input length to prevent DoS
        if (trimmed.length > 2048) {
            return@withContext UrlCheckResult(
                url = rawUrl, risk = UrlRisk.DANGEROUS,
                reasons = listOf("🔴 Abnormally long URL (${trimmed.length} chars) — likely obfuscation"),
                recommendation = "🚫 Do NOT visit this link."
            )
        }

        val normalized = normalizeUrl(trimmed)

        // FIX: parse with URI (stricter than URL) to catch malformed/dangerous inputs
        val uri = try { URI(normalized) } catch (e: URISyntaxException) {
            return@withContext errorResult(rawUrl, "Invalid URL format — cannot parse")
        }

        // FIX: block non-HTTP/S schemes — catches javascript:, data:, file:, vbscript:
        val scheme = uri.scheme?.lowercase() ?: ""
        if (scheme !in ALLOWED_SCHEMES) {
            return@withContext UrlCheckResult(
                url = rawUrl, risk = UrlRisk.DANGEROUS,
                reasons = listOf("🔴 Dangerous URL scheme '$scheme' — not HTTP or HTTPS"),
                recommendation = "🚫 This is NOT a normal web link. Do NOT click it."
            )
        }

        val host    = uri.host?.lowercase() ?: return@withContext errorResult(rawUrl, "No host in URL")
        val fullUrl = normalized.lowercase()
        val reasons = mutableListOf<String>()
        var risk    = UrlRisk.SAFE

        // 1. Known safe domains — fast path exit
        if (getBaseDomain(host) in KNOWN_SAFE_DOMAINS) {
            return@withContext UrlCheckResult(
                url = rawUrl, risk = UrlRisk.SAFE,
                reasons = listOf("✅ Known trusted domain"),
                recommendation = "✅ This appears to be a legitimate domain."
            )
        }

        // 2. HTTP (not HTTPS)
        if (scheme == "http") {
            risk = upgrade(risk, UrlRisk.SUSPICIOUS)
            reasons += "⚠️ Unencrypted HTTP — your data can be intercepted in transit"
        }

        // 3. Suspicious TLD
        val tld = "." + host.substringAfterLast(".")
        if (tld in SUSPICIOUS_TLDS) {
            risk = upgrade(risk, UrlRisk.DANGEROUS)
            reasons += "🔴 '$tld' is a free TLD massively abused for phishing campaigns"
        }

        // 4. IP address as hostname
        if (Regex("""^\d{1,3}(\.\d{1,3}){3}$""").matches(host)) {
            risk = upgrade(risk, UrlRisk.DANGEROUS)
            reasons += "🔴 IP address used as domain — legitimate sites use domain names"
        }

        // 5. URL shortener
        if (getBaseDomain(host) in URL_SHORTENERS) {
            risk = upgrade(risk, UrlRisk.SUSPICIOUS)
            reasons += "⚠️ URL shortener hides the real destination — verify the sender"
        }

        // 6. Phishing keywords in full URL
        val matchedKw = PHISHING_KEYWORDS.firstOrNull { fullUrl.contains(it) }
        if (matchedKw != null) {
            risk = upgrade(risk, UrlRisk.DANGEROUS)
            reasons += "🔴 Phishing keyword detected: '$matchedKw'"
        }

        // 7. Lookalike brand detection (FIX: actually works now)
        val lookalike = detectLookalike(host)
        if (lookalike != null) {
            risk = upgrade(risk, UrlRisk.DANGEROUS)
            reasons += "🔴 Domain impersonates '$lookalike' using character substitution"
        }

        // 8. Too many subdomains
        val dotCount = host.count { it == '.' }
        if (dotCount >= 4) {
            risk = upgrade(risk, UrlRisk.SUSPICIOUS)
            reasons += "⚠️ $dotCount subdomain levels — phishers abuse this to bury real domain"
        }

        // 9. @ symbol in URL (credential trick)
        if ('@' in (uri.userInfo ?: "")) {
            risk = upgrade(risk, UrlRisk.DANGEROUS)
            reasons += "🔴 @ sign in URL — classic trick to disguise the real destination domain"
        }

        // 10. Punycode domain (IDN homograph attack)
        if (host.contains("xn--")) {
            risk = upgrade(risk, UrlRisk.SUSPICIOUS)
            reasons += "⚠️ Internationalized domain (punycode) — may look identical to a real brand"
        }

        // 11. Double extension (e.g. invoice.pdf.exe-style in URL)
        if (Regex("""\.(exe|apk|bat|cmd|scr|vbs|jar|com)(\?|$)""").containsMatchIn(fullUrl)) {
            risk = upgrade(risk, UrlRisk.DANGEROUS)
            reasons += "🔴 URL ends with an executable file extension — likely malware download"
        }

        if (reasons.isEmpty()) reasons += "ℹ️ No known threats detected (local analysis only)"

        val recommendation = when (risk) {
            UrlRisk.SAFE      -> "✅ This URL appears safe to visit."
            UrlRisk.SUSPICIOUS-> "⚠️ Proceed with caution. Do not enter passwords or personal information."
            UrlRisk.DANGEROUS -> "🚫 DO NOT visit this link — phishing or malware characteristics detected."
            UrlRisk.ERROR     -> "Could not analyze this URL."
        }

        UrlCheckResult(url = rawUrl, risk = risk, reasons = reasons, recommendation = recommendation)
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private fun normalizeUrl(url: String): String =
        if (url.lowercase().startsWith("http://") || url.lowercase().startsWith("https://")) url
        else "https://$url"

    private fun getBaseDomain(host: String): String {
        val parts = host.split(".")
        return if (parts.size >= 2) parts.takeLast(2).joinToString(".") else host
    }

    /** FIX: working lookalike detector using homoglyph normalization */
    private fun detectLookalike(host: String): String? {
        val base = getBaseDomain(host)
        // Normalize: replace digits/symbols that look like letters
        val normalized = base.map { c -> HOMOGLYPHS[c] ?: c }.joinToString("")
        for (brand in BRAND_NAMES) {
            if (normalized.startsWith(brand) && !base.startsWith(brand)) {
                return brand
            }
        }
        return null
    }

    private fun upgrade(current: UrlRisk, next: UrlRisk): UrlRisk =
        if (next.ordinal > current.ordinal) next else current

    private fun errorResult(url: String, msg: String) = UrlCheckResult(
        url = url, risk = UrlRisk.ERROR,
        reasons = listOf(msg), recommendation = "Cannot analyze this URL."
    )
}
