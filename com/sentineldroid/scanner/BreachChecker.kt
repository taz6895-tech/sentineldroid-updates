package com.sentineldroid.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

data class BreachResult(
    val email: String,
    val breached: Boolean,
    val breaches: List<BreachEntry>,
    val error: String? = null
)

data class BreachEntry(
    val name: String,
    val domain: String,
    val date: String,
    val dataClasses: List<String>,
    val description: String
)

class BreachChecker {

    companion object {
        // FIX: HIBP v3 requires an API key for breachedaccount endpoint.
        // Users can get a free key at https://haveibeenpwned.com/API/Key
        // Set to empty string to use the informational fallback instead.
        var HIBP_API_KEY = ""

        private const val TIMEOUT_MS = 8000
    }

    /**
     * Checks if an email address appears in known data breaches via HIBP.
     * Requires an API key for full results; falls back to helpful guidance if not set.
     */
    suspend fun checkEmail(email: String): BreachResult = withContext(Dispatchers.IO) {
        // FIX: validate and sanitize email before any use
        val sanitized = email.trim().lowercase()
        if (!android.util.Patterns.EMAIL_ADDRESS.matcher(sanitized).matches()) {
            return@withContext BreachResult(
                email = "[invalid]", breached = false, breaches = emptyList(),
                error = "Invalid email address format"
            )
        }

        if (HIBP_API_KEY.isBlank()) {
            return@withContext BreachResult(
                email = sanitized, breached = false, breaches = emptyList(),
                error = "API_KEY_REQUIRED"
            )
        }

        var conn: HttpURLConnection? = null
        return@withContext try {
            val encoded = java.net.URLEncoder.encode(sanitized, "UTF-8")
            val url = URL("https://haveibeenpwned.com/api/v3/breachedaccount/$encoded?truncateResponse=false")
            conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod  = "GET"
                connectTimeout = TIMEOUT_MS
                readTimeout    = TIMEOUT_MS
                // FIX: never log or echo the email back in headers
                setRequestProperty("User-Agent",   "SentinelDroid-Android")
                setRequestProperty("hibp-api-key", HIBP_API_KEY)
                setRequestProperty("Accept",       "application/json")
            }

            when (val code = conn.responseCode) {
                200  -> {
                    val body    = conn.inputStream.bufferedReader().readText()
                    val entries = parseBreaches(body)
                    BreachResult(email = sanitized, breached = true, breaches = entries)
                }
                404  -> BreachResult(email = sanitized, breached = false, breaches = emptyList())
                401  -> BreachResult(email = sanitized, breached = false, breaches = emptyList(),
                            error = "Invalid API key. Get one at haveibeenpwned.com/API/Key")
                429  -> {
                    val retryAfter = conn.getHeaderField("Retry-After") ?: "60"
                    BreachResult(email = sanitized, breached = false, breaches = emptyList(),
                        error = "Rate limited — retry in $retryAfter seconds")
                }
                503  -> BreachResult(email = sanitized, breached = false, breaches = emptyList(),
                            error = "HIBP service temporarily unavailable")
                else -> BreachResult(email = sanitized, breached = false, breaches = emptyList(),
                            error = "Unexpected response: HTTP $code")
            }
        } catch (e: java.net.UnknownHostException) {
            BreachResult(email = sanitized, breached = false, breaches = emptyList(),
                error = "No internet connection")
        } catch (e: java.net.SocketTimeoutException) {
            BreachResult(email = sanitized, breached = false, breaches = emptyList(),
                error = "Request timed out — try again")
        } catch (e: Exception) {
            BreachResult(email = sanitized, breached = false, breaches = emptyList(),
                error = "Connection failed")
        } finally {
            // FIX: always disconnect to release resources
            conn?.disconnect()
        }
    }

    /**
     * Privacy-safe password check using HIBP k-anonymity model.
     * ONLY the first 5 hex chars of the SHA-1 hash leave the device.
     * The actual password and the remaining 35 chars of the hash never leave.
     */
    suspend fun checkPassword(password: String): Pair<Boolean, Int> = withContext(Dispatchers.IO) {
        if (password.isBlank()) return@withContext Pair(false, 0)
        // FIX: cap length to prevent DoS via huge string fed into SHA-1 in a loop
        if (password.length > 1024) return@withContext Pair(false, 0)

        var conn: HttpURLConnection? = null
        return@withContext try {
            val sha1   = sha1(password).uppercase()
            val prefix = sha1.substring(0, 5)   // only this is sent
            val suffix = sha1.substring(5)       // stays on device

            conn = (URL("https://api.pwnedpasswords.com/range/$prefix").openConnection()
                    as HttpURLConnection).apply {
                requestMethod  = "GET"
                connectTimeout = TIMEOUT_MS
                readTimeout    = TIMEOUT_MS
                setRequestProperty("User-Agent",  "SentinelDroid-Android")
                // FIX: request padded response to prevent traffic analysis attacks
                setRequestProperty("Add-Padding", "true")
            }

            if (conn.responseCode != 200) return@withContext Pair(false, 0)

            conn.inputStream.bufferedReader().useLines { lines ->
                for (line in lines) {
                    val parts = line.trim().split(":")
                    if (parts.size == 2 && parts[0].equals(suffix, ignoreCase = true)) {
                        val count = parts[1].trim().toIntOrNull() ?: 0
                        // FIX: 0 count means it was a padding entry, not real
                        return@withContext Pair(count > 0, count)
                    }
                }
                Pair(false, 0)
            }
        } catch (e: Exception) {
            Pair(false, 0)
        } finally {
            conn?.disconnect()
        }
    }

    private fun sha1(input: String): String {
        val md    = MessageDigest.getInstance("SHA-1")
        val bytes = md.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun parseBreaches(json: String): List<BreachEntry> {
        val entries = mutableListOf<BreachEntry>()
        val blocks  = json.removePrefix("[").trimEnd(']')
            .split("},").map { it.trim().trimEnd('}') + "}" }

        for (block in blocks) {
            try {
                val name   = extractString(block, "Name")        ?: continue
                val domain = extractString(block, "Domain")      ?: ""
                val date   = extractString(block, "BreachDate")  ?: ""
                // FIX: strip ALL HTML tags and limit length
                val desc   = (extractString(block, "Description") ?: "")
                    .replace(Regex("<[^>]{0,200}>"), "")
                    .take(300)
                val data   = extractArray(block, "DataClasses")
                entries += BreachEntry(name, domain, date, data, desc)
            } catch (_: Exception) { /* skip malformed entry */ }
        }
        return entries
    }

    private fun extractString(json: String, key: String): String? {
        // FIX: limit match length to prevent ReDoS on malformed JSON
        val regex = Regex(""""$key"\s*:\s*"([^"]{0,2000})"""")
        return regex.find(json)?.groupValues?.get(1)
    }

    private fun extractArray(json: String, key: String): List<String> {
        val regex = Regex(""""$key"\s*:\s*\[([^\]]{0,2000})\]""")
        val match = regex.find(json)?.groupValues?.get(1) ?: return emptyList()
        return match.split(",")
            .map { it.trim().removeSurrounding("\"") }
            .filter { it.isNotBlank() }
    }
}
