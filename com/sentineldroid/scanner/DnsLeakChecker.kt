package com.sentineldroid.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

data class DnsLeakResult(
    val isLeaking: Boolean,
    val vpnActive: Boolean,
    val dnsServers: List<DnsServerEntry>,
    val publicIp: String,
    val ipLocation: String,
    val riskLevel: ThreatLevel,
    val summary: String,
    val recommendations: List<String>,
    val error: String? = null
)

data class DnsServerEntry(
    val ip: String,
    val provider: String,
    val country: String,
    val isTrusted: Boolean,
    val isKnownGood: Boolean
)

class DnsLeakChecker {

    companion object {
        private const val TIMEOUT_MS = 6000

        // Known safe/trusted DNS providers
        private val TRUSTED_DNS = mapOf(
            "1.1.1.1"       to Pair("Cloudflare",       "🟢 Trusted"),
            "1.0.0.1"       to Pair("Cloudflare",       "🟢 Trusted"),
            "8.8.8.8"       to Pair("Google",           "🟢 Trusted"),
            "8.8.4.4"       to Pair("Google",           "🟢 Trusted"),
            "9.9.9.9"       to Pair("Quad9",            "🟢 Trusted"),
            "149.112.112.112" to Pair("Quad9",          "🟢 Trusted"),
            "208.67.222.222" to Pair("OpenDNS",         "🟢 Trusted"),
            "208.67.220.220" to Pair("OpenDNS",         "🟢 Trusted"),
            "94.140.14.14"  to Pair("AdGuard",          "🟢 Trusted"),
            "185.228.168.9" to Pair("CleanBrowsing",    "🟢 Trusted"),
            "76.76.19.19"   to Pair("Alternate DNS",    "🟢 Trusted")
        )
    }

    suspend fun check(context: android.content.Context): DnsLeakResult = withContext(Dispatchers.IO) {
        // Check if VPN is active
        val cm = context.getSystemService(android.content.Context.CONNECTIVITY_SERVICE)
                as android.net.ConnectivityManager
        val vpnActive = cm.activeNetwork?.let {
            cm.getNetworkCapabilities(it)?.hasTransport(
                android.net.NetworkCapabilities.TRANSPORT_VPN
            )
        } == true

        // Get public IP and location via Cloudflare trace (no auth needed, minimal data)
        val (publicIp, ipLocation) = fetchCloudflareTrace()

        // Resolve DNS via multiple methods to detect leaks
        val dnsServers = mutableListOf<DnsServerEntry>()

        // Method 1: Check what IP cloudflare-dns.com resolves to
        // (if DNS is going through VPN, this should resolve to VPN's DNS)
        val resolvedDns = resolveDnsServer()
        dnsServers.addAll(resolvedDns)

        // Method 2: Test DNS-over-HTTPS availability
        val dohWorking = testDnsOverHttps()

        // Determine if there's a leak
        val isLeaking = vpnActive && dnsServers.any { !it.isTrusted && !it.isKnownGood }
        val hasUnknownDns = dnsServers.any { !it.isKnownGood && !it.isTrusted }

        val (risk, summary) = buildRiskAssessment(vpnActive, isLeaking, hasUnknownDns, dohWorking, dnsServers)
        val recommendations = buildRecommendations(vpnActive, isLeaking, dohWorking, hasUnknownDns)

        DnsLeakResult(
            isLeaking       = isLeaking,
            vpnActive       = vpnActive,
            dnsServers      = dnsServers,
            publicIp        = publicIp,
            ipLocation      = ipLocation,
            riskLevel       = risk,
            summary         = summary,
            recommendations = recommendations
        )
    }

    private fun fetchCloudflareTrace(): Pair<String, String> {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL("https://1.1.1.1/cdn-cgi/trace").openConnection() as HttpURLConnection).apply {
                connectTimeout = TIMEOUT_MS; readTimeout = TIMEOUT_MS
                setRequestProperty("User-Agent", "SentinelDroid-Android")
            }
            val body = conn.inputStream.bufferedReader().readText()
            val ip   = Regex("ip=(\\S+)").find(body)?.groupValues?.get(1) ?: "Unknown"
            val loc  = Regex("loc=(\\S+)").find(body)?.groupValues?.get(1) ?: "Unknown"
            Pair(ip, loc)
        } catch (e: Exception) {
            Pair("Unavailable", "Unknown")
        } finally {
            conn?.disconnect()
        }
    }

    private fun resolveDnsServer(): List<DnsServerEntry> {
        val servers = mutableListOf<DnsServerEntry>()
        return try {
            // Resolve well-known hosts and check which IPs respond
            // We check a few DNS servers directly to see what's reachable
            val testHosts = listOf("cloudflare-dns.com", "dns.google", "dns9.quad9.net")
            val reachable = mutableSetOf<String>()

            for (host in testHosts) {
                try {
                    val addresses = InetAddress.getAllByName(host)
                    addresses.forEach { addr ->
                        val ip = addr.hostAddress ?: return@forEach
                        val entry = TRUSTED_DNS[ip]
                        if (entry != null && ip !in reachable) {
                            reachable.add(ip)
                            servers.add(DnsServerEntry(
                                ip          = ip,
                                provider    = entry.first,
                                country     = "Known",
                                isTrusted   = true,
                                isKnownGood = true
                            ))
                        }
                    }
                } catch (e: Exception) { /* skip unresolvable */ }
            }

            // Check system DNS via NetworkInterface
            try {
                val systemDns = getSystemDnsServers()
                for (dns in systemDns) {
                    if (dns !in reachable) {
                        val known = TRUSTED_DNS[dns]
                        reachable.add(dns)
                        servers.add(DnsServerEntry(
                            ip          = dns,
                            provider    = known?.first ?: "Unknown Provider",
                            country     = if (known != null) "Known" else "Unknown",
                            isTrusted   = known != null,
                            isKnownGood = known != null
                        ))
                    }
                }
            } catch (e: Exception) { /* skip */ }

            servers.ifEmpty {
                listOf(DnsServerEntry("Unknown", "Could not detect DNS servers",
                    "Unknown", false, false))
            }
        } catch (e: Exception) {
            listOf(DnsServerEntry("Error", "Detection failed: ${e.javaClass.simpleName}",
                "Unknown", false, false))
        }
    }

    private fun getSystemDnsServers(): List<String> {
        val servers = mutableListOf<String>()
        try {
            // Read system property for DNS (works on most Android)
            val getprop = Runtime.getRuntime().exec("getprop")
            val output  = getprop.inputStream.bufferedReader().readText()
            getprop.destroy()
            val dnsRegex = Regex("""net\.\S*dns\S*\]:\s*\[([^\]]+)\]""")
            dnsRegex.findAll(output).forEach { match ->
                val ip = match.groupValues[1].trim()
                if (ip.isNotEmpty() && ip != "0.0.0.0" &&
                    Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""").matches(ip)) {
                    servers.add(ip)
                }
            }
        } catch (e: Exception) { /* getprop may not work on all devices */ }
        return servers.distinct()
    }

    private fun testDnsOverHttps(): Boolean {
        var conn: HttpURLConnection? = null
        return try {
            // Test if DNS-over-HTTPS (DoH) is reachable — indicates modern secure DNS
            conn = (URL("https://cloudflare-dns.com/dns-query?name=example.com&type=A")
                .openConnection() as HttpURLConnection).apply {
                connectTimeout = TIMEOUT_MS; readTimeout = TIMEOUT_MS
                setRequestProperty("Accept", "application/dns-json")
                setRequestProperty("User-Agent", "SentinelDroid-Android")
            }
            conn.responseCode == 200
        } catch (e: Exception) { false } finally { conn?.disconnect() }
    }

    private fun buildRiskAssessment(
        vpnActive: Boolean, isLeaking: Boolean,
        hasUnknownDns: Boolean, dohWorking: Boolean,
        servers: List<DnsServerEntry>
    ): Pair<ThreatLevel, String> {
        return when {
            isLeaking -> Pair(ThreatLevel.HIGH,
                "🔴 DNS LEAK DETECTED — Your DNS queries are leaking outside your VPN. " +
                "Your ISP can see which websites you visit even though your VPN is on.")
            vpnActive && !isLeaking -> Pair(ThreatLevel.SAFE,
                "✅ No DNS leak — DNS traffic appears to be routed through your VPN.")
            hasUnknownDns -> Pair(ThreatLevel.MEDIUM,
                "🟠 Unknown DNS server detected — your queries may be going to an untrusted resolver.")
            !vpnActive && dohWorking -> Pair(ThreatLevel.LOW,
                "🟡 No VPN active, but DNS-over-HTTPS is working. Your DNS is encrypted but your IP is visible.")
            !vpnActive -> Pair(ThreatLevel.MEDIUM,
                "🟠 No VPN active. Your ISP can see all DNS lookups (every website you visit).")
            else -> Pair(ThreatLevel.SAFE, "✅ DNS configuration looks normal.")
        }
    }

    private fun buildRecommendations(
        vpnActive: Boolean, isLeaking: Boolean,
        dohWorking: Boolean, hasUnknownDns: Boolean
    ): List<String> {
        val recs = mutableListOf<String>()
        if (isLeaking) {
            recs += "🔧 Enable DNS leak protection in your VPN settings"
            recs += "🔧 Switch to a VPN provider with built-in DNS leak protection"
            recs += "🔧 Set your DNS manually to 1.1.1.1 (Cloudflare) or 9.9.9.9 (Quad9)"
        }
        if (!vpnActive) {
            recs += "💡 Use a trusted VPN to hide your browsing from your ISP"
        }
        if (!dohWorking) {
            recs += "💡 Enable Private DNS in Android Settings → Network → Private DNS → 'one.one.one.one'"
        }
        if (hasUnknownDns) {
            recs += "⚠️ Change your DNS to a known provider: Cloudflare (1.1.1.1), Google (8.8.8.8), or Quad9 (9.9.9.9)"
        }
        if (recs.isEmpty()) recs += "✅ No immediate action needed"
        return recs
    }
}
