package com.sentineldroid.scanner

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class VirusScanner(private val context: Context) {

    // ─── Known malware / stalkerware package database ─────────────────────────
    // Sources: ESET, Kaspersky, Lookout, EFF's Coalition Against Stalkerware lists
    private val KNOWN_MALWARE = mapOf(
        // Stalkerware / Spyware
        "com.thetruthspy.android" to "TheTruthSpy: Commercial stalkerware that hides itself and uploads your SMS, calls, location, and photos to a remote server",
        "com.spymaster.android" to "SpyMaster Pro: Hidden stalkerware that intercepts messages and tracks location without victim's knowledge",
        "com.highstermobi.android" to "Highster Mobile: Stalkerware marketed as 'phone monitoring' that operates completely hidden",
        "com.mspy.android" to "mSpy Stalkerware: Uploads contacts, SMS, GPS, and app activity to external servers",
        "com.flexispy.android" to "FlexiSpy: Advanced spyware capable of intercepting calls and activating the microphone remotely",
        "com.hoverwatch.android" to "Hoverwatch: Hidden tracker that captures screenshots, SMS, and GPS location",
        "com.spyera.android" to "Spyera: Stealth spyware with keylogging and call interception",
        "com.ikeymonitor.android" to "iKeyMonitor: Keylogger + GPS tracker that operates in stealth mode",
        "com.cocospy.app" to "CocoSpy Stalkerware: Tracks location, SMS, and browsing history without consent",
        "com.minspy.android" to "MinSpy: Hidden monitoring app that exfiltrates device data",
        "com.umobix.android" to "uMobix: Parental control tool with stalkerware capabilities when used covertly",
        "app.spybubble.android" to "SpyBubble: Stalkerware that transmits messages and location to third-party",
        "com.xnspy.android" to "XNSPY: Remote phone monitoring without knowledge of device owner",
        "com.clevguard.kidsguard" to "KidsGuard Pro (stalkerware mode): Can be deployed as adult stalkerware",

        // Banking Trojans
        "com.android.overlay.servicemanager" to "BankBot Trojan: Overlays fake login screens on banking apps to steal credentials",
        "com.android.hacking.tool" to "Android RAT (Remote Access Trojan): Gives attacker full remote control of device",
        "com.google.android.overlay" to "Anubis Banking Trojan: Impersonates Google services to steal banking credentials",
        "com.cerberus.android.rat" to "Cerberus Banking Trojan: Steals 2FA codes and overlays banking apps",
        "com.teabot.android" to "TeaBot Trojan: Intercepts 2FA SMS codes and banking credentials",
        "com.flubot.android" to "FluBot: SMS-spreading banking trojan with device takeover capabilities",
        "com.sharkbot.android" to "SharkBot: Advanced banking trojan with automatic transfer system",
        "com.brunhilda.dropper" to "Brunhilda Dropper: Installs malware payloads after bypassing Play Protect",
        "com.sova.android" to "SOVA Banking Trojan: Ransomware + banking credential stealer",

        // Adware / Clicker fraud
        "com.adware.clicker.hidden" to "Hidden Clicker Adware: Runs in background clicking ads to commit advertising fraud",
        "com.fakevpn.freevpn" to "Fake VPN / Adware: Claims to be a VPN but steals credentials and serves aggressive ads",

        // Ransomware
        "com.android.locker.encrypt" to "Android Locker Ransomware: Encrypts files and demands payment to unlock",
        "com.lockscreen.encrypt.ransom" to "Lock-Screen Ransomware: Locks device and demands ransom",

        // RATs / Remote Access
        "com.androrat.server" to "AndroRAT: Open-source Remote Access Trojan giving attacker full device control",
        "com.ahmyth.rat" to "AhMyth RAT: Keylogging, camera access, GPS, and file exfiltration",
        "com.spynote.rat" to "SpyNote RAT: Full remote access tool with stealth features",
        "com.droidjack.rat" to "DroidJack: Commercial RAT sold on dark web forums",

        // Cryptominers
        "com.coinhive.miner" to "CoinHive Cryptominer: Mines cryptocurrency using your battery and CPU without consent",
        "com.android.hidden.miner" to "Hidden Cryptominer: Drains battery and CPU mining crypto in background",

        // Rootkits / Bootkits
        "com.rootkit.persistent" to "Android Rootkit: Achieves root persistence to survive factory reset",
        "com.necro.android.dropper" to "Necro Dropper: Dropper found in SDK supply-chain attacks on legitimate apps"
    )

    // Package name patterns that strongly suggest malware (heuristics)
    private val SUSPICIOUS_PATTERNS = listOf(
        "monitor", "track", "spy", "stealth", "hidden", "ghost", "invisible",
        "keylog", "intercept", "sniff", "rat.", ".rat", "trojan", "malware",
        "hack", "crack", "cheat", "exploit", "root.tool", "rootkit"
    )

    // Known-safe app prefixes to avoid false positives
    private val SAFE_PREFIXES = setOf(
        "com.google.", "com.android.", "com.samsung.", "com.oneplus.", "com.huawei.",
        "com.xiaomi.", "com.oppo.", "com.realme.", "com.miui.", "android.",
        "com.sec.", "com.motorola.", "com.lge.", "com.htc.", "com.sony.",
        "com.netflix.", "com.spotify.", "com.facebook.", "com.instagram.",
        "com.whatsapp.", "com.twitter.", "com.snapchat.", "com.tiktok.",
        "com.amazon.", "com.microsoft.", "com.apple.", "org.telegram.",
        "com.discord.", "com.reddit.", "com.linkedin.", "com.paypal.",
        "com.uber.", "com.lyft.", "com.airbnb.", "com.doordash."
    )

    suspend fun scan(): List<VirusItem> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val results = mutableListOf<VirusItem>()

        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        for (pkg in packages) {
            val pkgName = pkg.packageName
            val appInfo = pkg.applicationInfo ?: continue

            // Skip known-safe prefixes
            if (SAFE_PREFIXES.any { pkgName.startsWith(it) }) continue

            val appName = try { pm.getApplicationLabel(appInfo).toString() } catch (e: Exception) { pkgName }
            val icon = try { pm.getApplicationIcon(pkgName) } catch (e: Exception) { null }

            // 1. Check known malware database
            val knownMatch = KNOWN_MALWARE[pkgName]
            if (knownMatch != null) {
                results.add(VirusItem(
                    appName = appName,
                    packageName = pkgName,
                    reason = "⚠️ KNOWN MALWARE — $knownMatch",
                    severity = ThreatLevel.CRITICAL,
                    icon = icon
                ))
                continue
            }

            // 2. Check suspicious package name patterns
            val lowerPkg = pkgName.lowercase()
            val matchedPattern = SUSPICIOUS_PATTERNS.firstOrNull { lowerPkg.contains(it) }
            if (matchedPattern != null) {
                results.add(VirusItem(
                    appName = appName,
                    packageName = pkgName,
                    reason = "Suspicious package name contains '$matchedPattern' — common in spyware/trackers",
                    severity = ThreatLevel.HIGH,
                    icon = icon
                ))
                continue
            }

            // 3. Check for hidden apps (no launcher icon = trying to stay invisible)
            val isHidden = checkIfHidden(pm, pkgName)
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (isHidden && !isSystem) {
                // Exclude known legitimate background services
                if (!isKnownLegitimateService(pkgName)) {
                    results.add(VirusItem(
                        appName = appName,
                        packageName = pkgName,
                        reason = "Hidden app — has no launcher icon and is not a system service. Malware often hides to avoid detection.",
                        severity = ThreatLevel.MEDIUM,
                        icon = icon
                    ))
                    continue
                }
            }

            // 4. Check for suspicious install source
            val installSource = getInstallSource(pm, pkgName)
            val isSideloaded = installSource == null && !isSystem
            if (isSideloaded) {
                val permissions = pkg.requestedPermissions ?: continue
                val flags = pkg.requestedPermissionsFlags ?: continue
                val dangerousCount = permissions.filterIndexed { i, _ ->
                    (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                }.count { perm ->
                    perm.startsWith("android.permission.") && isDangerousPermission(perm)
                }

                if (dangerousCount >= 3) {
                    results.add(VirusItem(
                        appName = appName,
                        packageName = pkgName,
                        reason = "Sideloaded app (not from Play Store) with $dangerousCount dangerous permissions. High risk of being malware.",
                        severity = ThreatLevel.MEDIUM,
                        icon = icon
                    ))
                }
            }
        }

        results.sortedByDescending { it.severity.ordinal }
    }

    private fun checkIfHidden(pm: PackageManager, pkgName: String): Boolean {
        val launchIntent = pm.getLaunchIntentForPackage(pkgName)
        return launchIntent == null
    }

    private fun isKnownLegitimateService(pkgName: String): Boolean {
        val legitimatePatterns = listOf(
            "inputmethod", "keyboard", "ime.", ".ime", "accessibility",
            "provider", "service", "daemon", "system", "framework",
            "launcher", "wallpaper", "theme", "font"
        )
        val lower = pkgName.lowercase()
        return legitimatePatterns.any { lower.contains(it) }
    }

    private fun getInstallSource(pm: PackageManager, pkgName: String): String? {
        return try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkgName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(pkgName)
            }
        } catch (e: Exception) { null }
    }

    private fun isDangerousPermission(perm: String): Boolean {
        val dangerous = setOf(
            "android.permission.READ_SMS", "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG", "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_PHONE_STATE", "android.permission.RECEIVE_SMS",
            "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.WRITE_SETTINGS"
        )
        return perm in dangerous
    }
}
