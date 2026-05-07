package com.sentineldroid.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

data class RootCheckResult(
    val isRooted: Boolean,
    val isEmulator: Boolean,
    val isDebugBuild: Boolean,
    val riskLevel: ThreatLevel,
    val findings: List<String>
)

object RootDetector {

    // Common su binary locations used by root tools
    private val SU_PATHS = arrayOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/system/su", "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
        "/data/local/su", "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su", "/su/bin/su"
    )

    // Packages installed by root/Magisk tooling
    private val ROOT_PACKAGES = arrayOf(
        "com.noshufou.android.su",          // SuperUser
        "com.noshufou.android.su.elite",    // SuperUser Elite
        "eu.chainfire.supersu",             // SuperSU
        "com.koushikdutta.superuser",       // CWM SuperUser
        "com.thirdparty.superuser",         // Third party
        "com.yellowes.su",                  // Yellow SU
        "com.topjohnwu.magisk",            // Magisk
        "io.github.huskydg.magisk",        // Magisk Delta
        "com.kingroot.kinguser",            // KingRoot
        "com.kingo.root",                  // KingoRoot
        "com.smedialink.oneclickroot",     // One Click Root
        "com.zhiqupk.root.global",         // Root Master
        "com.alephzain.framaroot"          // Framaroot
    )

    // Emulator detection fingerprints
    private val EMULATOR_PROPS = mapOf(
        Build.FINGERPRINT to listOf("generic", "unknown", "sdk_", "emulator", "android_x86"),
        Build.MODEL       to listOf("google_sdk", "emulator", "Android SDK built for"),
        Build.MANUFACTURER to listOf("Genymotion", "unknown"),
        Build.HARDWARE    to listOf("goldfish", "ranchu", "vbox86"),
        Build.PRODUCT     to listOf("sdk", "sdk_x86", "sdk_google", "vbox86p",
                                    "generic_x86", "google_sdk", "full_x86")
    )

    fun check(context: Context): RootCheckResult {
        val findings    = mutableListOf<String>()
        var rooted      = false
        var emulator    = false
        val debugBuild  = isDebugBuild(context)

        // ── Root checks ───────────────────────────────────────────────────────

        // 1. su binary presence
        for (path in SU_PATHS) {
            if (File(path).exists()) {
                rooted = true
                findings += "🔴 Root binary found: $path"
                break
            }
        }

        // 2. Root package installed
        val pm = context.packageManager
        for (pkg in ROOT_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0)
                rooted = true
                val name = try { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }
                           catch (e: Exception) { pkg }
                findings += "🔴 Root app installed: $name"
            } catch (e: PackageManager.NameNotFoundException) { /* not installed */ }
        }

        // 3. Can we write to /system? (read-only on non-rooted)
        val systemWritable = try { File("/system").canWrite() } catch (e: Exception) { false }
        if (systemWritable) {
            rooted = true
            findings += "🔴 /system partition is writable (root access active)"
        }

        // 4. test-keys build (unofficial/rooted ROM)
        val buildTags = Build.TAGS ?: ""
        if (buildTags.contains("test-keys")) {
            rooted = true
            findings += "⚠️ Device uses test-keys signing — unofficial/rooted ROM detected"
        }

        // 5. Magisk hide check (try to exec su)
        val canExecSu = canExecuteSu()
        if (canExecSu) {
            rooted = true
            findings += "🔴 su binary is executable — root shell accessible"
        }

        // ── Emulator checks ───────────────────────────────────────────────────

        for ((prop, keywords) in EMULATOR_PROPS) {
            val propLower = prop.lowercase()
            for (kw in keywords) {
                if (propLower.contains(kw.lowercase())) {
                    emulator = true
                    findings += "ℹ️ Emulator indicator: ${prop.take(40)}"
                    break
                }
            }
        }

        // Android emulator radio
        val radioVersion = Build.getRadioVersion() ?: ""
        if (radioVersion == "1.0.0.0") {
            emulator = true
            findings += "ℹ️ Emulator radio version detected"
        }

        // ── Debug build check ─────────────────────────────────────────────────

        if (debugBuild) {
            findings += "ℹ️ App running in debug mode — release build is more secure"
        }

        // ── Risk assessment ───────────────────────────────────────────────────

        val riskLevel = when {
            rooted && !emulator -> ThreatLevel.HIGH
            rooted              -> ThreatLevel.MEDIUM  // rooted emulator — testing context
            emulator            -> ThreatLevel.LOW
            debugBuild          -> ThreatLevel.LOW
            else                -> ThreatLevel.SAFE
        }

        if (findings.isEmpty()) findings += "✅ No root, emulator, or debug indicators found"

        return RootCheckResult(
            isRooted    = rooted,
            isEmulator  = emulator,
            isDebugBuild= debugBuild,
            riskLevel   = riskLevel,
            findings    = findings
        )
    }

    private fun canExecuteSu(): Boolean {
        // FIX: add hard timeout so this never hangs the scan
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            // Wait max 1 second — if su prompts for interaction it will time out
            val finished = process.waitFor(1, java.util.concurrent.TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                return false
            }
            val result = process.inputStream.bufferedReader().readText()
            process.destroy()
            result.contains("uid=0")
        } catch (e: Exception) { false }
    }

    private fun isDebugBuild(context: Context): Boolean {
        return try {
            val appInfo = context.packageManager.getApplicationInfo(context.packageName, 0)
            (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        } catch (e: Exception) { false }
    }
}
