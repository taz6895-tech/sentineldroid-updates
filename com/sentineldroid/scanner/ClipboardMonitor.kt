package com.sentineldroid.scanner

import android.app.AppOpsManager
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class ClipboardAccessEntry(
    val appName: String,
    val packageName: String,
    val lastAccessMs: Long,
    val risk: ThreatLevel,
    val icon: android.graphics.drawable.Drawable? = null
)

data class ClipboardSnapshot(
    val hasContent: Boolean,
    val contentType: String,       // "Text", "URL", "Password-like", "Empty"
    val contentPreview: String,    // masked for sensitive content
    val isSensitive: Boolean,
    val warning: String
)

class ClipboardMonitor(private val context: Context) {

    private val SAFE_APPS = setOf(
        "com.google.android.inputmethod.latin",
        "com.samsung.android.honeyboard",
        "com.swiftkey.swiftkeyapp",
        "com.google.android.gboard",
        "com.android.systemui"
    )

    /** Snapshot current clipboard content with sensitivity analysis */
    fun snapshotClipboard(): ClipboardSnapshot {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        if (!cm.hasPrimaryClip()) {
            return ClipboardSnapshot(false, "Empty", "", false, "Clipboard is empty")
        }

        val clip = cm.primaryClip ?: return ClipboardSnapshot(false, "Empty", "", false, "Clipboard is empty")
        val item = clip.getItemAt(0) ?: return ClipboardSnapshot(false, "Empty", "", false, "")
        val text = item.coerceToText(context).toString()

        if (text.isBlank()) return ClipboardSnapshot(false, "Empty", "", false, "Clipboard is empty")

        // Detect content type and sensitivity
        val (type, sensitive, warning, preview) = analyzeContent(text)

        return ClipboardSnapshot(
            hasContent     = true,
            contentType    = type,
            contentPreview = preview,
            isSensitive    = sensitive,
            warning        = warning
        )
    }

    private data class Analysis(val type: String, val sensitive: Boolean, val warning: String, val preview: String)

    private fun analyzeContent(text: String): Analysis {
        val lower = text.lowercase().trim()

        // Detect password-like content
        val looksLikePassword = text.length in 8..64 &&
            text.any { it.isUpperCase() } && text.any { it.isLowerCase() } &&
            text.any { it.isDigit() } && !text.contains(" ") &&
            !lower.startsWith("http")

        // Detect URLs
        val isUrl = lower.startsWith("http://") || lower.startsWith("https://") ||
            lower.startsWith("www.")

        // Detect credit card pattern (16 digits, optionally spaced)
        val ccPattern = Regex("""(\d{4}[\s-]?){4}""")
        val looksLikeCreditCard = ccPattern.containsMatchIn(text.replace(" ", "").replace("-", ""))
            && text.replace(" ", "").replace("-", "").length == 16

        // Detect crypto wallet address
        val looksLikeCrypto = (lower.startsWith("0x") && text.length == 42) ||
            (text.length in 26..35 && text.all { it.isLetterOrDigit() } &&
            (text.startsWith("1") || text.startsWith("3") || text.startsWith("bc1")))

        // Detect private key
        val looksLikeKey = text.length in 40..100 &&
            text.all { it.isLetterOrDigit() } && !text.contains(" ")

        return when {
            looksLikeCreditCard -> Analysis(
                "Credit Card Number", true,
                "⚠️ Clipboard may contain a credit card number! Any app can read this.",
                "****-****-****-" + text.takeLast(4).filter { it.isDigit() }
            )
            looksLikeCrypto -> Analysis(
                "Crypto Address", true,
                "⚠️ Clipboard has a crypto wallet address. Clipboard hijacking malware replaces addresses silently — always verify before pasting.",
                text.take(8) + "..." + text.takeLast(6)
            )
            looksLikeKey -> Analysis(
                "Possible Private Key / Secret", true,
                "🔴 Long hexadecimal string — may be a private key or token. Remove from clipboard after use.",
                "●".repeat(12) + "..."
            )
            looksLikePassword -> Analysis(
                "Password-like Text", true,
                "⚠️ Clipboard may contain a password. Clear it after pasting.",
                "●".repeat(minOf(text.length, 8))
            )
            isUrl -> Analysis(
                "URL / Link", false,
                "ℹ️ Clipboard contains a link.",
                text.take(60) + if (text.length > 60) "…" else ""
            )
            text.length > 200 -> Analysis(
                "Long Text", false,
                "ℹ️ Clipboard contains a long text block.",
                text.take(80) + "…"
            )
            else -> Analysis(
                "Text", false,
                "",
                text.take(80) + if (text.length > 80) "…" else ""
            )
        }
    }

    /** Get apps that have recently read the clipboard via AppOps */
    suspend fun getClipboardReaders(): List<ClipboardAccessEntry> = withContext(Dispatchers.IO) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return@withContext emptyList()

        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val pm     = context.packageManager
        val results= mutableListOf<ClipboardAccessEntry>()

        val packages = pm.getInstalledPackages(0)
        for (pkg in packages) {
            val pkgName = pkg.packageName
            val appInfo = pkg.applicationInfo ?: continue
            val uid     = appInfo.uid

            val lastRead = try {
                val ops = appOps.getOpsForPackage(uid, pkgName,
                    arrayOf(AppOpsManager.OPSTR_READ_CLIPBOARD))
                val op  = ops?.firstOrNull()?.ops?.firstOrNull {
                    it.opStr == AppOpsManager.OPSTR_READ_CLIPBOARD
                } ?: continue
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    op.getLastAccessTime(AppOpsManager.OP_FLAGS_ALL)
                } else 0L
            } catch (e: Exception) { continue }

            if (lastRead <= 0) continue

            val appName = try { pm.getApplicationLabel(appInfo).toString() }
                          catch (e: Exception) { pkgName }
            val icon    = try { pm.getApplicationIcon(pkgName) }
                          catch (e: Exception) { null }
            val isSafe  = SAFE_APPS.any { pkgName.startsWith(it) }
            val isSystem= (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0

            val minutesAgo = (System.currentTimeMillis() - lastRead) / 60_000
            val risk = when {
                isSafe || isSystem    -> ThreatLevel.SAFE
                minutesAgo < 5        -> ThreatLevel.HIGH
                minutesAgo < 60       -> ThreatLevel.MEDIUM
                else                  -> ThreatLevel.LOW
            }

            results.add(ClipboardAccessEntry(appName, pkgName, lastRead, risk, icon))
        }

        results.sortedByDescending { it.risk.ordinal }
    }

    fun clearClipboard() {
        try {
            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                cm.clearPrimaryClip()
            } else {
                val clip = android.content.ClipData.newPlainText("", "")
                cm.setPrimaryClip(clip)
            }
        } catch (e: Exception) { /* ignore */ }
    }

    fun formatTimeAgo(ms: Long): String {
        val diff = System.currentTimeMillis() - ms
        val m = diff / 60_000; val h = diff / 3_600_000; val d = diff / 86_400_000
        return when { m < 1 -> "Just now"; m < 60 -> "$m min ago"
                       h < 24 -> "$h hr ago"; d == 1L -> "Yesterday"; else -> "$d days ago" }
    }
}
