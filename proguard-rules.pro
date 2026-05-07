# SentinelDroid ProGuard Rules
# FIX: this file was referenced in build.gradle but missing — obfuscation was silently broken

# ── Keep app entry points ─────────────────────────────────────────────────────
-keep class com.sentineldroid.MainActivity
-keep class com.sentineldroid.ui.** { *; }
-keep class com.sentineldroid.update.UpdateBannerView { *; }

# ── Keep data classes (needed for serialization/reflection) ───────────────────
-keep class com.sentineldroid.scanner.ThreatItem    { *; }
-keep class com.sentineldroid.scanner.BreachEntry   { *; }
-keep class com.sentineldroid.scanner.BreachResult  { *; }
-keep class com.sentineldroid.scanner.VulnItem      { *; }
-keep class com.sentineldroid.scanner.VirusItem     { *; }
-keep class com.sentineldroid.scanner.NetworkThreat { *; }
-keep class com.sentineldroid.scanner.SecuritySummary { *; }
-keep class com.sentineldroid.scanner.LogEvent      { *; }
-keep class com.sentineldroid.scanner.RootCheckResult { *; }
-keep class com.sentineldroid.update.UpdateInfo     { *; }

# ── Obfuscate scanner internals (security-sensitive logic) ────────────────────
# These are obfuscated to make reverse-engineering harder
# The scanner logic, malware lists, and heuristics will be renamed

# ── AndroidX / Material ───────────────────────────────────────────────────────
-keep class androidx.** { *; }
-dontwarn androidx.**
-keep class com.google.android.material.** { *; }

# ── Biometric ─────────────────────────────────────────────────────────────────
-keep class androidx.biometric.** { *; }

# ── Navigation ────────────────────────────────────────────────────────────────
-keep class * extends androidx.fragment.app.Fragment {}
-keepnames class * extends androidx.fragment.app.Fragment

# ── Suppress warnings for unused platform classes ─────────────────────────────
-dontwarn java.lang.invoke.**
-dontwarn **$$Lambda$*
-dontwarn kotlin.**
-dontwarn kotlinx.**

# ── Security: remove debug logging in release builds ─────────────────────────
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# ── Prevent reflection-based attacks on internal classes ─────────────────────
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes EnclosingMethod

# ── Optimize aggressively ─────────────────────────────────────────────────────
-optimizationpasses 5
-allowaccessmodification
-dontusemixedcaseclassnames
