package com.sentineldroid.applock

import android.content.Context
import android.content.SharedPreferences
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import java.security.SecureRandom

class AppLockManager(private val context: Context) {

    private val prefs: SharedPreferences by lazy { buildEncryptedPrefs() }

    private fun buildEncryptedPrefs(): SharedPreferences {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                "sentineldroid_applock_enc",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            // Fallback if keystore unavailable (very old devices)
            context.getSharedPreferences("sentineldroid_applock", Context.MODE_PRIVATE)
        }
    }

    companion object {
        private const val KEY_LOCKED_APPS      = "locked_apps"
        private const val KEY_PIN_HASH         = "pin_hash"
        private const val KEY_PIN_SALT         = "pin_salt"
        private const val KEY_USE_BIOMETRIC    = "use_biometric"
        private const val KEY_APP_LOCK_ENABLED = "app_lock_enabled"
        private const val KEY_FAIL_COUNT       = "fail_count"
        private const val KEY_LOCKOUT_UNTIL_MS = "lockout_until_ms"

        private const val MAX_ATTEMPTS        = 5
        private const val LOCKOUT_DURATION_MS = 30_000L
        private const val MIN_PIN_LENGTH      = 4
        private const val MAX_PIN_LENGTH      = 12
        private const val SALT_BYTES          = 32
        private const val HASH_ITERATIONS     = 10_000

        private val WEAK_PINS = setOf(
            "1234","0000","1111","2222","3333","4444",
            "5555","6666","7777","8888","9999","0123",
            "1230","4321","0987","9876","1212","0101"
        )
    }

    fun isAppLockEnabled() = prefs.getBoolean(KEY_APP_LOCK_ENABLED, false)
    fun hasPinSet()        = prefs.getString(KEY_PIN_HASH, null) != null

    fun setPin(pin: String): Boolean {
        if (pin.length < MIN_PIN_LENGTH || pin.length > MAX_PIN_LENGTH) return false
        if (pin in WEAK_PINS || pin.all { it == pin[0] })               return false

        val salt = generateSalt()
        val hash = hashPin(pin, salt)
        prefs.edit()
            .putString(KEY_PIN_HASH,           hash)
            .putString(KEY_PIN_SALT,           salt)
            .putBoolean(KEY_APP_LOCK_ENABLED,  true)
            .putInt(KEY_FAIL_COUNT,            0)
            .putLong(KEY_LOCKOUT_UNTIL_MS,     0L)
            .apply()
        return true
    }

    /** Returns null=locked-out | true=correct | false=wrong */
    fun verifyPin(pin: String): Boolean? {
        val lockoutUntil = prefs.getLong(KEY_LOCKOUT_UNTIL_MS, 0L)
        if (System.currentTimeMillis() < lockoutUntil) return null

        val storedHash = prefs.getString(KEY_PIN_HASH, null) ?: return false
        val storedSalt = prefs.getString(KEY_PIN_SALT, null) ?: return false
        val correct    = constantTimeEquals(hashPin(pin, storedSalt), storedHash)

        if (correct) {
            prefs.edit().putInt(KEY_FAIL_COUNT, 0).putLong(KEY_LOCKOUT_UNTIL_MS, 0L).apply()
        } else {
            val fails = prefs.getInt(KEY_FAIL_COUNT, 0) + 1
            val edit  = prefs.edit().putInt(KEY_FAIL_COUNT, fails)
            if (fails >= MAX_ATTEMPTS) {
                edit.putLong(KEY_LOCKOUT_UNTIL_MS, System.currentTimeMillis() + LOCKOUT_DURATION_MS)
                    .putInt(KEY_FAIL_COUNT, 0)
            }
            edit.apply()
        }
        return correct
    }

    fun getLockoutRemainingMs(): Long {
        val until = prefs.getLong(KEY_LOCKOUT_UNTIL_MS, 0L)
        return maxOf(0L, until - System.currentTimeMillis())
    }

    fun getRemainingAttempts() = maxOf(0, MAX_ATTEMPTS - prefs.getInt(KEY_FAIL_COUNT, 0))

    fun clearPin() {
        prefs.edit()
            .remove(KEY_PIN_HASH).remove(KEY_PIN_SALT)
            .putBoolean(KEY_APP_LOCK_ENABLED, false)
            .putStringSet(KEY_LOCKED_APPS, emptySet())
            .putInt(KEY_FAIL_COUNT, 0).putLong(KEY_LOCKOUT_UNTIL_MS, 0L)
            .apply()
    }

    fun setBiometricEnabled(enabled: Boolean) =
        prefs.edit().putBoolean(KEY_USE_BIOMETRIC, enabled).apply()
    fun isBiometricEnabled() = prefs.getBoolean(KEY_USE_BIOMETRIC, false)

    fun getLockedApps(): Set<String> = prefs.getStringSet(KEY_LOCKED_APPS, emptySet()) ?: emptySet()

    fun lockApp(packageName: String) {
        if (!isValidPackageName(packageName)) return
        val s = getLockedApps().toMutableSet().also { it.add(packageName) }
        prefs.edit().putStringSet(KEY_LOCKED_APPS, s).apply()
    }

    fun unlockApp(packageName: String) {
        val s = getLockedApps().toMutableSet().also { it.remove(packageName) }
        prefs.edit().putStringSet(KEY_LOCKED_APPS, s).apply()
    }

    fun isAppLocked(pkg: String) = pkg in getLockedApps()

    fun isBiometricAvailable() = try {
        BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
    } catch (e: Exception) { false }

    fun showBiometricPrompt(
        activity: FragmentActivity,
        title: String = "Unlock SentinelDroid",
        subtitle: String = "Authenticate to access protected content",
        onSuccess: () -> Unit,
        onFailed: () -> Unit,
        onError: (String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(context)
        val cb = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) { onSuccess() }
            override fun onAuthenticationFailed() { onFailed() }
            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                val safe = when (code) {
                    BiometricPrompt.ERROR_LOCKOUT            -> "Too many attempts. Wait 30s."
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT  -> "Biometric locked. Use PIN."
                    BiometricPrompt.ERROR_CANCELED,
                    BiometricPrompt.ERROR_USER_CANCELED      -> "Canceled"
                    BiometricPrompt.ERROR_NO_BIOMETRICS      -> "No biometrics enrolled"
                    BiometricPrompt.ERROR_HW_NOT_PRESENT     -> "No biometric hardware"
                    else                                     -> "Authentication failed"
                }
                onError(safe)
            }
        }
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title).setSubtitle(subtitle)
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()
        BiometricPrompt(activity, executor, cb).authenticate(info)
    }

    private fun hashPin(pin: String, salt: String): String {
        val md    = MessageDigest.getInstance("SHA-256")
        var bytes = (pin + salt).toByteArray(Charsets.UTF_8)
        repeat(HASH_ITERATIONS) { bytes = md.digest(bytes) }
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun generateSalt(): String {
        val b = ByteArray(SALT_BYTES)
        SecureRandom().nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }

    private fun isValidPackageName(pkg: String) =
        pkg.isNotBlank() && pkg.length <= 255 &&
        pkg.matches(Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+\$"))
}
