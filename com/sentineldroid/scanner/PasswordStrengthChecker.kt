package com.sentineldroid.scanner

import kotlin.math.log2
import kotlin.math.pow

enum class PasswordGrade { VERY_WEAK, WEAK, FAIR, STRONG, VERY_STRONG }

data class PasswordStrengthResult(
    val grade: PasswordGrade,
    val score: Int,          // 0–100
    val entropy: Double,     // bits
    val crackTimeDisplay: String,
    val issues: List<String>,
    val suggestions: List<String>,
    val strengthLabel: String,
    val strengthColor: Int   // resource ID placeholder — mapped in fragment
)

object PasswordStrengthChecker {

    // Common weak passwords and patterns
    private val COMMON_PASSWORDS = setOf(
        "password", "password1", "123456", "12345678", "qwerty", "abc123",
        "letmein", "monkey", "master", "dragon", "111111", "baseball",
        "iloveyou", "trustno1", "sunshine", "princess", "welcome",
        "shadow", "superman", "michael", "football", "password123",
        "admin", "login", "pass", "test", "guest", "user"
    )

    private val KEYBOARD_WALKS = listOf(
        "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
        "1234567890", "0987654321", "1qaz2wsx", "qazwsx", "qweasd"
    )

    private val LEET_MAP = mapOf(
        '@' to 'a', '3' to 'e', '1' to 'i', '0' to 'o',
        '5' to 's', '7' to 't', '4' to 'a', '!' to 'i'
    )

    fun analyze(password: String): PasswordStrengthResult {
        if (password.isEmpty()) {
            return PasswordStrengthResult(
                PasswordGrade.VERY_WEAK, 0, 0.0,
                "Instant", listOf("Password is empty"), emptyList(),
                "Empty", 0
            )
        }

        val issues      = mutableListOf<String>()
        val suggestions = mutableListOf<String>()
        var score       = 0

        // ── Length ───────────────────────────────────────────────────────────
        val len = password.length
        score += when {
            len >= 20 -> 30
            len >= 16 -> 25
            len >= 12 -> 20
            len >= 10 -> 15
            len >= 8  -> 8
            else -> 0
        }
        if (len < 8)  issues      += "Too short (${len} chars) — minimum 8, ideally 16+"
        if (len < 12) suggestions += "Make it longer — aim for 16+ characters"

        // ── Character variety ────────────────────────────────────────────────
        val hasLower  = password.any { it.isLowerCase() }
        val hasUpper  = password.any { it.isUpperCase() }
        val hasDigit  = password.any { it.isDigit() }
        val hasSymbol = password.any { !it.isLetterOrDigit() }

        var charsetSize = 0
        if (hasLower)  { score += 5; charsetSize += 26 }
        if (hasUpper)  { score += 5; charsetSize += 26 }
        if (hasDigit)  { score += 5; charsetSize += 10 }
        if (hasSymbol) { score += 15; charsetSize += 32 }

        if (!hasUpper)  suggestions += "Add uppercase letters"
        if (!hasDigit)  suggestions += "Add numbers"
        if (!hasSymbol) suggestions += "Add symbols (!@#\$%^&*)"

        // ── Entropy calculation ──────────────────────────────────────────────
        val entropy = if (charsetSize > 0) len * log2(charsetSize.toDouble()) else 0.0
        score += when {
            entropy >= 100 -> 25
            entropy >= 72  -> 20
            entropy >= 50  -> 15
            entropy >= 36  -> 8
            else           -> 0
        }

        // ── Common password check ────────────────────────────────────────────
        val lowerPwd = password.lowercase()
        if (lowerPwd in COMMON_PASSWORDS) {
            score -= 40
            issues += "This is one of the most commonly used passwords — hackers try these first"
        }

        // ── Leet-speak normalization ─────────────────────────────────────────
        val deleeted = password.lowercase().map { LEET_MAP[it] ?: it }.joinToString("")
        if (deleeted in COMMON_PASSWORDS && lowerPwd !in COMMON_PASSWORDS) {
            score -= 20
            issues += "Leet-speak substitution (e.g. p@ssw0rd) is well-known to attackers"
        }

        // ── Keyboard walk detection ──────────────────────────────────────────
        val passwordLower = password.lowercase()
        val isKeyboardWalk = KEYBOARD_WALKS.any { walk ->
            passwordLower.contains(walk) || walk.contains(passwordLower)
        }
        if (isKeyboardWalk) {
            score -= 20
            issues += "Keyboard pattern detected (e.g. qwerty, 123456)"
        }

        // ── Repeated characters ───────────────────────────────────────────────
        val repeatedChars = Regex("""(.)\1{2,}""").containsMatchIn(password)
        if (repeatedChars) {
            score -= 10
            issues += "Repeated characters (e.g. aaa, 111) weaken the password"
        }

        // ── All same character class ─────────────────────────────────────────
        if (password.all { it.isLetter() }) {
            score -= 5
            suggestions += "Mix letters, numbers, and symbols"
        }

        // ── Year/date patterns ───────────────────────────────────────────────
        val yearPattern  = Regex("""(19|20)\d{2}""")
        val datePattern  = Regex("""\d{1,2}[/\-]\d{1,2}""")
        if (yearPattern.containsMatchIn(password)) {
            score -= 5
            issues += "Contains a year — predictable pattern"
        }
        if (datePattern.containsMatchIn(password)) {
            score -= 5
            issues += "Contains a date pattern — predictable"
        }

        // ── Clamp score ───────────────────────────────────────────────────────
        score = score.coerceIn(0, 100)

        // ── Grade ─────────────────────────────────────────────────────────────
        val grade = when {
            score >= 80 -> PasswordGrade.VERY_STRONG
            score >= 60 -> PasswordGrade.STRONG
            score >= 40 -> PasswordGrade.FAIR
            score >= 20 -> PasswordGrade.WEAK
            else        -> PasswordGrade.VERY_WEAK
        }

        // ── Crack time estimate ───────────────────────────────────────────────
        // Assumes 10 billion guesses/sec (modern GPU cluster)
        val combinations = charsetSize.toDouble().pow(len.toDouble())
        val secondsToCrack = combinations / 10_000_000_000.0
        val crackTime = formatCrackTime(secondsToCrack)

        val label = when (grade) {
            PasswordGrade.VERY_WEAK  -> "Very Weak"
            PasswordGrade.WEAK       -> "Weak"
            PasswordGrade.FAIR       -> "Fair"
            PasswordGrade.STRONG     -> "Strong"
            PasswordGrade.VERY_STRONG-> "Very Strong"
        }

        if (suggestions.isEmpty() && issues.isEmpty()) {
            suggestions += "✅ This password looks strong!"
        }

        return PasswordStrengthResult(
            grade          = grade,
            score          = score,
            entropy        = entropy,
            crackTimeDisplay = crackTime,
            issues         = issues,
            suggestions    = suggestions,
            strengthLabel  = label,
            strengthColor  = 0  // set by fragment
        )
    }

    private fun formatCrackTime(seconds: Double): String = when {
        seconds < 1         -> "Instant"
        seconds < 60        -> "${seconds.toInt()} seconds"
        seconds < 3_600     -> "${(seconds / 60).toInt()} minutes"
        seconds < 86_400    -> "${(seconds / 3_600).toInt()} hours"
        seconds < 2_592_000 -> "${(seconds / 86_400).toInt()} days"
        seconds < 31_536_000-> "${(seconds / 2_592_000).toInt()} months"
        seconds < 3.15e9    -> "${(seconds / 31_536_000).toInt()} years"
        seconds < 3.15e12   -> "${(seconds / 3.15e9).toLong()} thousand years"
        seconds < 3.15e15   -> "${(seconds / 3.15e12).toLong()} million years"
        else                -> "Centuries"
    }
}
