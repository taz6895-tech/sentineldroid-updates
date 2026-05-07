package com.sentineldroid.ui.breach

import android.os.Bundle
import android.text.InputType
import android.view.*
import android.widget.*
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.sentineldroid.R
import com.sentineldroid.scanner.BreachChecker
import com.sentineldroid.scanner.SecurityLogManager
import com.sentineldroid.scanner.ThreatLevel
import kotlinx.coroutines.launch

class BreachFragment : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, c: ViewGroup?, s: Bundle?) =
        inflater.inflate(R.layout.fragment_breach, c, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val etEmail: EditText          = view.findViewById(R.id.et_email)
        val etPassword: EditText       = view.findViewById(R.id.et_password)
        val btnCheckEmail: Button      = view.findViewById(R.id.btn_check_email)
        val btnCheckPassword: Button   = view.findViewById(R.id.btn_check_password)
        val resultsContainer: LinearLayout = view.findViewById(R.id.ll_breach_results)
        val tvStatus: TextView         = view.findViewById(R.id.tv_breach_status)
        val tvPasswordResult: TextView = view.findViewById(R.id.tv_password_result)
        val cbShowPassword: CheckBox   = view.findViewById(R.id.cb_show_password)
        val cardApiKey: LinearLayout   = view.findViewById(R.id.card_api_key_required)
        val btnGoSettings: Button      = view.findViewById(R.id.btn_go_to_settings)

        // API key banner — navigate to Settings if not set
        btnGoSettings.setOnClickListener {
            try { findNavController().navigate(R.id.settingsFragment) }
            catch (e: Exception) { /* already there */ }
        }

        cbShowPassword.setOnCheckedChangeListener { _, checked ->
            etPassword.inputType = if (checked)
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            else
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            etPassword.setSelection(etPassword.text.length)
        }

        // ── Email check ───────────────────────────────────────────────────────
        btnCheckEmail.setOnClickListener {
            val email = etEmail.text.toString().trim()
            if (email.isEmpty() || !android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
                tvStatus.text = "Please enter a valid email address"
                return@setOnClickListener
            }

            btnCheckEmail.isEnabled = false
            tvStatus.text           = "Checking breach databases..."
            resultsContainer.removeAllViews()
            cardApiKey.visibility   = View.GONE

            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    val result = BreachChecker().checkEmail(email)

                    when {
                        // FIX: handle API_KEY_REQUIRED explicitly
                        result.error == "API_KEY_REQUIRED" -> {
                            tvStatus.text         = "API key needed for full breach check"
                            cardApiKey.visibility = View.VISIBLE
                            addInfoCard(resultsContainer,
                                "🔑 Free API Key Required",
                                "The Have I Been Pwned service requires a free API key to check " +
                                "email addresses.\n\nGo to Settings → paste your key → " +
                                "come back to check.\n\n" +
                                "Alternatively, visit haveibeenpwned.com in your browser.",
                                ThreatLevel.LOW)
                        }
                        result.error != null && result.breaches.isEmpty() -> {
                            // Generic error — don't expose e.message to UI
                            tvStatus.text = "Could not complete check — ${sanitizeError(result.error)}"
                        }
                        !result.breached && result.error == null -> {
                            tvStatus.text = "✅ No breaches found for this email"
                            addInfoCard(resultsContainer,
                                "No breaches detected",
                                "This email was not found in any known data breach. " +
                                "Continue using strong, unique passwords.",
                                ThreatLevel.SAFE)
                        }
                        else -> {
                            SecurityLogManager(requireContext())
                                .logBreachDetected(email, result.breaches.size)
                            tvStatus.text = "🔴 Found in ${result.breaches.size} breach(es)!"
                            for (b in result.breaches) {
                                addBreachCard(resultsContainer, b.name, b.domain,
                                    b.date, b.dataClasses, b.description)
                            }
                            addInfoCard(resultsContainer, "What to do now",
                                "1. Change your password for the affected services immediately\n" +
                                "2. Change it everywhere you used the same password\n" +
                                "3. Enable two-factor authentication (2FA)\n" +
                                "4. Use a password manager for unique passwords",
                                ThreatLevel.HIGH)
                        }
                    }
                } catch (e: Exception) {
                    tvStatus.text = "Check failed — please try again"
                } finally {
                    btnCheckEmail.isEnabled = true
                }
            }
        }

        // ── Password check ────────────────────────────────────────────────────
        btnCheckPassword.setOnClickListener {
            val password = etPassword.text.toString()
            if (password.isEmpty()) {
                tvPasswordResult.text = "Enter a password to check"
                return@setOnClickListener
            }

            btnCheckPassword.isEnabled = false
            tvPasswordResult.text      = "Checking (k-anonymity — password stays on device)..."
            tvPasswordResult.setTextColor(ContextCompat.getColor(requireContext(), R.color.text_secondary))

            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    val (pwned, count) = BreachChecker().checkPassword(password)

                    if (pwned) {
                        tvPasswordResult.text = "🔴 Seen $count time(s) in breaches — do NOT use this password!"
                        tvPasswordResult.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_critical))
                    } else {
                        tvPasswordResult.text = "✅ Not found in known breaches"
                        tvPasswordResult.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_safe))
                    }
                } catch (e: Exception) {
                    tvPasswordResult.text = "Check failed — try again"
                } finally {
                    // FIX: clear password from EditText immediately after check
                    etPassword.text.clear()
                    cbShowPassword.isChecked = false
                    etPassword.inputType =
                        InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                    btnCheckPassword.isEnabled = true
                }
            }
        }
    }

    /** Sanitize error messages — never show raw exception messages to the user */
    private fun sanitizeError(error: String?): String = when {
        error == null                                  -> "Unknown error"
        error.contains("timeout", ignoreCase = true)  -> "Request timed out"
        error.contains("internet", ignoreCase = true) ||
        error.contains("host", ignoreCase = true)     -> "No internet connection"
        error.contains("rate", ignoreCase = true)     -> "Too many requests — wait and retry"
        error.contains("401") || error.contains("403") -> "Authentication failed"
        error.contains("503") || error.contains("502") -> "Service temporarily unavailable"
        else                                           -> "Connection failed"
    }

    private fun addBreachCard(container: LinearLayout, name: String, domain: String,
                               date: String, dataClasses: List<String>, description: String) {
        layoutInflater.inflate(R.layout.item_breach, container, false).also { card ->
            card.findViewById<TextView>(R.id.tv_breach_name).text = "🔓 $name"
            card.findViewById<TextView>(R.id.tv_breach_domain).text =
                domain.ifEmpty { "Unknown service" }
            card.findViewById<TextView>(R.id.tv_breach_date).text = "Breach date: $date"
            card.findViewById<TextView>(R.id.tv_breach_data).text =
                "Exposed: ${dataClasses.take(5).joinToString(", ")}"
            card.findViewById<TextView>(R.id.tv_breach_desc).text =
                description.ifEmpty { "No description available." }
            container.addView(card)
        }
    }

    private fun addInfoCard(container: LinearLayout, title: String, msg: String, level: ThreatLevel) {
        val ctx      = requireContext()
        val colorRes = when (level) {
            ThreatLevel.SAFE     -> R.color.threat_safe
            ThreatLevel.LOW      -> R.color.threat_low
            ThreatLevel.MEDIUM   -> R.color.threat_medium
            else                 -> R.color.threat_high
        }
        LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 16, 16, 16)
            setBackgroundColor(ContextCompat.getColor(ctx, R.color.surface))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.topMargin = 12 }

            addView(TextView(ctx).apply {
                text = title; textSize = 14f
                setTypeface(null, android.graphics.Typeface.BOLD)
                setTextColor(ContextCompat.getColor(ctx, colorRes))
            })
            addView(TextView(ctx).apply {
                text = msg; textSize = 13f
                setPadding(0, 8, 0, 0)
                setTextColor(ContextCompat.getColor(ctx, R.color.text_secondary))
            })
        }.also { container.addView(it) }
    }
}
