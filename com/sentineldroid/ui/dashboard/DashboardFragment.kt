package com.sentineldroid.ui.dashboard

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.sentineldroid.R
import com.sentineldroid.scanner.AppScanner
import com.sentineldroid.scanner.NetworkScanner
import com.sentineldroid.scanner.SecuritySummary
import com.sentineldroid.scanner.ThreatLevel
import com.sentineldroid.update.UpdateBannerView
import com.sentineldroid.update.UpdateChecker
import kotlinx.coroutines.launch

class DashboardFragment : Fragment() {

    private lateinit var scoreText: TextView
    private lateinit var scoreBar: ProgressBar
    private lateinit var scoreLabel: TextView
    private lateinit var statusCard: CardView
    private lateinit var highRiskText: TextView
    private lateinit var suspiciousText: TextView
    private lateinit var keyloggerText: TextView
    private lateinit var locationText: TextView
    private lateinit var networkText: TextView
    private lateinit var scanButton: Button
    private lateinit var loadingText: TextView
    private lateinit var updateBanner: UpdateBannerView
    private lateinit var tvAppVersion: TextView

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_dashboard, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        scoreText    = view.findViewById(R.id.tv_score)
        scoreBar     = view.findViewById(R.id.progress_score)
        scoreLabel   = view.findViewById(R.id.tv_score_label)
        statusCard   = view.findViewById(R.id.card_status)
        highRiskText = view.findViewById(R.id.tv_high_risk)
        suspiciousText = view.findViewById(R.id.tv_suspicious)
        keyloggerText  = view.findViewById(R.id.tv_keylogger)
        locationText   = view.findViewById(R.id.tv_location)
        networkText    = view.findViewById(R.id.tv_network)
        scanButton   = view.findViewById(R.id.btn_scan)
        loadingText  = view.findViewById(R.id.tv_loading)
        updateBanner = view.findViewById(R.id.update_banner)
        tvAppVersion = view.findViewById(R.id.tv_app_version)

        tvAppVersion.text = "SentinelDroid v${UpdateChecker.CURRENT_VERSION}"

        scanButton.setOnClickListener { runFullScan() }
        checkForUpdates()
        runFullScan()
    }

    // ─── Update Check ─────────────────────────────────────────────────────────

    private fun checkForUpdates() {
        val checker = UpdateChecker(requireContext())
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val info = checker.checkForUpdate()
                if (info.updateAvailable) {
                    updateBanner.showUpdate(info, checker)
                }
            } catch (e: Exception) {
                // Silently fail — don't bother user if update check fails
            }
        }
    }

    // ─── Security Scan ────────────────────────────────────────────────────────

    private fun runFullScan() {
        scanButton.isEnabled = false
        loadingText.visibility = View.VISIBLE
        loadingText.text = "Scanning device..."

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val appScanner = AppScanner(requireContext())
                val networkScanner = NetworkScanner(requireContext())

                loadingText.text = "Analyzing apps..."
                val summary = appScanner.buildSecuritySummary()

                loadingText.text = "Checking network..."
                val networkThreat = networkScanner.scanNetwork()

                val finalSummary = summary.copy(networkSafe = networkThreat.threatLevel <= ThreatLevel.LOW)
                updateUI(finalSummary, networkThreat.ssid, networkThreat.threatLevel)

            } catch (e: Exception) {
                loadingText.text = "Scan failed — please try again"
            } finally {
                loadingText.visibility = View.GONE
                scanButton.isEnabled = true
            }
        }
    }

    private fun updateUI(summary: SecuritySummary, networkSsid: String, netLevel: ThreatLevel) {
        scoreText.text = "${summary.score}"
        scoreBar.progress = summary.score

        val (labelText, labelColor) = when {
            summary.score >= 80 -> Pair("Good",    R.color.threat_safe)
            summary.score >= 60 -> Pair("Fair",    R.color.threat_low)
            summary.score >= 40 -> Pair("At Risk", R.color.threat_medium)
            else                -> Pair("Danger",  R.color.threat_critical)
        }
        scoreLabel.text = labelText
        scoreLabel.setTextColor(ContextCompat.getColor(requireContext(), labelColor))

        highRiskText.text = if (summary.highRiskApps == 0)
            "✅ No high-risk apps found"
        else "🔴 ${summary.highRiskApps} high-risk app(s) detected"

        suspiciousText.text = if (summary.suspiciousApps == 0)
            "✅ No suspicious apps"
        else "🟠 ${summary.suspiciousApps} suspicious app(s)"

        keyloggerText.text = if (!summary.keyloggerRisk)
            "✅ No keylogger risk detected"
        else "🔴 Potential keylogger found! Check Threats tab"

        locationText.text = if (summary.locationTrackers == 0)
            "✅ No background location trackers"
        else "🟠 ${summary.locationTrackers} background tracker(s)"

        networkText.text = when (netLevel) {
            ThreatLevel.SAFE -> "✅ Network secure ($networkSsid)"
            ThreatLevel.LOW  -> "🟡 Network OK ($networkSsid)"
            ThreatLevel.MEDIUM -> "🟠 Network uncertain ($networkSsid)"
            ThreatLevel.HIGH, ThreatLevel.CRITICAL -> "🔴 Insecure network! ($networkSsid)"
        }
    }
}
