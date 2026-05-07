package com.sentineldroid.ui.dns

import android.os.Bundle
import android.view.*
import android.widget.*
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.sentineldroid.R
import com.sentineldroid.scanner.DnsLeakChecker
import com.sentineldroid.scanner.ThreatLevel
import kotlinx.coroutines.launch

class DnsFragment : Fragment() {
    override fun onCreateView(i: LayoutInflater, c: ViewGroup?, s: Bundle?) =
        i.inflate(R.layout.fragment_dns, c, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val tvResult: TextView      = view.findViewById(R.id.tv_dns_result)
        val tvSummary: TextView     = view.findViewById(R.id.tv_dns_summary)
        val tvIp: TextView          = view.findViewById(R.id.tv_dns_ip)
        val tvVpn: TextView         = view.findViewById(R.id.tv_dns_vpn)
        val serversContainer: LinearLayout = view.findViewById(R.id.ll_dns_servers)
        val recsContainer: LinearLayout    = view.findViewById(R.id.ll_dns_recs)
        val btnCheck: Button        = view.findViewById(R.id.btn_dns_check)
        val tvStatus: TextView      = view.findViewById(R.id.tv_dns_status)

        val checker = DnsLeakChecker()

        btnCheck.setOnClickListener {
            btnCheck.isEnabled = false
            tvStatus.text = "Testing DNS configuration..."
            tvResult.text = "Checking..."
            serversContainer.removeAllViews()
            recsContainer.removeAllViews()

            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    val result = checker.check(requireContext())

                    val (label, color) = when (result.riskLevel) {
                        ThreatLevel.SAFE   -> Pair("✅ SECURE",   R.color.threat_safe)
                        ThreatLevel.LOW    -> Pair("🟡 LOW RISK", R.color.threat_low)
                        ThreatLevel.MEDIUM -> Pair("🟠 CAUTION",  R.color.threat_medium)
                        else               -> Pair("🔴 LEAK",     R.color.threat_high)
                    }
                    tvResult.text = label
                    tvResult.setTextColor(ContextCompat.getColor(requireContext(), color))
                    tvSummary.text = result.summary
                    tvIp.text = "Your public IP: ${result.publicIp} (${result.ipLocation})"
                    tvVpn.text = if (result.vpnActive) "🔒 VPN: Active" else "⚠️ VPN: Not active"
                    tvVpn.setTextColor(ContextCompat.getColor(requireContext(),
                        if (result.vpnActive) R.color.threat_safe else R.color.threat_medium))
                    tvStatus.text = "Check complete"

                    // DNS Servers
                    for (server in result.dnsServers) {
                        val tv = TextView(requireContext()).apply {
                            text = "${if (server.isTrusted) "✅" else "⚠️"} ${server.ip} — ${server.provider}"
                            textSize = 13f
                            setPadding(0, 6, 0, 6)
                            setTextColor(ContextCompat.getColor(requireContext(),
                                if (server.isTrusted) R.color.threat_safe else R.color.threat_medium))
                        }
                        serversContainer.addView(tv)
                    }

                    // Recommendations
                    for (rec in result.recommendations) {
                        recsContainer.addView(TextView(requireContext()).apply {
                            text = rec; textSize = 13f
                            setPadding(0, 6, 0, 6)
                            setTextColor(ContextCompat.getColor(requireContext(), R.color.text_primary))
                        })
                    }
                } catch (e: Exception) {
                    tvStatus.text = "Check failed — please try again"
                } finally { btnCheck.isEnabled = true }
            }
        }
    }
}
