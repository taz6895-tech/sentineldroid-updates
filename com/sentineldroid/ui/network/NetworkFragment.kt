package com.sentineldroid.ui.network

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.sentineldroid.R
import com.sentineldroid.scanner.NetworkScanner
import com.sentineldroid.scanner.ThreatLevel
import kotlinx.coroutines.launch

class NetworkFragment : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_network, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val tvSsid: TextView = view.findViewById(R.id.tv_ssid)
        val tvStatus: TextView = view.findViewById(R.id.tv_network_status)
        val tvDescription: TextView = view.findViewById(R.id.tv_network_description)
        val detailsContainer: LinearLayout = view.findViewById(R.id.ll_details)
        val btnScan: Button = view.findViewById(R.id.btn_check_network)

        fun scan() {
            btnScan.isEnabled = false
            tvStatus.text = "Scanning..."
            detailsContainer.removeAllViews()

            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    val scanner = NetworkScanner(requireContext())
                    val result = scanner.scanNetwork()

                    tvSsid.text = "Network: ${result.ssid}"
                    tvDescription.text = result.description

                    val (statusText, color) = when (result.threatLevel) {
                        ThreatLevel.SAFE -> Pair("SECURE", R.color.threat_safe)
                        ThreatLevel.LOW -> Pair("ACCEPTABLE", R.color.threat_low)
                        ThreatLevel.MEDIUM -> Pair("CAUTION", R.color.threat_medium)
                        ThreatLevel.HIGH -> Pair("DANGER", R.color.threat_high)
                        ThreatLevel.CRITICAL -> Pair("CRITICAL", R.color.threat_critical)
                    }
                    tvStatus.text = statusText
                    tvStatus.setTextColor(ContextCompat.getColor(requireContext(), color))

                    // Add detail rows
                    for (detail in result.details) {
                        val tv = TextView(requireContext()).apply {
                            text = detail
                            textSize = 14f
                            setPadding(0, 8, 0, 8)
                            setTextColor(ContextCompat.getColor(requireContext(), R.color.text_primary))
                        }
                        detailsContainer.addView(tv)
                    }

                } catch (e: Exception) {
                    tvStatus.text = "Scan failed — please try again"
                } finally {
                    btnScan.isEnabled = true
                }
            }
        }

        btnScan.setOnClickListener { scan() }
        scan()
    }
}
