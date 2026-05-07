package com.sentineldroid.ui.appscan

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.sentineldroid.R
import com.sentineldroid.adapter.ThreatItemAdapter
import com.sentineldroid.scanner.AppScanner
import kotlinx.coroutines.launch

class AppScanFragment : Fragment() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyText: TextView
    private lateinit var scanButton: Button
    private lateinit var statusText: TextView

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_app_scan, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        recyclerView = view.findViewById(R.id.rv_apps)
        emptyText = view.findViewById(R.id.tv_empty)
        scanButton = view.findViewById(R.id.btn_scan_apps)
        statusText = view.findViewById(R.id.tv_status)

        recyclerView.layoutManager = LinearLayoutManager(requireContext())

        scanButton.setOnClickListener { scanApps() }
        scanApps()
    }

    private fun scanApps() {
        scanButton.isEnabled = false
        statusText.text = "Scanning installed apps for spyware & suspicious permissions..."
        emptyText.visibility = View.GONE

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val scanner = AppScanner(requireContext())
                val threats = scanner.scanAllApps()

                if (threats.isEmpty()) {
                    emptyText.visibility = View.VISIBLE
                    emptyText.text = "✅ No suspicious apps detected.\nAll scanned apps appear safe."
                    recyclerView.visibility = View.GONE
                    statusText.text = "Scan complete — all clear!"
                } else {
                    recyclerView.visibility = View.VISIBLE
                    recyclerView.adapter = ThreatItemAdapter(threats)
                    statusText.text = "${threats.size} app(s) flagged — tap for details"
                }
            } catch (e: Exception) {
                statusText.text = "Operation failed — please try again"
            } finally {
                scanButton.isEnabled = true
            }
        }
    }
}
