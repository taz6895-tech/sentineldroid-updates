package com.sentineldroid.ui.clipboard

import android.os.Bundle
import android.view.*
import android.widget.*
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.sentineldroid.R
import com.sentineldroid.scanner.ClipboardMonitor
import com.sentineldroid.scanner.ThreatLevel
import kotlinx.coroutines.launch

class ClipboardFragment : Fragment() {
    override fun onCreateView(i: LayoutInflater, c: ViewGroup?, s: Bundle?) =
        i.inflate(R.layout.fragment_clipboard, c, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val tvType: TextView        = view.findViewById(R.id.tv_clip_type)
        val tvPreview: TextView     = view.findViewById(R.id.tv_clip_preview)
        val tvWarning: TextView     = view.findViewById(R.id.tv_clip_warning)
        val btnClear: Button        = view.findViewById(R.id.btn_clear_clipboard)
        val btnScan: Button         = view.findViewById(R.id.btn_clip_scan)
        val tvStatus: TextView      = view.findViewById(R.id.tv_clip_status)
        val container: LinearLayout = view.findViewById(R.id.ll_clip_readers)

        val monitor = ClipboardMonitor(requireContext())

        fun refresh() {
            val snap = monitor.snapshotClipboard()
            tvType.text    = "Type: ${snap.contentType}"
            tvPreview.text = if (snap.hasContent) snap.contentPreview else "(clipboard is empty)"
            tvWarning.text = snap.warning
            tvWarning.visibility = if (snap.warning.isNotBlank()) View.VISIBLE else View.GONE
            tvWarning.setTextColor(ContextCompat.getColor(requireContext(),
                if (snap.isSensitive) R.color.threat_high else R.color.text_secondary))
        }

        btnClear.setOnClickListener {
            monitor.clearClipboard()
            tvType.text    = "Type: Empty"
            tvPreview.text = "(clipboard cleared)"
            tvWarning.text = "✅ Clipboard cleared — sensitive data removed"
            tvWarning.visibility = View.VISIBLE
            tvWarning.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_safe))
        }

        btnScan.setOnClickListener {
            btnScan.isEnabled = false
            tvStatus.text = "Checking which apps have accessed clipboard..."
            container.removeAllViews()

            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    val readers = monitor.getClipboardReaders()
                    if (readers.isEmpty()) {
                        tvStatus.text = "✅ No clipboard access records found"
                    } else {
                        tvStatus.text = "${readers.size} app(s) have read clipboard"
                        for (entry in readers) {
                            val row = LinearLayout(requireContext()).apply {
                                orientation = LinearLayout.VERTICAL
                                setPadding(0, 10, 0, 10)
                            }
                            val riskColor = when (entry.risk) {
                                ThreatLevel.HIGH, ThreatLevel.CRITICAL -> R.color.threat_high
                                ThreatLevel.MEDIUM -> R.color.threat_medium
                                ThreatLevel.LOW    -> R.color.threat_low
                                else               -> R.color.threat_safe
                            }
                            row.addView(TextView(requireContext()).apply {
                                text = entry.appName; textSize = 14f
                                setTypeface(null, android.graphics.Typeface.BOLD)
                                setTextColor(ContextCompat.getColor(requireContext(), riskColor))
                            })
                            row.addView(TextView(requireContext()).apply {
                                text = "Last access: ${monitor.formatTimeAgo(entry.lastAccessMs)} · ${entry.packageName}"
                                textSize = 11f
                                setTextColor(ContextCompat.getColor(requireContext(), R.color.text_secondary))
                            })
                            container.addView(row)
                            container.addView(View(requireContext()).apply {
                                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1)
                                setBackgroundColor(ContextCompat.getColor(requireContext(), R.color.divider))
                            })
                        }
                    }
                } catch (e: Exception) {
                    tvStatus.text = "Scan failed — please try again"
                } finally { btnScan.isEnabled = true }
            }
        }

        refresh()
    }
}
