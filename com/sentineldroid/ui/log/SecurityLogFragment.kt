package com.sentineldroid.ui.log

import android.os.Bundle
import android.view.*
import android.widget.*
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.sentineldroid.R
import com.sentineldroid.scanner.LogEventType
import com.sentineldroid.scanner.SecurityLogManager
import com.sentineldroid.scanner.ThreatLevel

class SecurityLogFragment : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_log, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val container: LinearLayout = view.findViewById(R.id.ll_log_container)
        val btnClear: Button = view.findViewById(R.id.btn_clear_log)
        val tvEmpty: TextView = view.findViewById(R.id.tv_log_empty)

        val logManager = SecurityLogManager(requireContext())

        fun refresh() {
            container.removeAllViews()
            val events = logManager.getEvents()

            if (events.isEmpty()) {
                tvEmpty.visibility = View.VISIBLE
            } else {
                tvEmpty.visibility = View.GONE
                for (event in events) {
                    addLogRow(container, event)
                }
            }
        }

        btnClear.setOnClickListener {
            logManager.clearLog()
            refresh()
        }

        refresh()
    }

    private fun addLogRow(container: LinearLayout, event: com.sentineldroid.scanner.LogEvent) {
        val ctx = requireContext()
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(8, 10, 8, 10)
            gravity = android.view.Gravity.CENTER_VERTICAL
        }

        val emoji = when (event.type) {
            LogEventType.SCAN_COMPLETE -> "🔍"
            LogEventType.THREAT_FOUND -> "⚠️"
            LogEventType.VULN_FOUND -> "🔐"
            LogEventType.BREACH_DETECTED -> "🔓"
            LogEventType.NETWORK_ALERT -> "📡"
            LogEventType.VIRUS_FOUND -> "🦠"
            LogEventType.FIX_APPLIED -> "✅"
            LogEventType.APP_LOCK_AUTH -> "🔒"
        }

        val emojiTv = TextView(ctx).apply {
            text = emoji
            textSize = 20f
            setPadding(0, 0, 12, 0)
        }

        val textBlock = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val severityColor = when (event.severity) {
            ThreatLevel.CRITICAL, ThreatLevel.HIGH -> R.color.threat_high
            ThreatLevel.MEDIUM -> R.color.threat_medium
            ThreatLevel.LOW -> R.color.threat_low
            ThreatLevel.SAFE -> R.color.threat_safe
        }

        textBlock.addView(TextView(ctx).apply {
            text = event.title
            textSize = 13f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(ContextCompat.getColor(ctx, severityColor))
        })
        textBlock.addView(TextView(ctx).apply {
            text = event.detail
            textSize = 12f
            setTextColor(ContextCompat.getColor(ctx, R.color.text_secondary))
        })
        textBlock.addView(TextView(ctx).apply {
            text = event.formattedTime
            textSize = 11f
            setTextColor(ContextCompat.getColor(ctx, R.color.text_secondary))
        })

        row.addView(emojiTv)
        row.addView(textBlock)
        container.addView(row)

        val divider = View(ctx).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1)
            setBackgroundColor(ContextCompat.getColor(ctx, R.color.divider))
        }
        container.addView(divider)
    }
}
