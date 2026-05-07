package com.sentineldroid.ui.miccamera

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.*
import android.widget.*
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.sentineldroid.R
import com.sentineldroid.scanner.MicCameraGuard
import com.sentineldroid.scanner.ThreatLevel
import kotlinx.coroutines.launch

class MicCameraFragment : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_mic_camera, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val container: LinearLayout = view.findViewById(R.id.ll_sensor_container)
        val btnScan: Button = view.findViewById(R.id.btn_sensor_scan)
        val tvStatus: TextView = view.findViewById(R.id.tv_sensor_status)

        val guard = MicCameraGuard(requireContext())

        fun scan() {
            btnScan.isEnabled = false
            tvStatus.text = "Checking sensor access history..."
            container.removeAllViews()

            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    val entries = guard.getSensorUsage()

                    if (entries.isEmpty()) {
                        tvStatus.text = "✅ No recent sensor access found (or API not available on this device)"
                    } else {
                        tvStatus.text = "${entries.size} sensor access record(s) found"

                        // Group by sensor type
                        for (sensorType in listOf("Microphone", "Camera", "Location")) {
                            val group = entries.filter { it.sensorType == sensorType }
                            if (group.isEmpty()) continue

                            val emoji = group.first().emoji
                            val header = TextView(requireContext()).apply {
                                text = "$emoji $sensorType Access (${group.size} apps)"
                                textSize = 15f
                                setTypeface(null, android.graphics.Typeface.BOLD)
                                setTextColor(ContextCompat.getColor(requireContext(), R.color.text_primary))
                                setPadding(0, 16, 0, 8)
                            }
                            container.addView(header)

                            for (entry in group) {
                                addSensorCard(container, entry, guard)
                            }
                        }
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

    private fun addSensorCard(container: LinearLayout, entry: com.sentineldroid.scanner.SensorUsageEntry,
                               guard: MicCameraGuard) {
        val ctx = requireContext()
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(8, 10, 8, 10)
            gravity = android.view.Gravity.CENTER_VERTICAL
            val bg = when (entry.risk) {
                ThreatLevel.HIGH, ThreatLevel.CRITICAL ->
                    ContextCompat.getColor(ctx, R.color.threat_high)
                ThreatLevel.MEDIUM -> ContextCompat.getColor(ctx, R.color.threat_medium)
                else -> ContextCompat.getColor(ctx, R.color.surface)
            }
            setBackgroundColor(bg)
        }

        val textBlock = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        textBlock.addView(TextView(ctx).apply {
            text = entry.appName
            textSize = 13f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(ContextCompat.getColor(ctx, R.color.text_primary))
        })

        textBlock.addView(TextView(ctx).apply {
            text = "Last access: ${guard.formatTimeAgo(entry.lastUsedMs)}"
            textSize = 12f
            setTextColor(ContextCompat.getColor(ctx, R.color.text_secondary))
        })

        if (entry.risk >= ThreatLevel.MEDIUM) {
            textBlock.addView(TextView(ctx).apply {
                text = if (entry.risk == ThreatLevel.HIGH) "⚠️ Recent access — verify this is expected!" else "ℹ️ Accessed recently"
                textSize = 12f
                setTextColor(ContextCompat.getColor(ctx, if (entry.risk == ThreatLevel.HIGH) R.color.threat_high else R.color.threat_medium))
            })
        }

        val btnManage = Button(ctx).apply {
            text = "Manage"
            textSize = 11f
            setTextColor(ContextCompat.getColor(ctx, R.color.primary))
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            setOnClickListener {
                try {
                    startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.parse("package:${entry.packageName}")
                    })
                } catch (e: Exception) {}
            }
        }

        row.addView(textBlock)
        row.addView(btnManage)
        container.addView(row)

        val divider = View(ctx).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1)
            setBackgroundColor(ContextCompat.getColor(ctx, R.color.divider))
        }
        container.addView(divider)
    }
}
