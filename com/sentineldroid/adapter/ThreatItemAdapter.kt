package com.sentineldroid.adapter

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.sentineldroid.R
import com.sentineldroid.scanner.ThreatItem
import com.sentineldroid.scanner.ThreatLevel

class ThreatItemAdapter(private val items: List<ThreatItem>) :
    RecyclerView.Adapter<ThreatItemAdapter.ViewHolder>() {

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val icon: ImageView = view.findViewById(R.id.iv_app_icon)
        val appName: TextView = view.findViewById(R.id.tv_app_name)
        val packageName: TextView = view.findViewById(R.id.tv_package)
        val threatBadge: TextView = view.findViewById(R.id.tv_threat_badge)
        val description: TextView = view.findViewById(R.id.tv_description)
        val permissionsContainer: LinearLayout = view.findViewById(R.id.ll_permissions)
        val expandButton: TextView = view.findViewById(R.id.tv_expand)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_threat, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        val ctx = holder.itemView.context

        // Icon
        if (item.icon != null) {
            holder.icon.setImageDrawable(item.icon)
        } else {
            holder.icon.setImageResource(R.drawable.ic_app_default)
        }

        holder.appName.text = item.appName
        holder.packageName.text = item.packageName
        holder.description.text = item.description

        // Threat badge
        val (badgeText, badgeColor) = when (item.threatLevel) {
            ThreatLevel.CRITICAL -> Pair("CRITICAL", R.color.threat_critical)
            ThreatLevel.HIGH -> Pair("HIGH RISK", R.color.threat_high)
            ThreatLevel.MEDIUM -> Pair("MEDIUM", R.color.threat_medium)
            ThreatLevel.LOW -> Pair("LOW", R.color.threat_low)
            ThreatLevel.SAFE -> Pair("SAFE", R.color.threat_safe)
        }
        holder.threatBadge.text = badgeText
        holder.threatBadge.setBackgroundColor(ContextCompat.getColor(ctx, badgeColor))

        // Permissions (collapsed by default)
        holder.permissionsContainer.removeAllViews()
        holder.permissionsContainer.visibility = View.GONE

        for (perm in item.permissions) {
            val tv = TextView(ctx).apply {
                text = "• $perm"
                textSize = 12f
                setPadding(0, 4, 0, 4)
                setTextColor(ContextCompat.getColor(ctx, R.color.text_secondary))
            }
            holder.permissionsContainer.addView(tv)
        }

        if (item.permissions.isNotEmpty()) {
            holder.expandButton.visibility = View.VISIBLE
            holder.expandButton.text = "Show permissions ▼"
            holder.expandButton.setOnClickListener {
                if (holder.permissionsContainer.visibility == View.GONE) {
                    holder.permissionsContainer.visibility = View.VISIBLE
                    holder.expandButton.text = "Hide permissions ▲"
                } else {
                    holder.permissionsContainer.visibility = View.GONE
                    holder.expandButton.text = "Show permissions ▼"
                }
            }
        } else {
            holder.expandButton.visibility = View.GONE
        }
    }

    override fun getItemCount() = items.size
}
