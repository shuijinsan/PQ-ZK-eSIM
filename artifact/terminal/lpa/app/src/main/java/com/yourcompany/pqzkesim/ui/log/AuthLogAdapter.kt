package com.yourcompany.pqzkesim.ui.log

// 认证日志列表适配器

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.yourcompany.pqzkesim.App
import com.yourcompany.pqzkesim.R
import com.yourcompany.pqzkesim.data.model.AuthLogItem

class AuthLogAdapter : ListAdapter<AuthLogItem, AuthLogAdapter.ViewHolder>(DiffCallback) {

    companion object DiffCallback : DiffUtil.ItemCallback<AuthLogItem>() {
        override fun areItemsTheSame(oldItem: AuthLogItem, newItem: AuthLogItem): Boolean =
            oldItem.id == newItem.id

        override fun areContentsTheSame(oldItem: AuthLogItem, newItem: AuthLogItem): Boolean =
            oldItem == newItem
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvStatus: TextView = view.findViewById(R.id.item_tv_status)
        val tvTime: TextView = view.findViewById(R.id.item_tv_time)
        val tvDuration: TextView = view.findViewById(R.id.item_tv_duration)
        val tvSession: TextView = view.findViewById(R.id.item_tv_session)
        val tvCounter: TextView = view.findViewById(R.id.item_tv_counter)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_auth_log, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        val ctx = holder.itemView.context
        holder.tvStatus.text = when (item.status) {
            "SUCCESS" -> ctx.getString(R.string.log_status_success)
            "FAILED" -> ctx.getString(R.string.log_status_failed)
            else -> item.status
        }
        holder.tvTime.text = item.time
        holder.tvDuration.text = ctx.getString(R.string.log_item_duration_format, item.durationMs)
        holder.tvSession.text = ctx.getString(R.string.log_item_session_prefix, item.sessionId.take(8))
        holder.tvCounter.text = if (item.phoneNumber.isNotEmpty())
            ctx.getString(R.string.log_item_phone_prefix, item.phoneNumber)
        else
            ctx.getString(R.string.log_item_phone_none)
    }
}
