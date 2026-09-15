package com.yourcompany.pqzkesim.ui.log


import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.yourcompany.pqzkesim.R
import com.yourcompany.pqzkesim.viewmodel.LogViewModel

class LogFragment : Fragment() {

    private val viewModel: LogViewModel by activityViewModels()
    private lateinit var adapter: AuthLogAdapter
    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyView: TextView
    private lateinit var btnClear: TextView

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_log, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        recyclerView = view.findViewById(R.id.log_recycler_view)
        emptyView = view.findViewById(R.id.log_empty_view)
        btnClear = view.findViewById(R.id.log_btn_clear)

        adapter = AuthLogAdapter()
        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        recyclerView.adapter = adapter

        btnClear.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle(getString(R.string.log_dialog_clear_title))
                .setMessage(getString(R.string.log_dialog_clear_message))
                .setPositiveButton(getString(R.string.log_dialog_confirm)) { _, _ -> viewModel.clearAll() }
                .setNegativeButton(getString(R.string.log_dialog_cancel), null)
                .show()
        }

        viewModel.allLogs.observe(viewLifecycleOwner) { logs ->
            adapter.submitList(logs)
            val isEmpty = logs.isEmpty()
            recyclerView.visibility = if (isEmpty) View.GONE else View.VISIBLE
            btnClear.visibility = if (isEmpty) View.GONE else View.VISIBLE
            emptyView.visibility = if (isEmpty) View.VISIBLE else View.GONE
        }
    }
}
