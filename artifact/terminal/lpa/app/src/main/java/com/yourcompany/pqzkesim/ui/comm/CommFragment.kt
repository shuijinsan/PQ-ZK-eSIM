package com.yourcompany.pqzkesim.ui.comm

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import com.yourcompany.pqzkesim.R
import com.yourcompany.pqzkesim.data.model.OperatorStatus
import com.yourcompany.pqzkesim.viewmodel.CommViewModel
import com.yourcompany.pqzkesim.viewmodel.OperatorCardUiState

class CommFragment : Fragment() {

    private val viewModel: CommViewModel by viewModels()

    // Card views
    private lateinit var cardMobile: LinearLayout
    private lateinit var cardUnicom: LinearLayout
    private lateinit var cardTelecom: LinearLayout
    private lateinit var expandMobile: LinearLayout
    private lateinit var expandUnicom: LinearLayout
    private lateinit var expandTelecom: LinearLayout
    private lateinit var statusMobile: TextView
    private lateinit var statusUnicom: TextView
    private lateinit var statusTelecom: TextView

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_comm, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        bindViews(view)
        setupListeners()
        observeViewModel()
    }

    private fun bindViews(view: View) {
        cardMobile  = view.findViewById(R.id.card_mobile)
        cardUnicom  = view.findViewById(R.id.card_unicom)
        cardTelecom = view.findViewById(R.id.card_telecom)
        expandMobile  = view.findViewById(R.id.expand_mobile)
        expandUnicom  = view.findViewById(R.id.expand_unicom)
        expandTelecom = view.findViewById(R.id.expand_telecom)
        statusMobile  = view.findViewById(R.id.status_mobile)
        statusUnicom  = view.findViewById(R.id.status_unicom)
        statusTelecom = view.findViewById(R.id.status_telecom)
    }

    private fun setupListeners() {
        cardMobile.setOnClickListener  { viewModel.toggleExpand(0) }
        cardUnicom.setOnClickListener  { viewModel.toggleExpand(1) }
        cardTelecom.setOnClickListener { viewModel.toggleExpand(2) }
    }

    private fun observeViewModel() {
        viewModel.uiCards.observe(viewLifecycleOwner) { cards ->
            if (cards.size >= 3) {
                updateCard(cards[0], statusMobile, expandMobile)
                updateCard(cards[1], statusUnicom, expandUnicom)
                updateCard(cards[2], statusTelecom, expandTelecom)
            }
        }

        viewModel.expandedCardIndex.observe(viewLifecycleOwner) { index ->
            val cards = viewModel.uiCards.value ?: return@observe
            updateExpandState(0, index, expandMobile, cards.getOrNull(0))
            updateExpandState(1, index, expandUnicom, cards.getOrNull(1))
            updateExpandState(2, index, expandTelecom, cards.getOrNull(2))
        }
    }

    private fun updateCard(card: OperatorCardUiState, statusView: TextView,
                           expandLayout: LinearLayout) {
        val isBound = card.operatorInfo.status == OperatorStatus.BOUND

        // Status badge
        statusView.text = if (isBound) getString(R.string.comm_status_bound) else getString(R.string.comm_status_unbound)
        statusView.setTextColor(
            if (isBound) android.graphics.Color.parseColor("#10B981")
            else android.graphics.Color.parseColor("#EF4444")
        )

        // Rebuild expand content — each profile entry displayed vertically
        expandLayout.removeAllViews()

        if (isBound && card.phoneNumbers.isNotEmpty()) {
            val count = card.phoneNumbers.size
            for (i in 0 until count) {
                val phone = card.phoneNumbers.getOrElse(i) { "" }
                val iccid = card.iccids.getOrElse(i) { "" }
                val activatedAt = card.activatedAts.getOrElse(i) { "" }

                // Phone number
                addInfoRow(expandLayout, getString(R.string.comm_label_phone), phone)
                // ICCID
                if (iccid.isNotEmpty()) {
                    val displayIccid = if (iccid.length > 12) {
                        "${iccid.take(8)}...${iccid.takeLast(4)}"
                    } else iccid
                    addInfoRow(expandLayout, getString(R.string.comm_label_iccid), displayIccid)
                }
                // Activation time
                if (activatedAt.isNotEmpty()) {
                    addInfoRow(expandLayout, getString(R.string.comm_label_activated_time), activatedAt)
                }

                if (i < count - 1) {
                    val divider = View(requireContext()).apply {
                        val lp = LinearLayout.LayoutParams(
                            LinearLayout.LayoutParams.MATCH_PARENT,
                            (1.5f * resources.displayMetrics.density).toInt())
                        lp.setMargins(0, (10 * resources.displayMetrics.density).toInt(),
                            0, (10 * resources.displayMetrics.density).toInt())
                        layoutParams = lp
                        setBackgroundColor(android.graphics.Color.parseColor("#D1D5DB"))
                    }
                    expandLayout.addView(divider)
                }
            }
        } else {
            addInfoRow(expandLayout, "", getString(R.string.comm_no_service))
        }
    }

    private fun addInfoRow(parent: LinearLayout, label: String, value: String) {
        val row = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 6, 0, 6)
        }
        if (label.isNotEmpty()) {
            val labelTv = TextView(requireContext()).apply {
                text = label
                setTextColor(android.graphics.Color.parseColor("#6B7280"))
                textSize = 12f
            }
            row.addView(labelTv)
        }
        val valueTv = TextView(requireContext()).apply {
            text = value
            setTextColor(
                if (label.isEmpty()) android.graphics.Color.parseColor("#9CA3AF")
                else android.graphics.Color.parseColor("#1F2937")
            )
            textSize = 14f
            setPadding(0, if (label.isEmpty()) 0 else 4, 0, 0)
        }
        row.addView(valueTv)
        parent.addView(row)
    }

    private fun updateExpandState(cardIndex: Int, selectedIndex: Int,
                                  expandLayout: LinearLayout,
                                  card: OperatorCardUiState?) {
        expandLayout.visibility = if (cardIndex == selectedIndex) View.VISIBLE else View.GONE
    }
}
