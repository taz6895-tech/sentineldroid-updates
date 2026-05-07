package com.sentineldroid.ui.eraser

import android.os.Bundle
import android.view.*
import android.widget.*
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.sentineldroid.R
import com.sentineldroid.scanner.SecureFileEraser
import kotlinx.coroutines.launch
import java.io.File

class EraserFragment : Fragment() {

    private val eraser = SecureFileEraser()
    private val fileList = mutableListOf<File>()
    private val selected = mutableSetOf<String>()

    override fun onCreateView(i: LayoutInflater, c: ViewGroup?, s: Bundle?) =
        i.inflate(R.layout.fragment_eraser, c, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val btnLoad: Button         = view.findViewById(R.id.btn_eraser_load)
        val btnErase: Button        = view.findViewById(R.id.btn_eraser_erase)
        val container: LinearLayout = view.findViewById(R.id.ll_eraser_files)
        val tvStatus: TextView      = view.findViewById(R.id.tv_eraser_status)
        val tvTotal: TextView       = view.findViewById(R.id.tv_eraser_total)
        val spinnerPasses: Spinner  = view.findViewById(R.id.spinner_passes)

        val passOptions = arrayOf("1 pass (Fast)", "3 passes (Secure — DoD)", "7 passes (Maximum)")
        spinnerPasses.adapter = ArrayAdapter(requireContext(),
            android.R.layout.simple_spinner_item, passOptions).also {
            it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        spinnerPasses.setSelection(1) // Default: 3 passes

        btnLoad.setOnClickListener {
            container.removeAllViews()
            selected.clear()
            fileList.clear()

            val files = eraser.getErasableDownloads()
            fileList.addAll(files)

            if (files.isEmpty()) {
                tvStatus.text = "No files found in Downloads folder"
                tvTotal.text = ""
                btnErase.isEnabled = false
                return@setOnClickListener
            }

            tvStatus.text = "${files.size} file(s) in Downloads — check boxes to select"
            var totalBytes = 0L

            for (file in files) {
                totalBytes += file.length()
                val row = LinearLayout(requireContext()).apply {
                    orientation = LinearLayout.HORIZONTAL
                    setPadding(0, 8, 0, 8)
                    gravity = android.view.Gravity.CENTER_VERTICAL
                }
                val cb = CheckBox(requireContext()).apply {
                    text = "${file.name}\n${eraser.formatSize(file.length())}"
                    textSize = 13f
                    setTextColor(ContextCompat.getColor(requireContext(), R.color.text_primary))
                    setOnCheckedChangeListener { _, checked ->
                        if (checked) selected.add(file.absolutePath)
                        else selected.remove(file.absolutePath)
                        btnErase.isEnabled = selected.isNotEmpty()
                        tvTotal.text = "Selected: ${selected.size} file(s)"
                    }
                }
                row.addView(cb)
                container.addView(row)
                container.addView(View(requireContext()).apply {
                    layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1)
                    setBackgroundColor(ContextCompat.getColor(requireContext(), R.color.divider))
                })
            }

            tvTotal.text = "Total: ${files.size} files, ${eraser.formatSize(totalBytes)}"
            btnErase.isEnabled = false
        }

        btnErase.setOnClickListener {
            if (selected.isEmpty()) return@setOnClickListener

            val passes = when (spinnerPasses.selectedItemPosition) {
                0 -> SecureFileEraser.PASSES_FAST
                2 -> SecureFileEraser.PASSES_MAX
                else -> SecureFileEraser.PASSES_SECURE
            }

            btnErase.isEnabled = false
            btnLoad.isEnabled  = false
            tvStatus.text = "Securely erasing ${selected.size} file(s)..."

            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    val toErase = selected.map { File(it) }
                    val results = eraser.eraseFiles(toErase, passes) { cur, total, name ->
                        tvStatus.post { tvStatus.text = "Erasing $cur/$total: $name" }
                    }

                    val successCount = results.count { it.success }
                    val totalBytes = results.sumOf { it.bytesErased }

                    tvStatus.text = "✅ Erased $successCount/${results.size} files " +
                        "(${eraser.formatSize(totalBytes)}) with $passes pass${if (passes > 1) "es" else ""}"
                    container.removeAllViews()
                    selected.clear()
                    fileList.clear()
                    tvTotal.text = ""
                } catch (e: Exception) {
                    tvStatus.text = "Erase failed — please try again"
                } finally {
                    btnLoad.isEnabled  = true
                    btnErase.isEnabled = false
                }
            }
        }
    }
}
