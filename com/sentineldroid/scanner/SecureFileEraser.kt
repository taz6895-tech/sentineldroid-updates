package com.sentineldroid.scanner

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.SecureRandom

data class EraseResult(
    val fileName: String,
    val success: Boolean,
    val passes: Int,
    val bytesErased: Long,
    val message: String
)

class SecureFileEraser {

    companion object {
        const val PASSES_FAST   = 1   // Single random pass — fast
        const val PASSES_SECURE = 3   // DoD 5220.22-M standard (3-pass)
        const val PASSES_MAX    = 7   // Gutmann-inspired (7-pass)
        private const val BUFFER_SIZE = 65536  // 64 KB chunks
    }

    /**
     * Securely erases a file by overwriting it multiple times before deletion.
     * Each pass uses cryptographically random data from SecureRandom.
     *
     * Without this, deleted files can be recovered by forensic tools because
     * Android's standard delete only removes the directory entry, not the data.
     */
    suspend fun eraseFile(file: File, passes: Int = PASSES_SECURE): EraseResult =
        withContext(Dispatchers.IO) {
            if (!file.exists()) {
                return@withContext EraseResult(file.name, false, 0, 0, "File not found")
            }
            if (!file.canWrite()) {
                return@withContext EraseResult(file.name, false, 0, 0, "File is not writable")
            }

            val fileSize = file.length()
            val rng      = SecureRandom()
            val buffer   = ByteArray(BUFFER_SIZE)

            try {
                repeat(passes) { passNum ->
                    file.outputStream().use { stream ->
                        var remaining = fileSize
                        while (remaining > 0) {
                            val toWrite = minOf(remaining, BUFFER_SIZE.toLong()).toInt()
                            rng.nextBytes(buffer)
                            stream.write(buffer, 0, toWrite)
                            remaining -= toWrite
                        }
                        stream.flush()
                        stream.fd.sync()  // Force write to physical storage
                    }
                }

                // Final pass: write zeros
                file.outputStream().use { stream ->
                    buffer.fill(0)
                    var remaining = fileSize
                    while (remaining > 0) {
                        val toWrite = minOf(remaining, BUFFER_SIZE.toLong()).toInt()
                        stream.write(buffer, 0, toWrite)
                        remaining -= toWrite
                    }
                    stream.flush()
                    stream.fd.sync()
                }

                // Rename before delete (further obscures original filename)
                val tempFile = File(file.parent, "~${System.currentTimeMillis()}")
                file.renameTo(tempFile)
                tempFile.delete()

                EraseResult(file.name, true, passes, fileSize,
                    "✅ Securely erased with $passes overwrite pass${if (passes > 1) "es" else ""}")

            } catch (e: Exception) {
                // Try plain delete as fallback
                file.delete()
                EraseResult(file.name, false, 0, fileSize,
                    "⚠️ Secure erase failed, standard delete used: ${e.javaClass.simpleName}")
            }
        }

    /** Erase multiple files with progress callback */
    suspend fun eraseFiles(
        files: List<File>,
        passes: Int = PASSES_SECURE,
        onProgress: (current: Int, total: Int, fileName: String) -> Unit = { _, _, _ -> }
    ): List<EraseResult> = withContext(Dispatchers.IO) {
        files.mapIndexed { index, file ->
            onProgress(index + 1, files.size, file.name)
            eraseFile(file, passes)
        }
    }

    /** Get files in Download folder that can be erased */
    fun getErasableDownloads(): List<File> {
        val downloads = android.os.Environment.getExternalStoragePublicDirectory(
            android.os.Environment.DIRECTORY_DOWNLOADS
        )
        return try {
            downloads.listFiles()
                ?.filter { it.isFile && it.canWrite() }
                ?.sortedByDescending { it.lastModified() }
                ?: emptyList()
        } catch (e: Exception) { emptyList() }
    }

    fun formatSize(bytes: Long): String = when {
        bytes < 1024        -> "$bytes B"
        bytes < 1_048_576   -> "${bytes / 1024} KB"
        bytes < 1_073_741_824 -> "${bytes / 1_048_576} MB"
        else                -> String.format("%.1f GB", bytes / 1_073_741_824.0)
    }
}
