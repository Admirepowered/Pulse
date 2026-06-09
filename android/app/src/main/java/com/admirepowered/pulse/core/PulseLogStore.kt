package com.admirepowered.pulse.core

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class PulseLogEntry(
    val time: String,
    val level: String,
    val message: String,
)

object PulseLogStore {
    private const val LOG_FILE = "pulse.log"
    private const val MAX_LINES = 400
    private val lock = Any()
    private val formatter = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault())

    fun info(context: Context, message: String) {
        append(context, "INFO", message)
    }

    fun warn(context: Context, message: String) {
        append(context, "WARN", message)
    }

    fun error(context: Context, message: String) {
        append(context, "ERROR", message)
    }

    fun read(context: Context): List<PulseLogEntry> {
        val file = logFile(context)
        if (!file.exists()) return emptyList()
        return synchronized(lock) {
            file.readLines(Charsets.UTF_8)
                .takeLast(MAX_LINES)
                .mapNotNull(::decodeLine)
                .asReversed()
        }
    }

    fun clear(context: Context) {
        synchronized(lock) {
            logFile(context).writeText("", Charsets.UTF_8)
        }
    }

    private fun append(context: Context, level: String, message: String) {
        synchronized(lock) {
            val file = logFile(context)
            file.parentFile?.mkdirs()
            val line = "${formatter.format(Date())}\t$level\t${message.replace('\n', ' ')}"
            file.appendText("$line\n", Charsets.UTF_8)
            trim(file)
        }
    }

    private fun trim(file: File) {
        val lines = file.readLines(Charsets.UTF_8)
        if (lines.size <= MAX_LINES) return
        file.writeText(lines.takeLast(MAX_LINES).joinToString("\n", postfix = "\n"), Charsets.UTF_8)
    }

    private fun logFile(context: Context): File {
        return File(context.filesDir, LOG_FILE)
    }

    private fun decodeLine(line: String): PulseLogEntry? {
        val parts = line.split("\t", limit = 3)
        if (parts.size != 3) return null
        return PulseLogEntry(parts[0], parts[1], parts[2])
    }
}
