package com.admirepowered.pulse.core

import android.content.Context
import android.net.Uri
import java.io.File
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject

data class PulseBackgroundRecord(
    val id: String,
    val name: String,
    val path: String,
)

object PulseBackgroundStore {
    private const val DIR = "backgrounds"
    private const val MAX_BACKUP_BYTES = 20 * 1024 * 1024

    fun list(context: Context): List<PulseBackgroundRecord> {
        return backgroundDir(context)
            .listFiles()
            .orEmpty()
            .filter { it.isFile }
            .sortedBy { it.name }
            .mapIndexed { index, file ->
                PulseBackgroundRecord(
                    id = file.name,
                    name = "背景${index + 1}",
                    path = file.absolutePath,
                )
            }
    }

    fun add(context: Context, uri: Uri): PulseBackgroundRecord {
        val dir = backgroundDir(context)
        val file = File(dir, "background-${System.currentTimeMillis()}.img")
        val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalArgumentException("无法读取背景图片")
        require(bytes.isNotEmpty()) { "背景图片为空" }
        require(bytes.size <= 20 * 1024 * 1024) { "背景图片不能超过 20MB" }
        file.writeBytes(bytes)
        return list(context).first { it.id == file.name }
    }

    fun find(context: Context, id: String): PulseBackgroundRecord? {
        return list(context).firstOrNull { it.id == id }
    }

    fun delete(context: Context, id: String): PulseBackgroundRecord? {
        val target = File(backgroundDir(context), id)
        if (target.exists()) target.delete()
        return list(context).firstOrNull()
    }

    fun exportBackupJson(context: Context, selectedPath: String): JSONObject {
        val selectedId = selectedPath
            .takeIf { it.isNotBlank() }
            ?.let(::File)
            ?.name
            .orEmpty()
        val items = JSONArray()
        list(context).forEach { record ->
            val file = File(record.path)
            if (!file.exists() || !file.isFile || file.length() <= 0 || file.length() > MAX_BACKUP_BYTES) {
                return@forEach
            }
            val data = Base64.getEncoder().encodeToString(file.readBytes())
            items.put(
                JSONObject()
                    .put("id", record.id)
                    .put("name", record.name)
                    .put("data", data),
            )
        }
        return JSONObject()
            .put("selectedId", selectedId)
            .put("items", items)
    }

    fun importBackupJson(context: Context, json: JSONObject?): String {
        json ?: return ""
        val dir = backgroundDir(context)
        dir.listFiles().orEmpty().forEach { file ->
            if (file.isFile) file.delete()
        }
        val items = json.optJSONArray("items") ?: JSONArray()
        var selectedPath = ""
        val selectedId = json.optString("selectedId")
        for (index in 0 until items.length()) {
            val item = items.optJSONObject(index) ?: continue
            val id = cleanBackupId(item.optString("id")) ?: "background-${System.currentTimeMillis()}-$index.img"
            val data = runCatching { Base64.getDecoder().decode(item.optString("data")) }.getOrNull() ?: continue
            if (data.isEmpty() || data.size > MAX_BACKUP_BYTES) continue
            val file = File(dir, id)
            file.writeBytes(data)
            if (id == selectedId) {
                selectedPath = file.absolutePath
            }
        }
        return selectedPath
    }

    private fun backgroundDir(context: Context): File {
        return File(context.filesDir, DIR).apply { mkdirs() }
    }

    private fun cleanBackupId(value: String): String? {
        val id = value.substringAfterLast('/').substringAfterLast('\\').trim()
        if (id.isBlank() || id.length > 80) return null
        return id.takeIf { it.matches(Regex("""[A-Za-z0-9._-]+""")) }
    }
}
