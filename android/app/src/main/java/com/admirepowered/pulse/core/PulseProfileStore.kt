package com.admirepowered.pulse.core

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest

data class PulseProfileRecord(
    val id: String,
    val name: String,
    val url: String,
    val path: String,
    val updatedAt: Long,
)

object PulseProfileStore {
    private const val PREFS = "pulse_profiles"
    private const val ACTIVE_ID = "active_profile_id"
    private const val PROFILE_PREFIX = "profile_"

    fun list(context: Context): List<PulseProfileRecord> {
        ensureDefaultProfile(context)
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return prefs.all.keys
            .filter { it.startsWith(PROFILE_PREFIX) }
            .mapNotNull { key -> prefs.getString(key, null)?.let(::decodeRecord) }
            .sortedByDescending { it.updatedAt }
    }

    fun active(context: Context): PulseProfileRecord {
        val profiles = list(context)
        val activeId = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(ACTIVE_ID, null)
        return profiles.firstOrNull { it.id == activeId } ?: profiles.first()
    }

    fun select(context: Context, profileId: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(ACTIVE_ID, profileId)
            .apply()
    }

    fun importFromUrl(
        context: Context,
        profileUrl: String,
        activate: Boolean = true,
        useProxy: Boolean = false,
    ): PulseProfileRecord {
        val trimmedUrl = profileUrl.trim()
        require(trimmedUrl.startsWith("http://") || trimmedUrl.startsWith("https://")) {
            "请输入 http 或 https 订阅地址"
        }
        val body = download(context, trimmedUrl, useProxy)
        val id = stableId(trimmedUrl)
        val name = profileName(trimmedUrl)
        val file = profileFile(context, id)
        file.writeText(body, Charsets.UTF_8)
        val record = PulseProfileRecord(
            id = id,
            name = name,
            url = trimmedUrl,
            path = file.absolutePath,
            updatedAt = System.currentTimeMillis(),
        )
        val editor = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(PROFILE_PREFIX + id, encodeRecord(record))
        if (activate) {
            editor.putString(ACTIVE_ID, id)
        }
        editor.apply()
        return record
    }

    private fun ensureDefaultProfile(context: Context) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.all.keys.any { it.startsWith(PROFILE_PREFIX) }) {
            repairDefaultProfile(context)
            return
        }
        val file = profileFile(context, "default")
        if (!file.exists()) {
            file.writeText(defaultConfig(), Charsets.UTF_8)
        }
        repairDefaultProfile(context)
        val record = PulseProfileRecord(
            id = "default",
            name = "默认直连",
            url = "",
            path = file.absolutePath,
            updatedAt = System.currentTimeMillis(),
        )
        prefs.edit()
            .putString(PROFILE_PREFIX + record.id, encodeRecord(record))
            .putString(ACTIVE_ID, record.id)
            .apply()
    }

    private fun repairDefaultProfile(context: Context) {
        val file = profileFile(context, "default")
        if (!file.exists()) return
        val content = runCatching { file.readText(Charsets.UTF_8) }.getOrNull() ?: return
        if ("- name: DIRECT" in content) {
            file.writeText(defaultConfig(), Charsets.UTF_8)
        }
    }

    private fun profileFile(context: Context, id: String): File {
        val dir = File(context.filesDir, "profiles")
        dir.mkdirs()
        return File(dir, "$id.yaml")
    }

    private fun download(context: Context, profileUrl: String, useProxy: Boolean): String {
        if (useProxy) {
            val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", localProxyPort(context)))
            runCatching { download(profileUrl, proxy) }.getOrNull()?.let { return it }
        }
        return download(profileUrl, Proxy.NO_PROXY)
    }

    private fun download(profileUrl: String, proxy: Proxy): String {
        val connection = URL(profileUrl).openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = 15_000
        connection.readTimeout = 30_000
        connection.requestMethod = "GET"
        connection.setRequestProperty("User-Agent", "Pulse-Android")
        connection.inputStream.use { input ->
            return input.bufferedReader(Charsets.UTF_8).readText()
        }
    }

    private fun localProxyPort(context: Context): Int {
        val content = runCatching { active(context).path.let(::File).readText(Charsets.UTF_8) }
            .getOrDefault("")
        return mixedPortPattern.find(content)?.groupValues?.getOrNull(1)?.toIntOrNull()
            ?: portPattern.find(content)?.groupValues?.getOrNull(1)?.toIntOrNull()
            ?: 7890
    }

    private fun stableId(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }

    private fun profileName(profileUrl: String): String {
        val host = runCatching { URL(profileUrl).host }.getOrDefault("订阅")
        return if (host.isBlank()) "订阅" else host
    }

    private fun encodeRecord(record: PulseProfileRecord): String {
        return listOf(record.id, record.name, record.url, record.path, record.updatedAt.toString())
            .joinToString("\t") { it.replace("\t", " ") }
    }

    private fun decodeRecord(value: String): PulseProfileRecord? {
        val parts = value.split("\t")
        if (parts.size != 5) return null
        return PulseProfileRecord(
            id = parts[0],
            name = parts[1],
            url = parts[2],
            path = parts[3],
            updatedAt = parts[4].toLongOrNull() ?: 0L,
        )
    }

    private fun defaultConfig() = """
        mixed-port: 7890
        mode: rule
        log-level: info
        proxies: []
        proxy-groups:
          - name: Proxy
            type: select
            proxies:
              - DIRECT
        rules:
          - MATCH,DIRECT
    """.trimIndent()

    private val mixedPortPattern = Regex("""(?m)^\s*mixed-port\s*:\s*(\d+)\s*$""")
    private val portPattern = Regex("""(?m)^\s*port\s*:\s*(\d+)\s*$""")
}
