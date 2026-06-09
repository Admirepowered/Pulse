package com.admirepowered.pulse.core

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest
import java.util.Base64

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
    private const val SUBSCRIPTION_USER_AGENT = "clash-verge/v2.5.2"

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

    fun delete(context: Context, profileId: String): PulseProfileRecord {
        require(profileId != "default") { "默认配置不能删除" }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val record = prefs.getString(PROFILE_PREFIX + profileId, null)
            ?.let(::decodeRecord)
            ?: return active(context)
        runCatching { File(record.path).delete() }
        prefs.edit().remove(PROFILE_PREFIX + profileId).apply()
        val profiles = list(context)
        val activeId = prefs.getString(ACTIVE_ID, null)
        val next = if (activeId == profileId) {
            profiles.first()
        } else {
            profiles.firstOrNull { it.id == activeId } ?: profiles.first()
        }
        select(context, next.id)
        return next
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

    fun importFromUri(context: Context, uri: Uri, activate: Boolean = true): PulseProfileRecord {
        val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalArgumentException("无法读取配置文件")
        require(bytes.isNotEmpty()) { "配置文件为空" }
        val name = localProfileName(context, uri)
        val id = stableId("file:$name:${digestHex(bytes)}")
        val file = profileFile(context, id)
        file.writeBytes(bytes)
        val record = PulseProfileRecord(
            id = id,
            name = name,
            url = "",
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
            runCatching { download(profileUrl, proxy) }
                .onFailure { PulseLogStore.warn(context, "代理更新订阅失败，已尝试直连: ${it.message}") }
                .getOrNull()
                ?.let { return it }
        }
        return download(profileUrl, Proxy.NO_PROXY)
    }

    private fun download(profileUrl: String, proxy: Proxy): String {
        val connection = URL(profileUrl).openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = 15_000
        connection.readTimeout = 30_000
        connection.requestMethod = "GET"
        connection.setRequestProperty("User-Agent", SUBSCRIPTION_USER_AGENT)
        connection.setRequestProperty("Accept", "text/yaml, application/yaml, text/plain, */*")
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
        connection.disconnect()
        if (code !in 200..299) {
            throw IllegalStateException("订阅请求返回 $code: ${body.preview()}")
        }
        return normalizeProfileBody(body)
    }

    private fun normalizeProfileBody(body: String): String {
        val trimmed = body.trimStart('\uFEFF').trim()
        require(trimmed.isNotBlank()) { "订阅内容为空" }
        if (looksLikeMihomoConfig(trimmed)) return body

        val decoded = decodeBase64Text(trimmed)
        if (decoded != null) {
            val decodedText = decoded.trimStart('\uFEFF').trim()
            if (looksLikeMihomoConfig(decodedText)) {
                return decodedText
            }
            throw IllegalStateException("订阅返回了 Base64 节点列表，不是 mihomo YAML 配置，请检查订阅链接或服务端 UA 识别")
        }

        throw IllegalStateException("订阅内容不是 mihomo YAML 配置: ${trimmed.preview()}")
    }

    private fun looksLikeMihomoConfig(value: String): Boolean {
        return yamlConfigKeys.any { key -> Regex("""(?m)^\s*$key\s*:""").containsMatchIn(value) }
    }

    private fun decodeBase64Text(value: String): String? {
        val compact = value.replace(Regex("""\s+"""), "")
        if (compact.length < 32 || !Regex("""^[A-Za-z0-9+/=_-]+$""").matches(compact)) return null
        val variants = listOf(
            compact,
            compact.padEnd(compact.length + (4 - compact.length % 4) % 4, '='),
        ).distinct()
        for (candidate in variants) {
            for (decoder in listOf(Base64.getDecoder(), Base64.getUrlDecoder())) {
                val decoded = runCatching { decoder.decode(candidate) }.getOrNull() ?: continue
                val text = decoded.toString(Charsets.UTF_8)
                if (text.any { it == '\n' || it == ':' || it == '/' }) return text
            }
        }
        return null
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

    private fun digestHex(value: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun profileName(profileUrl: String): String {
        val host = runCatching { URL(profileUrl).host }.getOrDefault("订阅")
        return if (host.isBlank()) "订阅" else host
    }

    private fun localProfileName(context: Context, uri: Uri): String {
        val displayName = context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
        } ?: uri.lastPathSegment ?: "本地配置"
        return displayName
            .substringAfterLast('/')
            .removeSuffix(".yaml")
            .removeSuffix(".yml")
            .ifBlank { "本地配置" }
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
    private val yamlConfigKeys = listOf(
        "mixed-port",
        "port",
        "socks-port",
        "proxies",
        "proxy-groups",
        "proxy-providers",
        "rules",
    )

    private fun String.preview(): String {
        return replace(Regex("""\s+"""), " ").take(120)
    }
}
