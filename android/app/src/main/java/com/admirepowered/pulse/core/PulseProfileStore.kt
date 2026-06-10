package com.admirepowered.pulse.core

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.Base64
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

data class PulseProfileRecord(
    val id: String,
    val name: String,
    val url: String,
    val path: String,
    val updatedAt: Long,
    val subscription: PulseSubscriptionInfo = PulseSubscriptionInfo(),
)

data class PulseSubscriptionInfo(
    val upload: Long = 0,
    val download: Long = 0,
    val total: Long = 0,
    val expire: Long = 0,
    val updateInterval: Int = 0,
    val rawUserInfo: String = "",
    val updatedAt: Long = 0,
)

private data class DownloadedProfile(
    val body: String,
    val profileTitle: String,
    val contentDisposition: String,
    val subscriptionInfo: PulseSubscriptionInfo,
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
        val downloaded = download(context, trimmedUrl, useProxy)
        val id = stableId(trimmedUrl)
        val name = inferProfileName(trimmedUrl, downloaded)
        val file = profileFile(context, id)
        file.writeText(downloaded.body, Charsets.UTF_8)
        val record = PulseProfileRecord(
            id = id,
            name = name,
            url = trimmedUrl,
            path = file.absolutePath,
            updatedAt = System.currentTimeMillis(),
            subscription = downloaded.subscriptionInfo,
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
        val content = normalizeProfileBody(bytes.toString(Charsets.UTF_8))
        val name = localProfileName(context, uri)
        val id = stableId("file:$name:${digestHex(content.toByteArray(Charsets.UTF_8))}")
        val file = profileFile(context, id)
        file.writeText(content, Charsets.UTF_8)
        val record = PulseProfileRecord(
            id = id,
            name = name,
            url = "",
            path = file.absolutePath,
            updatedAt = System.currentTimeMillis(),
            subscription = PulseSubscriptionInfo(),
        )
        val editor = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(PROFILE_PREFIX + id, encodeRecord(record))
        if (activate) {
            editor.putString(ACTIVE_ID, id)
        }
        editor.apply()
        return record
    }

    fun importFromText(
        context: Context,
        text: String,
        name: String = "分享配置",
        activate: Boolean = true,
    ): PulseProfileRecord {
        val content = normalizeProfileBody(text)
        val cleanName = cleanProfileName(name) ?: "分享配置"
        val id = stableId("text:$cleanName:${digestHex(content.toByteArray(Charsets.UTF_8))}")
        val file = profileFile(context, id)
        file.writeText(content, Charsets.UTF_8)
        val record = PulseProfileRecord(
            id = id,
            name = cleanName,
            url = "",
            path = file.absolutePath,
            updatedAt = System.currentTimeMillis(),
            subscription = PulseSubscriptionInfo(),
        )
        val editor = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(PROFILE_PREFIX + id, encodeRecord(record))
        if (activate) {
            editor.putString(ACTIVE_ID, id)
        }
        editor.apply()
        return record
    }

    fun updateSource(
        context: Context,
        profileId: String,
        profileUrl: String,
        useProxy: Boolean = false,
    ): PulseProfileRecord {
        val current = find(context, profileId)
            ?: throw IllegalArgumentException("订阅不存在")
        val trimmedUrl = profileUrl.trim()
        require(trimmedUrl.startsWith("http://") || trimmedUrl.startsWith("https://")) {
            "请输入 http 或 https 订阅地址"
        }
        val downloaded = download(context, trimmedUrl, useProxy)
        val file = File(current.path)
        file.parentFile?.mkdirs()
        file.writeText(downloaded.body, Charsets.UTF_8)
        val next = current.copy(
            url = trimmedUrl,
            updatedAt = System.currentTimeMillis(),
            subscription = downloaded.subscriptionInfo,
        )
        save(context, next)
        return next
    }

    fun refreshFromUrl(
        context: Context,
        profileId: String,
        useProxy: Boolean = false,
    ): PulseProfileRecord {
        val current = find(context, profileId)
            ?: throw IllegalArgumentException("订阅不存在")
        require(current.url.isNotBlank()) { "本地配置没有订阅 URL" }
        return updateSource(context, profileId, current.url, useProxy)
    }

    fun autoRefreshDueProfiles(context: Context, nowMillis: Long = System.currentTimeMillis()): List<PulseProfileRecord> {
        return list(context).filter { record ->
            val intervalHours = record.subscription.updateInterval
            record.url.isNotBlank() &&
                intervalHours > 0 &&
                nowMillis - record.updatedAt >= intervalHours * 60L * 60L * 1000L
        }
    }

    fun readContent(context: Context, profileId: String): String {
        val record = find(context, profileId)
            ?: throw IllegalArgumentException("订阅不存在")
        return File(record.path).readText(Charsets.UTF_8)
    }

    fun saveContent(context: Context, profileId: String, content: String): PulseProfileRecord {
        val current = find(context, profileId)
            ?: throw IllegalArgumentException("订阅不存在")
        require(content.isNotBlank()) { "配置内容不能为空" }
        val normalizedContent = normalizeProfileBody(content)
        val file = File(current.path)
        file.parentFile?.mkdirs()
        file.writeText(normalizedContent, Charsets.UTF_8)
        val next = current.copy(updatedAt = System.currentTimeMillis())
        save(context, next)
        return next
    }

    fun rename(context: Context, profileId: String, name: String): PulseProfileRecord {
        val current = find(context, profileId)
            ?: throw IllegalArgumentException("订阅不存在")
        val cleanName = cleanProfileName(name) ?: throw IllegalArgumentException("订阅名称不能为空")
        val next = current.copy(
            name = cleanName,
            updatedAt = System.currentTimeMillis(),
        )
        save(context, next)
        return next
    }

    fun exportBackup(context: Context): String {
        ensureDefaultProfile(context)
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val activeId = prefs.getString(ACTIVE_ID, null).orEmpty()
        val profiles = JSONArray()
        val records = list(context)
        records.forEach { record ->
            profiles.put(
                JSONObject()
                    .put("id", record.id)
                    .put("name", record.name)
                    .put("url", record.url)
                    .put("updatedAt", record.updatedAt)
                    .put("subscription", record.subscription.toJson())
                    .put("content", runCatching { File(record.path).readText(Charsets.UTF_8) }.getOrDefault("")),
            )
        }
        return JSONObject()
            .put("format", "pulse-android-profiles")
            .put("version", 3)
            .put("exportedAt", System.currentTimeMillis())
            .put("activeProfileId", activeId)
            .put("profiles", profiles)
            .put("settings", PulseSettingsStore.exportBackupJson(context))
            .put("customRules", PulseCustomRuleStore.exportBackupJson(context, records.map { it.id }))
            .put("backgrounds", PulseBackgroundStore.exportBackupJson(context, PulseSettingsStore.load(context).backgroundImageUri))
            .toString(2)
    }

    fun importBackup(context: Context, backup: String): PulseProfileRecord {
        val json = JSONObject(backup)
        require(json.optString("format") == "pulse-android-profiles") { "WebDAV 备份格式不匹配" }
        val profiles = json.optJSONArray("profiles") ?: JSONArray()
        require(profiles.length() > 0) { "WebDAV 备份中没有订阅" }

        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val editor = prefs.edit()
        prefs.all.keys
            .filter { it.startsWith(PROFILE_PREFIX) }
            .forEach(editor::remove)

        val importedIds = mutableListOf<String>()
        val idMapping = mutableMapOf<String, String>()
        for (index in 0 until profiles.length()) {
            val item = profiles.optJSONObject(index) ?: continue
            val content = item.optString("content")
            if (content.isBlank()) continue
            val oldId = item.optString("id")
            val id = cleanBackupId(item.optString("id"))
                ?: stableId("${item.optString("url")}:${item.optString("name")}:$index")
            val file = profileFile(context, id)
            file.writeText(content, Charsets.UTF_8)
            val record = PulseProfileRecord(
                id = id,
                name = cleanProfileName(item.optString("name")) ?: "同步订阅",
                url = item.optString("url"),
                path = file.absolutePath,
                updatedAt = item.optLong("updatedAt").takeIf { it > 0 } ?: System.currentTimeMillis(),
                subscription = item.optJSONObject("subscription")?.toSubscriptionInfo() ?: PulseSubscriptionInfo(),
            )
            importedIds += id
            if (oldId.isNotBlank()) {
                idMapping[oldId] = id
            }
            editor.putString(PROFILE_PREFIX + id, encodeRecord(record))
        }
        require(importedIds.isNotEmpty()) { "WebDAV 备份中的订阅内容为空" }
        val activeId = json.optString("activeProfileId").takeIf { it in importedIds } ?: importedIds.first()
        editor.putString(ACTIVE_ID, activeId).apply()
        PulseSettingsStore.importBackupJson(context, json.optJSONObject("settings"))
        val selectedBackground = PulseBackgroundStore.importBackupJson(context, json.optJSONObject("backgrounds"))
        PulseSettingsStore.setBackgroundImageUri(context, selectedBackground)
        PulseCustomRuleStore.importBackupJson(context, json.optJSONObject("customRules"), idMapping)
        return active(context)
    }

    private fun find(context: Context, profileId: String): PulseProfileRecord? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return prefs.getString(PROFILE_PREFIX + profileId, null)?.let(::decodeRecord)
    }

    private fun save(context: Context, record: PulseProfileRecord) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(PROFILE_PREFIX + record.id, encodeRecord(record))
            .apply()
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
            subscription = PulseSubscriptionInfo(),
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

    private fun download(context: Context, profileUrl: String, useProxy: Boolean): DownloadedProfile {
        if (useProxy) {
            runCatching { download(profileUrl, PulseLocalProxy.httpProxy(context)) }
                .onFailure { PulseLogStore.warn(context, "代理更新订阅失败，已尝试直连: ${it.message}") }
                .getOrNull()
                ?.let { return it }
        }
        return download(profileUrl, Proxy.NO_PROXY)
    }

    private fun download(profileUrl: String, proxy: Proxy): DownloadedProfile {
        val connection = URL(profileUrl).openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = 15_000
        connection.readTimeout = 30_000
        connection.requestMethod = "GET"
        connection.setRequestProperty("User-Agent", SUBSCRIPTION_USER_AGENT)
        connection.setRequestProperty("Accept", "text/yaml, application/yaml, text/plain, */*")
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
        val profileTitle = connection.getHeaderField("profile-title").orEmpty()
        val contentDisposition = connection.getHeaderField("content-disposition").orEmpty()
        val subscriptionInfo = parseSubscriptionInfo(connection)
        connection.disconnect()
        if (code !in 200..299) {
            throw IllegalStateException("订阅请求返回 $code: ${body.preview()}")
        }
        return DownloadedProfile(
            body = normalizeProfileBody(body),
            profileTitle = profileTitle,
            contentDisposition = contentDisposition,
            subscriptionInfo = subscriptionInfo,
        )
    }

    private fun parseSubscriptionInfo(connection: HttpURLConnection): PulseSubscriptionInfo {
        val rawUserInfo = connection.getHeaderField("subscription-userinfo").orEmpty().trim()
        val values = mutableMapOf<String, Long>()
        rawUserInfo.split(";").forEach { part ->
            val key = part.substringBefore("=", "").trim().lowercase(Locale.ROOT)
            val value = part.substringAfter("=", "").trim().toLongOrNull() ?: return@forEach
            values[key] = value
        }
        val updateInterval = connection.getHeaderField("profile-update-interval")
            ?.trim()
            ?.toIntOrNull()
            ?: 0
        val info = PulseSubscriptionInfo(
            upload = values["upload"] ?: 0,
            download = values["download"] ?: 0,
            total = values["total"] ?: 0,
            expire = values["expire"] ?: 0,
            updateInterval = updateInterval,
            rawUserInfo = rawUserInfo,
            updatedAt = System.currentTimeMillis(),
        )
        return if (info.rawUserInfo.isBlank() && info.total <= 0 && info.expire <= 0 && info.updateInterval <= 0) {
            PulseSubscriptionInfo()
        } else {
            info
        }
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

    private fun stableId(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }

    private fun digestHex(value: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun inferProfileName(profileUrl: String, downloaded: DownloadedProfile): String {
        return listOf(
            downloaded.profileTitle,
            filenameFromDisposition(downloaded.contentDisposition),
            yamlTitle(downloaded.body),
            filenameFromUrl(profileUrl),
            hostFromUrl(profileUrl),
            "远程订阅",
        ).firstNotNullOfOrNull(::cleanProfileName) ?: "远程订阅"
    }

    private fun filenameFromDisposition(value: String): String {
        if (value.isBlank()) return ""
        return value.split(";")
            .map { it.trim() }
            .firstNotNullOfOrNull { part ->
                val key = part.substringBefore("=", "").trim().lowercase(Locale.ROOT)
                if (key != "filename" && key != "filename*") return@firstNotNullOfOrNull null
                part.substringAfter("=", "").trim().trim('"')
            }
            .orEmpty()
    }

    private fun filenameFromUrl(profileUrl: String): String {
        val parsed = runCatching { URL(profileUrl) }.getOrNull() ?: return ""
        val query = parsed.query.orEmpty()
        for (key in listOf("name", "title", "filename", "file")) {
            query.split("&")
                .firstOrNull { it.substringBefore("=") == key }
                ?.substringAfter("=", "")
                ?.takeIf { it.isNotBlank() }
                ?.let { return it }
        }
        return parsed.path.substringAfterLast('/')
    }

    private fun hostFromUrl(profileUrl: String): String {
        return runCatching { URL(profileUrl).host }.getOrDefault("")
    }

    private fun yamlTitle(body: String): String {
        body.take(4096).lineSequence().forEach { line ->
            val trimmed = line.trim()
            val lower = trimmed.lowercase(Locale.ROOT)
            for (prefix in listOf("name:", "profile:", "profile-name:", "title:")) {
                if (lower.startsWith(prefix)) {
                    return trimmed.substring(prefix.length).trim()
                }
            }
        }
        return ""
    }

    private fun cleanProfileName(value: String): String? {
        var name = value.trim()
        if (name.isBlank()) return null
        if (name.startsWith("UTF-8''", ignoreCase = true)) {
            name = name.substringAfter("''")
        }
        name = runCatching { URLDecoder.decode(name, Charsets.UTF_8.name()) }.getOrDefault(name)
        decodeBase64Text(name)?.takeIf { it.isNotBlank() }?.let { name = it }
        name = name.trim('"', '\'', ' ')
            .replace('\\', '/')
            .substringAfterLast('/')
        for (suffix in listOf(".yaml", ".yml", ".txt", ".conf")) {
            if (name.lowercase(Locale.ROOT).endsWith(suffix)) {
                name = name.dropLast(suffix.length)
                break
            }
        }
        name = name.replace(Regex("""[\\/:*?"<>|]+"""), " ").trim('.', '-', '_', ' ')
        return name.takeIf { it.isNotBlank() }
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
        val subscription = record.subscription
        return listOf(
            record.id,
            record.name,
            record.url,
            record.path,
            record.updatedAt.toString(),
            subscription.upload.toString(),
            subscription.download.toString(),
            subscription.total.toString(),
            subscription.expire.toString(),
            subscription.updateInterval.toString(),
            subscription.rawUserInfo,
            subscription.updatedAt.toString(),
        )
            .joinToString("\t") { it.replace("\t", " ") }
    }

    private fun PulseSubscriptionInfo.toJson(): JSONObject {
        return JSONObject()
            .put("upload", upload)
            .put("download", download)
            .put("total", total)
            .put("expire", expire)
            .put("updateInterval", updateInterval)
            .put("rawUserInfo", rawUserInfo)
            .put("updatedAt", updatedAt)
    }

    private fun JSONObject.toSubscriptionInfo(): PulseSubscriptionInfo {
        return PulseSubscriptionInfo(
            upload = optLong("upload"),
            download = optLong("download"),
            total = optLong("total"),
            expire = optLong("expire"),
            updateInterval = optInt("updateInterval"),
            rawUserInfo = optString("rawUserInfo"),
            updatedAt = optLong("updatedAt"),
        )
    }

    private fun cleanBackupId(value: String): String? {
        val id = value.trim()
        return id.takeIf { it.matches(Regex("""[A-Za-z0-9_-]{1,64}""")) }
    }

    private fun decodeRecord(value: String): PulseProfileRecord? {
        val parts = value.split("\t")
        if (parts.size != 5 && parts.size < 12) return null
        val subscription = if (parts.size >= 12) {
            PulseSubscriptionInfo(
                upload = parts[5].toLongOrNull() ?: 0,
                download = parts[6].toLongOrNull() ?: 0,
                total = parts[7].toLongOrNull() ?: 0,
                expire = parts[8].toLongOrNull() ?: 0,
                updateInterval = parts[9].toIntOrNull() ?: 0,
                rawUserInfo = parts[10],
                updatedAt = parts[11].toLongOrNull() ?: 0,
            )
        } else {
            PulseSubscriptionInfo()
        }
        return PulseProfileRecord(
            id = parts[0],
            name = parts[1],
            url = parts[2],
            path = parts[3],
            updatedAt = parts[4].toLongOrNull() ?: 0L,
            subscription = subscription,
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
