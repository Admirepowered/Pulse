package com.admirepowered.pulse.core

import android.content.Context
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

object PulseWebDavStore {
    private const val BACKUP_FILE = "pulse-android-profiles.json"

    fun uploadProfiles(
        context: Context,
        url: String,
        username: String,
        password: String,
    ): Int {
        val backup = PulseProfileStore.exportBackup(context)
        val bytes = backup.toByteArray(Charsets.UTF_8)
        val connection = openConnection(url, username, password, "PUT")
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        connection.doOutput = true
        connection.outputStream.use { it.write(bytes) }
        val code = connection.responseCode
        val body = connection.responseBody()
        connection.disconnect()
        if (code !in 200..299 && code != HttpURLConnection.HTTP_CREATED && code != HttpURLConnection.HTTP_NO_CONTENT) {
            throw IllegalStateException("WebDAV 上传失败 $code: ${body.preview()}")
        }
        return bytes.size
    }

    fun downloadProfiles(
        context: Context,
        url: String,
        username: String,
        password: String,
    ): Int {
        val connection = openConnection(url, username, password, "GET")
        val code = connection.responseCode
        val body = connection.responseBody()
        connection.disconnect()
        if (code !in 200..299) {
            throw IllegalStateException("WebDAV 下载失败 $code: ${body.preview()}")
        }
        PulseProfileStore.importBackup(context, body)
        return PulseProfileStore.list(context).size
    }

    private fun openConnection(
        rawUrl: String,
        username: String,
        password: String,
        method: String,
    ): HttpURLConnection {
        val target = normalizeUrl(rawUrl)
        val connection = URL(target).openConnection() as HttpURLConnection
        connection.connectTimeout = 15_000
        connection.readTimeout = 45_000
        connection.requestMethod = method
        connection.setRequestProperty("User-Agent", "Pulse-Android-WebDAV")
        if (username.isNotBlank() || password.isNotBlank()) {
            val token = Base64.getEncoder()
                .encodeToString("$username:$password".toByteArray(Charsets.UTF_8))
            connection.setRequestProperty("Authorization", "Basic $token")
        }
        return connection
    }

    private fun normalizeUrl(rawUrl: String): String {
        val trimmed = rawUrl.trim()
        require(trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            "请输入 http 或 https WebDAV 地址"
        }
        return if (trimmed.endsWith("/")) "$trimmed$BACKUP_FILE" else trimmed
    }

    private fun HttpURLConnection.responseBody(): String {
        val stream = if (responseCode in 200..299) inputStream else errorStream
        return stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
    }

    private fun String.preview(): String {
        return replace(Regex("""\s+"""), " ").take(160)
    }
}
