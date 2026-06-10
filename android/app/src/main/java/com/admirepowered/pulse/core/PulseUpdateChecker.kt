package com.admirepowered.pulse.core

import android.content.Context
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import org.json.JSONObject

data class PulseUpdateInfo(
    val currentVersion: String,
    val latestVersion: String,
    val releaseUrl: String,
    val hasUpdate: Boolean,
    val apkAssetName: String = "",
    val apkAssetUrl: String = "",
)

object PulseUpdateChecker {
    private const val LATEST_RELEASE_API = "https://api.github.com/repos/Admirepowered/Pulse/releases/latest"

    fun check(context: Context, currentVersion: String, useProxy: Boolean = false): PulseUpdateInfo {
        if (useProxy) {
            runCatching { check(currentVersion, PulseLocalProxy.httpProxy(context)) }
                .onFailure { PulseLogStore.warn(context, "代理检查更新失败，已尝试直连: ${it.message}") }
                .getOrNull()
                ?.let { return it }
        }
        return check(currentVersion, Proxy.NO_PROXY)
    }

    fun check(currentVersion: String): PulseUpdateInfo {
        return check(currentVersion, Proxy.NO_PROXY)
    }

    private fun check(currentVersion: String, proxy: Proxy): PulseUpdateInfo {
        val connection = URL(LATEST_RELEASE_API).openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = 10_000
        connection.readTimeout = 15_000
        connection.requestMethod = "GET"
        connection.setRequestProperty("Accept", "application/vnd.github+json")
        connection.setRequestProperty("User-Agent", "Pulse-Android/$currentVersion")
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
        connection.disconnect()
        if (code !in 200..299) {
            throw IllegalStateException("GitHub release API 返回 $code: ${body.preview()}")
        }
        val json = JSONObject(body)
        val tagName = json.optString("tag_name").ifBlank {
            throw IllegalStateException("GitHub release 缺少 tag_name")
        }
        val latestVersion = normalizeVersion(tagName)
        val normalizedCurrent = normalizeVersion(currentVersion)
        val apkAsset = findApkAsset(json)
        return PulseUpdateInfo(
            currentVersion = currentVersion,
            latestVersion = tagName,
            releaseUrl = json.optString("html_url").ifBlank {
                "https://github.com/Admirepowered/Pulse/releases/tag/$tagName"
            },
            hasUpdate = compareVersions(latestVersion, normalizedCurrent) > 0,
            apkAssetName = apkAsset?.first.orEmpty(),
            apkAssetUrl = apkAsset?.second.orEmpty(),
        )
    }

    private fun findApkAsset(json: JSONObject): Pair<String, String>? {
        val assets = json.optJSONArray("assets") ?: return null
        val candidates = (0 until assets.length())
            .mapNotNull { index -> assets.optJSONObject(index) }
            .mapNotNull { asset ->
                val name = asset.optString("name")
                val url = asset.optString("browser_download_url")
                if (!name.endsWith(".apk", ignoreCase = true) || url.isBlank()) {
                    null
                } else {
                    name to url
                }
            }
        return candidates.firstOrNull { (name, _) ->
            name.contains("android", ignoreCase = true) || name.contains("pulse", ignoreCase = true)
        } ?: candidates.firstOrNull()
    }

    private fun normalizeVersion(value: String): String {
        return value
            .trim()
            .removePrefix("v")
            .removePrefix("V")
            .substringBefore("-")
            .substringBefore("+")
    }

    private fun compareVersions(left: String, right: String): Int {
        val leftParts = left.split(".").map { it.toIntOrNull() ?: 0 }
        val rightParts = right.split(".").map { it.toIntOrNull() ?: 0 }
        val size = maxOf(leftParts.size, rightParts.size)
        for (index in 0 until size) {
            val leftValue = leftParts.getOrElse(index) { 0 }
            val rightValue = rightParts.getOrElse(index) { 0 }
            if (leftValue != rightValue) return leftValue.compareTo(rightValue)
        }
        return 0
    }

    private fun String.preview(): String {
        return replace(Regex("""\s+"""), " ").take(160)
    }
}
