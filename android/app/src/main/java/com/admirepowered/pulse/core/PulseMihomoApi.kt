package com.admirepowered.pulse.core

import com.admirepowered.pulse.ui.ConnectionItem
import com.admirepowered.pulse.ui.ProxyItem
import com.admirepowered.pulse.ui.ProxyMode
import com.admirepowered.pulse.ui.TrafficSnapshot
import java.net.HttpURLConnection
import java.net.URLEncoder
import java.net.URL
import org.json.JSONObject

object PulseMihomoApi {
    private const val BASE_URL = "http://127.0.0.1:9090"
    private const val DEFAULT_DELAY_URL = "https://www.gstatic.com/generate_204"

    fun proxies(): List<ProxyItem> {
        val json = JSONObject(request("GET", "/proxies"))
        val proxies = json.getJSONObject("proxies")
        val result = mutableListOf<ProxyItem>()
        val names = proxies.keys()
        while (names.hasNext()) {
            val groupName = names.next()
            val group = proxies.getJSONObject(groupName)
            val all = group.optJSONArray("all") ?: continue
            val selected = group.optString("now")
            for (index in 0 until all.length()) {
                val name = all.getString(index)
                result += ProxyItem(
                    id = "$groupName|$name",
                    name = name,
                    group = groupName,
                    delayMs = delayFor(proxies.optJSONObject(name)),
                    selected = name == selected,
                )
            }
        }
        return result
    }

    fun selectProxy(id: String) {
        val parts = id.split("|", limit = 2)
        require(parts.size == 2) { "节点标识无效" }
        val group = URLEncoder.encode(parts[0], Charsets.UTF_8.name())
        val body = JSONObject().put("name", parts[1]).toString()
        request("PUT", "/proxies/$group", body)
    }

    fun testProxyDelays(proxies: List<ProxyItem>, url: String = DEFAULT_DELAY_URL): Int {
        val names = proxies
            .map { it.name }
            .filterNot { it in builtinProxyNames }
            .distinct()
        var measured = 0
        for (name in names) {
            val proxy = URLEncoder.encode(name, Charsets.UTF_8.name())
            val target = URLEncoder.encode(url, Charsets.UTF_8.name())
            runCatching {
                request("GET", "/proxies/$proxy/delay?timeout=3000&url=$target")
                measured++
            }
        }
        return measured
    }

    fun setMode(mode: ProxyMode) {
        val mihomoMode = when (mode) {
            ProxyMode.Rule -> "rule"
            ProxyMode.Global -> "global"
            ProxyMode.Direct -> "direct"
        }
        PulseCoreBridge.setMode(mihomoMode).getOrThrow()
    }

    fun connections(): List<ConnectionItem> {
        val json = JSONObject(request("GET", "/connections"))
        val connections = json.optJSONArray("connections") ?: return emptyList()
        return buildList {
            for (index in 0 until connections.length()) {
                val connection = connections.getJSONObject(index)
                val metadata = connection.optJSONObject("metadata")
                val host = metadata?.optString("host")?.takeIf { it.isNotBlank() }
                    ?: metadata?.optString("destinationIP")?.takeIf { it.isNotBlank() }
                    ?: connection.optString("id")
                add(
                    ConnectionItem(
                        id = connection.optString("id", "$index"),
                        host = host,
                        rule = connection.optString("rule", "-"),
                        download = formatBytes(connection.optLong("download")),
                        upload = formatBytes(connection.optLong("upload")),
                        speed = "-",
                    ),
                )
            }
        }
    }

    fun traffic(): TrafficSnapshot {
        val connection = URL("$BASE_URL/traffic").openConnection() as HttpURLConnection
        connection.connectTimeout = 2_500
        connection.readTimeout = 5_000
        connection.requestMethod = "GET"
        val code = connection.responseCode
        if (code !in 200..299) {
            val text = connection.errorStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            throw IllegalStateException("mihomo API GET /traffic 返回 $code: $text")
        }
        val line = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readLine() }
        connection.disconnect()
        val json = JSONObject(line.orEmpty())
        return TrafficSnapshot(
            downloadTotal = formatBytes(json.optLong("downloadTotal")),
            uploadTotal = formatBytes(json.optLong("uploadTotal")),
            downloadSpeed = "${formatBytes(json.optLong("down"))}/s",
            uploadSpeed = "${formatBytes(json.optLong("up"))}/s",
        )
    }

    private fun delayFor(proxy: JSONObject?): Int? {
        val history = proxy?.optJSONArray("history") ?: return null
        if (history.length() == 0) return null
        val delay = history.optJSONObject(history.length() - 1)?.optInt("delay", -1) ?: -1
        return delay.takeIf { it >= 0 }
    }

    private fun formatBytes(value: Long): String {
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        var size = value.toDouble()
        var index = 0
        while (size >= 1024 && index < units.lastIndex) {
            size /= 1024
            index++
        }
        return if (index == 0) {
            "${size.toLong()} ${units[index]}"
        } else {
            "%.1f %s".format(size, units[index])
        }
    }

    private fun request(method: String, path: String, body: String? = null): String {
        val connection = URL(BASE_URL + path).openConnection() as HttpURLConnection
        connection.connectTimeout = 2_500
        connection.readTimeout = 5_000
        connection.requestMethod = method
        connection.setRequestProperty("Content-Type", "application/json")
        if (body != null) {
            connection.doOutput = true
            connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        }
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
        if (code !in 200..299) {
            throw IllegalStateException("mihomo API $method $path 返回 $code: $text")
        }
        return text
    }

    private val builtinProxyNames = setOf("DIRECT", "REJECT", "REJECT-DROP", "PASS")
}
