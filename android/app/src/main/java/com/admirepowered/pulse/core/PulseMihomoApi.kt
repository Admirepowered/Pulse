package com.admirepowered.pulse.core

import com.admirepowered.pulse.ui.ProxyItem
import java.net.HttpURLConnection
import java.net.URLEncoder
import java.net.URL
import org.json.JSONObject

object PulseMihomoApi {
    private const val BASE_URL = "http://127.0.0.1:9090"

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

    private fun delayFor(proxy: JSONObject?): Int? {
        val history = proxy?.optJSONArray("history") ?: return null
        if (history.length() == 0) return null
        val delay = history.optJSONObject(history.length() - 1)?.optInt("delay", -1) ?: -1
        return delay.takeIf { it >= 0 }
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
}
