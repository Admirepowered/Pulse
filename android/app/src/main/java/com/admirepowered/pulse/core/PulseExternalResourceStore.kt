package com.admirepowered.pulse.core

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL

data class PulseExternalResourceStatus(
    val name: String,
    val path: String,
    val exists: Boolean,
    val sizeBytes: Long,
    val updatedAt: Long,
)

data class PulseExternalResourceUpdateResult(
    val updated: Int,
    val total: Int,
    val failures: List<String>,
)

object PulseExternalResourceStore {
    private val resources = listOf(
        ExternalResource(
            name = "GeoSite.dat",
            url = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        ),
        ExternalResource(
            name = "geoip.metadb",
            url = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
        ),
    )

    fun update(context: Context, useProxy: Boolean = false): PulseExternalResourceUpdateResult {
        var updated = 0
        val failures = mutableListOf<String>()
        resources.forEach { resource ->
            val target = File(context.filesDir, resource.name)
            runCatching {
                download(context, resource, target, useProxy)
            }.onSuccess {
                updated++
            }.onFailure { error ->
                failures += "${resource.name}: ${error.message ?: error::class.java.simpleName}"
            }
        }
        if (updated == 0 && failures.isNotEmpty()) {
            throw IllegalStateException("外部资源更新失败: ${failures.joinToString("；")}")
        }
        return PulseExternalResourceUpdateResult(
            updated = updated,
            total = resources.size,
            failures = failures,
        )
    }

    fun status(context: Context): List<PulseExternalResourceStatus> {
        return resources.map { resource ->
            val file = File(context.filesDir, resource.name)
            PulseExternalResourceStatus(
                name = resource.name,
                path = file.absolutePath,
                exists = file.exists() && file.isFile && file.length() > 0,
                sizeBytes = if (file.exists()) file.length() else 0,
                updatedAt = if (file.exists()) file.lastModified() else 0,
            )
        }
    }

    private fun download(context: Context, resource: ExternalResource, target: File, useProxy: Boolean) {
        if (useProxy) {
            runCatching { download(resource, target, PulseLocalProxy.httpProxy(context)) }
                .onFailure { PulseLogStore.warn(context, "代理更新 ${resource.name} 失败，已尝试直连: ${it.message}") }
                .getOrNull()
                ?.let { return }
        }
        download(resource, target, Proxy.NO_PROXY)
    }

    private fun download(resource: ExternalResource, target: File, proxy: Proxy) {
        target.parentFile?.mkdirs()
        val temp = File(target.parentFile, "${target.name}.part")
        if (temp.exists() && !temp.delete()) {
            throw IllegalStateException("无法清理旧的临时文件 ${temp.name}")
        }
        val connection = URL(resource.url).openConnection(proxy) as HttpURLConnection
        try {
            connection.connectTimeout = 15_000
            connection.readTimeout = 60_000
            connection.requestMethod = "GET"
            connection.setRequestProperty("User-Agent", "Pulse Android")
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            if (code !in 200..299) {
                val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
                throw IllegalStateException("${resource.name} 请求返回 $code: ${body.take(160)}")
            }
            temp.outputStream().use { output ->
                val input = stream ?: throw IllegalStateException("${resource.name} 没有返回数据")
                input.use { it.copyTo(output) }
            }
            require(temp.length() > 0) { "${resource.name} 下载为空" }
            if (target.exists() && !target.delete()) {
                throw IllegalStateException("无法替换 ${target.name}")
            }
            if (!temp.renameTo(target)) {
                throw IllegalStateException("无法保存 ${target.name}")
            }
        } finally {
            connection.disconnect()
            if (temp.exists()) {
                temp.delete()
            }
        }
    }

    private data class ExternalResource(
        val name: String,
        val url: String,
    )
}
