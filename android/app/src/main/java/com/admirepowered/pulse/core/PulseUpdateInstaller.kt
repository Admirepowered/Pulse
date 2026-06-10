package com.admirepowered.pulse.core

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL

object PulseUpdateInstaller {
    fun downloadApk(
        context: Context,
        apkUrl: String,
        fileName: String,
        useProxy: Boolean = false,
        onProgress: (downloadedBytes: Long, totalBytes: Long) -> Unit = { _, _ -> },
    ): File {
        require(apkUrl.isNotBlank()) { "Release 中没有可下载的 Android APK" }
        val safeName = fileName.ifBlank { "pulse-update.apk" }
            .replace(Regex("""[^\w.\-]"""), "_")
            .let { if (it.endsWith(".apk", ignoreCase = true)) it else "$it.apk" }
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        val target = File(dir, safeName)
        val part = File(dir, "$safeName.part")

        if (useProxy) {
            runCatching {
                downloadApk(apkUrl, target, part, PulseLocalProxy.httpProxy(context), onProgress)
            }.onFailure { error ->
                PulseLogStore.warn(context, "代理下载更新失败，已尝试直连: ${error.message}")
            }.getOrNull()?.let { return it }
        }

        return downloadApk(apkUrl, target, part, Proxy.NO_PROXY, onProgress)
    }

    private fun downloadApk(
        apkUrl: String,
        target: File,
        part: File,
        proxy: Proxy,
        onProgress: (downloadedBytes: Long, totalBytes: Long) -> Unit,
    ): File {
        if (part.exists()) part.delete()

        val connection = URL(apkUrl).openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = 15_000
        connection.readTimeout = 60_000
        connection.requestMethod = "GET"
        connection.setRequestProperty("User-Agent", "Pulse-Android-Updater")
        try {
            val code = connection.responseCode
            if (code !in 200..299) {
                val body = connection.errorStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
                throw IllegalStateException("下载 APK 失败 $code: ${body.preview()}")
            }
            val totalBytes = connection.contentLengthLong.takeIf { it > 0 } ?: -1L
            connection.inputStream.use { input ->
                part.outputStream().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    var downloaded = 0L
                    var lastReported = 0L
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        output.write(buffer, 0, read)
                        downloaded += read
                        if (downloaded - lastReported >= 256 * 1024 || downloaded == totalBytes) {
                            lastReported = downloaded
                            onProgress(downloaded, totalBytes)
                        }
                    }
                    onProgress(downloaded, totalBytes)
                }
            }
        } finally {
            connection.disconnect()
        }
        if (target.exists()) target.delete()
        if (!part.renameTo(target)) {
            part.copyTo(target, overwrite = true)
            part.delete()
        }
        return target
    }

    fun openInstall(context: Context, apk: File) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !context.packageManager.canRequestPackageInstalls()) {
            val intent = Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${context.packageName}"),
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
            throw IllegalStateException("请先允许 Pulse 安装未知应用，然后再次点击安装更新")
        }
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            apk,
        )
        val intent = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }

    private fun String.preview(): String {
        return replace(Regex("""\s+"""), " ").take(160)
    }
}
