package com.admirepowered.pulse.core

import android.content.Intent
import android.net.Uri
import java.net.URLDecoder

object PulseProfileLinkParser {
    private val supportedSchemes = setOf("clash", "clashmeta", "mihomo", "pulse")
    private val linkPattern = Regex("""(?i)\b(?:clash|clashmeta|mihomo|pulse|https?)://[^\s"'<>]+""")

    fun extractProfileUrl(intent: Intent?): String? {
        return extractProfileUrls(intent).firstOrNull()
    }

    fun extractProfileUrls(intent: Intent?): List<String> {
        return when (intent?.action) {
            Intent.ACTION_VIEW -> intent.data?.let(::extractProfileUrl)?.let(::listOf).orEmpty()
            Intent.ACTION_SEND -> extractProfileUrls(intent.getStringExtra(Intent.EXTRA_TEXT).orEmpty())
            else -> emptyList()
        }.distinct()
    }

    fun extractProfileUrls(text: String): List<String> {
        val trimmed = text.trim()
        if (trimmed.isBlank()) return emptyList()
        return linkPattern.findAll(trimmed)
            .mapNotNull { match -> runCatching { Uri.parse(match.value) }.getOrNull() }
            .mapNotNull(::extractProfileUrl)
            .distinct()
            .toList()
    }

    fun extractProfileUri(intent: Intent?): Uri? {
        intent ?: return null
        return when (intent.action) {
            Intent.ACTION_VIEW -> intent.data?.takeIf(::isLocalProfileUri)
            Intent.ACTION_SEND -> streamUri(intent)?.takeIf(::isLocalProfileUri)
            else -> null
        }
    }

    fun extractProfileUris(intent: Intent?): List<Uri> {
        intent ?: return emptyList()
        return when (intent.action) {
            Intent.ACTION_VIEW -> intent.data?.takeIf(::isLocalProfileUri)?.let(::listOf).orEmpty()
            Intent.ACTION_SEND -> streamUri(intent)?.takeIf(::isLocalProfileUri)?.let(::listOf).orEmpty()
            Intent.ACTION_SEND_MULTIPLE -> streamUris(intent).filter(::isLocalProfileUri)
            else -> emptyList()
        }.distinct()
    }

    fun extractProfileText(intent: Intent?): String? {
        if (intent?.action != Intent.ACTION_SEND) return null
        val text = intent.getStringExtra(Intent.EXTRA_TEXT).orEmpty().trim()
        if (text.isBlank() || extractProfileUrls(text).isNotEmpty()) return null
        return text.takeIf(::looksLikeProfileText)
    }

    private fun extractProfileUrl(uri: Uri): String? {
        val scheme = uri.scheme?.lowercase() ?: return null
        if (scheme == "http" || scheme == "https") return uri.toString()
        if (scheme !in supportedSchemes) return null
        if (!isInstallConfig(uri)) return null
        return decodeRepeatedly(profileUrlParameter(uri))
            .takeIf { it.startsWith("http://") || it.startsWith("https://") }
    }

    private fun isInstallConfig(uri: Uri): Boolean {
        return uri.host.equals("install-config", ignoreCase = true) ||
            runCatching { uri.pathSegments.any { it.equals("install-config", ignoreCase = true) } }.getOrDefault(false) ||
            uri.toString().contains("install-config", ignoreCase = true)
    }

    private fun isLocalProfileUri(uri: Uri): Boolean {
        val scheme = uri.scheme?.lowercase() ?: return false
        return scheme == "content" || scheme == "file"
    }

    @Suppress("DEPRECATION")
    private fun streamUri(intent: Intent): Uri? {
        return intent.getParcelableExtra(Intent.EXTRA_STREAM)
    }

    @Suppress("DEPRECATION")
    private fun streamUris(intent: Intent): List<Uri> {
        return intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM).orEmpty()
    }

    private fun profileUrlParameter(uri: Uri): String {
        runCatching { uri.queryParameterNames }.getOrDefault(emptySet()).forEach { name ->
            if (name.lowercase() in profileUrlParameterNames) {
                runCatching { uri.getQueryParameter(name) }
                    .getOrNull()
                    ?.takeIf { it.isNotBlank() }
                    ?.let { return it }
            }
        }
        val raw = uri.toString()
        val marker = Regex("""(?i)(?:[?&#]|^)url=""").find(raw) ?: return ""
        return raw.substring(marker.range.last + 1).substringBefore('&')
    }

    private fun decodeRepeatedly(value: String): String {
        var current = value.trim()
        repeat(2) {
            val decoded = runCatching { URLDecoder.decode(current, Charsets.UTF_8.name()) }
                .getOrDefault(current)
                .trim()
            if (decoded == current) return current
            current = decoded
        }
        return current
    }

    private fun looksLikeProfileText(text: String): Boolean {
        return profileTextKeys.any { key ->
            Regex("""(?m)^\s*$key\s*:""").containsMatchIn(text)
        }
    }

    private val profileTextKeys = listOf(
        "mixed-port",
        "port",
        "socks-port",
        "allow-lan",
        "mode",
        "log-level",
        "dns",
        "proxies",
        "proxy-groups",
        "rules",
        "proxy-providers",
        "rule-providers",
        "tun",
    )

    private val profileUrlParameterNames = setOf("url", "link", "config", "profile")
}
