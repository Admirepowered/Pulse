package com.admirepowered.pulse.core

import android.content.Intent
import android.net.Uri
import java.net.URLDecoder

object PulseProfileLinkParser {
    private val supportedSchemes = setOf("clash", "clashmeta", "mihomo", "pulse")
    private val linkPattern = Regex("""(?i)\b(?:clash|clashmeta|mihomo|pulse|https?)://[^\s"'<>]+""")

    fun extractProfileUrl(intent: Intent?): String? {
        return when (intent?.action) {
            Intent.ACTION_VIEW -> intent.data?.let(::extractProfileUrl)
            Intent.ACTION_SEND -> extractProfileUrl(intent.getStringExtra(Intent.EXTRA_TEXT).orEmpty())
            else -> null
        }
    }

    private fun extractProfileUrl(text: String): String? {
        val trimmed = text.trim()
        if (trimmed.isBlank()) return null
        return linkPattern.findAll(trimmed)
            .mapNotNull { match -> runCatching { Uri.parse(match.value) }.getOrNull() }
            .mapNotNull(::extractProfileUrl)
            .firstOrNull()
    }

    private fun extractProfileUrl(uri: Uri): String? {
        val scheme = uri.scheme?.lowercase() ?: return null
        if (scheme == "http" || scheme == "https") return uri.toString()
        if (scheme !in supportedSchemes) return null
        if (!isInstallConfig(uri)) return null
        return decodeRepeatedly(uri.getQueryParameter("url").orEmpty())
            .takeIf { it.startsWith("http://") || it.startsWith("https://") }
    }

    private fun isInstallConfig(uri: Uri): Boolean {
        return uri.host.equals("install-config", ignoreCase = true) ||
            uri.pathSegments.any { it.equals("install-config", ignoreCase = true) }
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
}
