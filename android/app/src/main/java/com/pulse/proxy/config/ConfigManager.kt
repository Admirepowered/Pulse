package com.pulse.proxy.config

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Base64
import com.pulse.proxy.data.EndpointItem
import com.pulse.proxy.data.RuleActionOption
import com.pulse.proxy.data.RuleConditionOption
import com.pulse.proxy.data.SubscriptionProfile
import com.pulse.proxy.data.VisualRule
import com.pulse.proxy.service.NativeBinaryManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.URI
import java.util.UUID
import okhttp3.OkHttpClient
import okhttp3.Request

class ConfigManager(private val context: Context) {

    private val configDir: File
        get() = File(context.filesDir, "config")

    private val configFile: File
        get() = File(configDir, "config.toml")

    private val runtimeConfigFile: File
        get() = File(configDir, "runtime.toml")

    private val rulesFile: File
        get() = File(configDir, "rules.toml")

    private val visualRulesFile: File
        get() = File(configDir, "rules.tsv")

    private val subscriptionsFile: File
        get() = File(configDir, "subscriptions.tsv")

    private val selectionFile: File
        get() = File(configDir, "selection.properties")

    private val countryDbFile: File
        get() = File(context.filesDir, "Country.mmdb")

    fun initialize() {
        if (!configDir.exists()) {
            configDir.mkdirs()
        }
        if (!configFile.exists()) {
            copyAsset("config.toml.default", configFile)
        }
        val subscriptionFile = File(configDir, "subscription.toml")
        if (!subscriptionFile.exists()) {
            copyAsset("subscription.toml.default", subscriptionFile)
        }
        if (!rulesFile.exists()) {
            rulesFile.writeText(renderRulesToml(defaultVisualRules()))
        }
    }

    fun readConfig(): String {
        return if (configFile.exists()) configFile.readText() else ""
    }

    fun saveConfig(content: String) {
        configDir.mkdirs()
        configFile.writeText(content)
    }

    fun getConfigPath(): String = buildRuntimeConfig().absolutePath
    fun getConfigDir(): String = configDir.absolutePath

    fun readRules(): String {
        initialize()
        return renderRulesToml(readVisualRules())
    }

    fun saveRules(content: String) {
        initialize()
        rulesFile.writeText(content)
    }

    fun appendDefaultRules(): String {
        val current = readVisualRules().toMutableList()
        val existingNames = current.map { it.name }.toSet()
        defaultVisualRules().filterNot { it.name in existingNames }.forEach { current += it }
        saveVisualRules(current)
        return renderRulesToml(current)
    }

    fun readVisualRules(): List<VisualRule> {
        initialize()
        if (!visualRulesFile.exists()) {
            saveVisualRules(defaultVisualRules())
        }
        return visualRulesFile.readLines().mapNotNull { line ->
            val parts = line.split('\t')
            if (parts.size < 7) return@mapNotNull null
            VisualRule(
                id = parts[0],
                name = decode(parts[1]),
                action = RuleActionOption.entries.firstOrNull { it.value == parts[2] } ?: RuleActionOption.Proxy,
                condition = RuleConditionOption.entries.firstOrNull { it.value == parts[3] } ?: RuleConditionOption.DomainSuffix,
                value = decode(parts[4]),
                endpoint = decode(parts[5]),
                resolve = parts[6] == "true"
            )
        }
    }

    fun saveVisualRules(rules: List<VisualRule>) {
        initialize()
        visualRulesFile.writeText(
            rules.joinToString("\n") {
                listOf(
                    it.id,
                    encode(it.name),
                    it.action.value,
                    it.condition.value,
                    encode(it.value),
                    encode(it.endpoint),
                    it.resolve.toString()
                ).joinToString("\t")
            }
        )
    }

    fun listSubscriptions(): List<SubscriptionProfile> {
        initialize()
        if (!subscriptionsFile.exists()) return emptyList()

        return subscriptionsFile.readLines()
            .mapNotNull { line ->
                val parts = line.split('\t')
                if (parts.size < 4) return@mapNotNull null
                SubscriptionProfile(
                    id = parts[0],
                    name = decode(parts[1]),
                    url = decode(parts[2]),
                    fileName = decode(parts[3]),
                    type = parts.getOrNull(4)?.let { decode(it) } ?: "url"
                )
            }
    }

    fun selectedSubscriptionId(): String = readSelection()["subscription"].orEmpty()

    fun selectedEndpointKey(): String = readSelection()["endpoint"].orEmpty()

    fun setSelectedSubscription(id: String) {
        val endpoints = listEndpoints(id)
        val currentEndpoint = selectedEndpointKey()
        writeSelection(id, endpoints.firstOrNull { it.key == currentEndpoint }?.key ?: endpoints.firstOrNull()?.key.orEmpty())
    }

    fun setSelectedEndpoint(key: String) {
        writeSelection(selectedSubscriptionId(), key)
    }

    fun listEndpoints(subscriptionId: String = selectedSubscriptionId()): List<EndpointItem> {
        initialize()
        val profile = listSubscriptions().firstOrNull { it.id == subscriptionId } ?: return emptyList()
        val file = File(configDir, profile.fileName)
        if (!file.exists()) return emptyList()
        return parseEndpoints(file.readText())
    }

    suspend fun updateSubscription(url: String): String = withContext(Dispatchers.IO) {
        try {
            initialize()
            val trimmedUrl = url.trim()
            if (trimmedUrl.isBlank()) return@withContext "Subscription URL is empty"

            val content = downloadProfileText(trimmedUrl)
            importProfileContent(profileNameFromUrl(trimmedUrl), content, sourceUrl = trimmedUrl, type = "url")
        } catch (e: Exception) {
            "Subscription update failed: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    suspend fun importProfileFromUri(uri: Uri): String = withContext(Dispatchers.IO) {
        try {
            initialize()
            val displayName = displayNameForUri(uri)
            val content = context.contentResolver.openInputStream(uri)?.use { input ->
                input.readBytes().toString(Charsets.UTF_8)
            } ?: return@withContext "Failed to read selected file"
            importProfileContent(displayName, content, sourceUrl = "file://$displayName", type = "file")
        } catch (e: Exception) {
            "Profile import failed: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    fun buildRuntimeConfig(): File {
        initialize()
        val profiles = listSubscriptions()
        val selectedProfile = profiles.firstOrNull { it.id == selectedSubscriptionId() } ?: profiles.firstOrNull()
        val endpoints = selectedProfile?.let { listEndpoints(it.id) }.orEmpty()
        val endpointKey = selectedEndpointKey().ifBlank { endpoints.firstOrNull()?.key.orEmpty() }

        if (selectedProfile != null && selectedSubscriptionId() != selectedProfile.id) {
            writeSelection(selectedProfile.id, endpointKey)
        }

        val builder = StringBuilder()
        builder.appendLine("[local]")
        builder.appendLine("type = \"socks5\"")
        builder.appendLine("bind = \"127.0.0.1\"")
        builder.appendLine("port = 1080")
        builder.appendLine()
        builder.appendLine("[main]")
        if (selectedProfile != null) {
            builder.appendLine("include = [\"${escapeToml(selectedProfile.fileName)}\"]")
        }
        if (endpointKey.isNotBlank()) {
            builder.appendLine("endpoint = \"${escapeToml(endpointKey)}\"")
        }
        val countryDbAvailable = countryDbFile.exists() && countryDbFile.length() > 1024 * 1024
        if (countryDbAvailable) {
            builder.appendLine("country-db = \"${escapeToml(countryDbFile.absolutePath)}\"")
        }
        builder.appendLine()
        builder.append(renderRulesToml(readVisualRules(), includeRegionRules = countryDbAvailable).trim())
        builder.appendLine()

        runtimeConfigFile.writeText(builder.toString())
        return runtimeConfigFile
    }

    private fun copyAsset(assetName: String, dest: File) {
        try {
            context.assets.open(assetName).use { input ->
                dest.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
        } catch (_: Exception) {}
    }

    private fun runSubCommand(url: String): String {
        val binaryManager = NativeBinaryManager(context)
        val binFile = binaryManager.prepareVlessProxy()
            ?: return "Native binary not found for ABI ${binaryManager.abi()}. Reinstall the latest APK. Tried: ${binaryManager.describeSearchPaths()}"

        return try {
            val process = ProcessBuilder(binFile.absolutePath, "sub", url)
                .directory(context.filesDir)
                .redirectErrorStream(true)
                .start()

            val output = StringBuilder()
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                while (true) {
                    val line = reader.readLine() ?: break
                    output.appendLine(line)
                }
            }
            val exitCode = process.waitFor()
            if (exitCode != 0 && output.isBlank()) {
                output.append("Subscription update failed with exit code ").append(exitCode)
            }
            output.toString().trim()
        } catch (e: Exception) {
            "Failed to run sub: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    private fun runImportFileCommand(inputFile: File, outputName: String): String {
        val binaryManager = NativeBinaryManager(context)
        val binFile = binaryManager.prepareVlessProxy()
            ?: return "Native binary not found for ABI ${binaryManager.abi()}. Reinstall the latest APK. Tried: ${binaryManager.describeSearchPaths()}"

        return try {
            val process = ProcessBuilder(binFile.absolutePath, "import-file", inputFile.absolutePath, outputName)
                .directory(context.filesDir)
                .redirectErrorStream(true)
                .start()

            val output = StringBuilder()
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                while (true) {
                    val line = reader.readLine() ?: break
                    output.appendLine(line)
                }
            }
            val exitCode = process.waitFor()
            if (exitCode != 0 && output.isBlank()) {
                output.append("Profile import failed with exit code ").append(exitCode)
            }
            output.toString().trim()
        } catch (e: Exception) {
            "Failed to import profile: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    private fun importProfileContent(
        displayName: String,
        content: String,
        sourceUrl: String,
        type: String
    ): String {
        val profileName = displayName.substringBeforeLast('.').ifBlank { "Imported" }
        val fileName = uniqueProfileFileName(profileName)
        val file = File(configDir, fileName)
        val output = if (content.contains("[endpoints.")) {
            file.writeText(content)
            "Saved subscription: config/$fileName\nImported endpoints: ${parseEndpoints(content).size}"
        } else {
            val tempFile = File(configDir, "import-${UUID.randomUUID()}.txt")
            tempFile.writeText(content)
            runImportFileCommand(tempFile, fileName).also {
                try { tempFile.delete() } catch (_: Exception) {}
            }
        }

        if (!file.exists()) return output.ifBlank { "Profile import failed" }
        val endpoints = parseEndpoints(file.readText())
        val profiles = listSubscriptions().toMutableList()
        val profile = SubscriptionProfile(
            id = UUID.randomUUID().toString(),
            name = profileName,
            url = sourceUrl,
            fileName = fileName,
            type = type
        )
        profiles += profile
        writeSubscriptions(profiles)
        writeSelection(profile.id, endpoints.firstOrNull()?.key.orEmpty())
        return output.ifBlank { "Profile imported: $profileName" }
    }

    private fun downloadProfileText(url: String): String {
        val client = OkHttpClient.Builder()
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", "Pulse/1.0")
            .header("Accept", "*/*")
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw IllegalStateException("HTTP ${response.code}")
            }
            return response.body?.string() ?: throw IllegalStateException("Empty response")
        }
    }

    private fun profileNameFromUrl(url: String): String {
        return try {
            URI(url).host.orEmpty().ifBlank { "Profile" }
        } catch (_: Exception) {
            "Profile"
        }
    }

    private fun parseSavedSubscription(output: String): String? {
        val match = Regex("""Saved subscription:\s*config[/\\]([^\s]+)""").find(output)
        return match?.groupValues?.getOrNull(1)
    }

    private fun guessSubscriptionFileName(url: String): String {
        return try {
            val host = URI(url).host.orEmpty()
                .lowercase()
                .replace(Regex("[^a-z0-9._-]"), "-")
                .trim('-')
            "${host.ifBlank { "subscription" }}.toml"
        } catch (_: Exception) {
            "subscription.toml"
        }
    }

    private fun writeSubscriptions(profiles: List<SubscriptionProfile>) {
        configDir.mkdirs()
        subscriptionsFile.writeText(
            profiles.joinToString("\n") {
                listOf(it.id, encode(it.name), encode(it.url), encode(it.fileName), encode(it.type)).joinToString("\t")
            }
        )
    }

    private fun displayNameForUri(uri: Uri): String {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (nameIndex >= 0 && cursor.moveToFirst()) {
                return cursor.getString(nameIndex)
            }
        }
        return uri.lastPathSegment?.substringAfterLast('/') ?: "profile.txt"
    }

    private fun uniqueProfileFileName(name: String): String {
        val base = name.lowercase()
            .replace(Regex("[^a-z0-9._-]"), "-")
            .trim('-')
            .ifBlank { "profile" }
            .removeSuffix(".toml")
        var candidate = "$base.toml"
        var index = 2
        while (File(configDir, candidate).exists()) {
            candidate = "$base-$index.toml"
            index += 1
        }
        return candidate
    }

    private fun readSelection(): Map<String, String> {
        if (!selectionFile.exists()) return emptyMap()
        return selectionFile.readLines().mapNotNull { line ->
            val index = line.indexOf('=')
            if (index <= 0) null else line.substring(0, index) to line.substring(index + 1)
        }.toMap()
    }

    private fun writeSelection(subscriptionId: String, endpointKey: String) {
        configDir.mkdirs()
        selectionFile.writeText(
            buildString {
                append("subscription=").append(subscriptionId).append('\n')
                append("endpoint=").append(endpointKey).append('\n')
            }
        )
    }

    private fun parseEndpoints(content: String): List<EndpointItem> {
        val sections = Regex("""(?m)^\[endpoints\.([^\].]+)]\s*$""").findAll(content).toList()
        return sections.mapIndexed { index, match ->
            val key = match.groupValues[1]
            val start = match.range.last + 1
            val end = sections.getOrNull(index + 1)?.range?.first ?: content.length
            val body = content.substring(start, end)
            EndpointItem(
                key = key,
                name = readTomlString(body, "name"),
                server = readTomlString(body, "server"),
                type = readTomlString(body, "type")
            )
        }
    }

    private fun readTomlString(body: String, key: String): String {
        val match = Regex("""(?m)^\s*$key\s*=\s*["']([^"']*)["']""").find(body)
        return match?.groupValues?.getOrNull(1).orEmpty()
    }

    private fun encode(value: String): String =
        Base64.encodeToString(value.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)

    private fun decode(value: String): String =
        String(Base64.decode(value, Base64.NO_WRAP), Charsets.UTF_8)

    private fun escapeToml(value: String): String =
        value.replace("\\", "\\\\").replace("\"", "\\\"")

    private fun renderRulesToml(
        rules: List<VisualRule>,
        includeRegionRules: Boolean = true
    ): String {
        val builder = StringBuilder()
        if (includeRegionRules && rules.any { it.condition == RuleConditionOption.Region && it.value.equals("cn", ignoreCase = true) }) {
            builder.appendLine("[regions.cn]")
            builder.appendLine("cidrs = [\"1.0.1.0/24\", \"1.0.8.0/24\", \"1.0.32.0/24\", \"1.1.1.0/24\"]")
            builder.appendLine()
        }

        rules.forEachIndexed { index, rule ->
            if (!includeRegionRules && rule.condition == RuleConditionOption.Region) {
                return@forEachIndexed
            }

            val safeName = rule.name.lowercase()
                .replace(Regex("[^a-z0-9._-]"), "-")
                .trim('-')
                .ifBlank { "rule-${index + 1}" }

            builder.appendLine("[rules.${escapeToml(safeName)}]")
            builder.appendLine("action = \"${rule.action.value}\"")
            if (rule.action == RuleActionOption.Proxy && rule.endpoint.isNotBlank()) {
                builder.appendLine("endpoint = \"${escapeToml(rule.endpoint)}\"")
            }

            val values = rule.value.split(',', '\n')
                .map { it.trim() }
                .filter { it.isNotBlank() }
            when (rule.condition) {
                RuleConditionOption.Domain,
                RuleConditionOption.DomainSuffix,
                RuleConditionOption.DomainKeyword -> {
                    val list = values.joinToString(", ") { "\"${escapeToml(it)}\"" }
                    builder.appendLine("${rule.condition.value} = [$list]")
                }
                RuleConditionOption.Region -> {
                    builder.appendLine("region = \"${escapeToml(values.firstOrNull() ?: rule.value)}\"")
                    builder.appendLine("resolve = ${rule.resolve}")
                }
            }
            builder.appendLine()
        }

        return builder.toString().trimEnd()
    }

    companion object {
        fun defaultVisualRules(): List<VisualRule> = listOf(
            VisualRule(
                id = UUID.randomUUID().toString(),
                name = "Direct CN",
                action = RuleActionOption.Direct,
                condition = RuleConditionOption.Region,
                value = "cn",
                resolve = true
            ),
            VisualRule(
                id = UUID.randomUUID().toString(),
                name = "Reject Ads",
                action = RuleActionOption.Reject,
                condition = RuleConditionOption.DomainKeyword,
                value = "adservice,doubleclick"
            )
        )
    }
}
