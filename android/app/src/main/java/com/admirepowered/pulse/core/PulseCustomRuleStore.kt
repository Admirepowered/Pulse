package com.admirepowered.pulse.core

import android.content.Context
import com.admirepowered.pulse.ui.CustomRuleItem
import java.io.File
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

object PulseCustomRuleStore {
    private val supportedTypes = setOf(
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "IP-CIDR",
        "IP-CIDR6",
        "GEOIP",
        "GEOSITE",
        "MATCH",
    )

    fun read(context: Context, profileId: String): List<CustomRuleItem> {
        val file = ruleFile(context, profileId)
        if (!file.exists()) return emptyList()
        val array = JSONArray(file.readText(Charsets.UTF_8))
        return buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                add(
                    CustomRuleItem(
                        id = item.optString("id").ifBlank { newRuleId() },
                        type = item.optString("type", "DOMAIN-SUFFIX"),
                        payload = item.optString("payload"),
                        proxy = item.optString("proxy", "DIRECT"),
                        noResolve = item.optBoolean("noResolve"),
                    ),
                )
            }
        }.normalize()
    }

    fun write(context: Context, profileId: String, rules: List<CustomRuleItem>) {
        val normalized = rules.normalize()
        val array = rulesToJson(normalized)
        val file = ruleFile(context, profileId)
        file.parentFile?.mkdirs()
        file.writeText(array.toString(2), Charsets.UTF_8)
    }

    fun parseRuleText(text: String): List<CustomRuleItem> {
        return text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .mapNotNull(::parseRuleLine)
            .toList()
            .normalize()
    }

    fun exportBackupJson(context: Context, profileIds: List<String>): JSONObject {
        val json = JSONObject()
        profileIds.forEach { profileId ->
            val rules = read(context, profileId)
            if (rules.isNotEmpty()) {
                json.put(profileId, rulesToJson(rules))
            }
        }
        return json
    }

    fun importBackupJson(
        context: Context,
        json: JSONObject?,
        idMapping: Map<String, String>,
    ) {
        json ?: return
        val names = json.keys()
        while (names.hasNext()) {
            val oldId = names.next()
            val profileId = idMapping[oldId] ?: oldId
            val rules = rulesFromJson(json.optJSONArray(oldId)).normalize()
            if (rules.isNotEmpty()) {
                write(context, profileId, rules)
            }
        }
    }

    fun runtimeProfile(context: Context, profile: PulseProfileRecord, settings: PulseSettings): File {
        val source = File(profile.path).readText(Charsets.UTF_8)
        val rules = read(context, profile.id)
        val output = applyRuntimeSettings(injectRules(source, rules), settings)
        val file = File(runtimeDir(context), "${profile.id}.yaml")
        file.parentFile?.mkdirs()
        file.writeText(output, Charsets.UTF_8)
        return file
    }

    private fun applyRuntimeSettings(content: String, settings: PulseSettings): String {
        return setTopLevelValue(
            setTopLevelValue(content, "log-level", settings.coreLogLevel),
            "mode",
            settings.proxyMode,
        )
    }

    private fun setTopLevelValue(content: String, key: String, value: String): String {
        val normalizedContent = content.replace("\r\n", "\n")
        val regex = Regex("""(?m)^$key\s*:\s*.*$""")
        val replacement = "$key: $value"
        return if (regex.containsMatchIn(normalizedContent)) {
            normalizedContent.replace(regex, replacement)
        } else {
            replacement + "\n" + normalizedContent
        }
    }

    private fun injectRules(content: String, rules: List<CustomRuleItem>): String {
        val lines = rules.normalize().map { "  - ${ruleText(it)}" }
        if (lines.isEmpty()) return content
        val normalizedContent = content.replace("\r\n", "\n")
        val regex = Regex("""(?m)^rules\s*:\s*$""")
        val match = regex.find(normalizedContent)
        if (match == null) {
            return normalizedContent.trimEnd() + "\n\nrules:\n" + lines.joinToString("\n") + "\n"
        }
        val insertAt = match.range.last + 1
        return normalizedContent.substring(0, insertAt) +
            "\n" +
            lines.joinToString("\n") +
            normalizedContent.substring(insertAt)
    }

    private fun ruleText(rule: CustomRuleItem): String {
        val parts = mutableListOf(rule.type.uppercase(Locale.ROOT))
        if (parts.first() != "MATCH") {
            parts += rule.payload.trim()
        }
        parts += rule.proxy.trim()
        if (rule.noResolve) {
            parts += "no-resolve"
        }
        return parts.joinToString(",")
    }

    private fun parseRuleLine(line: String): CustomRuleItem? {
        val parts = line.split(",").map { it.trim() }.filter { it.isNotBlank() }
        if (parts.isEmpty()) return null
        val type = parts[0].uppercase(Locale.ROOT)
        if (type !in supportedTypes) return null
        val proxyIndex = if (type == "MATCH") 1 else 2
        val payload = if (type == "MATCH") "" else parts.getOrNull(1).orEmpty()
        val proxy = parts.getOrNull(proxyIndex).orEmpty()
        val noResolve = parts.drop(proxyIndex + 1).any { it.equals("no-resolve", ignoreCase = true) }
        return CustomRuleItem(
            id = newRuleId(),
            type = type,
            payload = payload,
            proxy = proxy,
            noResolve = noResolve,
        )
    }

    private fun List<CustomRuleItem>.normalize(): List<CustomRuleItem> {
        return mapNotNull { rule ->
            val type = rule.type.trim().uppercase(Locale.ROOT).ifBlank { "DOMAIN-SUFFIX" }
            val proxy = rule.proxy.trim().ifBlank { "DIRECT" }
            val payload = rule.payload.trim()
            if (type !in supportedTypes) return@mapNotNull null
            if (type != "MATCH" && payload.isBlank()) return@mapNotNull null
            CustomRuleItem(
                id = rule.id.ifBlank { newRuleId() },
                type = type,
                payload = if (type == "MATCH") "" else payload,
                proxy = proxy,
                noResolve = rule.noResolve,
            )
        }
    }

    private fun rulesToJson(rules: List<CustomRuleItem>): JSONArray {
        val array = JSONArray()
        rules.normalize().forEach { rule ->
            array.put(
                JSONObject()
                    .put("id", rule.id.ifBlank { newRuleId() })
                    .put("type", rule.type)
                    .put("payload", rule.payload)
                    .put("proxy", rule.proxy)
                    .put("noResolve", rule.noResolve),
            )
        }
        return array
    }

    private fun rulesFromJson(array: JSONArray?): List<CustomRuleItem> {
        array ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                add(
                    CustomRuleItem(
                        id = item.optString("id").ifBlank { newRuleId() },
                        type = item.optString("type", "DOMAIN-SUFFIX"),
                        payload = item.optString("payload"),
                        proxy = item.optString("proxy", "DIRECT"),
                        noResolve = item.optBoolean("noResolve"),
                    ),
                )
            }
        }
    }

    private fun ruleFile(context: Context, profileId: String): File {
        return File(File(context.filesDir, "custom-rules"), "$profileId.json")
    }

    private fun runtimeDir(context: Context): File {
        return File(context.filesDir, "runtime-profiles")
    }

    fun newRuleId(): String {
        return System.nanoTime().toString()
    }
}
