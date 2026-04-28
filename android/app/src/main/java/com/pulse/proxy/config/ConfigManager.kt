package com.pulse.proxy.config

import android.content.Context
import java.io.File

class ConfigManager(private val context: Context) {

    private val configDir: File
        get() = File(context.filesDir, "config")

    private val configFile: File
        get() = File(configDir, "config.toml")

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
    }

    fun readConfig(): String {
        return if (configFile.exists()) configFile.readText() else ""
    }

    fun saveConfig(content: String) {
        configDir.mkdirs()
        configFile.writeText(content)
    }

    fun getConfigPath(): String = configFile.absolutePath
    fun getConfigDir(): String = configDir.absolutePath

    private fun copyAsset(assetName: String, dest: File) {
        try {
            context.assets.open(assetName).use { input ->
                dest.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
        } catch (_: Exception) {}
    }
}
