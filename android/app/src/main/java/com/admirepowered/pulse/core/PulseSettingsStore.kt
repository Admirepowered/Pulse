package com.admirepowered.pulse.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

const val DEFAULT_DELAY_TEST_URL = "https://www.gstatic.com/generate_204"

data class PulseSettings(
    val allowLan: Boolean = false,
    val coreLogLevel: String = "silent",
    val proxyMode: String = "rule",
    val proxyUpdateProfiles: Boolean = true,
    val autoUpdateProfiles: Boolean = true,
    val autoStartVpn: Boolean = false,
    val themeMode: String = "System",
    val backgroundImageUri: String = "",
    val backgroundOpacityPercent: Int = 28,
    val backgroundBlurDp: Int = 0,
    val disableUpdateCheck: Boolean = false,
    val webDavEnabled: Boolean = false,
    val webDavUrl: String = "",
    val webDavUsername: String = "",
    val webDavPassword: String = "",
    val delayTestUrl: String = DEFAULT_DELAY_TEST_URL,
    val accessControlMode: String = "Off",
    val accessControlPackages: Set<String> = emptySet(),
)

object PulseSettingsStore {
    private const val PREFS = "pulse_settings"
    private const val ALLOW_LAN = "allow_lan"
    private const val CORE_LOG_LEVEL = "core_log_level"
    private const val PROXY_MODE = "proxy_mode"
    private const val PROXY_UPDATE_PROFILES = "proxy_update_profiles"
    private const val AUTO_UPDATE_PROFILES = "auto_update_profiles"
    private const val AUTO_START_VPN = "auto_start_vpn"
    private const val THEME_MODE = "theme_mode"
    private const val BACKGROUND_IMAGE_URI = "background_image_uri"
    private const val BACKGROUND_OPACITY_PERCENT = "background_opacity_percent"
    private const val BACKGROUND_BLUR_DP = "background_blur_dp"
    private const val DISABLE_UPDATE_CHECK = "disable_update_check"
    private const val WEBDAV_ENABLED = "webdav_enabled"
    private const val WEBDAV_URL = "webdav_url"
    private const val WEBDAV_USERNAME = "webdav_username"
    private const val WEBDAV_PASSWORD = "webdav_password"
    private const val DELAY_TEST_URL = "delay_test_url"
    private const val ACCESS_CONTROL_MODE = "access_control_mode"
    private const val ACCESS_CONTROL_PACKAGES = "access_control_packages"

    fun load(context: Context): PulseSettings {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return PulseSettings(
            allowLan = prefs.getBoolean(ALLOW_LAN, false),
            coreLogLevel = prefs.getString(CORE_LOG_LEVEL, "silent") ?: "silent",
            proxyMode = prefs.getString(PROXY_MODE, "rule") ?: "rule",
            proxyUpdateProfiles = prefs.getBoolean(PROXY_UPDATE_PROFILES, true),
            autoUpdateProfiles = prefs.getBoolean(AUTO_UPDATE_PROFILES, true),
            autoStartVpn = prefs.getBoolean(AUTO_START_VPN, false),
            themeMode = prefs.getString(THEME_MODE, "System") ?: "System",
            backgroundImageUri = prefs.getString(BACKGROUND_IMAGE_URI, "") ?: "",
            backgroundOpacityPercent = prefs.getInt(BACKGROUND_OPACITY_PERCENT, 28).coerceIn(0, 60),
            backgroundBlurDp = prefs.getInt(BACKGROUND_BLUR_DP, 0).coerceIn(0, 40),
            disableUpdateCheck = prefs.getBoolean(DISABLE_UPDATE_CHECK, false),
            webDavEnabled = prefs.getBoolean(WEBDAV_ENABLED, false),
            webDavUrl = prefs.getString(WEBDAV_URL, "") ?: "",
            webDavUsername = prefs.getString(WEBDAV_USERNAME, "") ?: "",
            webDavPassword = prefs.getString(WEBDAV_PASSWORD, "") ?: "",
            delayTestUrl = prefs.getString(DELAY_TEST_URL, DEFAULT_DELAY_TEST_URL)
                ?.takeIf { it.isNotBlank() }
                ?: DEFAULT_DELAY_TEST_URL,
            accessControlMode = prefs.getString(ACCESS_CONTROL_MODE, "Off") ?: "Off",
            accessControlPackages = prefs.getStringSet(ACCESS_CONTROL_PACKAGES, emptySet()).orEmpty(),
        )
    }

    fun setAllowLan(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(ALLOW_LAN, enabled)
            .apply()
    }

    fun setCoreLogLevel(context: Context, level: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(CORE_LOG_LEVEL, level.ifBlank { "silent" })
            .apply()
    }

    fun setProxyMode(context: Context, mode: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(PROXY_MODE, mode.ifBlank { "rule" })
            .apply()
    }

    fun setProxyUpdateProfiles(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(PROXY_UPDATE_PROFILES, enabled)
            .apply()
    }

    fun setAutoUpdateProfiles(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(AUTO_UPDATE_PROFILES, enabled)
            .apply()
    }

    fun setAutoStartVpn(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(AUTO_START_VPN, enabled)
            .apply()
    }

    fun setThemeMode(context: Context, mode: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(THEME_MODE, mode)
            .apply()
    }

    fun setBackgroundImageUri(context: Context, uri: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(BACKGROUND_IMAGE_URI, uri)
            .apply()
    }

    fun setBackgroundOpacityPercent(context: Context, value: Int) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putInt(BACKGROUND_OPACITY_PERCENT, value.coerceIn(0, 60))
            .apply()
    }

    fun setBackgroundBlurDp(context: Context, value: Int) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putInt(BACKGROUND_BLUR_DP, value.coerceIn(0, 40))
            .apply()
    }

    fun setDisableUpdateCheck(context: Context, disabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(DISABLE_UPDATE_CHECK, disabled)
            .apply()
    }

    fun setWebDavEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(WEBDAV_ENABLED, enabled)
            .apply()
    }

    fun setWebDavUrl(context: Context, url: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(WEBDAV_URL, url)
            .apply()
    }

    fun setWebDavUsername(context: Context, username: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(WEBDAV_USERNAME, username)
            .apply()
    }

    fun setWebDavPassword(context: Context, password: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(WEBDAV_PASSWORD, password)
            .apply()
    }

    fun setDelayTestUrl(context: Context, url: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(DELAY_TEST_URL, url.ifBlank { DEFAULT_DELAY_TEST_URL })
            .apply()
    }

    fun setAccessControlMode(context: Context, mode: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(ACCESS_CONTROL_MODE, mode)
            .apply()
    }

    fun setAccessControlPackages(context: Context, packages: Set<String>) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(ACCESS_CONTROL_PACKAGES, packages)
            .apply()
    }

    fun exportBackupJson(context: Context): JSONObject {
        val settings = load(context)
        return JSONObject()
            .put(ALLOW_LAN, settings.allowLan)
            .put(CORE_LOG_LEVEL, settings.coreLogLevel)
            .put(PROXY_MODE, settings.proxyMode)
            .put(PROXY_UPDATE_PROFILES, settings.proxyUpdateProfiles)
            .put(AUTO_UPDATE_PROFILES, settings.autoUpdateProfiles)
            .put(AUTO_START_VPN, settings.autoStartVpn)
            .put(THEME_MODE, settings.themeMode)
            .put(BACKGROUND_OPACITY_PERCENT, settings.backgroundOpacityPercent)
            .put(BACKGROUND_BLUR_DP, settings.backgroundBlurDp)
            .put(DISABLE_UPDATE_CHECK, settings.disableUpdateCheck)
            .put(WEBDAV_ENABLED, settings.webDavEnabled)
            .put(WEBDAV_URL, settings.webDavUrl)
            .put(WEBDAV_USERNAME, settings.webDavUsername)
            .put(DELAY_TEST_URL, settings.delayTestUrl)
            .put(ACCESS_CONTROL_MODE, settings.accessControlMode)
            .put(ACCESS_CONTROL_PACKAGES, JSONArray(settings.accessControlPackages.sorted()))
    }

    fun importBackupJson(context: Context, json: JSONObject?) {
        json ?: return
        val editor = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
        putBooleanIfPresent(editor, json, ALLOW_LAN)
        putStringIfPresent(editor, json, CORE_LOG_LEVEL, "silent")
        putStringIfPresent(editor, json, PROXY_MODE, "rule")
        putBooleanIfPresent(editor, json, PROXY_UPDATE_PROFILES)
        putBooleanIfPresent(editor, json, AUTO_UPDATE_PROFILES)
        putBooleanIfPresent(editor, json, AUTO_START_VPN)
        putStringIfPresent(editor, json, THEME_MODE, "System")
        putIntIfPresent(editor, json, BACKGROUND_OPACITY_PERCENT, 0, 60)
        putIntIfPresent(editor, json, BACKGROUND_BLUR_DP, 0, 40)
        putBooleanIfPresent(editor, json, DISABLE_UPDATE_CHECK)
        putBooleanIfPresent(editor, json, WEBDAV_ENABLED)
        putStringIfPresent(editor, json, WEBDAV_URL, "")
        putStringIfPresent(editor, json, WEBDAV_USERNAME, "")
        putStringIfPresent(editor, json, DELAY_TEST_URL, DEFAULT_DELAY_TEST_URL)
        putStringIfPresent(editor, json, ACCESS_CONTROL_MODE, "Off")
        json.optJSONArray(ACCESS_CONTROL_PACKAGES)?.let { array ->
            val packages = buildSet {
                for (index in 0 until array.length()) {
                    array.optString(index).takeIf { it.isNotBlank() }?.let(::add)
                }
            }
            editor.putStringSet(ACCESS_CONTROL_PACKAGES, packages)
        }
        editor.apply()
    }

    private fun putBooleanIfPresent(
        editor: android.content.SharedPreferences.Editor,
        json: JSONObject,
        key: String,
    ) {
        if (json.has(key)) {
            editor.putBoolean(key, json.optBoolean(key))
        }
    }

    private fun putStringIfPresent(
        editor: android.content.SharedPreferences.Editor,
        json: JSONObject,
        key: String,
        fallback: String,
    ) {
        if (json.has(key)) {
            editor.putString(key, json.optString(key).ifBlank { fallback })
        }
    }

    private fun putIntIfPresent(
        editor: android.content.SharedPreferences.Editor,
        json: JSONObject,
        key: String,
        min: Int,
        max: Int,
    ) {
        if (json.has(key)) {
            editor.putInt(key, json.optInt(key).coerceIn(min, max))
        }
    }
}
