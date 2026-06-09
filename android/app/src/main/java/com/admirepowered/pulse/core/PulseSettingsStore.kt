package com.admirepowered.pulse.core

import android.content.Context

data class PulseSettings(
    val allowLan: Boolean = false,
    val proxyUpdateProfiles: Boolean = true,
)

object PulseSettingsStore {
    private const val PREFS = "pulse_settings"
    private const val ALLOW_LAN = "allow_lan"
    private const val PROXY_UPDATE_PROFILES = "proxy_update_profiles"

    fun load(context: Context): PulseSettings {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return PulseSettings(
            allowLan = prefs.getBoolean(ALLOW_LAN, false),
            proxyUpdateProfiles = prefs.getBoolean(PROXY_UPDATE_PROFILES, true),
        )
    }

    fun setAllowLan(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(ALLOW_LAN, enabled)
            .apply()
    }

    fun setProxyUpdateProfiles(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(PROXY_UPDATE_PROFILES, enabled)
            .apply()
    }
}
