package com.admirepowered.pulse.core

import android.content.Context

data class PulseSettings(
    val proxyUpdateProfiles: Boolean = true,
)

object PulseSettingsStore {
    private const val PREFS = "pulse_settings"
    private const val PROXY_UPDATE_PROFILES = "proxy_update_profiles"

    fun load(context: Context): PulseSettings {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return PulseSettings(
            proxyUpdateProfiles = prefs.getBoolean(PROXY_UPDATE_PROFILES, true),
        )
    }

    fun setProxyUpdateProfiles(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(PROXY_UPDATE_PROFILES, enabled)
            .apply()
    }
}
