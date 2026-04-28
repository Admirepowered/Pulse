package com.pulse.proxy.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "pulse_settings")

class AppPreferences(private val context: Context) {

    companion object {
        private val KEY_VPN_AUTO_START = booleanPreferencesKey("vpn_auto_start")
        private val KEY_PROXY_PORT = intPreferencesKey("proxy_port")
        private val KEY_FIRST_LAUNCH = booleanPreferencesKey("first_launch_done")
    }

    val vpnAutoStart: Flow<Boolean> = context.dataStore.data.map { it[KEY_VPN_AUTO_START] ?: false }
    val proxyPort: Flow<Int> = context.dataStore.data.map { it[KEY_PROXY_PORT] ?: 1080 }
    val firstLaunchDone: Flow<Boolean> = context.dataStore.data.map { it[KEY_FIRST_LAUNCH] ?: false }

    suspend fun setVpnAutoStart(value: Boolean) {
        context.dataStore.edit { it[KEY_VPN_AUTO_START] = value }
    }

    suspend fun setProxyPort(port: Int) {
        context.dataStore.edit { it[KEY_PROXY_PORT] = port }
    }

    suspend fun setFirstLaunchDone() {
        context.dataStore.edit { it[KEY_FIRST_LAUNCH] = true }
    }
}
