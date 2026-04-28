package com.pulse.proxy

import android.app.Application
import com.pulse.proxy.config.ConfigManager
import com.pulse.proxy.config.MmdbManager

class PulseApp : Application() {

    lateinit var configManager: ConfigManager
        private set
    lateinit var mmdbManager: MmdbManager
        private set

    override fun onCreate() {
        super.onCreate()
        configManager = ConfigManager(this)
        configManager.initialize()
        mmdbManager = MmdbManager(this)
    }
}
