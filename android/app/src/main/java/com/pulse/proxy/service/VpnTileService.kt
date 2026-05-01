package com.pulse.proxy.service

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import com.pulse.proxy.MainActivity

class VpnTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (PulseVpnService.isRunning) {
            startService(Intent(this, PulseVpnService::class.java).apply {
                putExtra("action", "stop")
            })
            updateTile()
            return
        }

        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            val intent = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startActivityAndCollapse(intent)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
            return
        }

        ContextCompat.startForegroundService(this, Intent(this, PulseVpnService::class.java))
        updateTile()
    }

    private fun updateTile() {
        qsTile?.apply {
            state = if (PulseVpnService.isRunning) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            label = "Pulse VPN"
            subtitle = if (PulseVpnService.isRunning) "Running" else "Stopped"
            updateTile()
        }
    }
}
