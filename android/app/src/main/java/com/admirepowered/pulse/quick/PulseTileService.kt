package com.admirepowered.pulse.quick

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.admirepowered.pulse.MainActivity
import com.admirepowered.pulse.vpn.PulseVpnService

class PulseTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        refreshTile()
    }

    override fun onClick() {
        super.onClick()
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            val intent = Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startActivityAndCollapse(android.app.PendingIntent.getActivity(this, 0, intent, android.app.PendingIntent.FLAG_IMMUTABLE))
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
            return
        }
        if (PulseVpnService.isCoreRunning()) {
            PulseVpnService.stop(this)
        } else {
            PulseVpnService.start(this)
        }
        refreshTile()
    }

    private fun refreshTile() {
        qsTile?.apply {
            state = if (PulseVpnService.isCoreRunning()) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            label = "Pulse"
            subtitle = if (PulseVpnService.isCoreRunning()) "代理已开启" else "点击启动代理"
            updateTile()
        }
    }
}
