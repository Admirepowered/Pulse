package com.admirepowered.pulse.quick

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.admirepowered.pulse.EXTRA_REQUEST_VPN_START
import com.admirepowered.pulse.MainActivity
import com.admirepowered.pulse.core.PulseSettingsStore
import com.admirepowered.pulse.vpn.PulseVpnService

class PulseTileService : TileService() {
    private val handler = Handler(Looper.getMainLooper())

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
                .putExtra(EXTRA_REQUEST_VPN_START, true)
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
        scheduleRefresh()
    }

    override fun onStopListening() {
        handler.removeCallbacksAndMessages(null)
        super.onStopListening()
    }

    private fun scheduleRefresh() {
        handler.postDelayed({ refreshTile() }, 600)
        handler.postDelayed({ refreshTile() }, 1_500)
    }

    private fun refreshTile() {
        qsTile?.apply {
            val needsPermission = VpnService.prepare(this@PulseTileService) != null
            val running = PulseVpnService.isCoreRunning()
            state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            label = "Pulse"
            subtitle = when {
                running -> "${modeLabel(PulseSettingsStore.load(this@PulseTileService).proxyMode)}模式"
                needsPermission -> "需要 VPN 授权"
                else -> "点击启动代理"
            }
            updateTile()
        }
    }

    private fun modeLabel(mode: String): String {
        return when (mode) {
            "global" -> "全局"
            "direct" -> "直连"
            else -> "规则"
        }
    }
}
