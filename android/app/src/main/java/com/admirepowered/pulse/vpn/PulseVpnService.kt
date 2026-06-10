package com.admirepowered.pulse.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import androidx.core.app.NotificationCompat
import com.admirepowered.pulse.MainActivity
import com.admirepowered.pulse.R
import com.admirepowered.pulse.core.PulseCoreBridge
import com.admirepowered.pulse.core.PulseCustomRuleStore
import com.admirepowered.pulse.core.PulseLogStore
import com.admirepowered.pulse.core.PulseProfileStore
import com.admirepowered.pulse.core.PulseSettingsStore
import com.admirepowered.pulse.quick.PulseTileService
import java.io.IOException

class PulseVpnService : VpnService() {
    private var tunFd: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopVpn(stopService = true)
            ACTION_RESTART -> restartVpn()
            ACTION_SET_MODE -> setMode(intent.getStringExtra(EXTRA_MODE))
            ACTION_REFRESH_STATUS_UI -> refreshStatusUi()
            else -> startVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn(stopService = false)
        super.onDestroy()
    }

    private fun startVpn() {
        if (tunFd != null) return
        PulseLogStore.info(this, "开始启动 Pulse VPN")
        startForeground(NOTIFICATION_ID, buildNotification())
        val settings = PulseSettingsStore.load(this)
        val builder = Builder()
            .setSession("Pulse")
            .setMtu(9000)
            .addAddress("10.255.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
        applyAccessControl(builder, settings)
        val establishedTun = builder.establish()
        tunFd = establishedTun

        if (establishedTun == null) {
            PulseLogStore.error(this, "系统未返回可用的 TUN 文件描述符")
            stopVpn(stopService = true)
            return
        }
        val profile = PulseProfileStore.active(this)
        PulseLogStore.info(this, "使用配置启动 mihomo: ${profile.name}")
        val runtimeProfile = PulseCustomRuleStore.runtimeProfile(this, profile, settings)
        val coreFd = ParcelFileDescriptor.dup(establishedTun.fileDescriptor).detachFd()
        val result = PulseCoreBridge.start(runtimeProfile.absolutePath, filesDir.absolutePath, coreFd, settings.allowLan)
        if (result.isFailure) {
            PulseLogStore.error(this, result.exceptionOrNull()?.message ?: "mihomo 启动失败")
            closeDetachedFd(coreFd)
            stopVpn(stopService = true)
        } else {
            PulseLogStore.info(this, "mihomo core 已接管 TUN")
            requestTileRefresh(this)
        }
    }

    private fun restartVpn() {
        PulseLogStore.info(this, "重启 Pulse VPN")
        stopVpn(stopService = false)
        startVpn()
    }

    private fun setMode(mode: String?) {
        val normalized = mode?.takeIf { it in supportedModes } ?: return
        if (!PulseCoreBridge.isRunning()) {
            PulseSettingsStore.setProxyMode(this, normalized)
            return
        }
        PulseCoreBridge.setMode(normalized)
            .onSuccess {
                PulseSettingsStore.setProxyMode(this, normalized)
                PulseLogStore.info(this, "已切换代理模式: ${modeLabel(normalized)}")
            }
            .onFailure { error ->
                PulseLogStore.error(this, error.message ?: "切换代理模式失败")
            }
        refreshStatusUi()
    }

    private fun refreshStatusUi() {
        if (!PulseCoreBridge.isRunning()) return
        updateNotification()
        requestTileRefresh(this)
    }

    private fun stopVpn(stopService: Boolean) {
        PulseLogStore.info(this, if (stopService) "停止 Pulse VPN" else "释放 Pulse VPN")
        PulseCoreBridge.stop()
        try {
            tunFd?.close()
        } catch (_: IOException) {
        } finally {
            tunFd = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            requestTileRefresh(this)
            if (stopService) {
                stopSelf()
            }
        }
    }

    private fun closeDetachedFd(fd: Int) {
        if (fd < 0) return
        try {
            ParcelFileDescriptor.adoptFd(fd).close()
        } catch (_: IOException) {
        }
    }

    private fun buildNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val mode = PulseSettingsStore.load(this).proxyMode
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_status)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText("${getString(R.string.vpn_notification_text)} 当前模式：${modeLabel(mode)}")
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .addAction(R.drawable.ic_vpn_status, "规则", modePendingIntent("rule", 2))
            .addAction(R.drawable.ic_vpn_status, "全局", modePendingIntent("global", 3))
            .addAction(R.drawable.ic_vpn_status, "直连", modePendingIntent("direct", 4))
            .build()
    }

    private fun updateNotification() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification())
    }

    private fun modePendingIntent(mode: String, requestCode: Int): PendingIntent {
        val intent = Intent(this, PulseVpnService::class.java)
            .setAction(ACTION_SET_MODE)
            .putExtra(EXTRA_MODE, mode)
        return PendingIntent.getService(
            this,
            requestCode,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private fun applyAccessControl(builder: Builder, settings: com.admirepowered.pulse.core.PulseSettings) {
        val packages = settings.accessControlPackages
            .filter { it.isNotBlank() && it != packageName }
            .distinct()
        when (settings.accessControlMode) {
            "Include" -> {
                if (packages.isEmpty()) {
                    PulseLogStore.warn(this, "访问控制为仅代理选中应用，但未选择应用，已按不限制处理")
                    addDisallowedApplication(builder, packageName)
                    return
                }
                packages.forEach { addAllowedApplication(builder, it) }
                PulseLogStore.info(this, "仅代理 ${packages.size} 个选中应用")
            }

            "Exclude" -> {
                addDisallowedApplication(builder, packageName)
                packages.forEach { addDisallowedApplication(builder, it) }
                PulseLogStore.info(this, "绕过 ${packages.size} 个选中应用")
            }

            else -> {
                addDisallowedApplication(builder, packageName)
            }
        }
    }

    private fun addAllowedApplication(builder: Builder, packageName: String) {
        try {
            builder.addAllowedApplication(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            PulseLogStore.warn(this, "访问控制应用不存在: $packageName")
        } catch (error: UnsupportedOperationException) {
            PulseLogStore.warn(this, error.message ?: "当前系统不支持应用访问控制")
        }
    }

    private fun addDisallowedApplication(builder: Builder, packageName: String) {
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            PulseLogStore.warn(this, "访问控制应用不存在: $packageName")
        } catch (error: UnsupportedOperationException) {
            PulseLogStore.warn(this, error.message ?: "当前系统不支持应用访问控制")
        }
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)
    }

    companion object {
        private const val CHANNEL_ID = "pulse_vpn"
        private const val NOTIFICATION_ID = 1001
        private const val ACTION_START = "com.admirepowered.pulse.START_VPN"
        private const val ACTION_STOP = "com.admirepowered.pulse.STOP_VPN"
        private const val ACTION_RESTART = "com.admirepowered.pulse.RESTART_VPN"
        private const val ACTION_SET_MODE = "com.admirepowered.pulse.SET_MODE"
        private const val ACTION_REFRESH_STATUS_UI = "com.admirepowered.pulse.REFRESH_STATUS_UI"
        private const val EXTRA_MODE = "mode"
        private val supportedModes = setOf("rule", "global", "direct")

        private fun modeLabel(mode: String): String {
            return when (mode) {
                "global" -> "全局"
                "direct" -> "直连"
                else -> "规则"
            }
        }

        fun start(context: Context) {
            val intent = Intent(context, PulseVpnService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.startService(Intent(context, PulseVpnService::class.java).setAction(ACTION_STOP))
        }

        fun restart(context: Context) {
            val intent = Intent(context, PulseVpnService::class.java).setAction(ACTION_RESTART)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun isCoreRunning(): Boolean {
            return PulseCoreBridge.isRunning()
        }

        fun refreshStatusUi(context: Context) {
            if (!PulseCoreBridge.isRunning()) return
            context.startService(Intent(context, PulseVpnService::class.java).setAction(ACTION_REFRESH_STATUS_UI))
        }

        fun requestTileRefresh(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return
            TileService.requestListeningState(
                context,
                ComponentName(context, PulseTileService::class.java),
            )
        }
    }
}
