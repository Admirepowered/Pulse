package com.admirepowered.pulse.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.admirepowered.pulse.MainActivity
import com.admirepowered.pulse.R
import com.admirepowered.pulse.core.PulseCoreBridge
import com.admirepowered.pulse.core.PulseProfileStore
import java.io.IOException

class PulseVpnService : VpnService() {
    private var tunFd: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopVpn()
            else -> startVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun startVpn() {
        if (tunFd != null) return
        startForeground(NOTIFICATION_ID, buildNotification())
        val establishedTun = Builder()
            .setSession("Pulse")
            .setMtu(9000)
            .addAddress("10.255.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .establish()
        tunFd = establishedTun

        if (establishedTun == null) {
            stopVpn()
            return
        }
        val profile = PulseProfileStore.active(this)
        val coreFd = ParcelFileDescriptor.dup(establishedTun.fileDescriptor).detachFd()
        val result = PulseCoreBridge.start(profile.path, filesDir.absolutePath, coreFd)
        if (result.isFailure) {
            closeDetachedFd(coreFd)
            stopVpn()
        }
    }

    private fun stopVpn() {
        PulseCoreBridge.stop()
        try {
            tunFd?.close()
        } catch (_: IOException) {
        } finally {
            tunFd = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
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
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_status)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_text))
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()
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

        fun isCoreRunning(): Boolean {
            return PulseCoreBridge.isRunning()
        }
    }
}
