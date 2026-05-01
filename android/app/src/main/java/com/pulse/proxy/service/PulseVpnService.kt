package com.pulse.proxy.service

import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.pulse.proxy.MainActivity
import com.pulse.proxy.config.ConfigManager
import com.pulse.proxy.config.MmdbManager
import com.pulse.proxy.data.VpnStatus
import com.pulse.proxy.tun.ConnectionTracker
import com.pulse.proxy.tun.TcpForwarder
import com.pulse.proxy.util.LogBuffer
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

class PulseVpnService : VpnService() {

    private var tunFd: ParcelFileDescriptor? = null
    private var forwarder: TcpForwarder? = null
    private var tracker: ConnectionTracker? = null
    private var proxyManager: ProxyProcessManager? = null
    private var notificationManager: VpnNotificationManager? = null

    companion object {
        @Volatile var isRunning = false
            private set
        @Volatile var txBytes = 0L
            private set
        @Volatile var rxBytes = 0L
            private set
        @Volatile var activeConnections = 0
            private set
        @Volatile var startedAt = 0L
            private set
        @Volatile var proxyRunning = false
            private set
        val logBuffer = LogBuffer()

        fun stats(): VpnStatus {
            val runtime = Runtime.getRuntime()
            val used = runtime.totalMemory() - runtime.freeMemory()
            val uptime = if (isRunning && startedAt > 0L) {
                (System.currentTimeMillis() - startedAt) / 1000L
            } else {
                0L
            }
            return VpnStatus(
                running = isRunning,
                uptimeSeconds = uptime,
                txBytes = txBytes,
                rxBytes = rxBytes,
                activeConnections = activeConnections,
                memoryUsedBytes = used,
                memoryMaxBytes = runtime.maxMemory(),
                proxyRunning = proxyRunning
            )
        }
    }

    override fun onCreate() {
        super.onCreate()
        notificationManager = VpnNotificationManager(this)
        notificationManager?.createChannel()
        logBuffer.append("VPN service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.getStringExtra("action") == "stop") {
            stopVpn()
            return START_NOT_STICKY
        }
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        if (isRunning) return

        // Show foreground notification FIRST (required on Android 8+)
        val notification = notificationManager?.buildRunningNotification()
        if (notification != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    VpnNotificationManager.NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(VpnNotificationManager.NOTIFICATION_ID, notification)
            }
        }

        val configManager = ConfigManager(this)
        val mmdbManager = MmdbManager(this)
        proxyManager = ProxyProcessManager(this, logBuffer)

        kotlinx.coroutines.GlobalScope.launch {
            try {
                configManager.initialize()
                val mmdbReady = mmdbManager.ensureMmdbAvailable()
                if (!mmdbReady) {
                    logBuffer.append("Country database unavailable; region rules are skipped")
                }
            } catch (e: Exception) {
                logBuffer.append("Country database check failed: ${e.message}")
            }

            val configPath = configManager.getConfigPath()
            proxyManager?.start(configPath)
        }.start()

        // Build VPN
        val builder = Builder()
            .setMtu(1500)
            .addAddress("10.0.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("10.0.0.1")
            .setBlocking(true)
            .setSession("Pulse Proxy")

        // Exclude this app from VPN to avoid loop
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {}

        // Configure notification for VPN
        val configIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, configIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        builder.setConfigureIntent(pendingIntent)

        tunFd = builder.establish()
        if (tunFd == null) {
            logBuffer.append("Failed to establish VPN TUN device")
            stopVpn()
            return
        }

        tracker = ConnectionTracker()
        forwarder = TcpForwarder(
            tunFd = tunFd!!,
            tracker = tracker!!,
            protectDatagramSocket = { socket -> protect(socket) },
            protectSocket = { socket -> protect(socket) }
        )
        forwarder?.start()

        isRunning = true
        startedAt = System.currentTimeMillis()
        logBuffer.append("VPN started, local proxy at 127.0.0.1:1080")

        // Start stats monitoring
        Thread {
            while (isRunning) {
                Thread.sleep(1000)
                txBytes = tracker?.allConnections()?.sumOf { it.txBytes } ?: 0
                rxBytes = tracker?.allConnections()?.sumOf { it.rxBytes } ?: 0
                activeConnections = tracker?.activeConnections() ?: 0
                proxyRunning = proxyManager?.isRunning == true
            }
        }.start()
    }

    private fun stopVpn() {
        isRunning = false
        activeConnections = 0
        proxyRunning = false
        forwarder?.stop()
        forwarder = null
        tracker?.clear()
        tracker = null
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        proxyManager?.stop()
        proxyManager = null
        notificationManager?.cancelNotification()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        logBuffer.append("VPN stopped")
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
