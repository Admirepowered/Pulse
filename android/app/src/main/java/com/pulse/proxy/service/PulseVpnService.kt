package com.pulse.proxy.service

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.pulse.proxy.MainActivity
import com.pulse.proxy.config.ConfigManager
import com.pulse.proxy.config.MmdbManager
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
        val logBuffer = LogBuffer()

        fun stats(): Triple<Boolean, Long, Long> = Triple(isRunning, txBytes, rxBytes)
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

        // Initialize config
        val configManager = ConfigManager(this)
        configManager.initialize()

        // Download MMDB if needed (runs in background)
        val mmdbManager = MmdbManager(this)

        // Start proxy process
        proxyManager = ProxyProcessManager(this, logBuffer)
        val configPath = configManager.getConfigPath()

        // Start MMDB download and proxy
        kotlinx.coroutines.GlobalScope.launch {
            try {
                mmdbManager.ensureMmdbAvailable()
            } catch (_: Exception) {}

            proxyManager?.start(configPath)
        }.start()

        // Build VPN
        val builder = Builder()
            .setMtu(1500)
            .addAddress("10.0.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
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
        forwarder = TcpForwarder(tunFd!!, tracker!!)
        forwarder?.start()

        isRunning = true
        logBuffer.append("VPN started, local proxy at 127.0.0.1:1080")

        // Show foreground notification
        notificationManager?.showRunningNotification()

        // Start stats monitoring
        Thread {
            while (isRunning) {
                Thread.sleep(1000)
                txBytes = tracker?.allConnections()?.sumOf { it.txBytes } ?: 0
                rxBytes = tracker?.allConnections()?.sumOf { it.rxBytes } ?: 0
            }
        }.start()
    }

    private fun stopVpn() {
        isRunning = false
        forwarder?.stop()
        forwarder = null
        tracker?.clear()
        tracker = null
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        proxyManager?.stop()
        proxyManager = null
        notificationManager?.cancelNotification()
        logBuffer.append("VPN stopped")
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
