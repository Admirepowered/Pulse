package com.pulse.proxy.data

data class VpnStatus(
    val running: Boolean = false,
    val uptimeSeconds: Long = 0L,
    val txBytes: Long = 0L,
    val rxBytes: Long = 0L,
    val activeConnections: Int = 0,
    val proxyRunning: Boolean = false
)

data class TrafficStats(
    val uploadBytes: Long = 0L,
    val downloadBytes: Long = 0L
)

data class LogEntry(
    val timestamp: Long = System.currentTimeMillis(),
    val message: String = ""
)
