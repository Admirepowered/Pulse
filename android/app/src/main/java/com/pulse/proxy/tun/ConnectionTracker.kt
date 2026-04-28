package com.pulse.proxy.tun

import java.util.concurrent.ConcurrentHashMap

class ConnectionTracker {
    enum class State { ESTABLISHING, CONNECTED, CLOSING, CLOSED }

    data class TcpConnection(
        val key: String,
        val srcIp: Int,
        val srcPort: Int,
        val dstIp: Int,
        val dstPort: Int,
        val socks5Client: Socks5Client,
        var state: State = State.ESTABLISHING,
        val createdAt: Long = System.currentTimeMillis(),
        var lastActivityAt: Long = System.currentTimeMillis(),
        var clientSeq: Long = 0,      // next expected seq from client
        var remoteSeq: Long = 0,      // seq we use for packets to client
        var txBytes: Long = 0L,
        var rxBytes: Long = 0L
    )

    private val connections = ConcurrentHashMap<String, TcpConnection>()

    fun get(key: String): TcpConnection? = connections[key]

    fun getOrCreate(
        key: String,
        srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int,
        factory: () -> Socks5Client
    ): TcpConnection {
        return connections.getOrPut(key) {
            TcpConnection(
                key = key,
                srcIp = srcIp,
                srcPort = srcPort,
                dstIp = dstIp,
                dstPort = dstPort,
                socks5Client = factory()
            )
        }
    }

    fun remove(key: String): TcpConnection? = connections.remove(key)

    fun touch(key: String) {
        connections[key]?.lastActivityAt = System.currentTimeMillis()
    }

    fun activeConnections(): Int = connections.size

    fun allConnections(): Collection<TcpConnection> = connections.values

    fun cleanupIdle(idleTimeoutMs: Long = 300_000L) {
        val now = System.currentTimeMillis()
        val toRemove = connections.filter {
            now - it.value.lastActivityAt > idleTimeoutMs
        }
        toRemove.forEach { (key, conn) ->
            conn.socks5Client.close()
            connections.remove(key)
        }
    }

    fun clear() {
        connections.values.forEach { it.socks5Client.close() }
        connections.clear()
    }
}
