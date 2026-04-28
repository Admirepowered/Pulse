package com.pulse.proxy.tun

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

class Socks5Client(
    private val dstIp: Int,
    private val dstPort: Int,
    private val proxyHost: String = "127.0.0.1",
    private val proxyPort: Int = 1080
) {
    private var socket: Socket? = null
    private var input: InputStream? = null
    private var output: OutputStream? = null
    @Volatile var state = State.DISCONNECTED
        private set

    enum class State { DISCONNECTED, CONNECTED, CLOSED }

    fun connect(timeoutMs: Int = 5000): Boolean {
        return try {
            val sock = Socket()
            sock.soTimeout = timeoutMs
            sock.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)

            val out = sock.getOutputStream()
            val inp = sock.getInputStream()

            // SOCKS5 handshake: version(5), 1 auth method (0=no-auth)
            out.write(byteArrayOf(0x05, 0x01, 0x00))
            out.flush()
            val reply = ByteArray(2)
            if (inp.read(reply) != 2 || reply[0] != 0x05.toByte() || reply[1] != 0x00.toByte()) {
                sock.close(); return false
            }

            // SOCKS5 CONNECT to destination
            val connectReq = ByteArray(10)
            connectReq[0] = 0x05  // version
            connectReq[1] = 0x01  // CONNECT
            connectReq[2] = 0x00  // reserved
            connectReq[3] = 0x01  // IPv4 address type
            connectReq[4] = ((dstIp shr 24) and 0xFF).toByte()
            connectReq[5] = ((dstIp shr 16) and 0xFF).toByte()
            connectReq[6] = ((dstIp shr 8) and 0xFF).toByte()
            connectReq[7] = (dstIp and 0xFF).toByte()
            connectReq[8] = ((dstPort shr 8) and 0xFF).toByte()
            connectReq[9] = (dstPort and 0xFF).toByte()
            out.write(connectReq)
            out.flush()

            val connectReply = ByteArray(10)
            if (inp.read(connectReply) != 10 || connectReply[0] != 0x05.toByte()) {
                sock.close(); return false
            }
            if (connectReply[1] != 0x00.toByte()) {
                // 0x01=general failure, 0x02=not allowed, 0x03=network unreachable,
                // 0x04=host unreachable, 0x05=connection refused, 0x06=TTL expired
                sock.close(); return false
            }

            socket = sock
            this.input = inp
            this.output = out
            state = State.CONNECTED
            true
        } catch (_: Exception) {
            state = State.CLOSED
            false
        }
    }

    fun send(data: ByteArray, offset: Int, length: Int): Boolean {
        return try {
            output?.write(data, offset, length)
            output?.flush()
            true
        } catch (_: Exception) {
            false
        }
    }

    fun receive(buffer: ByteArray): Int {
        return try {
            input?.read(buffer) ?: -1
        } catch (_: Exception) {
            -1
        }
    }

    fun isConnected(): Boolean = state == State.CONNECTED && socket?.isConnected == true

    fun available(): Int = try { input?.available() ?: 0 } catch (_: Exception) { 0 }

    fun close() {
        state = State.CLOSED
        try { input?.close() } catch (_: Exception) {}
        try { output?.close() } catch (_: Exception) {}
        try { socket?.close() } catch (_: Exception) {}
    }
}
