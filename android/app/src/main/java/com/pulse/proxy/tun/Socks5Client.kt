package com.pulse.proxy.tun

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

class Socks5Client(
    private val dstIp: Int,
    private val dstPort: Int,
    private val dstHost: String? = null,
    private val proxyHost: String = "127.0.0.1",
    private val proxyPort: Int = 1080,
    private val protectSocket: (Socket) -> Boolean = { true }
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
            protectSocket(sock)
            sock.soTimeout = timeoutMs
            sock.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)

            val out = sock.getOutputStream()
            val inp = sock.getInputStream()

            // SOCKS5 handshake: version(5), 1 auth method (0=no-auth)
            out.write(byteArrayOf(0x05, 0x01, 0x00))
            out.flush()
            val reply = ByteArray(2)
            if (!readExact(inp, reply) || reply[0] != 0x05.toByte() || reply[1] != 0x00.toByte()) {
                sock.close(); return false
            }

            // SOCKS5 CONNECT to destination. Prefer a domain when DNS cache has one,
            // so Hysteria2 receives the original host instead of an already-resolved IP.
            val hostBytes = dstHost
                ?.trim()
                ?.takeIf { it.isNotEmpty() && it.length <= 255 }
                ?.toByteArray(Charsets.US_ASCII)
            val connectReq = if (hostBytes != null) {
                ByteArray(4 + 1 + hostBytes.size + 2).also { req ->
                    req[0] = 0x05  // version
                    req[1] = 0x01  // CONNECT
                    req[2] = 0x00  // reserved
                    req[3] = 0x03  // domain name address type
                    req[4] = hostBytes.size.toByte()
                    System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
                    val portOff = 5 + hostBytes.size
                    req[portOff] = ((dstPort shr 8) and 0xFF).toByte()
                    req[portOff + 1] = (dstPort and 0xFF).toByte()
                }
            } else {
                ByteArray(10).also { req ->
                    req[0] = 0x05  // version
                    req[1] = 0x01  // CONNECT
                    req[2] = 0x00  // reserved
                    req[3] = 0x01  // IPv4 address type
                    req[4] = ((dstIp shr 24) and 0xFF).toByte()
                    req[5] = ((dstIp shr 16) and 0xFF).toByte()
                    req[6] = ((dstIp shr 8) and 0xFF).toByte()
                    req[7] = (dstIp and 0xFF).toByte()
                    req[8] = ((dstPort shr 8) and 0xFF).toByte()
                    req[9] = (dstPort and 0xFF).toByte()
                }
            }
            out.write(connectReq)
            out.flush()

            val connectReply = ByteArray(10)
            if (!readExact(inp, connectReply) || connectReply[0] != 0x05.toByte()) {
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

    private fun readExact(input: InputStream, buffer: ByteArray): Boolean {
        var offset = 0
        while (offset < buffer.size) {
            val read = input.read(buffer, offset, buffer.size - offset)
            if (read <= 0) return false
            offset += read
        }
        return true
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
