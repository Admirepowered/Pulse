package com.pulse.proxy.tun

import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore

class TcpForwarder(
    private val tunFd: ParcelFileDescriptor,
    private val tracker: ConnectionTracker,
    private val protectDatagramSocket: (DatagramSocket) -> Boolean = { true },
    private val protectSocket: (Socket) -> Boolean = { true }
) {
    private val scope = CoroutineScope(Dispatchers.IO + Job())
    private var readJob: Job? = null
    private var writeJob: Job? = null
    private var cleanupJob: Job? = null

    @Volatile var isRunning = false
        private set

    @Volatile var totalTx = 0L
        private set
    @Volatile var totalRx = 0L
        private set

    private var remoteBaseSeq = 1000000L  // starting sequence number for our SYN-ACKs
    private val dnsUpstreams = listOf("223.5.5.5", "1.1.1.1", "8.8.8.8")
    private val dnsCache = ConcurrentHashMap<Int, String>()
    private val dnsCacheUpdatedAt = ConcurrentHashMap<Int, Long>()
    private val udpDirectPermits = Semaphore(64)

    fun start() {
        if (isRunning) return
        isRunning = true

        readJob = scope.launch { readLoop() }
        writeJob = scope.launch { writeLoop() }
        cleanupJob = scope.launch {
            while (isActive) {
                delay(60_000L)
                tracker.cleanupIdle()
                cleanupDnsCache()
            }
        }
    }

    fun stop() {
        isRunning = false
        readJob?.cancel()
        writeJob?.cancel()
        cleanupJob?.cancel()
        tracker.clear()
        dnsCache.clear()
        dnsCacheUpdatedAt.clear()
    }

    private suspend fun readLoop() {
        val fis = FileInputStream(tunFd.fileDescriptor)
        val buffer = ByteArray(65535)

        while (scope.isActive && isRunning) {
            val length = try {
                fis.read(buffer)
            } catch (_: Exception) {
                delay(10); continue
            }
            if (length <= 0) { delay(1); continue }

            val udp = IpPacket.parseUdp(buffer, length)
            if (udp != null) {
                if (udp.destPort == 53) {
                    scope.launch { handleDnsQuery(udp) }
                } else {
                    scope.launch { handleUdpDirect(udp) }
                }
                continue
            }

            val tcp = IpPacket.parse(buffer, length) ?: continue
            val key = IpPacket.connectionKey(tcp)

            tracker.touch(key)

            if (tcp.isRst) {
                handleRst(key, tcp)
                continue
            }

            if (tcp.isFin) {
                handleFin(key, tcp)
                continue
            }

            if (tcp.isSyn && !tcp.isAck) {
                handleSyn(key, tcp)
                continue
            }

            if (tcp.isAck && tcp.hasPayload) {
                handleData(key, tcp, buffer)
            }
        }
    }

    private fun handleSyn(key: String, tcp: IpPacket.TcpHeader) {
        if (tracker.get(key) == null && !tracker.canCreateConnection()) {
            sendRst(tcp)
            return
        }
        val dstHost = dnsCache[tcp.destIp]
        val conn = tracker.getOrCreate(
            key,
            tcp.sourceIp, tcp.sourcePort, tcp.destIp, tcp.destPort
        ) {
            Socks5Client(tcp.destIp, tcp.destPort, dstHost = dstHost, protectSocket = protectSocket)
        }

        conn.clientSeq = (tcp.sequenceNumber + 1) and 0xFFFFFFFFL

        // Generate our sequence number
        conn.remoteSeq = remoteBaseSeq
        remoteBaseSeq = (remoteBaseSeq + 1000) and 0x7FFFFFFFL

        // Complete the local TCP handshake first. The upstream SOCKS connection is
        // opened when the first payload arrives, so we can sniff HTTP Host/TLS SNI.
        conn.state = ConnectionTracker.State.CONNECTED
        sendSynAck(conn, tcp)
    }

    private fun handleData(key: String, tcp: IpPacket.TcpHeader, buffer: ByteArray) {
        val conn = tracker.get(key) ?: return
        if (conn.state != ConnectionTracker.State.CONNECTED) return

        val expected = conn.clientSeq
        if (tcp.sequenceNumber != expected) {
            // Out of order or retransmit - send ACK for expected seq
            sendAck(conn, tcp, expected)
            return
        }

        conn.clientSeq = (expected + tcp.payloadLength) and 0xFFFFFFFFL

        if (tcp.payloadLength > 0) {
            val payload = buffer.copyOfRange(tcp.payloadStart, tcp.payloadStart + tcp.payloadLength)
            if (!conn.socks5Client.isConnected()) {
                conn.pendingPayload = appendPayload(conn.pendingPayload, payload)
                val sniffedHost = sniffHost(conn.pendingPayload)
                val dstHost = sniffedHost ?: dnsCache[tcp.destIp]
                if (dstHost == null && shouldWaitForHost(conn.pendingPayload, tcp.destPort)) {
                    sendAck(conn, tcp, conn.clientSeq)
                    return
                }
                if (dstHost == null && shouldRequireHost()) {
                    sendRst(tcp)
                    tracker.remove(key)
                    return
                }
                conn.socks5Client.close()
                conn.socks5Client = Socks5Client(
                    tcp.destIp,
                    tcp.destPort,
                    dstHost = dstHost,
                    protectSocket = protectSocket
                )
                val ok = conn.socks5Client.connect()
                if (!ok) {
                    sendRst(tcp)
                    tracker.remove(key)
                    return
                }
                if (conn.pendingPayload.isNotEmpty()) {
                    val sentPending = conn.socks5Client.send(conn.pendingPayload, 0, conn.pendingPayload.size)
                    if (!sentPending) {
                        sendRst(tcp)
                        tracker.remove(key)
                        return
                    }
                    conn.txBytes += conn.pendingPayload.size
                    totalTx += conn.pendingPayload.size
                    conn.pendingPayload = ByteArray(0)
                    sendAck(conn, tcp, conn.clientSeq)
                    return
                }
            }
            val sent = conn.socks5Client.send(payload, 0, payload.size)
            if (!sent) {
                sendRst(tcp)
                tracker.remove(key)
                return
            }
            conn.txBytes += payload.size
            totalTx += payload.size
        }

        // Send ACK acknowledging the data
        sendAck(conn, tcp, conn.clientSeq)
    }

    private fun appendPayload(existing: ByteArray, chunk: ByteArray, maxSize: Int = 16 * 1024): ByteArray {
        if (existing.isEmpty()) return if (chunk.size <= maxSize) chunk else chunk.copyOf(maxSize)
        val newSize = (existing.size + chunk.size).coerceAtMost(maxSize)
        val out = ByteArray(newSize)
        System.arraycopy(existing, 0, out, 0, existing.size.coerceAtMost(newSize))
        val copyLen = (newSize - existing.size).coerceAtLeast(0)
        if (copyLen > 0) {
            System.arraycopy(chunk, 0, out, existing.size, copyLen)
        }
        return out
    }

    private fun shouldWaitForHost(payload: ByteArray, dstPort: Int): Boolean {
        if (payload.size >= 16 * 1024) return false
        if (dstPort == 80 || dstPort == 8080 || dstPort == 8081) {
            return looksLikePartialHttp(payload)
        }
        if (dstPort == 443 || dstPort == 8443) {
            return looksLikePartialTls(payload)
        }
        return payload.size < 4096
    }

    private fun shouldRequireHost(): Boolean {
        return true
    }

    private fun looksLikePartialHttp(payload: ByteArray): Boolean {
        val text = try {
            String(payload.copyOf(payload.size.coerceAtMost(4096)), Charsets.ISO_8859_1)
        } catch (_: Exception) {
            return false
        }
        val methods = listOf("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "PATCH ")
        return methods.any { text.startsWith(it) } && !text.contains("\r\n\r\n")
    }

    private fun looksLikePartialTls(payload: ByteArray): Boolean {
        if (payload.size < 5) return true
        if ((payload[0].toInt() and 0xFF) != 0x16) return false
        val recordLen = readU16(payload, 3)
        if (recordLen <= 0) return false
        return payload.size < 5 + recordLen
    }

    private fun sniffHost(payload: ByteArray): String? {
        return sniffHttpHost(payload) ?: sniffTlsSni(payload)
    }

    private fun sniffHttpHost(payload: ByteArray): String? {
        val prefix = if (payload.size > 2048) payload.copyOf(2048) else payload
        val text = try {
            String(prefix, Charsets.ISO_8859_1)
        } catch (_: Exception) {
            return null
        }
        val firstLineEnd = text.indexOf("\r\n").takeIf { it >= 0 } ?: return null
        val methodLine = text.substring(0, firstLineEnd)
        val looksHttp = methodLine.startsWith("GET ") ||
            methodLine.startsWith("POST ") ||
            methodLine.startsWith("HEAD ") ||
            methodLine.startsWith("PUT ") ||
            methodLine.startsWith("DELETE ") ||
            methodLine.startsWith("CONNECT ") ||
            methodLine.startsWith("OPTIONS ")
        if (!looksHttp) return null

        for (line in text.substring(firstLineEnd + 2).split("\r\n")) {
            if (line.isEmpty()) break
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            if (line.substring(0, colon).equals("host", ignoreCase = true)) {
                return normalizeHost(line.substring(colon + 1).trim())
            }
        }
        return null
    }

    private fun sniffTlsSni(payload: ByteArray): String? {
        if (payload.size < 5) return null
        if ((payload[0].toInt() and 0xFF) != 0x16) return null
        val recordLen = readU16(payload, 3)
        if (recordLen <= 0 || payload.size < 5 + recordLen) return null
        var offset = 5
        if ((payload[offset].toInt() and 0xFF) != 0x01) return null
        val handshakeLen = readU24(payload, offset + 1)
        offset += 4
        if (handshakeLen <= 0 || offset + handshakeLen > payload.size) return null

        offset += 2 + 32
        if (offset >= payload.size) return null
        val sessionIdLen = payload[offset].toInt() and 0xFF
        offset += 1 + sessionIdLen
        if (offset + 2 > payload.size) return null
        val cipherLen = readU16(payload, offset)
        offset += 2 + cipherLen
        if (offset >= payload.size) return null
        val compressionLen = payload[offset].toInt() and 0xFF
        offset += 1 + compressionLen
        if (offset + 2 > payload.size) return null

        val extensionsLen = readU16(payload, offset)
        offset += 2
        val extensionsEnd = offset + extensionsLen
        if (extensionsEnd > payload.size) return null

        while (offset + 4 <= extensionsEnd) {
            val type = readU16(payload, offset)
            val len = readU16(payload, offset + 2)
            offset += 4
            if (offset + len > extensionsEnd) return null
            if (type == 0) {
                if (offset + 2 > extensionsEnd) return null
                var sniOffset = offset + 2
                val sniEnd = offset + len
                while (sniOffset + 3 <= sniEnd) {
                    val nameType = payload[sniOffset].toInt() and 0xFF
                    val nameLen = readU16(payload, sniOffset + 1)
                    sniOffset += 3
                    if (sniOffset + nameLen > sniEnd) return null
                    if (nameType == 0) {
                        return normalizeHost(String(payload, sniOffset, nameLen, Charsets.US_ASCII))
                    }
                    sniOffset += nameLen
                }
            }
            offset += len
        }
        return null
    }

    private fun normalizeHost(host: String): String? {
        val trimmed = host.trim().trimEnd('.')
        if (trimmed.isBlank()) return null
        val withoutPort = if (trimmed.startsWith("[")) {
            return null
        } else {
            trimmed.substringBefore(':')
        }
        if (withoutPort.length > 255 || withoutPort.any { it.code <= 32 }) return null
        if (withoutPort.all { it.isDigit() || it == '.' }) return null
        return withoutPort.lowercase()
    }

    private fun handleFin(key: String, tcp: IpPacket.TcpHeader) {
        val conn = tracker.get(key) ?: return

        // Acknowledge the FIN
        conn.clientSeq = (tcp.sequenceNumber + 1) and 0xFFFFFFFFL
        conn.state = ConnectionTracker.State.CLOSING

        // Send FIN-ACK
        sendFinAck(conn, tcp)
        tracker.remove(key)
        conn.socks5Client.close()
    }

    private fun handleRst(key: String, tcp: IpPacket.TcpHeader) {
        tracker.get(key)?.socks5Client?.close()
        tracker.remove(key)
    }

    private suspend fun writeLoop() {
        val fos = FileOutputStream(tunFd.fileDescriptor)
        val buffer = ByteArray(8192)

        while (scope.isActive && isRunning) {
            var wrote = false
            for (conn in tracker.allConnections()) {
                if (conn.state != ConnectionTracker.State.CONNECTED) continue
                if (conn.socks5Client.available() <= 0) continue

                val len = try {
                    conn.socks5Client.receive(buffer)
                } catch (_: Exception) {
                    conn.socks5Client.close()
                    tracker.remove(conn.key)
                    continue
                }
                if (len <= 0) {
                    conn.socks5Client.close()
                    tracker.remove(conn.key)
                    continue
                }

                conn.rxBytes += len
                totalRx += len

                val packet = buildResponsePacket(conn, buffer, len)
                if (packet != null) {
                    try {
                        fos.write(packet)
                        fos.flush()
                        wrote = true
                    } catch (_: Exception) {}
                }

                conn.lastActivityAt = System.currentTimeMillis()
            }
            if (!wrote) delay(2)
        }
    }

    private fun sendSynAck(conn: ConnectionTracker.TcpConnection, req: IpPacket.TcpHeader) {
        val packet = buildTcpPacket(
            srcIp = req.destIp, dstIp = req.sourceIp,
            srcPort = req.destPort, dstPort = req.sourcePort,
            seqNum = conn.remoteSeq,
            ackNum = req.sequenceNumber + 1,
            flags = IpPacket.FLAG_SYN or IpPacket.FLAG_ACK,
            payload = null
        )
        writePacket(packet)
        conn.remoteSeq = (conn.remoteSeq + 1) and 0xFFFFFFFFL
    }

    private fun sendAck(conn: ConnectionTracker.TcpConnection, req: IpPacket.TcpHeader, ackSeq: Long) {
        val packet = buildTcpPacket(
            srcIp = req.destIp, dstIp = req.sourceIp,
            srcPort = req.destPort, dstPort = req.sourcePort,
            seqNum = conn.remoteSeq,
            ackNum = ackSeq,
            flags = IpPacket.FLAG_ACK,
            payload = null
        )
        writePacket(packet)
    }

    private fun sendFinAck(conn: ConnectionTracker.TcpConnection, req: IpPacket.TcpHeader) {
        val packet = buildTcpPacket(
            srcIp = req.destIp, dstIp = req.sourceIp,
            srcPort = req.destPort, dstPort = req.sourcePort,
            seqNum = conn.remoteSeq,
            ackNum = req.sequenceNumber + 1,
            flags = IpPacket.FLAG_FIN or IpPacket.FLAG_ACK,
            payload = null
        )
        writePacket(packet)
        conn.remoteSeq = (conn.remoteSeq + 1) and 0xFFFFFFFFL
    }

    private fun sendRst(req: IpPacket.TcpHeader) {
        val packet = buildTcpPacket(
            srcIp = req.destIp, dstIp = req.sourceIp,
            srcPort = req.destPort, dstPort = req.sourcePort,
            seqNum = req.acknowledgmentNumber,
            ackNum = 0,
            flags = IpPacket.FLAG_RST or IpPacket.FLAG_ACK,
            payload = null
        )
        writePacket(packet)
    }

    private fun buildResponsePacket(
        conn: ConnectionTracker.TcpConnection,
        data: ByteArray,
        len: Int
    ): ByteArray? {
        val seq = conn.remoteSeq
        conn.remoteSeq = (seq + len) and 0xFFFFFFFFL

        return buildTcpPacket(
            srcIp = conn.dstIp, dstIp = conn.srcIp,
            srcPort = conn.dstPort, dstPort = conn.srcPort,
            seqNum = seq,
            ackNum = conn.clientSeq,
            flags = IpPacket.FLAG_ACK or IpPacket.FLAG_PSH,
            payload = data.copyOf(len)
        )
    }

    private fun buildTcpPacket(
        srcIp: Int, dstIp: Int,
        srcPort: Int, dstPort: Int,
        seqNum: Long, ackNum: Long,
        flags: Int,
        payload: ByteArray?
    ): ByteArray {
        val ipHdrLen = 20
        val tcpHdrLen = 20
        val payloadLen = payload?.size ?: 0
        val totalIpLen = ipHdrLen + tcpHdrLen + payloadLen
        val packetLen = IpPacket.TUN_HEADER_SIZE + totalIpLen

        val buffer = ByteArray(packetLen)
        val buf = ByteBuffer.wrap(buffer).order(ByteOrder.BIG_ENDIAN)

        // IPv4 header
        val ipHdrOff = IpPacket.TUN_HEADER_SIZE
        buffer[ipHdrOff] = (0x45).toByte()       // version=4, IHL=5
        buffer[ipHdrOff + 1] = 0                 // DSCP/ECN
        buffer[ipHdrOff + 2] = ((totalIpLen shr 8) and 0xFF).toByte()
        buffer[ipHdrOff + 3] = (totalIpLen and 0xFF).toByte()
        buffer[ipHdrOff + 4] = 0                 // ID high
        buffer[ipHdrOff + 5] = 0                 // ID low
        buffer[ipHdrOff + 6] = 0x40.toByte()     // flags, don't fragment
        buffer[ipHdrOff + 7] = 0                 // fragment offset
        buffer[ipHdrOff + 8] = 64                // TTL
        buffer[ipHdrOff + 9] = IpPacket.IPPROTO_TCP.toByte()
        // checksum at ipHdrOff+10..11, computed below
        buffer[ipHdrOff + 12] = ((srcIp shr 24) and 0xFF).toByte()
        buffer[ipHdrOff + 13] = ((srcIp shr 16) and 0xFF).toByte()
        buffer[ipHdrOff + 14] = ((srcIp shr 8) and 0xFF).toByte()
        buffer[ipHdrOff + 15] = (srcIp and 0xFF).toByte()
        buffer[ipHdrOff + 16] = ((dstIp shr 24) and 0xFF).toByte()
        buffer[ipHdrOff + 17] = ((dstIp shr 16) and 0xFF).toByte()
        buffer[ipHdrOff + 18] = ((dstIp shr 8) and 0xFF).toByte()
        buffer[ipHdrOff + 19] = (dstIp and 0xFF).toByte()

        // IP checksum (header only)
        val ipSum = ipChecksum(buffer, ipHdrOff, ipHdrLen)
        buffer[ipHdrOff + 10] = ((ipSum shr 8) and 0xFF).toByte()
        buffer[ipHdrOff + 11] = (ipSum and 0xFF).toByte()

        // TCP header
        val tcpHdrOff = ipHdrOff + ipHdrLen
        buffer[tcpHdrOff] = ((srcPort shr 8) and 0xFF).toByte()
        buffer[tcpHdrOff + 1] = (srcPort and 0xFF).toByte()
        buffer[tcpHdrOff + 2] = ((dstPort shr 8) and 0xFF).toByte()
        buffer[tcpHdrOff + 3] = (dstPort and 0xFF).toByte()
        buffer[tcpHdrOff + 4] = ((seqNum shr 24) and 0xFF).toByte()
        buffer[tcpHdrOff + 5] = ((seqNum shr 16) and 0xFF).toByte()
        buffer[tcpHdrOff + 6] = ((seqNum shr 8) and 0xFF).toByte()
        buffer[tcpHdrOff + 7] = (seqNum and 0xFF).toByte()
        buffer[tcpHdrOff + 8] = ((ackNum shr 24) and 0xFF).toByte()
        buffer[tcpHdrOff + 9] = ((ackNum shr 16) and 0xFF).toByte()
        buffer[tcpHdrOff + 10] = ((ackNum shr 8) and 0xFF).toByte()
        buffer[tcpHdrOff + 11] = (ackNum and 0xFF).toByte()
        buffer[tcpHdrOff + 12] = ((tcpHdrLen / 4) shl 4).toByte()  // data offset
        buffer[tcpHdrOff + 13] = flags.toByte()
        buffer[tcpHdrOff + 14] = 0xFF.toByte()   // window size high (large window)
        buffer[tcpHdrOff + 15] = 0xFF.toByte()   // window size low
        buffer[tcpHdrOff + 16] = 0               // checksum (computed below)
        buffer[tcpHdrOff + 17] = 0
        buffer[tcpHdrOff + 18] = 0               // urgent pointer
        buffer[tcpHdrOff + 19] = 0

        // TCP payload
        if (payload != null && payload.isNotEmpty()) {
            System.arraycopy(payload, 0, buffer, tcpHdrOff + tcpHdrLen, payload.size)
        }

        // TCP checksum (pseudo-header + TCP header + payload)
        val tcpSum = tcpChecksum(buffer, ipHdrOff, tcpHdrOff, tcpHdrLen + payloadLen, srcIp, dstIp)
        buffer[tcpHdrOff + 16] = ((tcpSum shr 8) and 0xFF).toByte()
        buffer[tcpHdrOff + 17] = (tcpSum and 0xFF).toByte()

        return buffer
    }

    private fun handleDnsQuery(query: IpPacket.UdpPacket) {
        val queryName = parseDnsQuestionName(query.payload)
        for (upstream in dnsUpstreams) {
            val response = try {
                DatagramSocket().use { socket ->
                    protectDatagramSocket(socket)
                    socket.soTimeout = 2500
                    val request = DatagramPacket(
                        query.payload,
                        query.payload.size,
                        InetSocketAddress(upstream, 53)
                    )
                    socket.send(request)
                    val buffer = ByteArray(1500)
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    buffer.copyOf(packet.length)
                }
            } catch (_: Exception) {
                null
            }

            if (response != null && response.isNotEmpty()) {
                if (queryName != null) {
                    cacheDnsAnswers(response, queryName)
                }
                writePacket(
                    buildUdpPacket(
                        srcIp = query.destIp,
                        dstIp = query.sourceIp,
                        srcPort = query.destPort,
                        dstPort = query.sourcePort,
                        payload = response
                    )
                )
                return
            }
        }
    }

    private fun handleUdpDirect(packet: IpPacket.UdpPacket) {
        if (!udpDirectPermits.tryAcquire()) return
        val response = try {
            DatagramSocket().use { socket ->
                protectDatagramSocket(socket)
                socket.soTimeout = 1200
                val request = DatagramPacket(
                    packet.payload,
                    packet.payload.size,
                    InetSocketAddress(IpPacket.ipToStr(packet.destIp), packet.destPort)
                )
                socket.send(request)
                val buffer = ByteArray(65507)
                val reply = DatagramPacket(buffer, buffer.size)
                socket.receive(reply)
                buffer.copyOf(reply.length)
            }
        } catch (_: Exception) {
            null
        } finally {
            udpDirectPermits.release()
        }

        if (response != null && response.isNotEmpty()) {
            writePacket(
                buildUdpPacket(
                    srcIp = packet.destIp,
                    dstIp = packet.sourceIp,
                    srcPort = packet.destPort,
                    dstPort = packet.sourcePort,
                    payload = response
                )
            )
        }
    }

    private fun parseDnsQuestionName(payload: ByteArray): String? {
        if (payload.size < 12) return null
        val parts = mutableListOf<String>()
        var offset = 12
        while (offset < payload.size) {
            val len = payload[offset].toInt() and 0xFF
            if (len == 0) {
                return parts.joinToString(".").takeIf { it.isNotBlank() }
            }
            if ((len and 0xC0) != 0 || len > 63) return null
            offset += 1
            if (offset + len > payload.size) return null
            parts += String(payload, offset, len, Charsets.US_ASCII).lowercase()
            offset += len
        }
        return null
    }

    private fun cacheDnsAnswers(response: ByteArray, domain: String) {
        if (response.size < 12) return
        val qdCount = readU16(response, 4)
        val anCount = readU16(response, 6)
        var offset = 12

        repeat(qdCount) {
            offset = skipDnsName(response, offset)
            if (offset < 0 || offset + 4 > response.size) return
            offset += 4
        }

        repeat(anCount) {
            offset = skipDnsName(response, offset)
            if (offset < 0 || offset + 10 > response.size) return
            val type = readU16(response, offset)
            val klass = readU16(response, offset + 2)
            val rdLength = readU16(response, offset + 8)
            val rdataOffset = offset + 10
            if (rdataOffset + rdLength > response.size) return

            if (type == 1 && klass == 1 && rdLength == 4) {
                val ip = ((response[rdataOffset].toInt() and 0xFF) shl 24) or
                    ((response[rdataOffset + 1].toInt() and 0xFF) shl 16) or
                    ((response[rdataOffset + 2].toInt() and 0xFF) shl 8) or
                    (response[rdataOffset + 3].toInt() and 0xFF)
                dnsCache[ip] = domain
                dnsCacheUpdatedAt[ip] = System.currentTimeMillis()
            }
            offset = rdataOffset + rdLength
        }
    }

    private fun skipDnsName(packet: ByteArray, start: Int): Int {
        var offset = start
        var jumps = 0
        while (offset < packet.size && jumps < 32) {
            val len = packet[offset].toInt() and 0xFF
            if (len == 0) return offset + 1
            if ((len and 0xC0) == 0xC0) {
                return if (offset + 1 < packet.size) offset + 2 else -1
            }
            if ((len and 0xC0) != 0 || len > 63) return -1
            offset += 1 + len
            jumps += 1
        }
        return -1
    }

    private fun readU16(buffer: ByteArray, offset: Int): Int {
        if (offset + 1 >= buffer.size) return 0
        return ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
    }

    private fun readU24(buffer: ByteArray, offset: Int): Int {
        if (offset + 2 >= buffer.size) return 0
        return ((buffer[offset].toInt() and 0xFF) shl 16) or
            ((buffer[offset + 1].toInt() and 0xFF) shl 8) or
            (buffer[offset + 2].toInt() and 0xFF)
    }

    private fun cleanupDnsCache() {
        val cutoff = System.currentTimeMillis() - 10 * 60_000L
        for ((ip, updatedAt) in dnsCacheUpdatedAt) {
            if (updatedAt < cutoff) {
                dnsCache.remove(ip)
                dnsCacheUpdatedAt.remove(ip)
            }
        }
    }

    private fun buildUdpPacket(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHdrLen = 20
        val udpHdrLen = 8
        val totalIpLen = ipHdrLen + udpHdrLen + payload.size
        val packetLen = IpPacket.TUN_HEADER_SIZE + totalIpLen
        val buffer = ByteArray(packetLen)
        val buf = ByteBuffer.wrap(buffer).order(ByteOrder.BIG_ENDIAN)

        val ipHdrOff = IpPacket.TUN_HEADER_SIZE
        buffer[ipHdrOff] = 0x45.toByte()
        buffer[ipHdrOff + 1] = 0
        buffer[ipHdrOff + 2] = ((totalIpLen shr 8) and 0xFF).toByte()
        buffer[ipHdrOff + 3] = (totalIpLen and 0xFF).toByte()
        buffer[ipHdrOff + 4] = 0
        buffer[ipHdrOff + 5] = 0
        buffer[ipHdrOff + 6] = 0x40.toByte()
        buffer[ipHdrOff + 7] = 0
        buffer[ipHdrOff + 8] = 64
        buffer[ipHdrOff + 9] = IpPacket.IPPROTO_UDP.toByte()
        buffer[ipHdrOff + 12] = ((srcIp shr 24) and 0xFF).toByte()
        buffer[ipHdrOff + 13] = ((srcIp shr 16) and 0xFF).toByte()
        buffer[ipHdrOff + 14] = ((srcIp shr 8) and 0xFF).toByte()
        buffer[ipHdrOff + 15] = (srcIp and 0xFF).toByte()
        buffer[ipHdrOff + 16] = ((dstIp shr 24) and 0xFF).toByte()
        buffer[ipHdrOff + 17] = ((dstIp shr 16) and 0xFF).toByte()
        buffer[ipHdrOff + 18] = ((dstIp shr 8) and 0xFF).toByte()
        buffer[ipHdrOff + 19] = (dstIp and 0xFF).toByte()

        val ipSum = ipChecksum(buffer, ipHdrOff, ipHdrLen)
        buffer[ipHdrOff + 10] = ((ipSum shr 8) and 0xFF).toByte()
        buffer[ipHdrOff + 11] = (ipSum and 0xFF).toByte()

        val udpHdrOff = ipHdrOff + ipHdrLen
        val udpLen = udpHdrLen + payload.size
        buffer[udpHdrOff] = ((srcPort shr 8) and 0xFF).toByte()
        buffer[udpHdrOff + 1] = (srcPort and 0xFF).toByte()
        buffer[udpHdrOff + 2] = ((dstPort shr 8) and 0xFF).toByte()
        buffer[udpHdrOff + 3] = (dstPort and 0xFF).toByte()
        buffer[udpHdrOff + 4] = ((udpLen shr 8) and 0xFF).toByte()
        buffer[udpHdrOff + 5] = (udpLen and 0xFF).toByte()
        buffer[udpHdrOff + 6] = 0
        buffer[udpHdrOff + 7] = 0
        System.arraycopy(payload, 0, buffer, udpHdrOff + udpHdrLen, payload.size)

        val udpSum = udpChecksum(buffer, udpHdrOff, udpLen, srcIp, dstIp)
        buffer[udpHdrOff + 6] = ((udpSum shr 8) and 0xFF).toByte()
        buffer[udpHdrOff + 7] = (udpSum and 0xFF).toByte()

        return buffer
    }

    private fun ipChecksum(buffer: ByteArray, offset: Int, len: Int): Int {
        var sum = 0
        for (i in 0 until len step 2) {
            val w = ((buffer[offset + i].toInt() and 0xFF) shl 8) or
                    (if (i + 1 < len) (buffer[offset + i + 1].toInt() and 0xFF) else 0)
            sum += w
        }
        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun tcpChecksum(
        buffer: ByteArray, ipOff: Int, tcpOff: Int,
        tcpLen: Int, srcIp: Int, dstIp: Int
    ): Int {
        var sum = 0

        // Pseudo-header
        sum += ((srcIp shr 16) and 0xFFFF)
        sum += (srcIp and 0xFFFF)
        sum += ((dstIp shr 16) and 0xFFFF)
        sum += (dstIp and 0xFFFF)
        sum += 6  // protocol = TCP
        sum += tcpLen

        // TCP header + payload
        for (i in 0 until tcpLen step 2) {
            val w = ((buffer[tcpOff + i].toInt() and 0xFF) shl 8) or
                    (if (i + 1 < tcpLen) (buffer[tcpOff + i + 1].toInt() and 0xFF) else 0)
            sum += w
        }

        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun udpChecksum(
        buffer: ByteArray,
        udpOff: Int,
        udpLen: Int,
        srcIp: Int,
        dstIp: Int
    ): Int {
        var sum = 0
        sum += ((srcIp shr 16) and 0xFFFF)
        sum += (srcIp and 0xFFFF)
        sum += ((dstIp shr 16) and 0xFFFF)
        sum += (dstIp and 0xFFFF)
        sum += IpPacket.IPPROTO_UDP
        sum += udpLen

        for (i in 0 until udpLen step 2) {
            val w = ((buffer[udpOff + i].toInt() and 0xFF) shl 8) or
                (if (i + 1 < udpLen) (buffer[udpOff + i + 1].toInt() and 0xFF) else 0)
            sum += w
        }

        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val checksum = sum.inv() and 0xFFFF
        return if (checksum == 0) 0xFFFF else checksum
    }

    private fun writePacket(packet: ByteArray) {
        try {
            val fos = FileOutputStream(tunFd.fileDescriptor)
            fos.write(packet)
            fos.flush()
        } catch (_: Exception) {}
    }
}
