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
import java.nio.ByteBuffer
import java.nio.ByteOrder

class TcpForwarder(
    private val tunFd: ParcelFileDescriptor,
    private val tracker: ConnectionTracker
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

    fun start() {
        if (isRunning) return
        isRunning = true

        readJob = scope.launch { readLoop() }
        writeJob = scope.launch { writeLoop() }
        cleanupJob = scope.launch {
            while (isActive) {
                delay(60_000L)
                tracker.cleanupIdle()
            }
        }
    }

    fun stop() {
        isRunning = false
        readJob?.cancel()
        writeJob?.cancel()
        cleanupJob?.cancel()
        tracker.clear()
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
        val conn = tracker.getOrCreate(
            key,
            tcp.sourceIp, tcp.sourcePort, tcp.destIp, tcp.destPort
        ) {
            Socks5Client(tcp.destIp, tcp.destPort)
        }

        conn.clientSeq = (tcp.sequenceNumber + 1) and 0xFFFFFFFFL

        val ok = conn.socks5Client.connect()
        if (!ok) {
            sendRst(tcp)
            tracker.remove(key)
            return
        }

        // Generate our sequence number
        conn.remoteSeq = remoteBaseSeq
        remoteBaseSeq = (remoteBaseSeq + 1000) and 0x7FFFFFFFL

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
            val sent = conn.socks5Client.send(buffer, tcp.payloadStart, tcp.payloadLength)
            if (!sent) {
                sendRst(tcp)
                tracker.remove(key)
                return
            }
            conn.txBytes += tcp.payloadLength
            totalTx += tcp.payloadLength
        }

        // Send ACK acknowledging the data
        sendAck(conn, tcp, conn.clientSeq)
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

        // TUN header
        buf.putShort(0)                    // flags
        buf.putShort(IpPacket.PROTO_IPV4)  // protocol = IPv4

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

    private fun writePacket(packet: ByteArray) {
        try {
            val fos = FileOutputStream(tunFd.fileDescriptor)
            fos.write(packet)
            fos.flush()
        } catch (_: Exception) {}
    }
}
