package com.pulse.proxy.tun

import java.nio.ByteBuffer
import java.nio.ByteOrder

object IpPacket {
    // Android TUN frame: 4-byte header (flags:2 + protocol:2) before IP packet
    const val TUN_HEADER_SIZE = 4
    const val PROTO_IPV4 = 0x0800.toShort()
    const val IPPROTO_TCP = 6

    // TCP flags
    const val FLAG_FIN = 0x01
    const val FLAG_SYN = 0x02
    const val FLAG_RST = 0x04
    const val FLAG_PSH = 0x08
    const val FLAG_ACK = 0x10

    data class TcpHeader(
        val sourceIp: Int,       // network-order IPv4
        val destIp: Int,
        val sourcePort: Int,
        val destPort: Int,
        val sequenceNumber: Long,    // unsigned 32-bit stored in Long
        val acknowledgmentNumber: Long,
        val dataOffset: Int,         // TCP header length in bytes
        val flags: Int,
        val windowSize: Int,
        val payloadStart: Int,       // offset in buffer where payload starts
        val payloadLength: Int       // length of payload in buffer
    ) {
        val isSyn: Boolean get() = (flags and FLAG_SYN) != 0
        val isAck: Boolean get() = (flags and FLAG_ACK) != 0
        val isFin: Boolean get() = (flags and FLAG_FIN) != 0
        val isRst: Boolean get() = (flags and FLAG_RST) != 0
        val hasPayload: Boolean get() = payloadLength > 0
    }

    fun parse(buffer: ByteArray, length: Int): TcpHeader? {
        if (length < TUN_HEADER_SIZE + 40) return null  // min: TUN hdr + IP + TCP

        val buf = ByteBuffer.wrap(buffer, 0, length).order(ByteOrder.BIG_ENDIAN)

        val tunFlags = buf.getShort()
        val protocol = buf.getShort()
        if (protocol != PROTO_IPV4) return null

        // IPv4 header
        val ipStart = buf.position()
        val versionIhl = (buffer[ipStart].toInt() and 0xFF)
        if ((versionIhl shr 4) != 4) return null     // not IPv4
        val ipHdrLen = (versionIhl and 0x0F) * 4
        if (ipHdrLen < 20 || length < TUN_HEADER_SIZE + ipHdrLen + 20) return null

        val ipProtocol = (buffer[ipStart + 9].toInt() and 0xFF)
        if (ipProtocol != IPPROTO_TCP) return null

        val totalLen = ((buffer[ipStart + 2].toInt() and 0xFF) shl 8) or
                       (buffer[ipStart + 3].toInt() and 0xFF)

        val srcIp = ((buffer[ipStart + 12].toInt() and 0xFF) shl 24) or
                    ((buffer[ipStart + 13].toInt() and 0xFF) shl 16) or
                    ((buffer[ipStart + 14].toInt() and 0xFF) shl 8) or
                    (buffer[ipStart + 15].toInt() and 0xFF)

        val dstIp = ((buffer[ipStart + 16].toInt() and 0xFF) shl 24) or
                    ((buffer[ipStart + 17].toInt() and 0xFF) shl 16) or
                    ((buffer[ipStart + 18].toInt() and 0xFF) shl 8) or
                    (buffer[ipStart + 19].toInt() and 0xFF)

        // TCP header
        val tcpStart = ipStart + ipHdrLen
        val srcPort = ((buffer[tcpStart].toInt() and 0xFF) shl 8) or
                      (buffer[tcpStart + 1].toInt() and 0xFF)
        val dstPort = ((buffer[tcpStart + 2].toInt() and 0xFF) shl 8) or
                      (buffer[tcpStart + 3].toInt() and 0xFF)

        val seqNum = ((buffer[tcpStart + 4].toLong() and 0xFF) shl 24) or
                     ((buffer[tcpStart + 5].toLong() and 0xFF) shl 16) or
                     ((buffer[tcpStart + 6].toLong() and 0xFF) shl 8) or
                     (buffer[tcpStart + 7].toLong() and 0xFF)

        val ackNum = ((buffer[tcpStart + 8].toLong() and 0xFF) shl 24) or
                     ((buffer[tcpStart + 9].toLong() and 0xFF) shl 16) or
                     ((buffer[tcpStart + 10].toLong() and 0xFF) shl 8) or
                     (buffer[tcpStart + 11].toLong() and 0xFF)

        val dataOffReserved = (buffer[tcpStart + 12].toInt() and 0xFF)
        val tcpHdrLen = ((dataOffReserved shr 4) and 0x0F) * 4
        if (tcpHdrLen < 20) return null

        val flags = (buffer[tcpStart + 13].toInt() and 0xFF)

        val window = ((buffer[tcpStart + 14].toInt() and 0xFF) shl 8) or
                     (buffer[tcpStart + 15].toInt() and 0xFF)

        val payloadStart = tcpStart + tcpHdrLen
        val ipPayloadLen = totalLen - ipHdrLen
        val payloadLen = (ipPayloadLen - tcpHdrLen).coerceAtLeast(0)
        val actualPayloadLen = (length - payloadStart).coerceAtMost(payloadLen).coerceAtLeast(0)

        return TcpHeader(
            sourceIp = srcIp,
            destIp = dstIp,
            sourcePort = srcPort,
            destPort = dstPort,
            sequenceNumber = seqNum,
            acknowledgmentNumber = ackNum,
            dataOffset = tcpHdrLen,
            flags = flags,
            windowSize = window,
            payloadStart = payloadStart,
            payloadLength = actualPayloadLen
        )
    }

    fun connectionKey(tcp: TcpHeader): String {
        return "${ipToStr(tcp.sourceIp)}:${tcp.sourcePort}->${ipToStr(tcp.destIp)}:${tcp.destPort}"
    }

    fun ipToStr(ip: Int): String {
        return "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"
    }

    fun ipToBytes(ip: Int): ByteArray {
        return byteArrayOf(
            ((ip shr 24) and 0xFF).toByte(),
            ((ip shr 16) and 0xFF).toByte(),
            ((ip shr 8) and 0xFF).toByte(),
            (ip and 0xFF).toByte()
        )
    }
}
