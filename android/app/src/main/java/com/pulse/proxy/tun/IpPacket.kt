package com.pulse.proxy.tun

import java.nio.ByteBuffer
import java.nio.ByteOrder

object IpPacket {
    const val TUN_HEADER_SIZE = 0
    const val IPPROTO_TCP = 6
    const val IPPROTO_UDP = 17

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

    data class UdpPacket(
        val sourceIp: Int,
        val destIp: Int,
        val sourcePort: Int,
        val destPort: Int,
        val payload: ByteArray
    )

    fun parse(buffer: ByteArray, length: Int): TcpHeader? {
        if (length < 40) return null  // min: IP + TCP

        // IPv4 header
        val ipStart = 0
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

    fun parseUdp(buffer: ByteArray, length: Int): UdpPacket? {
        if (length < 28) return null

        val ipStart = 0
        val versionIhl = buffer[ipStart].toInt() and 0xFF
        if ((versionIhl shr 4) != 4) return null
        val ipHdrLen = (versionIhl and 0x0F) * 4
        if (ipHdrLen < 20 || length < TUN_HEADER_SIZE + ipHdrLen + 8) return null

        val ipProtocol = buffer[ipStart + 9].toInt() and 0xFF
        if (ipProtocol != IPPROTO_UDP) return null

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

        val udpStart = ipStart + ipHdrLen
        val srcPort = ((buffer[udpStart].toInt() and 0xFF) shl 8) or
            (buffer[udpStart + 1].toInt() and 0xFF)
        val dstPort = ((buffer[udpStart + 2].toInt() and 0xFF) shl 8) or
            (buffer[udpStart + 3].toInt() and 0xFF)
        val udpLen = ((buffer[udpStart + 4].toInt() and 0xFF) shl 8) or
            (buffer[udpStart + 5].toInt() and 0xFF)
        if (udpLen < 8) return null

        val payloadStart = udpStart + 8
        val payloadLen = (udpLen - 8).coerceAtMost(TUN_HEADER_SIZE + totalLen - payloadStart)
        if (payloadLen <= 0 || payloadStart + payloadLen > length) return null

        return UdpPacket(
            sourceIp = srcIp,
            destIp = dstIp,
            sourcePort = srcPort,
            destPort = dstPort,
            payload = buffer.copyOfRange(payloadStart, payloadStart + payloadLen)
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
