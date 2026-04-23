package com.firewall.app.vpn

import java.net.InetAddress
import java.nio.ByteBuffer

class Packet(val backingBuffer: ByteBuffer) {
    val array = backingBuffer.array()
    val limit = backingBuffer.limit()

    val version: Int
    val ipHeaderLength: Int
    val totalLength: Int
    val protocol: Int

    var sourceIp: InetAddress
    var destinationIp: InetAddress

    var sourcePort: Int = 0
    var destinationPort: Int = 0

    val isTCP: Boolean
    val isUDP: Boolean

    var transportHeaderOffset = 0
    var payloadOffset = 0

    // TCP specific
    var sequenceNumber: Long = 0
    var acknowledgmentNumber: Long = 0
    var isSyn: Boolean = false
    var isAck: Boolean = false
    var isFin: Boolean = false
    var isRst: Boolean = false
    var isPsh: Boolean = false

    init {
        val start = 0
        val vhl = array[start].toInt() and 0xFF
        version = vhl shr 4

        if (version == 4) {
            ipHeaderLength = (vhl and 0x0F) * 4
            totalLength = ((array[start + 2].toInt() and 0xFF) shl 8) or (array[start + 3].toInt() and 0xFF)
            protocol = array[start + 9].toInt() and 0xFF

            val srcBytes = ByteArray(4)
            System.arraycopy(array, start + 12, srcBytes, 0, 4)
            sourceIp = InetAddress.getByAddress(srcBytes)

            val dstBytes = ByteArray(4)
            System.arraycopy(array, start + 16, dstBytes, 0, 4)
            destinationIp = InetAddress.getByAddress(dstBytes)

            transportHeaderOffset = start + ipHeaderLength

        } else if (version == 6) {
            ipHeaderLength = 40
            val payloadLen = ((array[start + 4].toInt() and 0xFF) shl 8) or (array[start + 5].toInt() and 0xFF)
            totalLength = 40 + payloadLen
            protocol = array[start + 6].toInt() and 0xFF

            val srcBytes = ByteArray(16)
            System.arraycopy(array, start + 8, srcBytes, 0, 16)
            sourceIp = InetAddress.getByAddress(srcBytes)

            val dstBytes = ByteArray(16)
            System.arraycopy(array, start + 24, dstBytes, 0, 16)
            destinationIp = InetAddress.getByAddress(dstBytes)

            transportHeaderOffset = start + 40
        } else {
            throw IllegalArgumentException("Unknown IP version")
        }

        isTCP = protocol == 6
        isUDP = protocol == 17

        if ((isTCP || isUDP) && transportHeaderOffset + 4 <= limit) {
            sourcePort = ((array[transportHeaderOffset].toInt() and 0xFF) shl 8) or (array[transportHeaderOffset + 1].toInt() and 0xFF)
            destinationPort = ((array[transportHeaderOffset + 2].toInt() and 0xFF) shl 8) or (array[transportHeaderOffset + 3].toInt() and 0xFF)

            if (isTCP && transportHeaderOffset + 20 <= limit) {
                sequenceNumber = ((array[transportHeaderOffset + 4].toLong() and 0xFF) shl 24) or
                                 ((array[transportHeaderOffset + 5].toLong() and 0xFF) shl 16) or
                                 ((array[transportHeaderOffset + 6].toLong() and 0xFF) shl 8) or
                                 (array[transportHeaderOffset + 7].toLong() and 0xFF)

                acknowledgmentNumber = ((array[transportHeaderOffset + 8].toLong() and 0xFF) shl 24) or
                                       ((array[transportHeaderOffset + 9].toLong() and 0xFF) shl 16) or
                                       ((array[transportHeaderOffset + 10].toLong() and 0xFF) shl 8) or
                                       (array[transportHeaderOffset + 11].toLong() and 0xFF)

                val dataOffsetAndFlags = ((array[transportHeaderOffset + 12].toInt() and 0xFF) shl 8) or (array[transportHeaderOffset + 13].toInt() and 0xFF)
                val tcpHeaderLen = (dataOffsetAndFlags shr 12) * 4
                payloadOffset = transportHeaderOffset + tcpHeaderLen

                val flags = dataOffsetAndFlags and 0x1FF
                isFin = (flags and 0x01) != 0
                isSyn = (flags and 0x02) != 0
                isRst = (flags and 0x04) != 0
                isPsh = (flags and 0x08) != 0
                isAck = (flags and 0x10) != 0
            } else if (isUDP) {
                payloadOffset = transportHeaderOffset + 8
            }
        }
    }

    fun getPayload(): ByteArray {
        val length = totalLength - payloadOffset
        if (length <= 0) return ByteArray(0)
        val payload = ByteArray(length)
        System.arraycopy(array, payloadOffset, payload, 0, length)
        return payload
    }

    fun swapSourceAndDestination() {
        val tempIp = sourceIp
        sourceIp = destinationIp
        destinationIp = tempIp

        val srcIpBytes = sourceIp.address
        val dstIpBytes = destinationIp.address

        if (version == 4) {
            System.arraycopy(srcIpBytes, 0, array, 12, 4)
            System.arraycopy(dstIpBytes, 0, array, 16, 4)
        } else if (version == 6) {
            System.arraycopy(srcIpBytes, 0, array, 8, 16)
            System.arraycopy(dstIpBytes, 0, array, 24, 16)
        }

        if (isTCP || isUDP) {
            val tempPort = sourcePort
            sourcePort = destinationPort
            destinationPort = tempPort

            array[transportHeaderOffset] = (sourcePort shr 8).toByte()
            array[transportHeaderOffset + 1] = sourcePort.toByte()
            array[transportHeaderOffset + 2] = (destinationPort shr 8).toByte()
            array[transportHeaderOffset + 3] = destinationPort.toByte()
        }
    }

    fun updateChecksums() {
        if (version == 4) {
            array[10] = 0
            array[11] = 0
            val ipChecksum = IpUtil.computeChecksum(array, 0, ipHeaderLength)
            array[10] = (ipChecksum.toInt() shr 8).toByte()
            array[11] = ipChecksum.toByte()

            if (isTCP || isUDP) {
                val sumOff = if (isTCP) transportHeaderOffset + 16 else transportHeaderOffset + 6
                array[sumOff] = 0
                array[sumOff + 1] = 0

                val tcpUdpLen = totalLength - ipHeaderLength
                val checksum = IpUtil.computeTcpUdpChecksum(array, ipHeaderLength, protocol, 12, 16, tcpUdpLen)

                array[sumOff] = (checksum.toInt() shr 8).toByte()
                array[sumOff + 1] = checksum.toByte()
            }
        }
    }
}
