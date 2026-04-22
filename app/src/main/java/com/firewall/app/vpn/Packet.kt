package com.firewall.app.vpn

import java.nio.ByteBuffer

class Packet(val buffer: ByteBuffer) {
    val version: Int
    val headerLength: Int
    val totalLength: Int
    val protocol: Int
    val sourceIp: String
    val destinationIp: String

    var sourcePort: Int = 0
    var destinationPort: Int = 0

    val isTCP: Boolean get() = protocol == 6
    val isUDP: Boolean get() = protocol == 17

    val ipHeaderOffset = 0
    var transportHeaderOffset = 0
    var payloadOffset = 0

    init {
        val startPos = buffer.position()
        val versionAndHeaderLen = buffer.get(startPos).toInt() and 0xFF
        version = versionAndHeaderLen shr 4
        headerLength = (versionAndHeaderLen and 0x0F) * 4

        totalLength = buffer.getShort(startPos + 2).toInt() and 0xFFFF
        protocol = buffer.get(startPos + 9).toInt() and 0xFF

        val srcIpBytes = ByteArray(4)
        buffer.position(startPos + 12)
        buffer.get(srcIpBytes)
        sourceIp = srcIpBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }

        val dstIpBytes = ByteArray(4)
        buffer.get(dstIpBytes)
        destinationIp = dstIpBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }

        transportHeaderOffset = startPos + headerLength

        if (isTCP || isUDP) {
            sourcePort = buffer.getShort(transportHeaderOffset).toInt() and 0xFFFF
            destinationPort = buffer.getShort(transportHeaderOffset + 2).toInt() and 0xFFFF

            if (isTCP) {
                val tcpHeaderLen = ((buffer.get(transportHeaderOffset + 12).toInt() and 0xF0) shr 4) * 4
                payloadOffset = transportHeaderOffset + tcpHeaderLen
            } else if (isUDP) {
                payloadOffset = transportHeaderOffset + 8
            }
        }

        buffer.position(startPos) // Reset buffer position
    }

    fun getPayload(): ByteArray {
        val length = totalLength - payloadOffset
        if (length <= 0) return ByteArray(0)

        buffer.position(payloadOffset)
        val payload = ByteArray(length)
        buffer.get(payload)
        buffer.position(0)
        return payload
    }
}
