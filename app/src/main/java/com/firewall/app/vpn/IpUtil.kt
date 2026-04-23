package com.firewall.app.vpn

object IpUtil {
    fun computeChecksum(data: ByteArray, offset: Int, length: Int, skipOffset: Int = -1): Short {
        var sum = 0L
        var i = offset
        val end = offset + length

        while (i < end - 1) {
            if (i == skipOffset) {
                i += 2
                continue
            }
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }

        if (i == end - 1) {
            val word = (data[i].toInt() and 0xFF) shl 8
            sum += word
        }

        while ((sum shr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return (sum.inv() and 0xFFFF).toShort()
    }

    fun computeTcpUdpChecksum(packet: ByteArray, ipHeaderLen: Int, protocol: Int, sourceIpOff: Int, destIpOff: Int, tcpUdpLen: Int): Short {
        var sum = 0L

        // Pseudo header
        for (i in 0 until 4) {
            sum += ((packet[sourceIpOff + i * 2].toInt() and 0xFF) shl 8) or (packet[sourceIpOff + i * 2 + 1].toInt() and 0xFF)
            sum += ((packet[destIpOff + i * 2].toInt() and 0xFF) shl 8) or (packet[destIpOff + i * 2 + 1].toInt() and 0xFF)
        }
        sum += protocol
        sum += tcpUdpLen

        // Payload
        val start = ipHeaderLen
        val end = start + tcpUdpLen
        var i = start

        val skipChecksumOff = if (protocol == 6) start + 16 else start + 6

        while (i < end - 1) {
            if (i == skipChecksumOff) {
                i += 2
                continue
            }
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }

        if (i == end - 1) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }

        while ((sum shr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return (sum.inv() and 0xFFFF).toShort()
    }
}
