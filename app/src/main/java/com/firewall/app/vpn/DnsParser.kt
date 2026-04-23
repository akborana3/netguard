package com.firewall.app.vpn

import java.nio.ByteBuffer

object DnsParser {
    fun parseDomain(payload: ByteArray): String? {
        if (payload.size < 13) return null

        try {
            var offset = 12 // Skip header
            val domainBuilder = java.lang.StringBuilder()

            while (offset < payload.size) {
                val len = payload[offset].toInt() and 0xFF
                if (len == 0) break

                // Check for pointer
                if ((len and 0xC0) == 0xC0) {
                    val pointer = ((len and 0x3F) shl 8) or (payload[offset + 1].toInt() and 0xFF)
                    val resolved = parseDomainAt(payload, pointer)
                    if (domainBuilder.isNotEmpty()) domainBuilder.append(".")
                    domainBuilder.append(resolved)
                    break
                }

                if (domainBuilder.isNotEmpty()) domainBuilder.append(".")
                for (j in 0 until len) {
                    if (offset + 1 + j < payload.size) {
                        domainBuilder.append(payload[offset + 1 + j].toInt().toChar())
                    }
                }
                offset += len + 1
            }
            return domainBuilder.toString()
        } catch (e: Exception) {
            return null
        }
    }

    private fun parseDomainAt(payload: ByteArray, offset: Int): String {
        var curr = offset
        val domainBuilder = java.lang.StringBuilder()
        while (curr < payload.size) {
            val len = payload[curr].toInt() and 0xFF
            if (len == 0) break

            if ((len and 0xC0) == 0xC0) {
                val pointer = ((len and 0x3F) shl 8) or (payload[curr + 1].toInt() and 0xFF)
                val resolved = parseDomainAt(payload, pointer)
                if (domainBuilder.isNotEmpty()) domainBuilder.append(".")
                domainBuilder.append(resolved)
                break
            }

            if (domainBuilder.isNotEmpty()) domainBuilder.append(".")
            for (j in 0 until len) {
                domainBuilder.append(payload[curr + 1 + j].toInt().toChar())
            }
            curr += len + 1
        }
        return domainBuilder.toString()
    }
}
