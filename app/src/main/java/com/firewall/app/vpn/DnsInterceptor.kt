package com.firewall.app.vpn

import java.nio.ByteBuffer

object DnsInterceptor {
    private val blockedDomains = setOf("ads.google.com", "adservice.google.com", "doubleclick.net")

    fun isAdDomain(payload: ByteArray): Boolean {
        // Very basic DNS packet parsing to extract queried domains
        if (payload.size < 13) return false

        try {
            var offset = 12 // Skip DNS header
            while (offset < payload.size) {
                val len = payload[offset].toInt() and 0xFF
                if (len == 0) break
                offset += len + 1
            }
            if (offset >= payload.size) return false

            // Reconstruct domain (simplified)
            var i = 12
            val domainBuilder = java.lang.StringBuilder()
            while (i < payload.size) {
                val len = payload[i].toInt() and 0xFF
                if (len == 0) break
                if (domainBuilder.isNotEmpty()) domainBuilder.append(".")
                for (j in 0 until len) {
                    if (i + 1 + j < payload.size) {
                        domainBuilder.append(payload[i + 1 + j].toInt().toChar())
                    }
                }
                i += len + 1
            }
            val domain = domainBuilder.toString()
            return blockedDomains.any { domain.contains(it, ignoreCase = true) }
        } catch (e: Exception) {
            return false
        }
    }
}
