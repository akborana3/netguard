package com.firewall.app.vpn

import java.nio.ByteBuffer

object InspectUtils {

    fun getSni(payload: ByteArray): String? {
        try {
            if (payload.size < 43) return null

            // Check for TLS Handshake (Type 22)
            if (payload[0].toInt() != 22) return null

            // Client Hello (Type 1)
            if (payload[5].toInt() != 1) return null

            val buffer = ByteBuffer.wrap(payload)
            buffer.position(43) // Skip header and random

            val sessionIdLength = buffer.get().toInt() and 0xFF
            buffer.position(buffer.position() + sessionIdLength)

            val cipherSuitesLength = buffer.short.toInt() and 0xFFFF
            buffer.position(buffer.position() + cipherSuitesLength)

            val compressionMethodsLength = buffer.get().toInt() and 0xFF
            buffer.position(buffer.position() + compressionMethodsLength)

            if (buffer.remaining() < 2) return null

            val extensionsLength = buffer.short.toInt() and 0xFFFF
            val extensionsEnd = buffer.position() + extensionsLength

            while (buffer.position() < extensionsEnd) {
                val extensionType = buffer.short.toInt() and 0xFFFF
                val extensionDataLength = buffer.short.toInt() and 0xFFFF

                if (extensionType == 0) { // Server Name Indication
                    buffer.short // list length
                    buffer.get() // type
                    val serverNameLength = buffer.short.toInt() and 0xFFFF
                    val serverNameBytes = ByteArray(serverNameLength)
                    buffer.get(serverNameBytes)
                    return String(serverNameBytes)
                }
                buffer.position(buffer.position() + extensionDataLength)
            }
        } catch (e: Exception) {
            // Ignored
        }
        return null
    }

    fun getHttpHost(payload: ByteArray): String? {
        try {
            val text = String(payload, Charsets.US_ASCII)
            if (text.startsWith("GET ") || text.startsWith("POST ") || text.startsWith("PUT ") || text.startsWith("CONNECT ")) {
                val lines = text.split("\r\n")
                for (line in lines) {
                    if (line.startsWith("Host: ", ignoreCase = true)) {
                        return line.substring(6).trim()
                    }
                }
            }
        } catch (e: Exception) {
            // Ignored
        }
        return null
    }
}
