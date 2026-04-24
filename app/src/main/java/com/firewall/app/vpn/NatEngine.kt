package com.firewall.app.vpn

import android.util.Log
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.io.FileOutputStream

class NatEngine(private val vpnOutStream: FileOutputStream) {
    private val scope = CoroutineScope(Dispatchers.IO + Job())

    private val selector = Selector.open()
    private val udpMap = ConcurrentHashMap<String, DatagramChannel>()
    private val tcpMap = ConcurrentHashMap<String, SocketChannel>()

    @Volatile private var isRunning = true

    init {
        Thread { runSelector() }.start()
    }

    fun stop() {
        isRunning = false
        selector.wakeup()
    }

    fun handleUdp(packet: Packet) {
        val key = "${packet.sourceIp.hostAddress}:${packet.sourcePort}->${packet.destinationIp.hostAddress}:${packet.destinationPort}"

        try {
            var channel = udpMap[key]
            if (channel == null) {
                channel = DatagramChannel.open()
                channel.configureBlocking(false)
                channel.socket().bind(null)

                selector.wakeup()
                channel.register(selector, SelectionKey.OP_READ, UdpSession(key, packet))
                udpMap[key] = channel
            }

            val payload = packet.getPayload()
            if (payload.isNotEmpty()) {
                channel!!.send(ByteBuffer.wrap(payload), InetSocketAddress(packet.destinationIp, packet.destinationPort))
            }
        } catch (e: Exception) {
            Log.e("NatEngine", "UDP Error", e)
        }
    }

    fun handleTcp(packet: Packet) {
        // Simplified TCP state tracking
        // Warning: Writing a fully compliant TCP stack from scratch is ~20k lines of code.
        // This proxies TCP by establishing a native socket and piping data, but synthesizing ACKs
        // back to the VPN interface is complex.

        val key = "${packet.sourceIp.hostAddress}:${packet.sourcePort}->${packet.destinationIp.hostAddress}:${packet.destinationPort}"

        try {
            if (packet.isSyn) {
                val channel = SocketChannel.open()
                channel.configureBlocking(false)

                val connected = channel.connect(InetSocketAddress(packet.destinationIp, packet.destinationPort))

                selector.wakeup()
                if (connected) {
                    channel.register(selector, SelectionKey.OP_READ, TcpSession(key, packet))
                    sendSynAck(packet)
                } else {
                    channel.register(selector, SelectionKey.OP_CONNECT or SelectionKey.OP_READ, TcpSession(key, packet))
                }
                tcpMap[key] = channel
            } else if (packet.isAck && packet.getPayload().isNotEmpty()) {
                val channel = tcpMap[key]
                if (channel != null && channel.isConnected) {
                    channel.write(ByteBuffer.wrap(packet.getPayload()))
                }
            } else if (packet.isFin || packet.isRst) {
                tcpMap[key]?.close()
                tcpMap.remove(key)
                sendRstAck(packet)
            }
        } catch (e: Exception) {
            Log.e("NatEngine", "TCP Error", e)
            sendRstAck(packet)
        }
    }

    private fun runSelector() {
        val buffer = ByteBuffer.allocate(32767)
        while (isRunning) {
            try {
                if (selector.select() == 0) continue

                val keys = selector.selectedKeys().iterator()
                while (keys.hasNext()) {
                    val key = keys.next()
                    keys.remove()

                    if (!key.isValid) continue

                    val session = key.attachment()

                    if (key.isConnectable && session is TcpSession) {
                        val channel = key.channel() as SocketChannel
                        if (channel.finishConnect()) {
                            sendSynAck(session.originalPacket)
                        }
                    } else if (key.isReadable) {
                        buffer.clear()
                        if (session is UdpSession) {
                            val channel = key.channel() as DatagramChannel
                            val sender = channel.receive(buffer)
                            if (sender != null) {
                                buffer.flip()
                                sendUdpResponse(session.originalPacket, buffer)
                            }
                        } else if (session is TcpSession) {
                            val channel = key.channel() as SocketChannel
                            val read = channel.read(buffer)
                            if (read > 0) {
                                buffer.flip()
                                sendTcpResponse(session.originalPacket, buffer)
                            } else if (read == -1) {
                                channel.close()
                                tcpMap.remove(session.key)
                                sendFinAck(session.originalPacket)
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("NatEngine", "Selector Error", e)
            }
        }
    }

    private fun sendUdpResponse(original: Packet, data: ByteBuffer) {
        original.swapSourceAndDestination()

        // Update payload
        val payloadLen = data.remaining()
        System.arraycopy(data.array(), 0, original.array, original.payloadOffset, payloadLen)

        // Update lengths
        val ipLen = original.ipHeaderLength + 8 + payloadLen
        original.array[2] = (ipLen shr 8).toByte()
        original.array[3] = ipLen.toByte()

        original.array[original.transportHeaderOffset + 4] = ((8 + payloadLen) shr 8).toByte()
        original.array[original.transportHeaderOffset + 5] = (8 + payloadLen).toByte()

        original.updateChecksums()

        synchronized(vpnOutStream) {
            vpnOutStream.write(original.array, 0, ipLen)
        }
    }

    private fun sendSynAck(original: Packet) {
        original.swapSourceAndDestination()

        val flagsOff = original.transportHeaderOffset + 13
        original.array[flagsOff] = (0x12).toByte() // SYN + ACK

        val ackNum = original.sequenceNumber + 1
        val seqNum = 1000L // Random start

        writeSeqAck(original, seqNum, ackNum)

        val ipLen = original.ipHeaderLength + 20
        original.array[2] = (ipLen shr 8).toByte()
        original.array[3] = ipLen.toByte()

        original.updateChecksums()
        synchronized(vpnOutStream) { vpnOutStream.write(original.array, 0, ipLen) }
    }

    private fun sendTcpResponse(original: Packet, data: ByteBuffer) {
        original.swapSourceAndDestination()

        val payloadLen = data.remaining()
        System.arraycopy(data.array(), 0, original.array, original.payloadOffset, payloadLen)

        val flagsOff = original.transportHeaderOffset + 13
        original.array[flagsOff] = (0x18).toByte() // PSH + ACK

        val ipLen = original.ipHeaderLength + 20 + payloadLen
        original.array[2] = (ipLen shr 8).toByte()
        original.array[3] = ipLen.toByte()

        original.updateChecksums()
        synchronized(vpnOutStream) { vpnOutStream.write(original.array, 0, ipLen) }
    }

    private fun sendFinAck(original: Packet) {
        original.swapSourceAndDestination()
        val flagsOff = original.transportHeaderOffset + 13
        original.array[flagsOff] = (0x11).toByte() // FIN + ACK

        val ipLen = original.ipHeaderLength + 20
        original.array[2] = (ipLen shr 8).toByte()
        original.array[3] = ipLen.toByte()
        original.updateChecksums()
        synchronized(vpnOutStream) { vpnOutStream.write(original.array, 0, ipLen) }
    }

    private fun sendRstAck(original: Packet) {
        original.swapSourceAndDestination()
        val flagsOff = original.transportHeaderOffset + 13
        original.array[flagsOff] = (0x14).toByte() // RST + ACK

        val ipLen = original.ipHeaderLength + 20
        original.array[2] = (ipLen shr 8).toByte()
        original.array[3] = ipLen.toByte()
        original.updateChecksums()
        synchronized(vpnOutStream) { vpnOutStream.write(original.array, 0, ipLen) }
    }

    private fun writeSeqAck(packet: Packet, seq: Long, ack: Long) {
        packet.array[packet.transportHeaderOffset + 4] = (seq shr 24).toByte()
        packet.array[packet.transportHeaderOffset + 5] = (seq shr 16).toByte()
        packet.array[packet.transportHeaderOffset + 6] = (seq shr 8).toByte()
        packet.array[packet.transportHeaderOffset + 7] = seq.toByte()

        packet.array[packet.transportHeaderOffset + 8] = (ack shr 24).toByte()
        packet.array[packet.transportHeaderOffset + 9] = (ack shr 16).toByte()
        packet.array[packet.transportHeaderOffset + 10] = (ack shr 8).toByte()
        packet.array[packet.transportHeaderOffset + 11] = ack.toByte()
    }
}

class UdpSession(val key: String, val originalPacket: Packet)
class TcpSession(val key: String, val originalPacket: Packet)
