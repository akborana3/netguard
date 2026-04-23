package com.firewall.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import com.firewall.app.db.AppDatabase
import com.firewall.app.db.AppRule
import com.firewall.app.db.TrafficLog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.Calendar

class FirewallVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    private var isRunning = false

    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())
    private lateinit var database: AppDatabase
    private var natEngine: NatEngine? = null

    override fun onCreate() {
        super.onCreate()
        database = AppDatabase.getDatabase(this)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, createNotification())
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        if (vpnInterface != null) return

        serviceScope.launch {
            val builder = Builder()
                .addAddress("10.0.0.2", 24)
                .addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128)
                .addRoute("0.0.0.0", 0) // Route all IPv4
                .addRoute("::", 0)     // Route all IPv6
                .addDnsServer("8.8.8.8")
                .setSession("Firewall Control")
                .setBlocking(true)

            protect(System.identityHashCode(this@FirewallVpnService))

            try {
                vpnInterface = builder.establish()
                isRunning = true
                vpnThread = Thread { runVpnLoop() }
                vpnThread?.start()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to establish VPN", e)
            }
        }
    }

    private fun stopVpn() {
        isRunning = false
        natEngine?.stop()
        vpnThread?.interrupt()
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun runVpnLoop() {
        val vpnFd = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(vpnFd)
        val outputStream = FileOutputStream(vpnFd)

        natEngine = NatEngine(outputStream)
        val packetBuffer = ByteBuffer.allocate(32767)
        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        while (isRunning && !Thread.currentThread().isInterrupted) {
            try {
                packetBuffer.clear()
                val length = inputStream.read(packetBuffer.array())
                if (length > 0) {
                    packetBuffer.limit(length)
                    val packet = Packet(packetBuffer)

                    val uid = getUidForConnectionCompat(packet.protocol, packet.sourceIp.hostAddress ?: "", packet.sourcePort, packet.destinationIp.hostAddress ?: "", packet.destinationPort)

                    val activeNetwork = connectivityManager.activeNetwork
                    val networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
                    val isWifi = networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
                    val isMobile = networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true

                    val rule = if (uid != -1) database.appRuleDao().getRuleByUidSync(uid) else null
                    val shouldBlock = if (rule != null) checkBlockingRulesSync(rule, isWifi, isMobile) else false

                    var isAd = false
                    var dnsDomain: String? = null
                    var sni: String? = null
                    var httpHost: String? = null

                    val payload = packet.getPayload()

                    if (packet.isUDP && packet.destinationPort == 53) {
                        dnsDomain = DnsParser.parseDomain(payload)
                        if (dnsDomain != null && DnsInterceptor.isAdDomain(payload)) {
                            isAd = true
                        }
                    } else if (packet.isTCP && packet.destinationPort == 443) {
                        sni = InspectUtils.getSni(payload)
                    } else if (packet.isTCP && packet.destinationPort == 80) {
                        httpHost = InspectUtils.getHttpHost(payload)
                    }

                    val finalBlock = shouldBlock || isAd

                    logTraffic(uid, packet, finalBlock, isAd, dnsDomain ?: sni ?: httpHost)

                    if (!finalBlock) {
                        if (packet.isUDP) {
                            natEngine?.handleUdp(packet)
                        } else if (packet.isTCP) {
                            natEngine?.handleTcp(packet)
                        }
                    } else {
                        if (packet.isUDP && packet.destinationPort == 53) {
                            // Synthesize Fake DNS response (NXDOMAIN)
                            // Implementation omitted for brevity, but the packet is safely dropped.
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "VPN Loop Error", e)
            }
        }
    }

    private fun getUidForConnectionCompat(protocol: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val connProtocol = if (protocol == 6) OsConstants.IPPROTO_TCP else OsConstants.IPPROTO_UDP

            try {
                val localAddress = InetSocketAddress(srcIp, srcPort)
                val remoteAddress = InetSocketAddress(dstIp, dstPort)
                return cm.getConnectionOwnerUid(connProtocol, localAddress, remoteAddress)
            } catch (e: Exception) {
                return -1
            }
        }
        // Fallback for pre-Q would involve parsing /proc/net/tcp and udp
        return -1
    }

    private fun checkBlockingRulesSync(rule: AppRule, isWifi: Boolean, isMobile: Boolean): Boolean {
        val calendar = Calendar.getInstance()
        val currentHour = calendar.get(Calendar.HOUR_OF_DAY)
        val currentMinute = calendar.get(Calendar.MINUTE)
        val currentTime = currentHour * 60 + currentMinute

        if (rule.scheduleEnabled) {
            val startParts = rule.startTime.split(":")
            val endParts = rule.endTime.split(":")
            if (startParts.size == 2 && endParts.size == 2) {
                val startMins = startParts[0].toInt() * 60 + startParts[1].toInt()
                val endMins = endParts[0].toInt() * 60 + endParts[1].toInt()

                if (startMins < endMins) {
                    if (currentTime in startMins..endMins) return true
                } else {
                    if (currentTime >= startMins || currentTime <= endMins) return true
                }
            }
        }

        if (isWifi && rule.blockWifi) return true
        if (isMobile && rule.blockMobile) return true

        return false
    }

    private fun logTraffic(uid: Int, packet: Packet, isBlocked: Boolean, isAd: Boolean, meta: String?) {
        serviceScope.launch {
            val protocolStr = when {
                packet.isTCP -> "TCP"
                packet.isUDP -> "UDP"
                else -> "Other"
            }

            val rule = if (uid != -1) database.appRuleDao().getRuleByUidSync(uid) else null
            val pkgName = rule?.packageName ?: "unknown"

            val metaInfo = if (meta != null) " [$meta]" else ""
            val adInfo = if (isAd) " (Ad Blocked)" else ""

            database.trafficLogDao().insertLog(
                TrafficLog(
                    timestamp = System.currentTimeMillis(),
                    packageName = pkgName,
                    uid = uid,
                    destinationIp = packet.destinationIp.hostAddress ?: "",
                    destinationPort = packet.destinationPort,
                    protocol = protocolStr + metaInfo + adInfo,
                    isBlocked = isBlocked
                )
            )
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Firewall Status",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Advanced Network Control")
            .setContentText("Intercepting and routing traffic")
            .setSmallIcon(android.R.drawable.ic_secure)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }

    companion object {
        const val ACTION_STOP = "com.firewall.app.STOP_VPN"
        private const val CHANNEL_ID = "firewall_channel"
        private const val NOTIFICATION_ID = 1
        private const val TAG = "FirewallVpnService"
    }
}
