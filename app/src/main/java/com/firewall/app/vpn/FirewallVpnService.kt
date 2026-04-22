package com.firewall.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
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
import kotlinx.coroutines.runBlocking
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
            val rules = database.appRuleDao().getAllRules().first()

            val builder = Builder()
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .setSession("Firewall")
                .setBlocking(true)

            protect(System.identityHashCode(this@FirewallVpnService))

            val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNetwork = connectivityManager.activeNetwork
            val networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
            val isWifi = networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            val isMobile = networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true

            // To provide a functional "allow" without a full user-space TCP stack (which is >5000 lines of C/Kotlin),
            // we use Android's built-in Split Tunneling to route only the BLOCKED apps through the VPN
            // interface, where we will simply drop their packets. Allowed apps bypass the VPN entirely
            // and use the standard internet connection.

            var blockedAppCount = 0
            for (rule in rules) {
                val shouldBlock = checkBlockingRulesSync(rule, isWifi, isMobile)
                if (shouldBlock) {
                    try {
                        builder.addAllowedApplication(rule.packageName)
                        blockedAppCount++
                    } catch (e: PackageManager.NameNotFoundException) {
                        Log.e(TAG, "Package not found: ${rule.packageName}")
                    }
                }
            }

            // If nothing is blocked, we can't establish a VPN that allows nothing in Android without errors.
            // But if it's 0, it means all apps are allowed, so we just don't start the interceptor.
            if (blockedAppCount > 0) {
                try {
                    vpnInterface = builder.establish()
                    isRunning = true
                    vpnThread = Thread { runVpnLoop() }
                    vpnThread?.start()
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to establish VPN", e)
                }
            } else {
                Log.d(TAG, "No apps blocked, VPN is idle.")
                isRunning = true // Keep service alive for state management
            }
        }
    }

    private fun stopVpn() {
        isRunning = false
        vpnThread?.interrupt()
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun runVpnLoop() {
        val vpnFd = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(vpnFd)

        val packetBuffer = ByteBuffer.allocate(32767)

        while (isRunning && !Thread.currentThread().isInterrupted) {
            try {
                packetBuffer.clear()
                val length = inputStream.read(packetBuffer.array())
                if (length > 0) {
                    packetBuffer.limit(length)
                    val packet = Packet(packetBuffer)

                    if (packet.version == 4) {
                        val uid = getUidForConnectionCompat(packet.protocol, packet.sourceIp, packet.sourcePort, packet.destinationIp, packet.destinationPort)

                        var isAd = false
                        if (packet.isUDP && packet.destinationPort == 53) {
                            val payload = packet.getPayload()
                            if (DnsInterceptor.isAdDomain(payload)) {
                                isAd = true
                            }
                        }

                        // Because we used split tunneling, ANY packet arriving here belongs to a blocked app.
                        // We log it and DROP it (do nothing).
                        logTraffic(uid, packet, isBlocked = true, isAd = isAd)
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
                } else { // crosses midnight
                    if (currentTime >= startMins || currentTime <= endMins) return true
                }
            }
        }

        if (isWifi && rule.blockWifi) return true
        if (isMobile && rule.blockMobile) return true

        return false
    }

    private fun logTraffic(uid: Int, packet: Packet, isBlocked: Boolean, isAd: Boolean) {
        serviceScope.launch {
            val protocolStr = when {
                packet.isTCP -> "TCP"
                packet.isUDP -> "UDP"
                else -> "Other"
            }

            val rule = if (uid != -1) database.appRuleDao().getRuleByUidSync(uid) else null
            val pkgName = rule?.packageName ?: "unknown"

            val extraInfo = if (isAd) " (DNS Ad Blocked)" else ""

            database.trafficLogDao().insertLog(
                TrafficLog(
                    timestamp = System.currentTimeMillis(),
                    packageName = pkgName,
                    uid = uid,
                    destinationIp = packet.destinationIp,
                    destinationPort = packet.destinationPort,
                    protocol = protocolStr + extraInfo,
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
            .setContentTitle("Firewall is active")
            .setContentText("Protecting your network traffic")
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
