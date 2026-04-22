package com.firewall.app.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "traffic_logs")
data class TrafficLog(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val timestamp: Long,
    val packageName: String,
    val uid: Int,
    val destinationIp: String,
    val destinationPort: Int,
    val protocol: String, // TCP/UDP
    val isBlocked: Boolean
)
