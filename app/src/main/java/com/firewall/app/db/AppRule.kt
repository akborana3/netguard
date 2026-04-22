package com.firewall.app.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "app_rules")
data class AppRule(
    @PrimaryKey val packageName: String,
    val uid: Int,
    val appName: String,
    val blockWifi: Boolean = false,
    val blockMobile: Boolean = false,
    val scheduleEnabled: Boolean = false,
    val startTime: String = "00:00",
    val endTime: String = "23:59"
)
