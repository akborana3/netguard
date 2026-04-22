package com.firewall.app.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface TrafficLogDao {
    @Query("SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT 100")
    fun getRecentLogs(): Flow<List<TrafficLog>>

    @Insert
    suspend fun insertLog(log: TrafficLog)

    @Query("DELETE FROM traffic_logs")
    suspend fun clearLogs()
}
