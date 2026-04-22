package com.firewall.app.ui

import android.app.Application
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.firewall.app.db.AppDatabase
import com.firewall.app.db.AppRule
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val database = AppDatabase.getDatabase(application)
    private val ruleDao = database.appRuleDao()
    private val logDao = database.trafficLogDao()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    val appRules = ruleDao.getAllRules().combine(_searchQuery) { rules, query ->
        if (query.isEmpty()) {
            rules
        } else {
            rules.filter { it.appName.contains(query, ignoreCase = true) || it.packageName.contains(query, ignoreCase = true) }
        }
    }

    val trafficLogs = logDao.getRecentLogs()

    private val _isVpnActive = MutableStateFlow(false)
    val isVpnActive: StateFlow<Boolean> = _isVpnActive.asStateFlow()

    init {
        loadInstalledApps()
    }

    private fun loadInstalledApps() {
        viewModelScope.launch(Dispatchers.IO) {
            val pm = getApplication<Application>().packageManager
            val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)

            val rules = packages.filter {
                (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 || (it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            }.map { appInfo ->
                AppRule(
                    packageName = appInfo.packageName,
                    uid = appInfo.uid,
                    appName = pm.getApplicationLabel(appInfo).toString()
                )
            }

            rules.forEach { rule ->
                val existing = ruleDao.getRuleByUid(rule.uid)
                if (existing == null) {
                    ruleDao.insertRule(rule)
                }
            }
        }
    }

    fun toggleAppWifi(rule: AppRule) {
        viewModelScope.launch(Dispatchers.IO) {
            ruleDao.insertRule(rule.copy(blockWifi = !rule.blockWifi))
        }
    }

    fun toggleAppMobile(rule: AppRule) {
        viewModelScope.launch(Dispatchers.IO) {
            ruleDao.insertRule(rule.copy(blockMobile = !rule.blockMobile))
        }
    }

    fun updateSchedule(rule: AppRule, enabled: Boolean, start: String, end: String) {
        viewModelScope.launch(Dispatchers.IO) {
            ruleDao.insertRule(rule.copy(scheduleEnabled = enabled, startTime = start, endTime = end))
        }
    }

    fun setVpnActive(active: Boolean) {
        _isVpnActive.value = active
    }

    fun updateSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun clearLogs() {
        viewModelScope.launch(Dispatchers.IO) {
            logDao.clearLogs()
        }
    }
}
