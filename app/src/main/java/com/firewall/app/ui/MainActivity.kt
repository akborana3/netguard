package com.firewall.app.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.firewall.app.db.AppRule
import com.firewall.app.db.TrafficLog
import com.firewall.app.vpn.FirewallVpnService
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val vpnRequest = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            viewModel.setVpnActive(false)
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            MaterialTheme(colorScheme = if (androidx.compose.foundation.isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                var currentTab by remember { mutableStateOf(0) }

                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val rules by viewModel.appRules.collectAsState(initial = emptyList())
                    val logs by viewModel.trafficLogs.collectAsState(initial = emptyList())
                    val isActive by viewModel.isVpnActive.collectAsState()
                    val searchQuery by viewModel.searchQuery.collectAsState()

                    Scaffold(
                        topBar = {
                            TopAppBar(
                                title = { Text("Firewall") },
                                actions = {
                                    Text(if (isActive) "ON" else "OFF", modifier = Modifier.padding(end = 8.dp))
                                    Switch(
                                        checked = isActive,
                                        onCheckedChange = { toggleVpn(it) }
                                    )
                                }
                            )
                        },
                        bottomBar = {
                            NavigationBar {
                                NavigationBarItem(
                                    icon = { Icon(Icons.Default.List, contentDescription = "Apps") },
                                    label = { Text("Apps") },
                                    selected = currentTab == 0,
                                    onClick = { currentTab = 0 }
                                )
                                NavigationBarItem(
                                    icon = { Icon(Icons.Default.Settings, contentDescription = "Logs") },
                                    label = { Text("Logs") },
                                    selected = currentTab == 1,
                                    onClick = { currentTab = 1 }
                                )
                            }
                        }
                    ) { padding ->
                        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
                            if (currentTab == 0) {
                                OutlinedTextField(
                                    value = searchQuery,
                                    onValueChange = { viewModel.updateSearchQuery(it) },
                                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                                    placeholder = { Text("Search apps...") },
                                    leadingIcon = { Icon(Icons.Default.Search, null) }
                                )

                                AppList(
                                    rules = rules,
                                    onToggleWifi = { viewModel.toggleAppWifi(it) },
                                    onToggleMobile = { viewModel.toggleAppMobile(it) },
                                    onUpdateSchedule = { rule, enabled, start, end ->
                                        viewModel.updateSchedule(rule, enabled, start, end)
                                    }
                                )
                            } else {
                                Row(modifier = Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                    Text("Traffic Logs (${logs.size})", fontWeight = FontWeight.Bold)
                                    Button(onClick = { viewModel.clearLogs() }) {
                                        Text("Clear")
                                    }
                                }
                                LogList(logs = logs)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun toggleVpn(start: Boolean) {
        if (start) {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                vpnRequest.launch(intent)
            } else {
                startVpnService()
            }
        } else {
            stopVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, FirewallVpnService::class.java)
        startService(intent)
        viewModel.setVpnActive(true)
    }

    private fun stopVpnService() {
        val intent = Intent(this, FirewallVpnService::class.java).apply {
            action = FirewallVpnService.ACTION_STOP
        }
        startService(intent)
        viewModel.setVpnActive(false)
    }
}

@Composable
fun AppList(
    rules: List<AppRule>,
    onToggleWifi: (AppRule) -> Unit,
    onToggleMobile: (AppRule) -> Unit,
    onUpdateSchedule: (AppRule, Boolean, String, String) -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)
    ) {
        items(rules) { rule ->
            AppRuleItem(
                rule = rule,
                onToggleWifi = { onToggleWifi(rule) },
                onToggleMobile = { onToggleMobile(rule) },
                onUpdateSchedule = onUpdateSchedule
            )
            Divider()
        }
    }
}

@Composable
fun AppRuleItem(
    rule: AppRule,
    onToggleWifi: () -> Unit,
    onToggleMobile: () -> Unit,
    onUpdateSchedule: (AppRule, Boolean, String, String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded }
            .padding(vertical = 12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = rule.appName, fontWeight = FontWeight.Bold)
                Text(text = rule.packageName, style = MaterialTheme.typography.bodySmall)
            }

            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Wi-Fi", style = MaterialTheme.typography.labelSmall)
                Switch(
                    checked = !rule.blockWifi,
                    onCheckedChange = { onToggleWifi() }
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Data", style = MaterialTheme.typography.labelSmall)
                Switch(
                    checked = !rule.blockMobile,
                    onCheckedChange = { onToggleMobile() }
                )
            }
        }

        if (expanded) {
            Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Time-based Blocking", fontWeight = FontWeight.SemiBold)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Enable Schedule")
                        Spacer(Modifier.weight(1f))
                        Switch(
                            checked = rule.scheduleEnabled,
                            onCheckedChange = { onUpdateSchedule(rule, it, rule.startTime, rule.endTime) }
                        )
                    }
                    if (rule.scheduleEnabled) {
                        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                            Text("Start: ${rule.startTime}", color = MaterialTheme.colorScheme.primary)
                            Text("End: ${rule.endTime}", color = MaterialTheme.colorScheme.primary)
                        }
                        Text("Time picker implementation requires additional dialogs", style = MaterialTheme.typography.bodySmall, color = Color.Gray)
                    }
                }
            }
        }
    }
}

@Composable
fun LogList(logs: List<TrafficLog>) {
    val formatter = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp)
    ) {
        items(logs) { log ->
            val time = formatter.format(Date(log.timestamp))
            val color = if (log.isBlocked) Color.Red else Color.Green

            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("${log.packageName}", fontWeight = FontWeight.Bold)
                    Text("${log.destinationIp}:${log.destinationPort} [${log.protocol}]", style = MaterialTheme.typography.bodyMedium)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(time, style = MaterialTheme.typography.bodySmall)
                    Text(if (log.isBlocked) "BLOCKED" else "ALLOWED", color = color, fontWeight = FontWeight.Bold)
                }
            }
            Divider()
        }
    }
}
