/**
 * Master Controller for CyberGuard SIEM Lite Console
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialise Navbar User Profile display
    const user = Auth.getUser();
    if (user) {
        const userDisplay = document.getElementById('user-profile-display');
        if (userDisplay) {
            userDisplay.innerHTML = `
                <i class="bi bi-person-fill text-info me-1"></i>
                Analyst: <strong class="text-light">${user.username}</strong>
                <span class="badge bg-secondary ms-2 text-capitalize" style="font-size: 0.65rem;">
                    ${user.role}
                </span>
            `;
        }
        
        // Hide Admin-only features if user is just an Analyst
        if (user.role !== 'Admin') {
            const adminElements = document.querySelectorAll('.admin-only');
            adminElements.forEach(el => el.style.display = 'none');
        }
    }

    // 2. Setup WebSocket Connection (Flask-SocketIO)
    let socket = null;
    try {
        socket = io();
        
        socket.on('connect', () => {
            console.log('[+] WebSocket Connected to SIEM back-channel.');
            const dbBadge = document.getElementById('db-status-badge');
            if (dbBadge) {
                dbBadge.classList.remove('bg-secondary');
                dbBadge.classList.add('severity-low');
                dbBadge.innerHTML = '<i class="bi bi-broadcast"></i> WEB SEC: STREAMING';
            }
        });

        socket.on('disconnect', () => {
            console.warn('[-] WebSocket Disconnected from SIEM backend.');
        });
        
    } catch (e) {
        console.warn("Socket.io client load bypassed or offline fallback initialized:", e);
    }

    // 3. Page Router dispatch
    const path = window.location.pathname;
    if (path === '/' || path === '/index.html') {
        initDashboard(socket);
    } else if (path === '/logs') {
        initLogsPage(socket);
    } else if (path === '/alerts') {
        initAlertsPage(socket);
    } else if (path === '/incidents') {
        initIncidentsPage(socket);
    } else if (path === '/audit') {
        initAuditPage();
    }
});

// Helper: Custom Severity Badges
function getSeverityBadgeHTML(severity) {
    const sev = severity ? severity.toLowerCase() : 'low';
    let icon = 'bi-info-circle-fill';
    if (sev === 'critical') icon = 'bi-radioactive';
    else if (sev === 'high') icon = 'bi-shield-fill-x';
    else if (sev === 'medium') icon = 'bi-shield-fill-exclamation';
    
    return `<span class="severity-badge severity-${sev}"><i class="bi ${icon}"></i>${sev}</span>`;
}

// =================================================================
// 📊 DASHBOARD ENGINE
// =================================================================
let dailyEventsChart = null;
let logsSeverityChart = null;
let alertsTypeChart = null;
let incidentsStatusChart = null;

async function initDashboard(socket) {
    const consoleLogs = [
        'CyberGuard SIEM Correlation Simulator v1.0.0 initialized.',
        'Select a threat vector below to execute attack logs...'
    ];
    updateTerminalUI(consoleLogs);

    // Initial load
    await loadDashboardStats();

    // Setup Socket IO listener to refresh counters on new events dynamically
    if (socket) {
        socket.on('new_log', (log) => {
            // Quick increment total logs count on screen
            const logEl = document.getElementById('stat-total-logs');
            if (logEl) {
                logEl.innerText = parseInt(logEl.innerText) + 1;
            }
        });
        
        socket.on('new_alert', (alert) => {
            // Toast alert popup notification on dashboard screen
            showToastAlert(alert);
            // Refresh dashboard
            loadDashboardStats();
        });
    }

    // Bind attack simulation triggers (Simulator Panel)
    const bruteBtn = document.getElementById('btn-sim-brute');
    const scanBtn = document.getElementById('btn-sim-scan');
    const loginBtn = document.getElementById('btn-sim-login');

    if (bruteBtn) bruteBtn.addEventListener('click', () => triggerAttackSimulation('brute-force'));
    if (scanBtn) scanBtn.addEventListener('click', () => triggerAttackSimulation('port-scan'));
    if (loginBtn) loginBtn.addEventListener('click', () => triggerAttackSimulation('suspicious-login'));
}

async function loadDashboardStats() {
    try {
        const res = await fetch('/api/reports/stats', {
            method: 'GET',
            headers: Auth.getHeaders()
        });
        if (!res.ok) return;
        const data = await res.json();
        
        // Update Stats values
        document.getElementById('stat-total-logs').innerText = data.summary.totalLogs;
        document.getElementById('stat-total-alerts').innerText = data.summary.totalAlerts;
        document.getElementById('stat-active-incidents').innerText = data.summary.activeIncidents;
        document.getElementById('stat-critical-alerts').innerText = data.summary.criticalAlerts;

        // Render IP hit list (Requirement 1: Top Attacking IP Addresses)
        const ipList = document.getElementById('top-attacking-ips-list');
        if (ipList) {
            ipList.innerHTML = '';
            if (data.topAttackingIps && data.topAttackingIps.length > 0) {
                data.topAttackingIps.forEach(item => {
                    ipList.innerHTML += `
                        <div class="d-flex justify-content-between align-items-center mb-2 p-2 border-bottom border-secondary small">
                            <span class="font-monospace text-info"><i class="bi bi-radar"></i> ${item.ip}</span>
                            <span class="badge bg-danger rounded-pill">${item.count} events</span>
                        </div>
                    `;
                });
            } else {
                ipList.innerHTML = '<div class="text-muted text-center py-3 small">No hostile IPs logged</div>';
            }
        }

        // Render GeoIP Login locations (Requirement 2)
        const geoList = document.getElementById('geo-login-locations-list');
        if (geoList) {
            geoList.innerHTML = '';
            if (data.geoDistributions && data.geoDistributions.length > 0) {
                data.geoDistributions.forEach(item => {
                    geoList.innerHTML += `
                        <div class="d-flex justify-content-between align-items-center mb-2 p-2 border-bottom border-secondary small">
                            <span class="text-light"><i class="bi bi-geo-alt-fill text-warning me-1"></i> ${item.location}</span>
                            <span class="badge bg-secondary">${item.count} logins</span>
                        </div>
                    `;
                });
            } else {
                geoList.innerHTML = '<div class="text-muted text-center py-3 small">No external login events mapped</div>';
            }
        }

        // Load recent alerts feed table
        loadRecentAlertsDashboard();

        // Render Charts using Chart.js
        renderDashboardCharts(data);

    } catch (e) {
        console.error("Dashboard statistics loading failed:", e);
    }
}

async function loadRecentAlertsDashboard() {
    const listTable = document.getElementById('recent-alerts-table-body');
    if (!listTable) return;
    try {
        const res = await fetch('/api/alerts', {
            method: 'GET',
            headers: Auth.getHeaders()
        });
        if (!res.ok) return;
        const alerts = await res.json();
        listTable.innerHTML = '';
        
        const recent = alerts.slice(0, 5);
        if (recent.length > 0) {
            recent.forEach(alert => {
                const date = new Date(alert.created_at).toLocaleString();
                listTable.innerHTML += `
                    <tr>
                        <td class="text-muted font-monospace">${date}</td>
                        <td class="fw-semibold text-light">${alert.alert_type}</td>
                        <td>${getSeverityBadgeHTML(alert.severity)}</td>
                        <td class="font-monospace text-info">${alert.source_ip}</td>
                        <td>
                            <span class="badge status-badge status-${alert.status.toLowerCase().replace(' ', '')}">
                                ${alert.status}
                            </span>
                        </td>
                    </tr>
                `;
            });
        } else {
            listTable.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-3">No alert records logged</td></tr>`;
        }
    } catch(e) {
        console.error("Failed loading recent alerts list:", e);
    }
}

function renderDashboardCharts(data) {
    // 1. Line Chart: Daily Events
    const dailyCtx = document.getElementById('chart-daily-events');
    if (dailyCtx) {
        if (dailyEventsChart) dailyEventsChart.destroy();
        dailyEventsChart = new Chart(dailyCtx, {
            type: 'line',
            data: {
                labels: data.dailyEvents.map(x => x.date),
                datasets: [{
                    label: 'Security Logs Ingestion Volume',
                    data: data.dailyEvents.map(x => x.count),
                    borderColor: '#38bdf8',
                    backgroundColor: 'rgba(56, 189, 248, 0.1)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
                    y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }
                }
            }
        });
    }

    // 2. Donut Chart: Logs by Severity
    const severityCtx = document.getElementById('chart-logs-severity');
    if (severityCtx) {
        if (logsSeverityChart) logsSeverityChart.destroy();
        
        const labels = Object.keys(data.logsBySeverity);
        const counts = Object.values(data.logsBySeverity);
        
        logsSeverityChart = new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: ['#38bdf8', '#00ff66', '#f59e0b', '#ef4444', '#a855f7'],
                    borderColor: '#0b0e14',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#94a3b8', font: { size: 10 } }
                    }
                }
            }
        });
    }

    // 3. Bar Chart: Alerts by Type
    const alertsCtx = document.getElementById('chart-alerts-type');
    if (alertsCtx) {
        if (alertsTypeChart) alertsTypeChart.destroy();
        
        const labels = Object.keys(data.alertsByType);
        const counts = Object.values(data.alertsByType);
        
        alertsTypeChart = new Chart(alertsCtx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: '#ef4444',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 9 } } },
                    y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }
                }
            }
        });
    }

    // 4. Pie Chart: Incidents by Status
    const incidentsCtx = document.getElementById('chart-incidents-status');
    if (incidentsCtx) {
        if (incidentsStatusChart) incidentsStatusChart.destroy();
        
        const labels = Object.keys(data.incidentsByStatus);
        const counts = Object.values(data.incidentsByStatus);
        
        incidentsStatusChart = new Chart(incidentsCtx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: ['#ef4444', '#2563eb', '#16a34a', '#475569'],
                    borderColor: '#0b0e14',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#94a3b8', font: { size: 10 } }
                    }
                }
            }
        });
    }
}

function updateTerminalUI(logsList) {
    const termBody = document.getElementById('sim-terminal-body');
    if (!termBody) return;
    termBody.innerHTML = '';
    logsList.forEach(line => {
        let css = 'terminal-response';
        if (line.startsWith('[$]')) {
            termBody.innerHTML += `<div class="terminal-line terminal-prompt"><span class="terminal-response">${line.substring(3)}</span></div>`;
            return;
        }
        if (line.includes('FAILED') || line.includes('Alert')) css = 'terminal-error';
        if (line.includes('SUCCESS') || line.includes('GENERATED') || line.includes('completed')) css = 'terminal-success';
        
        termBody.innerHTML += `<div class="terminal-line ${css}">${line}</div>`;
    });
    termBody.scrollTop = termBody.scrollHeight;
}

async function triggerAttackSimulation(type) {
    const consoleLines = [];
    const addLine = (text) => {
        consoleLines.push(text);
        updateTerminalUI(consoleLines);
    };

    try {
        if (type === 'brute-force') {
            addLine('[$] hydra -l admin -P top_passwords.txt ssh://192.168.1.100');
            addLine('[~] Resolving host... 192.168.1.100. Initiating SSH attack...');
            
            const res = await fetch('/api/simulator/brute-force', {
                method: 'POST',
                headers: Auth.getHeaders()
            });
            const data = await res.json();
            
            data.logs.forEach((l, idx) => {
                addLine(`[-] [SSH] Attempt ${idx + 1}/5 | user: ${l.username} | FAILED (Access denied)`);
            });
            addLine('[!] Correlation Engine Event: LOGIN_FAILED thresholds reached.');
            addLine('[✓] SIEM ALERT GENERATED: [Brute Force Attack] - Severity: HIGH');
            addLine('[+] Simulation finished successfully.');
            
        } else if (type === 'port-scan') {
            addLine('[$] nmap -sS -p 1-1024 203.0.113.50');
            addLine('[~] Scanning TCP stealth ports connection sweeps...');
            
            const res = await fetch('/api/simulator/port-scan', {
                method: 'POST',
                headers: Auth.getHeaders()
            });
            const data = await res.json();
            
            data.logs.slice(0, 5).forEach(l => {
                addLine(`[*] Probe matched on ${l.message.split(' ').slice(4).join(' ')}`);
            });
            addLine('[*] ... (truncated 5 additional scanning records)');
            addLine('[!] Correlation Engine Event: Fast port probes from single IP address.');
            addLine('[✓] SIEM ALERT GENERATED: [Port Scan] - Severity: HIGH');
            addLine('[+] Simulation finished.');
            
        } else if (type === 'suspicious-login') {
            addLine('[$] ssh root@192.0.2.75');
            addLine('[~] Establishing VPN tunnel from Moscow Proxy endpoint...');
            
            const res = await fetch('/api/simulator/suspicious-login', {
                method: 'POST',
                headers: Auth.getHeaders()
            });
            const data = await res.json();
            const log = data.logs[0];
            
            addLine(`[+] Authentication SUCCESS for username '${log.username}'`);
            addLine('[!] Correlation Engine Event: Successful root login between 2 AM and 5 AM.');
            addLine('[✓] SIEM CRITICAL ALERT GENERATED: [Suspicious Login]');
            addLine('[+] Simulation finished.');
        }
        
        // Refresh Dashboard stats
        loadDashboardStats();
    } catch(e) {
        addLine('[-] Error: Connection reset by server.');
    }
}

function showToastAlert(alertDoc) {
    // Append alert notification banner at top of dashboard
    const container = document.getElementById('toast-alerts-container');
    if (!container) return;
    
    const div = document.createElement('div');
    div.className = `alert alert-danger border-danger bg-dark shadow-lg d-flex justify-content-between align-items-center mb-2 animate-pulse`;
    div.innerHTML = `
        <div>
            <i class="bi bi-radioactive text-danger fs-5 me-2"></i>
            <strong class="text-light">CRITICAL THREAT TRIGGERED:</strong> 
            <span class="text-white">${alertDoc.alert_type} from ${alertDoc.source_ip}</span>
        </div>
        <button type="button" class="btn-close btn-close-white btn-sm ms-3" onclick="this.parentElement.remove()"></button>
    `;
    container.appendChild(div);
    // Auto remove after 10s
    setTimeout(() => div.remove(), 10000);
}

// =================================================================
// 🔍 LOGS MONITOR PAGE (Requirement 3: Filters)
// =================================================================
let logsPage = 1;

async function initLogsPage(socket) {
    // Load logs
    await loadLogsTable();

    // Bind CSV Export button
    const csvBtn = document.getElementById('btn-export-logs-csv');
    if (csvBtn) {
        csvBtn.addEventListener('click', () => {
            window.location.href = '/api/reports/export/csv/logs?token=' + Auth.getToken();
        });
    }

    // Live Telemetry stream Toggle
    let streamActive = true;
    const streamBtn = document.getElementById('btn-logs-stream-toggle');
    if (streamBtn) {
        streamBtn.addEventListener('click', () => {
            streamActive = !streamActive;
            if (streamActive) {
                streamBtn.className = 'btn btn-sm btn-success font-cyber';
                streamBtn.innerHTML = '<i class="bi bi-play-fill animate-pulse"></i> LIVE STREAM';
            } else {
                streamBtn.className = 'btn btn-sm btn-outline-secondary font-cyber';
                streamBtn.innerHTML = '<i class="bi bi-pause-fill"></i> PAUSED';
            }
        });
    }

    // Dynamic Filter actions
    const inputs = ['filter-search', 'filter-severity', 'filter-event-type', 'filter-source-ip', 'filter-username', 'filter-start-date', 'filter-end-date'];
    inputs.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('change', () => { logsPage = 1; loadLogsTable(); });
            if (id === 'filter-search') {
                el.addEventListener('input', () => { logsPage = 1; loadLogsTable(); });
            }
        }
    });

    const resetBtn = document.getElementById('btn-reset-filters');
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            inputs.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = '';
            });
            logsPage = 1;
            loadLogsTable();
        });
    }

    // Socket Ingest pushes
    if (socket) {
        socket.on('new_log', (log) => {
            if (!streamActive || logsPage !== 1) return;
            // Append log row at top of table
            const tbody = document.getElementById('logs-table-body');
            if (tbody) {
                const tr = document.createElement('tr');
                tr.className = 'log-row-new';
                const date = new Date(log.timestamp).toLocaleString();
                tr.innerHTML = `
                    <td class="text-muted font-monospace small">${date}</td>
                    <td class="font-monospace text-info">${log.ip_address}</td>
                    <td class="text-light small">${log.source}</td>
                    <td><span class="badge bg-dark border border-secondary">${log.event_type}</span></td>
                    <td>${getSeverityBadgeHTML(log.severity)}</td>
                    <td class="text-truncate" style="max-width: 250px;">${log.message}</td>
                    <td><span class="badge bg-success bg-opacity-10 text-success border border-success">${log.status}</span></td>
                `;
                tbody.insertBefore(tr, tbody.firstChild);
                // trim to max page size
                if (tbody.children.length > 15) {
                    tbody.removeChild(tbody.lastChild);
                }
            }
        });
    }
}

async function loadLogsTable() {
    const searchVal = document.getElementById('filter-search')?.value;
    const severity = document.getElementById('filter-severity')?.value;
    const etype = document.getElementById('filter-event-type')?.value;
    const sourceIp = document.getElementById('filter-source-ip')?.value;
    const username = document.getElementById('filter-username')?.value;
    const startDate = document.getElementById('filter-start-date')?.value;
    const endDate = document.getElementById('filter-end-date')?.value;

    const tbody = document.getElementById('logs-table-body');
    if (!tbody) return;

    try {
        const queryParams = new URLSearchParams({
            page: logsPage,
            limit: 15,
            search: searchVal || '',
            severity: severity || '',
            event_type: etype || '',
            ip_address: sourceIp || '',
            username: username || '',
            startDate: startDate || '',
            endDate: endDate || ''
        });

        const res = await fetch(`/api/logs?${queryParams.toString()}`, {
            method: 'GET',
            headers: Auth.getHeaders()
        });
        if (!res.ok) return;
        const data = await res.json();
        
        tbody.innerHTML = '';
        if (data.logs && data.logs.length > 0) {
            data.logs.forEach(log => {
                const date = new Date(log.timestamp).toLocaleString();
                const statusClass = log.status === 'success' ? 'bg-success bg-opacity-10 text-success border border-success' : 'bg-danger bg-opacity-10 text-danger border border-danger';
                tbody.innerHTML += `
                    <tr>
                        <td class="text-muted font-monospace small">${date}</td>
                        <td class="font-monospace text-info">${log.ip_address}</td>
                        <td class="text-light small">${log.source}</td>
                        <td><span class="badge bg-dark border border-secondary">${log.event_type}</span></td>
                        <td>${getSeverityBadgeHTML(log.severity)}</td>
                        <td class="text-truncate" style="max-width: 250px;" title="${log.message}">${log.message}</td>
                        <td><span class="badge ${statusClass}">${log.status}</span></td>
                    </tr>
                `;
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">No records matched</td></tr>';
        }

        // Render Pagination buttons
        renderPaginationControls(data);
    } catch(e) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger py-4">Failed to load log telemetry</td></tr>';
    }
}

function renderPaginationControls(data) {
    const container = document.getElementById('logs-pagination-container');
    if (!container) return;
    container.innerHTML = '';
    
    if (data.pages <= 1) return;

    container.innerHTML += `
        <button ${logsPage === 1 ? 'disabled' : ''} class="btn btn-sm btn-outline-info font-cyber me-2" onclick="changeLogsPage(${logsPage - 1})">
            <i class="bi bi-chevron-left"></i> Previous
        </button>
        <span class="small text-muted font-monospace align-self-center">Page ${data.page} of ${data.pages}</span>
        <button ${logsPage === data.pages ? 'disabled' : ''} class="btn btn-sm btn-outline-info font-cyber ms-2" onclick="changeLogsPage(${logsPage + 1})">
            Next <i class="bi bi-chevron-right"></i>
        </button>
    `;
}

window.changeLogsPage = (p) => {
    logsPage = p;
    loadLogsTable();
};


// =================================================================
// 🚨 ALERTS MANAGEMENT PAGE
// =================================================================
async function initAlertsPage(socket) {
    await loadAlertsTable();

    // Bind CSV Export button
    const csvBtn = document.getElementById('btn-export-alerts-csv');
    if (csvBtn) {
        csvBtn.addEventListener('click', () => {
            window.location.href = '/api/reports/export/csv/alerts?token=' + Auth.getToken();
        });
    }

    if (socket) {
        socket.on('new_alert', () => loadAlertsTable());
    }
}

async function loadAlertsTable() {
    const tbody = document.getElementById('alerts-table-body');
    if (!tbody) return;

    try {
        const res = await fetch('/api/alerts', {
            method: 'GET',
            headers: Auth.getHeaders()
        });
        if (!res.ok) return;
        const alerts = await res.json();
        
        tbody.innerHTML = '';
        if (alerts.length > 0) {
            alerts.forEach(a => {
                const date = new Date(a.created_at).toLocaleString();
                const owner = a.assigned_to ? `<span class="text-info font-monospace">${a.assigned_to}</span>` : '<span class="text-muted">Unassigned</span>';
                
                tbody.innerHTML += `
                    <tr>
                        <td class="text-muted font-monospace small">${date}</td>
                        <td class="fw-semibold text-light">${a.alert_type}</td>
                        <td>${getSeverityBadgeHTML(a.severity)}</td>
                        <td class="font-monospace text-info">${a.source_ip}</td>
                        <td>${owner}</td>
                        <td>
                            <span class="badge status-badge status-${a.status.toLowerCase().replace(' ', '')}">
                                ${a.status}
                            </span>
                        </td>
                        <td>
                            <button class="btn btn-sm btn-cyber-primary py-0.5" onclick="openAlertModal('${a._id}')">Triage</button>
                        </td>
                    </tr>
                `;
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">No active threat alarms raised</td></tr>';
        }
    } catch(e) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger py-4">Failed to load alarms</td></tr>';
    }
}

let activeTriageAlertId = null;
window.openAlertModal = async (id) => {
    activeTriageAlertId = id;
    try {
        const res = await fetch('/api/alerts', {
            method: 'GET',
            headers: Auth.getHeaders()
        });
        const alerts = await res.json();
        const alert = alerts.find(a => a._id === id);
        
        if (!alert) return;
        
        document.getElementById('modal-alert-title').innerText = alert.alert_type;
        document.getElementById('modal-alert-desc').innerText = alert.description;
        document.getElementById('modal-alert-ip').innerText = alert.source_ip;
        document.getElementById('modal-alert-severity').innerHTML = getSeverityBadgeHTML(alert.severity);
        document.getElementById('modal-alert-status').value = alert.status;
        document.getElementById('modal-alert-assignee').value = alert.assigned_to || '';
        
        // Open Bootstrap Modal
        const alertModal = new bootstrap.Modal(document.getElementById('alertTriageModal'));
        alertModal.show();
    } catch(e) {
        alert("Failed to load alert properties.");
    }
};

// Bind Save triage changes button
const saveTriageBtn = document.getElementById('btn-save-triage');
if (saveTriageBtn) {
    saveTriageBtn.addEventListener('click', async () => {
        if (!activeTriageAlertId) return;
        const status = document.getElementById('modal-alert-status').value;
        const assignee = document.getElementById('modal-alert-assignee').value;
        
        try {
            const res = await fetch(`/api/alerts/${activeTriageAlertId}`, {
                method: 'PUT',
                headers: Auth.getHeaders(),
                body: JSON.stringify({
                    status: status,
                    assigned_to: assignee || null
                })
            });
            if (res.ok) {
                // Close modal
                bootstrap.Modal.getInstance(document.getElementById('alertTriageModal')).hide();
                loadAlertsTable();
            }
        } catch(e) {
            alert("Error updating alert properties");
        }
    });
}

// Bind Escalate to Incident button
const escalateBtn = document.getElementById('btn-escalate-incident');
if (escalateBtn) {
    escalateBtn.addEventListener('click', async () => {
        if (!activeTriageAlertId) return;
        
        const title = document.getElementById('modal-alert-title').innerText;
        const desc = document.getElementById('modal-alert-desc').innerText;
        const severity = document.getElementById('modal-alert-severity').innerText.replace(/\s/g, ''); // Extract text
        const assignee = document.getElementById('modal-alert-assignee').value;
        
        try {
            // 1. Create incident
            const incRes = await fetch('/api/incidents', {
                method: 'POST',
                headers: Auth.getHeaders(),
                body: JSON.stringify({
                    title: `Incident: Escalation of ${title}`,
                    description: desc,
                    severity: severity || 'Medium',
                    assigned_to: assignee || null
                })
            });
            
            if (incRes.ok) {
                // 2. Resolve alert
                await fetch(`/api/alerts/${activeTriageAlertId}`, {
                    method: 'PUT',
                    headers: Auth.getHeaders(),
                    body: JSON.stringify({ status: 'Resolved' })
                });
                
                bootstrap.Modal.getInstance(document.getElementById('alertTriageModal')).hide();
                loadAlertsTable();
                alert("Alert successfully escalated to full incident workflow!");
            }
        } catch(e) {
            alert("Incident escalation failed");
        }
    });
}


// =================================================================
// 🛡️ INCIDENTS BOARD PAGE
// =================================================================
async function initIncidentsPage() {
    await loadIncidentsTable();

    // Bind CSV Export button
    const csvBtn = document.getElementById('btn-export-incidents-csv');
    if (csvBtn) {
        csvBtn.addEventListener('click', () => {
            window.location.href = '/api/reports/export/csv/incidents?token=' + Auth.getToken();
        });
    }

    // Bind Manual Incident Creation Form
    const createForm = document.getElementById('form-create-incident');
    if (createForm) {
        createForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const title = document.getElementById('inc-title').value;
            const desc = document.getElementById('inc-desc').value;
            const severity = document.getElementById('inc-severity').value;
            const assignee = document.getElementById('inc-assignee').value;
            
            try {
                const res = await fetch('/api/incidents', {
                    method: 'POST',
                    headers: Auth.getHeaders(),
                    body: JSON.stringify({
                        title: title,
                        description: desc,
                        severity: severity,
                        assigned_to: assignee || null
                    })
                });
                if (res.ok) {
                    createForm.reset();
                    loadIncidentsTable();
                    alert("Incident logged successfully.");
                }
            } catch(e) {
                alert("Failed creating incident");
            }
        });
    }
}

async function loadIncidentsTable() {
    const tbody = document.getElementById('incidents-table-body');
    if (!tbody) return;

    try {
        const res = await fetch('/api/incidents', {
            method: 'GET',
            headers: Auth.getHeaders()
        });
        if (!res.ok) return;
        const incidents = await res.json();
        
        tbody.innerHTML = '';
        if (incidents.length > 0) {
            incidents.forEach(i => {
                const date = new Date(i.created_at).toLocaleString();
                const owner = i.assigned_to ? `<span class="text-info font-monospace">${i.assigned_to}</span>` : '<span class="text-muted">Unassigned</span>';
                
                tbody.innerHTML += `
                    <tr>
                        <td class="text-muted font-monospace small">${date}</td>
                        <td class="fw-semibold text-light">${i.title}</td>
                        <td>${getSeverityBadgeHTML(i.severity)}</td>
                        <td>${owner}</td>
                        <td>
                            <span class="badge status-badge status-${i.status.toLowerCase().replace('-', '')}">
                                ${i.status}
                            </span>
                        </td>
                        <td>
                            <button class="btn btn-sm btn-cyber-primary py-0.5" onclick="openIncidentModal('${i._id}')">Manage</button>
                        </td>
                    </tr>
                `;
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No incidents files logged</td></tr>';
        }
    } catch(e) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-danger py-4">Failed to load incidents</td></tr>';
    }
}

let activeIncidentManageId = null;
window.openIncidentModal = async (id) => {
    activeIncidentManageId = id;
    try {
        const res = await fetch('/api/incidents', {
            method: 'GET',
            headers: Auth.getHeaders()
        });
        const incidents = await res.json();
        const inc = incidents.find(i => i._id === id);
        if (!inc) return;
        
        document.getElementById('modal-inc-title').innerText = inc.title;
        document.getElementById('modal-inc-desc').innerText = inc.description;
        document.getElementById('modal-inc-status').value = inc.status;
        document.getElementById('modal-inc-assignee').value = inc.assigned_to || '';
        
        // Open modal
        const incModal = new bootstrap.Modal(document.getElementById('incidentManageModal'));
        incModal.show();
    } catch(e) {
        alert("Failed to load incident detail properties.");
    }
};

const saveIncBtn = document.getElementById('btn-save-incident-changes');
if (saveIncBtn) {
    saveIncBtn.addEventListener('click', async () => {
        if (!activeIncidentManageId) return;
        const status = document.getElementById('modal-inc-status').value;
        const assignee = document.getElementById('modal-inc-assignee').value;
        
        try {
            const res = await fetch(`/api/incidents/${activeIncidentManageId}`, {
                method: 'PUT',
                headers: Auth.getHeaders(),
                body: JSON.stringify({
                    status: status,
                    assigned_to: assignee || null
                })
            });
            if (res.ok) {
                bootstrap.Modal.getInstance(document.getElementById('incidentManageModal')).hide();
                loadIncidentsTable();
            }
        } catch(e) {
            alert("Failed saving incident properties.");
        }
    });
}


// =================================================================
// 📜 AUDIT TRAIL PAGE
// =================================================================
async function initAuditPage() {
    const tbody = document.getElementById('audit-table-body');
    if (!tbody) return;

    try {
        const res = await fetch('/api/audit', {
            method: 'GET',
            headers: Auth.getHeaders()
        });
        if (!res.ok) return;
        const audits = await res.json();
        
        tbody.innerHTML = '';
        if (audits.length > 0) {
            audits.forEach(a => {
                const date = new Date(a.timestamp).toLocaleString();
                tbody.innerHTML += `
                    <tr>
                        <td class="text-muted font-monospace small">${date}</td>
                        <td><span class="badge bg-dark border border-info text-info font-monospace">${a.action}</span></td>
                        <td class="fw-semibold text-light">${a.user}</td>
                        <td class="font-monospace text-info">${a.ip_address}</td>
                        <td class="text-light font-monospace text-wrap" style="font-size: 0.8rem;">${a.details}</td>
                    </tr>
                `;
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">No audit transactions found</td></tr>';
        }
    } catch(e) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-danger py-4">Failed to load audit logs</td></tr>';
    }
}
