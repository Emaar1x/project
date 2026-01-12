// Testing lab attack control

let attackStatusInterval = null;
let detectionCheckInterval = null;

document.addEventListener('DOMContentLoaded', () => {
    // Load adapter info
    loadAdapterInfo();
    setInterval(loadAdapterInfo, 5000);
    
    // Scan controls
    document.getElementById('start-scan-btn').addEventListener('click', startScan);
    document.getElementById('stop-scan-btn').addEventListener('click', stopScan);
    
    // Attack controls
    document.getElementById('attack-type-select').addEventListener('change', function() {
        const hasTarget = selectedNetwork !== null;
        document.getElementById('start-attack-btn').disabled = !hasTarget || !this.value;
    });
    
    document.getElementById('start-attack-btn').addEventListener('click', startAttack);
    document.getElementById('stop-attack-btn').addEventListener('click', stopAttack);
    document.getElementById('stop-all-attacks-btn').addEventListener('click', stopAllAttacks);
    
    // Load attack logs
    loadAttackLogs();
    setInterval(loadAttackLogs, 5000);
    
    // Check attack status
    attackStatusInterval = setInterval(checkAttackStatus, 2000);
    detectionCheckInterval = setInterval(checkDetection, 3000);
});

async function startAttack() {
    const attackType = document.getElementById('attack-type-select').value;
    
    if (!attackType) {
        alert('Please select an attack type');
        return;
    }
    
    if (!selectedNetwork) {
        alert('Please select a target network first');
        return;
    }
    
    if (!confirm(`Start ${attackType} attack on ${selectedNetwork.ssid || selectedNetwork.bssid}?`)) {
        return;
    }
    
    try {
        const response = await fetch('/api/attack/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                attack_type: attackType,
                target: {
                    bssid: selectedNetwork.bssid,
                    ssid: selectedNetwork.ssid,
                    channel: selectedNetwork.channel
                }
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('start-attack-btn').disabled = true;
            document.getElementById('stop-attack-btn').disabled = false;
            document.getElementById('attack-status-text').textContent = 'Active';
            document.getElementById('attack-status-text').className = 'status-active';
            // Reset detection check timing
            detectionCheckStartTime = null;
            detectionCheckAttempts = 0;
            document.getElementById('detection-status').textContent = 'Waiting to check...';
            document.getElementById('detection-status').className = 'status-checking';
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Error starting attack: ' + error.message);
    }
}

async function stopAttack() {
    try {
        const response = await fetch('/api/attack/stop', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('start-attack-btn').disabled = false;
            document.getElementById('stop-attack-btn').disabled = true;
            document.getElementById('attack-status-text').textContent = 'Stopped';
            document.getElementById('attack-status-text').className = '';
            document.getElementById('detection-status').textContent = '-';
            document.getElementById('detection-status').className = '';
        }
    } catch (error) {
        alert('Error stopping attack: ' + error.message);
    }
}

async function checkAttackStatus() {
    try {
        const response = await fetch('/api/attack/status');
        const data = await response.json();
        
        if (!data.active) {
            document.getElementById('start-attack-btn').disabled = false;
            document.getElementById('stop-attack-btn').disabled = true;
            document.getElementById('attack-status-text').textContent = 'Idle';
            document.getElementById('attack-status-text').className = '';
        }
    } catch (error) {
        console.error('Error checking attack status:', error);
    }
}

let detectionCheckStartTime = null;
let detectionCheckAttempts = 0;
const MAX_DETECTION_CHECK_TIME = 30000; // 30 seconds max wait
const DETECTION_CHECK_INTERVAL = 2000; // Check every 2 seconds
const MIN_WAIT_BEFORE_CHECK = 5000; // Wait at least 5 seconds before first check

async function checkDetection() {
    try {
        // Check attack logs for correlation
        const logsResponse = await fetch('/api/attack/logs?limit=1');
        const logs = await logsResponse.json();
        
        if (logs.length > 0 && logs[0].stop_time === null) {
            // Active attack
            const attackLog = logs[0];
            const attackType = attackLog.attack_type;
            const attackStartTime = new Date(attackLog.start_time).getTime();
            const now = Date.now();
            const timeSinceStart = now - attackStartTime;
            
            // Initialize detection check timing
            if (detectionCheckStartTime === null) {
                detectionCheckStartTime = now;
                detectionCheckAttempts = 0;
                document.getElementById('detection-status').textContent = 'Checking...';
                document.getElementById('detection-status').className = 'status-checking';
                return; // Wait before first check
            }
            
            // Wait at least MIN_WAIT_BEFORE_CHECK before checking
            if (timeSinceStart < MIN_WAIT_BEFORE_CHECK) {
                const remaining = Math.ceil((MIN_WAIT_BEFORE_CHECK - timeSinceStart) / 1000);
                document.getElementById('detection-status').textContent = `Checking... (wait ${remaining}s)`;
                document.getElementById('detection-status').className = 'status-checking';
                return;
            }
            
            detectionCheckAttempts++;
            
            // Check if attack log shows detected
            if (attackLog.detected) {
                document.getElementById('detection-status').textContent = '✅ Detected';
                document.getElementById('detection-status').className = 'status-detected';
                detectionCheckStartTime = null; // Reset for next attack
                return;
            }
            
            // Check recent alerts for detection
            const alertsResponse = await fetch('/api/alerts?limit=10');
            const alerts = await alertsResponse.json();
            
            // Check if any recent alerts match
            const detected = alerts.some(alert => {
                if (attackType === 'Deauthentication' && alert.alert_type === 'Deauthentication Attack') {
                    return alert.attacker_mac === attackLog.target_bssid || 
                           alert.details?.includes('[Detected during test]') ||
                           alert.details?.includes('Deauth flood');
                }
                if (attackType === 'Handshake Capture' && alert.alert_type === 'Handshake Capture') {
                    return alert.attacker_mac === attackLog.target_bssid || 
                           alert.details?.includes('[Detected during test]') ||
                           alert.details?.includes('Handshake capture');
                }
                if (attackType === 'Rogue Access Point' && alert.alert_type === 'Rogue Access Point') {
                    return alert.attacker_mac === attackLog.target_bssid || 
                           alert.details?.includes('[Detected during test]') ||
                           alert.details?.includes('Rogue AP');
                }
                return false;
            });
            
            if (detected) {
                document.getElementById('detection-status').textContent = '✅ Detected';
                document.getElementById('detection-status').className = 'status-detected';
                detectionCheckStartTime = null; // Reset for next attack
            } else {
                // Only show "Not detected" after waiting long enough
                const timeSinceCheckStart = now - detectionCheckStartTime;
                if (timeSinceCheckStart >= MAX_DETECTION_CHECK_TIME) {
                    document.getElementById('detection-status').textContent = '❌ Not detected';
                    document.getElementById('detection-status').className = 'status-not-detected';
                    detectionCheckStartTime = null; // Reset for next attack
                } else {
                    const remaining = Math.ceil((MAX_DETECTION_CHECK_TIME - timeSinceCheckStart) / 1000);
                    document.getElementById('detection-status').textContent = `Checking... (${remaining}s remaining)`;
                    document.getElementById('detection-status').className = 'status-checking';
                }
            }
        } else {
            // No active attack - reset detection check
            detectionCheckStartTime = null;
            detectionCheckAttempts = 0;
        }
    } catch (error) {
        console.error('Error checking detection:', error);
    }
}

async function loadAdapterInfo() {
    try {
        const response = await fetch('/api/adapters');
        const data = await response.json();
        
        document.getElementById('testing-monitor-adapter').textContent = 
            data.monitor_adapter || 'Not assigned';
        document.getElementById('testing-attack-adapter').textContent = 
            data.attack_adapter || 'Not assigned';
    } catch (error) {
        console.error('Error loading adapter info:', error);
    }
}

async function stopAllAttacks() {
    if (!confirm('Stop all active attacks?')) {
        return;
    }
    
    try {
        const response = await fetch('/api/attack/stop-all', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('All attacks stopped');
            document.getElementById('start-attack-btn').disabled = false;
            document.getElementById('stop-attack-btn').disabled = true;
            document.getElementById('attack-status-text').textContent = 'Idle';
            document.getElementById('attack-status-text').className = '';
            document.getElementById('detection-status').textContent = '-';
            document.getElementById('detection-status').className = '';
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Error stopping attacks: ' + error.message);
    }
}

async function loadAttackLogs() {
    try {
        const response = await fetch('/api/attack/logs?limit=20');
        const logs = await response.json();
        
        const tbody = document.getElementById('logs-tbody');
        
        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="no-data">No attack logs yet</td></tr>';
            return;
        }
        
        tbody.innerHTML = logs.map(log => {
            const startTime = new Date(log.start_time).toLocaleString();
            const target = log.target_ssid || log.target_bssid || 'Unknown';
            const detected = log.detected ? '✅ Yes' : '❌ No';
            const detectedClass = log.detected ? 'detected' : 'not-detected';
            
            return `
                <tr>
                    <td>${startTime}</td>
                    <td>${log.attack_type}</td>
                    <td>${target}</td>
                    <td>${log.adapter || '-'}</td>
                    <td class="${detectedClass}">${detected}</td>
                </tr>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Error loading attack logs:', error);
    }
}

