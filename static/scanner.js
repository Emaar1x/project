// Network scanner functionality

let scanInterval = null;
let selectedNetwork = null;

async function loadAdapters() {
    try {
        const response = await fetch('/api/adapters');
        const data = await response.json();
        
        const monitorSelect = document.getElementById('monitor-adapter-select');
        const attackSelect = document.getElementById('attack-adapter-select');
        
        // Clear existing options
        monitorSelect.innerHTML = '<option value="">Select...</option>';
        attackSelect.innerHTML = '<option value="">Select...</option>';
        
        // Add interfaces
        data.interfaces.forEach(iface => {
            const monitorOption = document.createElement('option');
            monitorOption.value = iface;
            monitorOption.textContent = iface;
            if (data.monitor_adapter === iface) {
                monitorOption.selected = true;
            }
            monitorSelect.appendChild(monitorOption);
            
            const attackOption = document.createElement('option');
            attackOption.value = iface;
            attackOption.textContent = iface;
            if (data.attack_adapter === iface) {
                attackOption.selected = true;
            }
            attackSelect.appendChild(attackOption);
        });
    } catch (error) {
        console.error('Error loading adapters:', error);
    }
}

async function assignAdapters() {
    const monitorAdapter = document.getElementById('monitor-adapter-select').value;
    const attackAdapter = document.getElementById('attack-adapter-select').value;
    
    if (!monitorAdapter || !attackAdapter) {
        showMessage('assignment-status', 'Please select both adapters', 'error');
        return;
    }
    
    if (monitorAdapter === attackAdapter) {
        showMessage('assignment-status', 'Cannot use same adapter for both roles', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/adapters/assign', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                monitor_adapter: monitorAdapter,
                attack_adapter: attackAdapter
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showMessage('assignment-status', 'Adapters assigned successfully', 'success');
        } else {
            showMessage('assignment-status', data.message, 'error');
        }
    } catch (error) {
        showMessage('assignment-status', 'Error assigning adapters: ' + error.message, 'error');
    }
}

async function startScan() {
    // Get attack adapter from API
    try {
        const adapterResponse = await fetch('/api/adapters');
        const adapterData = await adapterResponse.json();
        const attackAdapter = adapterData.attack_adapter;
        
        if (!attackAdapter) {
            alert('Please assign an attack adapter first (from Dashboard)');
            return;
        }
        
        const response = await fetch('/api/scan/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({interface: attackAdapter})
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('start-scan-btn').disabled = true;
            document.getElementById('stop-scan-btn').disabled = false;
            document.getElementById('scan-status').textContent = 'Scanning...';
            document.getElementById('scan-status').className = 'status-badge scanning';
            
            // Start polling for results
            scanInterval = setInterval(updateScanResults, 2000);
        } else {
            alert('Error: ' + data.message);
        }
    } catch (error) {
        alert('Error starting scan: ' + error.message);
    }
}

async function stopScan() {
    try {
        const response = await fetch('/api/scan/stop', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('start-scan-btn').disabled = false;
            document.getElementById('stop-scan-btn').disabled = true;
            document.getElementById('scan-status').textContent = 'Stopped';
            document.getElementById('scan-status').className = 'status-badge';
            
            if (scanInterval) {
                clearInterval(scanInterval);
                scanInterval = null;
            }
        }
    } catch (error) {
        alert('Error stopping scan: ' + error.message);
    }
}

async function updateScanResults() {
    try {
        const response = await fetch('/api/scan/results');
        const data = await response.json();
        
        const tbody = document.getElementById('networks-tbody');
        
        if (!data.results || data.results.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="no-data">No networks found yet...</td></tr>';
            return;
        }
        
        tbody.innerHTML = data.results.map(network => {
            const isSelected = selectedNetwork && selectedNetwork.bssid === network.bssid;
            return `
                <tr class="${isSelected ? 'selected' : ''}" data-bssid="${network.bssid}" 
                    data-ssid="${network.ssid || ''}" data-channel="${network.channel || ''}">
                    <td><input type="radio" name="network" value="${network.bssid}" ${isSelected ? 'checked' : ''}></td>
                    <td>${network.ssid || '<hidden>'}</td>
                    <td>${network.bssid}</td>
                    <td>${network.channel || '-'}</td>
                    <td>${network.encryption || '-'}</td>
                    <td>${network.rssi ? network.rssi + ' dBm' : '-'}</td>
                </tr>
            `;
        }).join('');
        
        // Add click handlers
        tbody.querySelectorAll('tr').forEach(row => {
            row.addEventListener('click', function() {
                const radio = this.querySelector('input[type="radio"]');
                if (radio) {
                    radio.checked = true;
                    selectNetwork(this);
                }
            });
        });
        
        // Update scan status
        if (data.scanning) {
            document.getElementById('scan-status').textContent = `Scanning... (${data.count} networks)`;
        } else {
            document.getElementById('scan-status').textContent = `Complete (${data.count} networks)`;
            document.getElementById('scan-status').className = 'status-badge';
        }
        
    } catch (error) {
        console.error('Error updating scan results:', error);
    }
}

function selectNetwork(row) {
    selectedNetwork = {
        bssid: row.dataset.bssid,
        ssid: row.dataset.ssid,
        channel: row.dataset.channel
    };
    
    document.getElementById('target-bssid').textContent = selectedNetwork.bssid;
    document.getElementById('target-ssid').textContent = selectedNetwork.ssid || '<hidden>';
    document.getElementById('target-channel').textContent = selectedNetwork.channel || '-';
    
    // Enable attack button if attack type is selected
    const attackType = document.getElementById('attack-type-select').value;
    document.getElementById('start-attack-btn').disabled = !attackType;
    
    // Update row selection
    document.querySelectorAll('#networks-tbody tr').forEach(r => {
        r.classList.remove('selected');
    });
    row.classList.add('selected');
}

function showMessage(elementId, message, type) {
    const element = document.getElementById(elementId);
    element.textContent = message;
    element.className = `status-message ${type}`;
    setTimeout(() => {
        element.textContent = '';
        element.className = 'status-message';
    }, 3000);
}

// Initialize - adapter assignment is now handled in dashboard.html

