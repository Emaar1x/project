// Additional chart utilities for WiFi IDPS
// This file can be extended with custom chart functions

function formatMAC(mac) {
    if (!mac) return 'N/A';
    return mac.toUpperCase().replace(/(.{2})/g, '$1:').slice(0, -1);
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function getSeverityColor(severity) {
    const colors = {
        'low': '#4caf50',
        'medium': '#ff9800',
        'high': '#f44336',
        'critical': '#d32f2f'
    };
    return colors[severity] || colors['medium'];
}

// Export functions for use in dashboard
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        formatMAC,
        formatTimestamp,
        getSeverityColor
    };
}

