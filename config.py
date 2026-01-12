"""
Configuration file for WiFi IDPS
"""
import os

# Network interface configuration
INTERFACE = os.getenv('WIDPS_INTERFACE', 'wlan0mon')
MONITOR_MODE = True

# Detection thresholds
DEAUTH_THRESHOLD = 5   # Deauth frames per second (increased to reduce false positives)
EAPOL_THRESHOLD = 3    # EAPOL frames per minute (increased to reduce false positives)
ROGUE_AP_CHECK_INTERVAL = 30  # seconds

# Database configuration
DATABASE_PATH = 'logs/widps.db'

# Logging configuration
ALERT_LOG_PATH = 'logs/alerts.log'
PCAP_PATH = 'logs/captures.pcap'

# Prevention settings
PREVENTION_ENABLED = False  # Enable via UI button
AUTO_BLOCK = True  # When prevention is enabled, automatically block attackers
BLOCK_DURATION = 300  # seconds (5 minutes)

# Known SSIDs (whitelist)
KNOWN_SSIDS = []

# Known MAC addresses (whitelist)
KNOWN_MACS = []

# Flask configuration
FLASK_HOST = '0.0.0.0'
FLASK_PORT = 5000
FLASK_DEBUG = False

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

