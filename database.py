"""
Database operations for WiFi IDPS
"""
import sqlite3
import threading
from datetime import datetime
from config import DATABASE_PATH
import os
import logging

logger = logging.getLogger(__name__)

class Database:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(Database, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.conn = None
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                attacker_mac TEXT,
                victim_mac TEXT,
                ssid TEXT,
                signal_strength INTEGER,
                packet_count INTEGER,
                details TEXT,
                severity TEXT DEFAULT 'medium'
            )
        ''')
        
        # Devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT UNIQUE NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                packet_count INTEGER DEFAULT 0,
                signal_strength INTEGER,
                is_known INTEGER DEFAULT 0,
                device_type TEXT
            )
        ''')
        
        # Access points table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL,
                ssid TEXT,
                channel INTEGER,
                encryption TEXT,
                signal_strength INTEGER,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_rogue INTEGER DEFAULT 0,
                UNIQUE(bssid, ssid)
            )
        ''')
        
        # Statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                deauth_count INTEGER DEFAULT 0,
                eapol_count INTEGER DEFAULT 0,
                rogue_ap_count INTEGER DEFAULT 0,
                suspicious_mac_count INTEGER DEFAULT 0,
                total_packets INTEGER DEFAULT 0
            )
        ''')
        
        # Prevention logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS prevention_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action_type TEXT NOT NULL,
                attacker_mac TEXT,
                attack_type TEXT,
                details TEXT,
                block_until TEXT,
                interface TEXT
            )
        ''')
        
        # Attack logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT NOT NULL,
                adapter TEXT,
                target_bssid TEXT,
                target_ssid TEXT,
                target_channel INTEGER,
                start_time TEXT NOT NULL,
                stop_time TEXT,
                detected INTEGER DEFAULT 0,
                detection_time TEXT
            )
        ''')
        
        # Prevention logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS prevention_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action_type TEXT NOT NULL,
                attacker_mac TEXT,
                attack_type TEXT,
                details TEXT,
                block_until TEXT,
                interface TEXT
            )
        ''')
        
        self.conn.commit()
    
    def add_alert(self, alert_type, attacker_mac=None, victim_mac=None, 
                  ssid=None, signal_strength=None, packet_count=None, 
                  details=None, severity='medium'):
        """Add a new alert to the database"""
        import logging
        logger = logging.getLogger(__name__)
        
        with self.lock:
            cursor = self.conn.cursor()
            timestamp = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, attacker_mac, victim_mac,
                                  ssid, signal_strength, packet_count, details, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, alert_type, attacker_mac, victim_mac, ssid,
                  signal_strength, packet_count, details, severity))
            self.conn.commit()
            alert_id = cursor.lastrowid
            logger.warning(f"✅ ALERT #{alert_id} STORED: {alert_type} - {details}")
            return alert_id
    
    def get_recent_alerts(self, limit=100):
        """Get recent alerts"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM alerts
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_alerts_by_type(self, alert_type, limit=50):
        """Get alerts by type"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM alerts
                WHERE alert_type = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (alert_type, limit))
            return [dict(row) for row in cursor.fetchall()]
    
    def update_device(self, mac_address, signal_strength=None, packet_count=None):
        """Update or insert device information"""
        with self.lock:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute('SELECT * FROM devices WHERE mac_address = ?', (mac_address,))
            device = cursor.fetchone()
            
            if device:
                updates = ['last_seen = ?']
                params = [now]
                
                if signal_strength is not None:
                    updates.append('signal_strength = ?')
                    params.append(signal_strength)
                
                if packet_count is not None:
                    updates.append('packet_count = packet_count + ?')
                    params.append(packet_count)
                
                params.append(mac_address)
                cursor.execute(f'''
                    UPDATE devices SET {', '.join(updates)}
                    WHERE mac_address = ?
                ''', params)
            else:
                cursor.execute('''
                    INSERT INTO devices (mac_address, first_seen, last_seen,
                                       signal_strength, packet_count)
                    VALUES (?, ?, ?, ?, ?)
                ''', (mac_address, now, now, signal_strength, packet_count or 1))
            
            self.conn.commit()
    
    def update_access_point(self, bssid, ssid=None, channel=None, 
                            encryption=None, signal_strength=None, is_rogue=False):
        """Update or insert access point information"""
        with self.lock:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute('SELECT * FROM access_points WHERE bssid = ?', (bssid,))
            ap = cursor.fetchone()
            
            if ap:
                updates = ['last_seen = ?']
                params = [now]
                
                if ssid is not None:
                    updates.append('ssid = ?')
                    params.append(ssid)
                if channel is not None:
                    updates.append('channel = ?')
                    params.append(channel)
                if encryption is not None:
                    updates.append('encryption = ?')
                    params.append(encryption)
                if signal_strength is not None:
                    updates.append('signal_strength = ?')
                    params.append(signal_strength)
                if is_rogue:
                    updates.append('is_rogue = 1')
                
                params.append(bssid)
                cursor.execute(f'''
                    UPDATE access_points SET {', '.join(updates)}
                    WHERE bssid = ?
                ''', params)
            else:
                cursor.execute('''
                    INSERT INTO access_points (bssid, ssid, channel, encryption,
                                             signal_strength, first_seen, last_seen, is_rogue)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (bssid, ssid, channel, encryption, signal_strength, now, now, int(is_rogue)))
            
            self.conn.commit()
    
    def add_statistics(self, deauth_count=0, eapol_count=0, rogue_ap_count=0,
                      suspicious_mac_count=0, total_packets=0):
        """Add statistics entry"""
        with self.lock:
            cursor = self.conn.cursor()
            timestamp = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO statistics (timestamp, deauth_count, eapol_count,
                                      rogue_ap_count, suspicious_mac_count, total_packets)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, deauth_count, eapol_count, rogue_ap_count,
                  suspicious_mac_count, total_packets))
            self.conn.commit()
    
    def get_statistics(self, hours=24):
        """Get statistics for the last N hours"""
        with self.lock:
            cursor = self.conn.cursor()
            from datetime import datetime, timedelta
            cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
            cursor.execute('''
                SELECT * FROM statistics
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
            ''', (cutoff,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_attack_summary(self):
        """Get summary of attacks"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT alert_type, COUNT(*) as count
                FROM alerts
                GROUP BY alert_type
            ''')
            return {row['alert_type']: row['count'] for row in cursor.fetchall()}
    
    def add_prevention_log(self, action_type, attacker_mac=None, attack_type=None, 
                          details=None, block_until=None, interface=None, **kwargs):
        """Add prevention action log"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO prevention_logs 
                (timestamp, action_type, attacker_mac, attack_type, details, block_until, interface)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                action_type,
                attacker_mac,
                attack_type,
                details,
                block_until,
                interface
            ))
            self.conn.commit()
    
    def get_prevention_logs(self, limit=50):
        """Get recent prevention logs"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM prevention_logs
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def add_attack_log(self, attack_type, adapter=None, target_bssid=None, 
                      target_ssid=None, target_channel=None, start_time=None):
        """Add attack log entry"""
        with self.lock:
            cursor = self.conn.cursor()
            if not start_time:
                start_time = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO attack_logs (attack_type, adapter, target_bssid,
                                        target_ssid, target_channel, start_time)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (attack_type, adapter, target_bssid, target_ssid, target_channel, start_time))
            self.conn.commit()
            return cursor.lastrowid
    
    def update_attack_log(self, attack_type, stop_time=None, detected=False, detection_time=None):
        """Update attack log with stop time and detection status"""
        with self.lock:
            cursor = self.conn.cursor()
            if not stop_time:
                stop_time = datetime.now().isoformat()
            
            # Find most recent attack of this type without stop_time
            cursor.execute('''
                SELECT id FROM attack_logs
                WHERE attack_type = ? AND stop_time IS NULL
                ORDER BY start_time DESC
                LIMIT 1
            ''', (attack_type,))
            row = cursor.fetchone()
            
            if row:
                cursor.execute('''
                    UPDATE attack_logs
                    SET stop_time = ?, detected = ?, detection_time = ?
                    WHERE id = ?
                ''', (stop_time, int(detected), detection_time, row['id']))
                self.conn.commit()
                return True
            return False
    
    def get_attack_logs(self, limit=50):
        """Get recent attack logs"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM attack_logs
                ORDER BY start_time DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_active_attack_by_ssid(self, ssid):
        """Get active attack log by SSID"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM attack_logs
                WHERE stop_time IS NULL
                AND target_ssid = ?
                AND attack_type = 'Rogue Access Point'
                ORDER BY start_time DESC
                LIMIT 1
            ''', (ssid,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def correlate_attack_detection(self, alert_type, attacker_mac, bssid=None, ssid=None):
        """Correlate detection alert with active attack"""
        with self.lock:
            cursor = self.conn.cursor()
            
            # Map alert types to attack types
            attack_type_map = {
                'Deauthentication Attack': 'Deauthentication',
                'Handshake Capture': 'Handshake Capture',
                'Rogue Access Point': 'Rogue Access Point'
            }
            
            attack_type = attack_type_map.get(alert_type, alert_type)
            
            # Find active attack matching this detection
            # Try multiple matching strategies
            cursor.execute('''
                SELECT * FROM attack_logs
                WHERE stop_time IS NULL
                AND attack_type = ?
                AND (
                    target_bssid = ? OR
                    target_bssid = ? OR
                    (target_ssid = ? AND ? IS NOT NULL)
                )
                ORDER BY start_time DESC
                LIMIT 1
            ''', (attack_type, attacker_mac, bssid, ssid, ssid))
            row = cursor.fetchone()
            
            if row:
                detection_time = datetime.now().isoformat()
                cursor.execute('''
                    UPDATE attack_logs
                    SET detected = 1, detection_time = ?
                    WHERE id = ?
                ''', (detection_time, row['id']))
                self.conn.commit()
                logger.info(f"Correlated {alert_type} detection with attack log ID {row['id']}")
                return True
            else:
                logger.debug(f"No active attack found to correlate with {alert_type} detection (attacker: {attacker_mac}, bssid: {bssid}, ssid: {ssid})")
            return False
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

