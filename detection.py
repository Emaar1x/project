"""
Attack detection logic for WiFi IDPS
"""
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import Dot11, Dot11Deauth, Dot11Auth, Dot11AssoReq, Dot11ReassoReq, EAPOL
from config import (DEAUTH_THRESHOLD, EAPOL_THRESHOLD, ROGUE_AP_CHECK_INTERVAL,
                    KNOWN_SSIDS, KNOWN_MACS)
from database import Database
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackDetector:
    def __init__(self):
        self.db = Database()
        
        # Deauthentication attack detection
        self.deauth_counter = defaultdict(lambda: {'count': 0, 'timestamps': deque()})
        self.deauth_window = timedelta(seconds=1)
        
        # EAPOL handshake detection
        self.eapol_counter = defaultdict(lambda: {'count': 0, 'timestamps': deque()})
        self.eapol_window = timedelta(minutes=1)
        
        # Rogue AP detection
        self.known_aps = {}  # {ssid: [bssids]}
        self.ap_last_seen = {}
        self.rogue_check_interval = timedelta(seconds=ROGUE_AP_CHECK_INTERVAL)
        
        # Alert rate limiting (prevent spam)
        self.last_alert_time = {}  # {alert_key: timestamp}
        self.alert_cooldown = timedelta(seconds=30)  # 30 seconds between same alerts
        
        # Packet counters
        self.total_packets = 0
        self.packet_stats = {
            'deauth': 0,
            'eapol': 0,
            'rogue_ap': 0
        }
    
    def process_packet(self, packet):
        """Process a captured packet and detect attacks"""
        self.total_packets += 1
        
        # Log first few packets
        if self.total_packets <= 3:
            logger.info(f"🔍 Processing packet #{self.total_packets}")
        
        if not packet.haslayer(Dot11):
            return
        
        # Extract basic information
        if packet.haslayer(Dot11):
            try:
                signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None
            except:
                signal_strength = None
            
            # Deauthentication attack detection
            if packet.haslayer(Dot11Deauth):
                self._detect_deauth_attack(packet, signal_strength)
            
            # EAPOL handshake detection
            if packet.haslayer(EAPOL):
                self._detect_handshake_capture(packet, signal_strength)
            
            # Rogue AP detection - check for beacon frames
            try:
                if hasattr(packet, 'type') and hasattr(packet, 'subtype'):
                    if packet.type == 0 and packet.subtype == 8:  # Beacon frame
                        self._detect_rogue_ap(packet, signal_strength)
            except:
                pass
    
    def _detect_deauth_attack(self, packet, signal_strength):
        """Detect deauthentication flood attacks"""
        if not packet.haslayer(Dot11Deauth):
            return
        
        try:
            # Get MAC addresses - deauth frames have addr1 (receiver) and addr2 (transmitter)
            # For deauth attacks, addr2 is usually the AP/BSSID, addr1 is the victim
            attacker_mac = packet.addr2 if hasattr(packet, 'addr2') else None
            victim_mac = packet.addr1 if hasattr(packet, 'addr1') else None
            
            if not attacker_mac:
                logger.debug("Deauth packet missing addr2")
                return
            
            logger.debug(f"Deauth packet: attacker={attacker_mac}, victim={victim_mac}, count before={self.deauth_counter.get(f'{attacker_mac}_{victim_mac}', {}).get('count', 0)}")
            
            now = datetime.now()
            key = f"{attacker_mac}_{victim_mac}"
            
            # Clean old timestamps
            while (self.deauth_counter[key]['timestamps'] and 
                   now - self.deauth_counter[key]['timestamps'][0] > self.deauth_window):
                self.deauth_counter[key]['timestamps'].popleft()
                self.deauth_counter[key]['count'] -= 1
            
            # Add new timestamp
            self.deauth_counter[key]['timestamps'].append(now)
            self.deauth_counter[key]['count'] += 1
            
            # Check threshold
            current_count = self.deauth_counter[key]['count']
            
            # Log every deauth packet (always log, not just debug)
            logger.warning(f"🔔 Deauth packet detected: {attacker_mac} -> {victim_mac} | Count: {current_count}/{DEAUTH_THRESHOLD}")
            
            if current_count >= DEAUTH_THRESHOLD:
                # Rate limit alerts
                alert_key = f"deauth_{attacker_mac}_{victim_mac}"
                if not self._should_alert(alert_key):
                    logger.debug(f"Alert rate limited for {alert_key}")
                    return
                
                self.packet_stats['deauth'] += 1
                details = f"Deauth flood detected: {current_count} frames in 1 second"
                logger.warning(f"🚨 DEAUTH ATTACK DETECTED: {current_count} frames from {attacker_mac} to {victim_mac}")
                
                # First, try to find any active deauth attack and correlate it
                is_test = False
                with self.db.lock:
                    cursor = self.db.conn.cursor()
                    cursor.execute('''
                        SELECT * FROM attack_logs
                        WHERE stop_time IS NULL
                        AND attack_type = 'Deauthentication'
                        ORDER BY start_time DESC
                        LIMIT 1
                    ''')
                    row = cursor.fetchone()
                    if row:
                        # Found active deauth attack, correlate it directly
                        detection_time = datetime.now().isoformat()
                        row_id = row['id']
                        target_bssid = row['target_bssid'] if 'target_bssid' in row.keys() else None
                        cursor.execute('''
                            UPDATE attack_logs
                            SET detected = 1, detection_time = ?
                            WHERE id = ?
                        ''', (detection_time, row_id))
                        self.db.conn.commit()
                        is_test = True
                        logger.info(f"✅ Correlated deauth detection with active attack log ID {row_id} (target: {target_bssid}, attacker: {attacker_mac})")
                
                # Also try the standard correlation method
                if not is_test:
                    is_test = self.db.correlate_attack_detection(
                        'Deauthentication Attack',
                        attacker_mac,
                        bssid=attacker_mac,
                        ssid=None
                    )
                
                if is_test:
                    details += " [Detected during test]"
                
                alert_id = self.db.add_alert(
                    alert_type='Deauthentication Attack',
                    attacker_mac=attacker_mac,
                    victim_mac=victim_mac,
                    signal_strength=signal_strength,
                    packet_count=self.deauth_counter[key]['count'],
                    details=details,
                    severity='high'
                )
                
                logger.warning(f"ALERT: {details} - Attacker: {attacker_mac}, Victim: {victim_mac}")
                
                # Trigger prevention if available
                if hasattr(self, 'prevention') and self.prevention:
                    self.prevention.handle_alert(
                        'Deauthentication Attack',
                        attacker_mac,
                        victim_mac=victim_mac,
                        alert_id=alert_id,
                        signal_strength=signal_strength
                    )
                
                # Reset counter after alert
                self.deauth_counter[key]['count'] = 0
                self.deauth_counter[key]['timestamps'].clear()
        except Exception as e:
            logger.error(f"Error in deauth detection: {e}", exc_info=True)
    
    def _detect_handshake_capture(self, packet, signal_strength):
        """Detect EAPOL handshake capture attempts"""
        if not packet.haslayer(EAPOL):
            return
        
        try:
            # Get MAC addresses - for EAPOL, addr1 is receiver, addr2 is transmitter
            attacker_mac = packet.addr2 if hasattr(packet, 'addr2') else None
            victim_mac = packet.addr1 if hasattr(packet, 'addr1') else None
            
            if not attacker_mac:
                return
            
            logger.info(f"🔐 EAPOL packet detected: {attacker_mac} -> {victim_mac}")
            
            now = datetime.now()
            key = attacker_mac
            
            # Clean old timestamps
            while (self.eapol_counter[key]['timestamps'] and 
                   now - self.eapol_counter[key]['timestamps'][0] > self.eapol_window):
                self.eapol_counter[key]['timestamps'].popleft()
                self.eapol_counter[key]['count'] -= 1
            
            # Add new timestamp
            self.eapol_counter[key]['timestamps'].append(now)
            self.eapol_counter[key]['count'] += 1
            
            current_count = self.eapol_counter[key]['count']
            logger.info(f"🔐 EAPOL count for {attacker_mac}: {current_count}/{EAPOL_THRESHOLD}")
            
            # Check threshold - lowered for better detection
            if current_count >= EAPOL_THRESHOLD:
                # Rate limit alerts
                alert_key = f"eapol_{attacker_mac}"
                if not self._should_alert(alert_key):
                    return
                
                self.packet_stats['eapol'] += 1
                details = f"Handshake capture attempt: {current_count} EAPOL frames in 1 minute"
                logger.warning(f"🚨 HANDSHAKE CAPTURE DETECTED: {current_count} EAPOL frames from {attacker_mac}")
                
                # First, try to find any active handshake capture attack and correlate it
                is_test = False
                with self.db.lock:
                    cursor = self.db.conn.cursor()
                    cursor.execute('''
                        SELECT * FROM attack_logs
                        WHERE stop_time IS NULL
                        AND attack_type = 'Handshake Capture'
                        ORDER BY start_time DESC
                        LIMIT 1
                    ''')
                    row = cursor.fetchone()
                    if row:
                        # Found active handshake capture, correlate it directly
                        detection_time = datetime.now().isoformat()
                        row_id = row['id']
                        target_bssid = row['target_bssid'] if 'target_bssid' in row.keys() else None
                        cursor.execute('''
                            UPDATE attack_logs
                            SET detected = 1, detection_time = ?
                            WHERE id = ?
                        ''', (detection_time, row_id))
                        self.db.conn.commit()
                        is_test = True
                        logger.info(f"✅ Correlated handshake capture detection with active attack log ID {row_id} (target: {target_bssid})")
                
                # Also try the standard correlation method
                if not is_test:
                    is_test = self.db.correlate_attack_detection(
                        'Handshake Capture',
                        attacker_mac,
                        bssid=attacker_mac,
                        ssid=None
                    )
                
                if is_test:
                    details += " [Detected during test]"
                
                alert_id = self.db.add_alert(
                    alert_type='Handshake Capture',
                    attacker_mac=attacker_mac,
                    victim_mac=victim_mac,
                    signal_strength=signal_strength,
                    packet_count=self.eapol_counter[key]['count'],
                    details=details,
                    severity='high'
                )
                
                logger.warning(f"ALERT: {details} - Attacker: {attacker_mac}")
                
                # Trigger prevention if available
                if hasattr(self, 'prevention') and self.prevention:
                    self.prevention.handle_alert(
                        'Handshake Capture',
                        attacker_mac,
                        victim_mac=victim_mac,
                        alert_id=alert_id,
                        signal_strength=signal_strength
                    )
        except Exception as e:
            logger.error(f"Error in EAPOL detection: {e}", exc_info=True)
    
    def _detect_rogue_ap(self, packet, signal_strength):
        """Detect rogue access points (Evil Twin)"""
        if packet.type != 0 or packet.subtype != 8:
            return
        
        try:
            if not hasattr(packet, 'info'):
                return
            
            ssid = packet.info.decode('utf-8', errors='ignore') if packet.info else None
            bssid = packet.addr2 if hasattr(packet, 'addr2') else None
            
            if not ssid or not bssid:
                return
            
            # Extract channel from packet if available
            channel = None
            if hasattr(packet, 'channel'):
                channel = packet.channel
            
            # Check if there's an active rogue AP attack for this SSID (check before whitelist check)
            active_rogue_attack = self.db.get_active_attack_by_ssid(ssid)
            if active_rogue_attack and not isinstance(active_rogue_attack, dict):
                active_rogue_attack = dict(active_rogue_attack)
            
            # Also check if there's any active rogue AP attack (by BSSID or SSID)
            if not active_rogue_attack:
                with self.db.lock:
                    cursor = self.db.conn.cursor()
                    cursor.execute('''
                        SELECT * FROM attack_logs
                        WHERE stop_time IS NULL
                        AND attack_type = 'Rogue Access Point'
                        AND (target_ssid = ? OR target_bssid = ? OR target_bssid IS NULL)
                        ORDER BY start_time DESC
                        LIMIT 1
                    ''', (ssid, bssid))
                    row = cursor.fetchone()
                    if row:
                        # Convert Row to dict properly
                        if hasattr(row, 'keys'):
                            active_rogue_attack = {key: row[key] for key in row.keys()}
                        else:
                            active_rogue_attack = dict(row)
            
            # If still no match, check for ANY active rogue AP attack (most recent one)
            if not active_rogue_attack:
                with self.db.lock:
                    cursor = self.db.conn.cursor()
                    cursor.execute('''
                        SELECT * FROM attack_logs
                        WHERE stop_time IS NULL
                        AND attack_type = 'Rogue Access Point'
                        ORDER BY start_time DESC
                        LIMIT 1
                    ''')
                    row = cursor.fetchone()
                    if row:
                        # Convert Row to dict properly
                        if hasattr(row, 'keys'):
                            active_rogue_attack = {key: row[key] for key in row.keys()}
                        else:
                            active_rogue_attack = dict(row)
                        target_ssid = active_rogue_attack.get('target_ssid', 'Unknown') if isinstance(active_rogue_attack, dict) else 'Unknown'
                        logger.info(f"Found active rogue AP attack (SSID: {target_ssid}), checking if beacon matches")
            
            # Check if SSID is in whitelist
            if ssid in KNOWN_SSIDS:
                # Update known AP
                if ssid not in self.known_aps:
                    self.known_aps[ssid] = []
                if bssid not in self.known_aps[ssid]:
                    self.known_aps[ssid].append(bssid)
                    logger.info(f"Known AP: {ssid} - {bssid}")
                
                # Check for duplicate SSID with different BSSID (rogue AP)
                if len(self.known_aps[ssid]) > 1:
                    # Multiple BSSIDs for same SSID - potential rogue
                    known_bssids = self.known_aps[ssid]
                    if bssid not in known_bssids:
                        known_bssids.append(bssid)
                    
                    # If we have multiple BSSIDs, check if this is a rogue
                    if len(known_bssids) > 1:
                        # Rate limit alerts
                        alert_key = f"rogue_{ssid}_{bssid}"
                        if not self._should_alert(alert_key):
                            # Still update database but don't spam alerts
                            self.db.update_access_point(
                                bssid=bssid,
                                ssid=ssid,
                                channel=channel,
                                signal_strength=signal_strength,
                                is_rogue=True
                            )
                            return
                        
                        # Rogue AP detected!
                        self.packet_stats['rogue_ap'] += 1
                        other_bssids = [b for b in known_bssids if b != bssid]
                        details = f"Rogue AP detected: SSID '{ssid}' with BSSID {bssid} (known BSSIDs: {', '.join(other_bssids)})"
                        
                        # Correlate with attack log
                        is_test = self.db.correlate_attack_detection(
                            'Rogue Access Point',
                            bssid,
                            bssid=bssid,
                            ssid=ssid
                        )
                        
                        if is_test:
                            details += " [Detected during test]"
                        
                        alert_id = self.db.add_alert(
                            alert_type='Rogue Access Point',
                            attacker_mac=bssid,
                            ssid=ssid,
                            signal_strength=signal_strength,
                            details=details,
                            severity='critical'
                        )
                        
                        self.db.update_access_point(
                            bssid=bssid,
                            ssid=ssid,
                            channel=channel,
                            signal_strength=signal_strength,
                            is_rogue=True
                        )
                        
                        logger.warning(f"ALERT: {details}")
                        
                        # Trigger prevention if available
                        if hasattr(self, 'prevention') and self.prevention:
                            self.prevention.handle_alert(
                                'Rogue Access Point',
                                bssid,
                                ssid=ssid,
                                alert_id=alert_id,
                                signal_strength=signal_strength
                            )
                        return
            else:
                # SSID not in whitelist - check if there's an active rogue AP attack
                if active_rogue_attack:
                    # This is likely the rogue AP from our test
                    # Rate limit alerts
                    alert_key = f"rogue_{ssid}_{bssid}"
                    if not self._should_alert(alert_key):
                        self.db.update_access_point(
                            bssid=bssid,
                            ssid=ssid,
                            channel=channel,
                            signal_strength=signal_strength,
                            is_rogue=True
                        )
                        return
                    
                    # Rogue AP detected from active attack
                    self.packet_stats['rogue_ap'] += 1
                    details = f"Rogue AP detected: SSID '{ssid}' with BSSID {bssid} [Detected during test]"
                    
                    # First, try to find any active rogue AP attack and correlate it
                    is_test = False
                    with self.db.lock:
                        cursor = self.db.conn.cursor()
                        cursor.execute('''
                            SELECT * FROM attack_logs
                            WHERE stop_time IS NULL
                            AND attack_type = 'Rogue Access Point'
                            ORDER BY start_time DESC
                            LIMIT 1
                        ''')
                        row = cursor.fetchone()
                        if row:
                            # Found active rogue AP attack, correlate it directly
                            detection_time = datetime.now().isoformat()
                            row_id = row['id']
                            # Get target_ssid safely from Row object
                            if hasattr(row, 'keys') and 'target_ssid' in row.keys():
                                target_ssid_val = row['target_ssid']
                            else:
                                target_ssid_val = None
                            cursor.execute('''
                                UPDATE attack_logs
                                SET detected = 1, detection_time = ?
                                WHERE id = ?
                            ''', (detection_time, row_id))
                            self.db.conn.commit()
                            is_test = True
                            logger.info(f"✅ Correlated rogue AP detection with active attack log ID {row_id} (SSID: {ssid}, target SSID: {target_ssid_val})")
                    
                    # Also try the standard correlation method
                    if not is_test:
                        is_test = self.db.correlate_attack_detection(
                            'Rogue Access Point',
                            bssid,
                            bssid=bssid,
                            ssid=ssid
                        )
                    
                    if is_test:
                        details += " [Detected during test]"
                    
                    self.db.add_alert(
                        alert_type='Rogue Access Point',
                        attacker_mac=bssid,
                        ssid=ssid,
                        signal_strength=signal_strength,
                        details=details,
                        severity='critical'
                    )
                    
                    self.db.update_access_point(
                        bssid=bssid,
                        ssid=ssid,
                        channel=channel,
                        signal_strength=signal_strength,
                        is_rogue=True
                    )
                    
                    logger.warning(f"ALERT: {details}")
                    return
                else:
                    # SSID not in whitelist and no active attack - check for duplicate SSID with different BSSID (rogue AP)
                    for known_ssid, known_bssids in self.known_aps.items():
                        if ssid == known_ssid and bssid not in known_bssids:
                            # Rate limit alerts
                            alert_key = f"rogue_{ssid}_{bssid}"
                            if not self._should_alert(alert_key):
                                # Still update database but don't spam alerts
                                self.db.update_access_point(
                                    bssid=bssid,
                                    ssid=ssid,
                                    channel=channel,
                                    signal_strength=signal_strength,
                                    is_rogue=True
                                )
                                return
                            
                            # Rogue AP detected!
                            self.packet_stats['rogue_ap'] += 1
                            details = f"Rogue AP detected: SSID '{ssid}' with BSSID {bssid} (known BSSIDs: {', '.join(known_bssids)})"
                            
                            # Correlate with attack log
                            is_test = self.db.correlate_attack_detection(
                                'Rogue Access Point',
                                bssid,
                                bssid=bssid,
                                ssid=ssid
                            )
                            
                            if is_test:
                                details += " [Detected during test]"
                            
                            self.db.add_alert(
                                alert_type='Rogue Access Point',
                                attacker_mac=bssid,
                                ssid=ssid,
                                signal_strength=signal_strength,
                                details=details,
                                severity='critical'
                            )
                            
                            self.db.update_access_point(
                                bssid=bssid,
                                ssid=ssid,
                                channel=channel,
                                signal_strength=signal_strength,
                                is_rogue=True
                            )
                            
                            logger.warning(f"ALERT: {details}")
                            return
            
            # Update AP in database
            self.db.update_access_point(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                signal_strength=signal_strength,
                is_rogue=False
            )
            
            self.ap_last_seen[bssid] = datetime.now()
        except Exception as e:
            logger.error(f"Error in rogue AP detection: {e}")
    
    def _should_alert(self, alert_key):
        """Check if alert should be sent (rate limiting)"""
        now = datetime.now()
        if alert_key in self.last_alert_time:
            if now - self.last_alert_time[alert_key] < self.alert_cooldown:
                return False
        self.last_alert_time[alert_key] = now
        return True
    
    def get_statistics(self):
        """Get current detection statistics"""
        return {
            'total_packets': self.total_packets,
            'deauth_attacks': self.packet_stats['deauth'],
            'eapol_attacks': self.packet_stats['eapol'],
            'rogue_aps': self.packet_stats['rogue_ap']
        }
    
    def reset_counters(self):
        """Reset detection counters"""
        self.deauth_counter.clear()
        self.eapol_counter.clear()
        self.packet_stats = {
            'deauth': 0,
            'eapol': 0,
            'rogue_ap': 0
        }

