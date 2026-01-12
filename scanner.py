"""
WiFi network scanner using aircrack-ng tools
"""
import subprocess
import re
import json
import threading
import time
import logging
import os
import csv
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.scanning = False
        self.scan_thread = None
        self.scan_results = []
        self.scan_process = None
        self.attack_adapter = None
        self.last_scan_time = None
    
    def start_scan(self, interface):
        """Start network scan on specified interface"""
        if self.scanning:
            return {'success': False, 'message': 'Scan already in progress'}
        
        if not interface:
            return {'success': False, 'message': 'No interface specified'}
        
        logger.info(f"Starting network scan on interface: {interface}")
        self.attack_adapter = interface
        self.scanning = True
        self.scan_results = []
        
        # Start scan in background thread
        self.scan_thread = threading.Thread(target=self._scan_networks, args=(interface,), daemon=True)
        self.scan_thread.start()
        
        return {'success': True, 'message': 'Scan started'}
    
    def stop_scan(self):
        """Stop network scan"""
        logger.info("Stopping network scan")
        self.scanning = False
        if self.scan_process:
            try:
                self.scan_process.terminate()
                self.scan_process.wait(timeout=5)
            except:
                try:
                    self.scan_process.kill()
                except:
                    pass
            self.scan_process = None
        
        return {'success': True, 'message': 'Scan stopped'}
    
    def _scan_networks(self, interface):
        """Perform network scan using airodump-ng"""
        scan_timestamp = int(time.time())
        csv_file = None
        monitor_mode_enabled = False
        
        try:
            # Check if interface exists and is up
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                   capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                logger.error(f"Interface {interface} not found")
                self.scanning = False
                return
            
            # Check if interface is in monitor mode
            iwconfig_result = subprocess.run(['iwconfig', interface], 
                                            capture_output=True, text=True, timeout=5)
            is_monitor = 'Mode:Monitor' in iwconfig_result.stdout
            
            # If not in monitor mode, try to enable it (for scanning)
            if not is_monitor:
                logger.info(f"Interface {interface} not in monitor mode, attempting to enable...")
                try:
                    # Bring interface down
                    subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                                 capture_output=True, timeout=5)
                    time.sleep(0.5)
                    
                    # Try to set monitor mode
                    subprocess.run(['iw', interface, 'set', 'type', 'monitor'], 
                                 capture_output=True, timeout=5)
                    time.sleep(0.5)
                    
                    # Bring interface up
                    subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                                 capture_output=True, timeout=5)
                    time.sleep(1)
                    
                    # Verify monitor mode
                    iwconfig_check = subprocess.run(['iwconfig', interface], 
                                                   capture_output=True, text=True, timeout=5)
                    if 'Mode:Monitor' in iwconfig_check.stdout:
                        monitor_mode_enabled = True
                        logger.info(f"Monitor mode enabled on {interface} for scanning")
                    else:
                        logger.warning(f"Could not enable monitor mode on {interface}, scanning may be limited")
                except Exception as e:
                    logger.warning(f"Could not enable monitor mode: {e}, continuing anyway")
            
            # Create unique output filename
            output_base = f'/tmp/widps_scan_{scan_timestamp}'
            
            # Run airodump-ng with proper flags - scan all channels
            # Note: airodump-ng scans all channels by default
            # Remove --band flag as it may not be supported in all versions
            cmd = [
                'airodump-ng',
                '--write', output_base,
                '--output-format', 'csv',
                '--write-interval', '5',
                interface
            ]
            
            logger.info(f"Running: {' '.join(cmd)}")
            self.scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for CSV file to be created (airodump-ng creates it after a few seconds)
            csv_file = f'{output_base}-01.csv'
            max_wait = 20  # Wait up to 20 seconds for file creation
            waited = 0
            while waited < max_wait and self.scanning:
                if os.path.exists(csv_file):
                    # Check if file has content (not just created empty)
                    try:
                        file_size = os.path.getsize(csv_file)
                        if file_size > 50:  # At least 50 bytes (header + some data)
                            logger.info(f"CSV file created: {csv_file} ({file_size} bytes)")
                            break
                        else:
                            logger.debug(f"CSV file exists but is small ({file_size} bytes), waiting...")
                    except:
                        pass
                time.sleep(1)
                waited += 1
            
            if not os.path.exists(csv_file):
                logger.warning(f"CSV file not created after {max_wait} seconds")
                # Check stderr for errors
                if self.scan_process.poll() is not None:
                    try:
                        stderr_output = self.scan_process.stderr.read() if self.scan_process.stderr else ""
                        logger.error(f"airodump-ng exited with code {self.scan_process.returncode}")
                        if stderr_output:
                            logger.error(f"Error output: {stderr_output[:500]}")
                    except:
                        pass
                else:
                    logger.info("airodump-ng process is still running, but CSV not created yet")
            
            # Continue scanning and parsing results
            parse_count = 0
            while self.scanning:
                time.sleep(5)  # Check every 5 seconds (give more time for networks to appear)
                
                if os.path.exists(csv_file):
                    parse_count += 1
                    logger.info(f"Parsing scan results (attempt {parse_count})")
                    networks_before = len(self.scan_results)
                    self._parse_scan_results(csv_file)
                    networks_after = len(self.scan_results)
                    logger.info(f"Parsed scan results - found {networks_after} networks (was {networks_before})")
                else:
                    logger.debug(f"Waiting for CSV file: {csv_file}")
                
                # Check if process is still running
                if self.scan_process.poll() is not None:
                    logger.warning("airodump-ng process ended unexpectedly")
                    # Try to read stderr for error info
                    try:
                        if self.scan_process.stderr:
                            stderr_output = self.scan_process.stderr.read()
                            if stderr_output:
                                logger.error(f"airodump-ng stderr: {stderr_output.decode('utf-8', errors='ignore')[:500]}")
                    except:
                        pass
                    break
            
            # Cleanup
            if self.scan_process:
                try:
                    self.scan_process.terminate()
                    self.scan_process.wait(timeout=5)
                except:
                    try:
                        self.scan_process.kill()
                    except:
                        pass
                self.scan_process = None
            
            # Restore managed mode if we enabled monitor mode
            if monitor_mode_enabled:
                try:
                    logger.info(f"Restoring managed mode on {interface}")
                    subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                                 capture_output=True, timeout=5)
                    time.sleep(0.5)
                    subprocess.run(['iw', interface, 'set', 'type', 'managed'], 
                                 capture_output=True, timeout=5)
                    time.sleep(0.5)
                    subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                                 capture_output=True, timeout=5)
                except Exception as e:
                    logger.warning(f"Could not restore managed mode: {e}")
            
        except Exception as e:
            logger.error(f"Error in network scan: {e}", exc_info=True)
            self.scanning = False
        finally:
            self.scanning = False
            self.last_scan_time = datetime.now().isoformat()
            logger.info("Network scan thread ended")
    
    def _parse_scan_results(self, csv_file):
        """Parse airodump-ng CSV output"""
        if not os.path.exists(csv_file):
            logger.debug(f"CSV file does not exist: {csv_file}")
            return
        
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content or len(content.strip()) < 10:
                logger.warning(f"CSV file is empty or too short ({len(content) if content else 0} chars)")
                # Log first 200 chars for debugging
                if content:
                    logger.info(f"First 200 chars of file: {content[:200]}")
                return
            
            # Parse CSV - handle different line endings
            lines_raw = content.replace('\r\n', '\n').replace('\r', '\n').split('\n')
            reader = csv.reader(lines_raw)
            lines = []
            for row in reader:
                lines.append(row)
            
            if not lines:
                logger.debug("No lines in CSV file")
                return
            
            logger.info(f"CSV file has {len(lines)} lines, content length: {len(content)} characters")
            
            # Find where AP data starts (after header)
            ap_start = None
            for i, line in enumerate(lines):
                if line and len(line) > 0:
                    # Look for BSSID header - can be in different formats
                    first_col = str(line[0]).strip().upper()
                    if 'BSSID' in first_col or first_col == 'BSSID':
                        ap_start = i + 1
                        logger.info(f"Found BSSID header at line {i}, AP data starts at {ap_start}")
                        logger.debug(f"Header line: {line[:5]}")
                        break
            
            if ap_start is None:
                logger.warning("Could not find BSSID header in CSV file")
                logger.info(f"CSV file content (first 20 lines, {len(lines)} total):")
                for i, line in enumerate(lines[:20]):
                    logger.info(f"  Line {i}: {line[:10] if len(line) > 10 else line} (length: {len(line)})")
                
                # Try alternative: look for any line that might be a header or data
                # Sometimes airodump-ng CSV has different formats
                logger.info("Attempting alternative parsing...")
                # Check if first non-empty line might be data
                for i, line in enumerate(lines):
                    if line and len(line) > 0 and line[0].strip():
                        first_col = line[0].strip()
                        # Check if it looks like a MAC address (has colons)
                        if ':' in first_col and len(first_col) >= 12:
                            logger.info(f"Found potential data at line {i}, treating as start of AP data")
                            ap_start = i
                            break
                
                if ap_start is None:
                    logger.error("Could not determine where AP data starts in CSV file")
                    return
            
            # Parse AP entries (until empty line or station data)
            networks = []
            parsed_count = 0
            skipped_count = 0
            
            for i in range(ap_start, len(lines)):
                line = lines[i]
                
                # Stop at empty line (separates APs from stations)
                if not line or len(line) == 0 or (len(line) == 1 and not line[0].strip()):
                    logger.debug(f"Stopped at empty line {i} (found {parsed_count} networks, skipped {skipped_count})")
                    break
                
                # Skip if line is too short (need at least BSSID)
                if len(line) < 1:
                    continue
                
                try:
                    bssid = line[0].strip() if line[0] else ''
                    
                    # Skip invalid BSSIDs - check for MAC address format
                    if not bssid:
                        skipped_count += 1
                        continue
                    
                    # Check if it looks like a MAC address (has colons and is reasonable length)
                    if ':' not in bssid or len(bssid) < 12:
                        # Might be station data starting - stop here
                        if not any(char.isdigit() for char in bssid[:2]):
                            logger.debug(f"Stopped at line {i} - appears to be station data: {bssid[:20]}")
                            break
                        skipped_count += 1
                        continue
                    
                    # Validate MAC format (should have 5 colons)
                    if bssid.count(':') != 5:
                        skipped_count += 1
                        continue
                    
                    first_seen = line[1].strip() if len(line) > 1 else ''
                    last_seen = line[2].strip() if len(line) > 2 else ''
                    channel = line[3].strip() if len(line) > 3 else ''
                    speed = line[4].strip() if len(line) > 4 else ''
                    privacy = line[5].strip() if len(line) > 5 else ''
                    cipher = line[6].strip() if len(line) > 6 else ''
                    auth = line[7].strip() if len(line) > 7 else ''
                    power = line[8].strip() if len(line) > 8 else ''
                    beacons = line[9].strip() if len(line) > 9 else ''
                    iv = line[10].strip() if len(line) > 10 else ''
                    lan_ip = line[11].strip() if len(line) > 11 else ''
                    id_length = line[12].strip() if len(line) > 12 else ''
                    essid = line[13].strip() if len(line) > 13 else ''
                    
                    # Clean ESSID (remove quotes and special chars)
                    essid = essid.strip('"').strip().strip("'").strip()
                    
                    # Parse power (RSSI) - can be negative number
                    try:
                        rssi = int(power) if power and power != '-1' and power.strip() else None
                    except (ValueError, AttributeError):
                        rssi = None
                    
                    # Parse channel
                    try:
                        channel_num = int(channel) if channel and channel.strip() else None
                    except (ValueError, AttributeError):
                        channel_num = None
                    
                    # Determine encryption
                    encryption = 'Open'
                    if privacy and privacy.upper() != 'OPN':
                        privacy_upper = privacy.upper()
                        if 'WPA2' in privacy_upper:
                            encryption = 'WPA2'
                        elif 'WPA' in privacy_upper:
                            encryption = 'WPA'
                        elif 'WEP' in privacy_upper:
                            encryption = 'WEP'
                        else:
                            encryption = privacy
                    
                    network = {
                        'bssid': bssid,
                        'ssid': essid if essid else '<hidden>',
                        'channel': channel_num,
                        'rssi': rssi,
                        'encryption': encryption,
                        'privacy': privacy,
                        'cipher': cipher,
                        'auth': auth,
                        'first_seen': first_seen,
                        'last_seen': last_seen
                    }
                    
                    # Avoid duplicates by BSSID
                    if not any(n.get('bssid') == bssid for n in networks):
                        networks.append(network)
                        parsed_count += 1
                    else:
                        skipped_count += 1
                
                except Exception as e:
                    skipped_count += 1
                    logger.debug(f"Error parsing network line {i}: {e}")
                    if i < ap_start + 5:  # Only log first few errors
                        logger.debug(f"Line content: {line[:8] if len(line) > 8 else line}")
                    continue
            
            # Update results
            if networks:
                self.scan_results = networks
                logger.info(f"✅ Successfully parsed {len(networks)} networks from scan (skipped {skipped_count} invalid lines)")
                # Log first few networks for verification
                for i, net in enumerate(networks[:3]):
                    logger.info(f"  Network {i+1}: {net.get('ssid', '<hidden>')} ({net.get('bssid')}) - Ch{net.get('channel')} - {net.get('encryption')}")
            else:
                logger.warning(f"⚠️ No networks found in CSV file (checked {len(lines) - ap_start if ap_start else 0} lines from position {ap_start}, skipped {skipped_count})")
                # Log sample lines for debugging
                if ap_start is not None and ap_start < len(lines):
                    logger.info("Sample lines from AP section:")
                    for i in range(ap_start, min(ap_start + 10, len(lines))):
                        sample_line = lines[i]
                        logger.info(f"  Line {i}: {sample_line[:15] if len(sample_line) > 15 else sample_line} (length: {len(sample_line)})")
                        # Also log raw content
                        if len(sample_line) > 0:
                            logger.info(f"    First column: '{sample_line[0] if len(sample_line) > 0 else 'N/A'}'")
                
                # Additional debugging: check if CSV has any content at all
                logger.info(f"CSV file stats: {len(lines)} total lines, content length: {len(content)} chars")
                if len(content) < 100:
                    logger.warning(f"CSV file seems very small ({len(content)} chars) - might be empty or incomplete")
            
        except Exception as e:
            logger.error(f"Error parsing scan results: {e}", exc_info=True)
    
    def get_results(self):
        """Get current scan results"""
        return {
            'scanning': self.scanning,
            'results': self.scan_results,
            'count': len(self.scan_results),
            'last_scan': self.last_scan_time,
            'adapter': self.attack_adapter
        }
    
    def is_scanning(self):
        """Check if scan is in progress"""
        return self.scanning

