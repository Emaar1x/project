"""
Prevention actions for WiFi IDPS
"""
import subprocess
import logging
import threading
import time
from datetime import datetime, timedelta
from database import Database
from config import PREVENTION_ENABLED, AUTO_BLOCK, BLOCK_DURATION, INTERFACE

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PreventionEngine:
    def __init__(self, monitor_interface=None, prevention_interface=None):
        self.db = Database()
        self.enabled = PREVENTION_ENABLED
        self.auto_block = AUTO_BLOCK
        self.blocked_macs = {}  # {mac: unblock_time}
        self.block_duration = BLOCK_DURATION
        self.monitor_interface = monitor_interface or INTERFACE
        self.prevention_interface = prevention_interface  # Dedicated prevention adapter
        self.blocking_processes = {}  # Track active blocking processes {mac: process}
        self.block_lock = threading.Lock()  # Thread safety for blocking operations
        self.prevention_stats = {
            'total_blocks': 0,
            'total_logs': 0,
            'active_blocks': 0
        }
        self.continuous_blocking = {}  # Track continuous blocking threads {mac: thread}
    
    def enable(self):
        """Enable prevention mode"""
        self.enabled = True
        logger.info("Prevention mode ENABLED")
    
    def disable(self):
        """Disable prevention mode"""
        self.enabled = False
        logger.info("Prevention mode DISABLED")
    
    def is_enabled(self):
        """Check if prevention is enabled"""
        return self.enabled
    
    def set_monitor_interface(self, interface):
        """Update the monitor interface for blocking operations"""
        self.monitor_interface = interface
        logger.info(f"Prevention monitor interface set to: {interface}")
    
    def set_prevention_interface(self, interface):
        """Set the dedicated prevention adapter interface"""
        self.prevention_interface = interface
        logger.info(f"Prevention adapter interface set to: {interface}")
    
    def handle_alert(self, alert_type, attacker_mac, **kwargs):
        """Handle an alert and take prevention action if enabled"""
        if not self.enabled:
            return
        
        logger.info(f"Prevention handling alert: {alert_type} from {attacker_mac}")
        
        if alert_type == 'Deauthentication Attack':
            self.log_attacker(attacker_mac, alert_type, **kwargs)
            if self.auto_block:
                self.block_attacker(attacker_mac, alert_type, **kwargs)
        
        elif alert_type == 'Rogue Access Point':
            self.log_attacker(attacker_mac, alert_type, **kwargs)
            # For rogue APs, block the attacker by sending deauth to disrupt the AP
            if self.auto_block:
                logger.warning(f"🛡️ Rogue AP detected: {attacker_mac} - Blocking AP")
                self.block_attacker(attacker_mac, alert_type, **kwargs)
        
        elif alert_type == 'Handshake Capture':
            self.log_attacker(attacker_mac, alert_type, **kwargs)
            # Block the attacker performing handshake capture
            if self.auto_block:
                logger.warning(f"🛡️ Handshake capture detected: {attacker_mac} - Blocking attacker")
                self.block_attacker(attacker_mac, alert_type, **kwargs)
        
        elif alert_type == 'Suspicious MAC':
            self.log_attacker(attacker_mac, alert_type, **kwargs)
            if self.auto_block:
                self.block_attacker(attacker_mac, alert_type, **kwargs)
    
    def log_attacker(self, mac, attack_type, **kwargs):
        """Log attacker information to database"""
        try:
            # Store prevention action in database
            self.db.add_prevention_log(
                action_type='logged',
                attacker_mac=mac,
                attack_type=attack_type,
                details=f"Attacker logged: {attack_type}",
                interface=self.prevention_interface or self.monitor_interface,
                **kwargs
            )
            self.prevention_stats['total_logs'] += 1
            logger.warning(f"🛡️ ATTACKER LOGGED: {mac} - {attack_type}")
        except Exception as e:
            logger.error(f"Error logging attacker: {e}")
    
    def block_attacker(self, mac, attack_type, **kwargs):
        """Block an attacker using continuous deauthentication (LAB ONLY)"""
        if not mac:
            return
        
        with self.block_lock:
            # Record block time (current time + duration) - do this first for correct timestamp
            block_until = datetime.now() + timedelta(seconds=self.block_duration)
            
            # Check if already blocked
            if mac in self.blocked_macs:
                if datetime.now() < self.blocked_macs[mac]:
                    logger.info(f"MAC {mac} already blocked until {self.blocked_macs[mac]}")
                    # Restart continuous blocking if not running
                    if mac not in self.continuous_blocking or not self.continuous_blocking[mac].is_alive():
                        self._start_continuous_blocking(mac, attack_type, self.blocked_macs[mac], **kwargs)
                    return
                else:
                    # Block expired, update with new time
                    self.blocked_macs[mac] = block_until
            else:
                # New block
                self.blocked_macs[mac] = block_until
            
            try:
                logger.warning(f"🛡️ BLOCKING ATTACKER: {mac} - {attack_type} until {block_until}")
                
                # Start continuous blocking
                self._start_continuous_blocking(mac, attack_type, block_until, **kwargs)
                
                # Update stats
                self.prevention_stats['total_blocks'] += 1
                self.prevention_stats['active_blocks'] = len([m for m, t in self.blocked_macs.items() 
                                                             if datetime.now() < t])
                
                # Store prevention action in database with correct timestamp
                try:
                    interface = self.prevention_interface or self.monitor_interface
                    self.db.add_prevention_log(
                        action_type='blocked',
                        attacker_mac=mac,
                        attack_type=attack_type,
                        details=f"Attacker blocked for {self.block_duration} seconds",
                        block_until=block_until.isoformat(),
                        interface=interface,
                        **kwargs
                    )
                except Exception as e:
                    logger.error(f"Error logging prevention action: {e}")
                    
            except Exception as e:
                logger.error(f"Error blocking attacker {mac}: {e}", exc_info=True)
    
    def _start_continuous_blocking(self, mac, attack_type, block_until, **kwargs):
        """Start continuous blocking thread for an attacker"""
        if mac in self.continuous_blocking:
            thread = self.continuous_blocking[mac]
            if thread.is_alive():
                return  # Already blocking
        
        # Get the prevention interface
        interface = self.prevention_interface or self.monitor_interface
        if not interface:
            logger.error("No prevention interface available for blocking")
            return
        
        # Ensure prevention interface is in monitor mode
        try:
            iwconfig_result = subprocess.run(
                ['iwconfig', interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            if 'Mode:Monitor' not in iwconfig_result.stdout:
                logger.warning(f"Interface {interface} is not in monitor mode - attempting to enable")
                subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                             capture_output=True, timeout=5)
                time.sleep(0.5)
                subprocess.run(['iw', interface, 'set', 'type', 'monitor'], 
                             capture_output=True, timeout=5)
                time.sleep(0.5)
                subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                             capture_output=True, timeout=5)
                time.sleep(1)
        except Exception as e:
            logger.error(f"Error checking/enabling monitor mode on prevention interface: {e}")
            return
        
        # Start continuous blocking thread
        def continuous_block():
            """Continuously send deauth packets until block expires"""
            logger.warning(f"🛡️ Starting continuous blocking for {mac} on {interface}")
            
            while True:
                try:
                    # Check if block has expired
                    if datetime.now() >= block_until:
                        logger.info(f"Block expired for {mac}, stopping continuous blocking")
                        break
                    
                    with self.block_lock:
                        if mac not in self.blocked_macs:
                            logger.info(f"MAC {mac} removed from blocked list, stopping")
                            break
                        
                        if datetime.now() >= self.blocked_macs[mac]:
                            logger.info(f"Block expired for {mac}, stopping continuous blocking")
                            break
                    
                    # Send deauth packets continuously (every 2 seconds)
                    # Use --deauth 0 for continuous mode, but we'll control it manually
                    command = [
                        'aireplay-ng',
                        '--deauth', '10',  # Send 10 deauth packets per burst
                        '-a', mac,  # Target MAC (the attacker)
                        interface
                    ]
                    
                    logger.debug(f"🛡️ Sending deauth burst to {mac} on {interface}")
                    
                    # Run blocking command
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # Store process
                    with self.block_lock:
                        self.blocking_processes[mac] = process
                    
                    # Wait for process to complete (usually takes 1-2 seconds)
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        process.wait(timeout=1)
                    
                    # Small delay before next burst
                    time.sleep(1)
                    
                except Exception as e:
                    logger.error(f"Error in continuous blocking for {mac}: {e}")
                    time.sleep(2)
            
            # Cleanup
            with self.block_lock:
                if mac in self.blocking_processes:
                    try:
                        self.blocking_processes[mac].terminate()
                        self.blocking_processes[mac].wait(timeout=1)
                    except:
                        try:
                            self.blocking_processes[mac].kill()
                        except:
                            pass
                    del self.blocking_processes[mac]
                if mac in self.continuous_blocking:
                    del self.continuous_blocking[mac]
            
            logger.info(f"🛡️ Stopped continuous blocking for {mac}")
        
        # Start the blocking thread
        thread = threading.Thread(target=continuous_block, daemon=True)
        thread.start()
        self.continuous_blocking[mac] = thread
        logger.warning(f"✅ Continuous blocking started for {mac}")
    
    def unblock_attacker(self, mac):
        """Unblock a previously blocked MAC"""
        if mac in self.blocked_macs:
            del self.blocked_macs[mac]
            logger.info(f"MAC {mac} unblocked")
    
    def get_blocked_macs(self):
        """Get list of currently blocked MACs"""
        from datetime import datetime
        active_blocks = {}
        now = datetime.now()
        
        with self.block_lock:
            for mac, unblock_time in list(self.blocked_macs.items()):
                if now < unblock_time:
                    # Return ISO format timestamp for proper display
                    active_blocks[mac] = unblock_time.isoformat()
                else:
                    # Remove expired blocks
                    del self.blocked_macs[mac]
                    # Stop continuous blocking if running
                    if mac in self.continuous_blocking:
                        thread = self.continuous_blocking[mac]
                        if thread.is_alive():
                            # Thread will stop itself when it checks the time
                            pass
                        del self.continuous_blocking[mac]
                    if mac in self.blocking_processes:
                        try:
                            self.blocking_processes[mac].terminate()
                        except:
                            pass
                        del self.blocking_processes[mac]
        
        self.prevention_stats['active_blocks'] = len(active_blocks)
        return active_blocks
    
    def get_stats(self):
        """Get prevention statistics"""
        return {
            'total_blocks': self.prevention_stats['total_blocks'],
            'total_logs': self.prevention_stats['total_logs'],
            'active_blocks': len(self.get_blocked_macs()),
            'enabled': self.enabled,
            'auto_block': self.auto_block,
            'prevention_interface': self.prevention_interface or self.monitor_interface
        }

