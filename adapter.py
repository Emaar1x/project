"""
WiFi adapter control for monitor mode management
"""
import subprocess
import re
import logging
import time
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdapterController:
    def __init__(self):
        self.monitor_interface = None
        self.managed_interface = None
        self.monitor_mode_active = False
        self.monitor_adapter = None  # Base adapter for monitoring
        self.attack_adapter = None   # Adapter for attacks/scanning
        self.prevention_adapter = None  # Adapter for prevention/blocking
    
    def get_wifi_interfaces(self):
        """Get list of available WiFi interfaces with friendly names"""
        try:
            interfaces = []
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
            
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line or 'no wireless extensions' in line:
                    match = re.search(r'^(\w+)\s+', line)
                    if match:
                        iface_name = match.group(1)
                        
                        # Get friendly name (driver/chipset info)
                        friendly_name = self._get_interface_friendly_name(iface_name)
                        
                        interfaces.append({
                            'name': iface_name,
                            'friendly_name': friendly_name,
                            'display': f"{iface_name} – {friendly_name}"
                        })
            
            return interfaces
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return []
    
    def _get_interface_friendly_name(self, interface):
        """Get friendly name for interface (driver/chipset)"""
        try:
            # Try to get driver info
            result = subprocess.run(
                ['ethtool', '-i', interface],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'driver:' in line.lower():
                        driver = line.split(':')[1].strip()
                        return driver
            
            # Try alternative method - check /sys/class/net
            driver_path = f'/sys/class/net/{interface}/device/driver'
            if os.path.exists(driver_path):
                driver = os.path.basename(os.readlink(driver_path))
                return driver
            
            # Try lspci for PCI devices
            result = subprocess.run(
                ['lspci'],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                # Look for network controllers
                for line in result.stdout.split('\n'):
                    if 'Network controller' in line or 'Wireless' in line:
                        # Extract vendor/model
                        parts = line.split(':')
                        if len(parts) > 2:
                            return parts[-1].strip()
            
            return 'Unknown'
        except Exception as e:
            logger.debug(f"Could not get friendly name for {interface}: {e}")
            return 'Unknown'
    
    def get_interface_status(self, interface):
        """Get current status of an interface"""
        try:
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=10)
            output = result.stdout.lower()
            
            status = {
                'interface': interface,
                'exists': result.returncode == 0,
                'mode': 'unknown',
                'up': False
            }
            
            if 'mode:monitor' in output:
                status['mode'] = 'monitor'
                status['monitor_mode'] = True
            elif 'mode:managed' in output:
                status['mode'] = 'managed'
                status['monitor_mode'] = False
            
            # Check if interface is up
            result2 = subprocess.run(['ip', 'link', 'show', interface], 
                                    capture_output=True, text=True, timeout=5)
            if 'state UP' in result2.stdout:
                status['up'] = True
            
            return status
        except Exception as e:
            logger.error(f"Error getting interface status: {e}")
            return {'interface': interface, 'exists': False, 'mode': 'unknown', 'up': False}
    
    def enable_monitor_mode(self, interface):
        """Enable monitor mode on interface"""
        try:
            # Check if already in monitor mode
            status = self.get_interface_status(interface)
            if status['mode'] == 'monitor':
                logger.info(f"Interface {interface} already in monitor mode")
                self.monitor_interface = interface
                self.managed_interface = interface.replace('mon', '')
                self.monitor_mode_active = True
                return {'success': True, 'interface': interface, 'message': 'Already in monitor mode'}
            
            # Stop any existing monitor mode processes
            self._kill_conflicting_processes(interface)
            
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                          capture_output=True, timeout=5)
            time.sleep(0.5)
            
            # Use airmon-ng to enable monitor mode
            result = subprocess.run(['airmon-ng', 'start', interface], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                # Try alternative method with iw
                logger.info("airmon-ng failed, trying iw command")
                subprocess.run(['iw', interface, 'set', 'type', 'monitor'], 
                             capture_output=True, timeout=5)
                subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                             capture_output=True, timeout=5)
                monitor_if = interface
            else:
                # Find the new monitor interface name
                output = result.stdout
                monitor_match = re.search(r'\(monitor mode enabled on (\w+)\)', output)
                if monitor_match:
                    monitor_if = monitor_match.group(1)
                else:
                    # Usually adds 'mon' suffix
                    monitor_if = interface + 'mon' if not interface.endswith('mon') else interface
            
            # Verify monitor mode
            time.sleep(1)
            status = self.get_interface_status(monitor_if)
            
            if status['mode'] == 'monitor':
                self.monitor_interface = monitor_if
                self.managed_interface = interface
                self.monitor_mode_active = True
                logger.info(f"Monitor mode enabled on {monitor_if}")
                return {'success': True, 'interface': monitor_if, 'message': 'Monitor mode enabled'}
            else:
                return {'success': False, 'message': 'Failed to enable monitor mode'}
                
        except Exception as e:
            logger.error(f"Error enabling monitor mode: {e}")
            return {'success': False, 'message': str(e)}
    
    def disable_monitor_mode(self, interface):
        """Disable monitor mode and restore managed mode"""
        try:
            # Find the base interface name
            base_interface = interface.replace('mon', '') if interface.endswith('mon') else interface
            
            # Stop any conflicting processes
            self._kill_conflicting_processes(interface)
            
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                          capture_output=True, timeout=5)
            time.sleep(0.5)
            
            # Use airmon-ng to stop monitor mode
            result = subprocess.run(['airmon-ng', 'stop', interface], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                # Try alternative method
                subprocess.run(['iw', interface, 'set', 'type', 'managed'], 
                             capture_output=True, timeout=5)
            
            # Verify managed mode
            time.sleep(1)
            status = self.get_interface_status(base_interface)
            
            if status['mode'] == 'managed' or status['mode'] == 'unknown':
                self.monitor_interface = None
                self.managed_interface = base_interface
                self.monitor_mode_active = False
                logger.info(f"Monitor mode disabled, restored {base_interface}")
                return {'success': True, 'interface': base_interface, 'message': 'Monitor mode disabled'}
            else:
                return {'success': False, 'message': 'Failed to disable monitor mode'}
                
        except Exception as e:
            logger.error(f"Error disabling monitor mode: {e}")
            return {'success': False, 'message': str(e)}
    
    def _kill_conflicting_processes(self, interface):
        """Kill processes that might interfere with monitor mode"""
        try:
            result = subprocess.run(['airmon-ng', 'check', 'kill'], 
                                  capture_output=True, text=True, timeout=10)
            # Note: This may kill network manager, which is expected
        except Exception as e:
            logger.debug(f"Error killing conflicting processes: {e}")
    
    def assign_adapters(self, monitor_adapter=None, attack_adapter=None, prevention_adapter=None):
        """Assign adapters to monitor, attack, and prevention roles"""
        # Check for duplicate assignments
        adapters = [monitor_adapter, attack_adapter, prevention_adapter]
        adapters = [a for a in adapters if a]  # Remove None values
        if len(adapters) != len(set(adapters)):
            return {'success': False, 'message': 'Same adapter cannot be used for multiple roles'}
        
        interfaces = self.get_wifi_interfaces()
        
        # Extract interface names from the list (handle both dict and string formats)
        interface_names = []
        for iface in interfaces:
            if isinstance(iface, dict):
                interface_names.append(iface['name'])
            else:
                interface_names.append(iface)
        
        # Validate adapters exist
        if monitor_adapter and monitor_adapter not in interface_names:
            return {'success': False, 'message': f'Monitor adapter {monitor_adapter} not found'}
        if attack_adapter and attack_adapter not in interface_names:
            return {'success': False, 'message': f'Attack adapter {attack_adapter} not found'}
        if prevention_adapter and prevention_adapter not in interface_names:
            return {'success': False, 'message': f'Prevention adapter {prevention_adapter} not found'}
        
        # Update assignments (None means don't change)
        if monitor_adapter is not None:
            self.monitor_adapter = monitor_adapter
        if attack_adapter is not None:
            self.attack_adapter = attack_adapter
        if prevention_adapter is not None:
            self.prevention_adapter = prevention_adapter
        
        logger.info(f"Adapters assigned: Monitor={self.monitor_adapter}, Attack={self.attack_adapter}, Prevention={self.prevention_adapter}")
        
        return {'success': True, 'message': 'Adapters assigned successfully'}
    
    def deassign_all_adapters(self):
        """Deassign all adapters"""
        self.monitor_adapter = None
        self.attack_adapter = None
        self.prevention_adapter = None
        logger.info("All adapters deassigned")
        return {'success': True, 'message': 'All adapters deassigned'}
    
    def get_assigned_adapters(self):
        """Get currently assigned adapters"""
        return {
            'monitor_adapter': self.monitor_adapter,
            'attack_adapter': self.attack_adapter,
            'prevention_adapter': self.prevention_adapter
        }
    
    def get_status(self):
        """Get current adapter status"""
        interfaces = self.get_wifi_interfaces()
        
        # Convert to simple list format for backward compatibility
        interface_names = [iface['name'] if isinstance(iface, dict) else iface for iface in interfaces]
        
        # Get prevention adapter status
        prevention_status = None
        if self.prevention_adapter:
            prevention_status = self.get_interface_status(self.prevention_adapter)
        
        status = {
            'interfaces': interfaces,  # Full info with friendly names
            'interface_names': interface_names,  # Simple list for compatibility
            'monitor_mode_active': self.monitor_mode_active,
            'monitor_interface': self.monitor_interface,
            'managed_interface': self.managed_interface,
            'monitor_adapter': self.monitor_adapter,
            'attack_adapter': self.attack_adapter,
            'prevention_adapter': self.prevention_adapter,
            'prevention_status': prevention_status
        }
        
        if self.monitor_interface:
            if_status = self.get_interface_status(self.monitor_interface)
            status['current_interface'] = if_status
        elif interface_names:
            if_status = self.get_interface_status(interface_names[0])
            status['current_interface'] = if_status
        
        return status

