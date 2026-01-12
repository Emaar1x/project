"""
Packet capture and monitoring for WiFi IDPS
"""
import threading
import logging
from scapy.all import sniff, Dot11
from scapy.config import conf
from config import INTERFACE, PCAP_PATH
from detection import AttackDetector
from prevention import PreventionEngine
from database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WiFiMonitor:
    def __init__(self, interface=INTERFACE):
        self.interface = interface
        self.detector = AttackDetector()
        self.prevention = PreventionEngine(monitor_interface=interface)
        # Link prevention to detector so it can be called on alerts
        self.detector.prevention = self.prevention
        self.db = Database()
        self.running = False
        self.sniff_thread = None
        self.packet_count = 0
        self.pcap_writer = None
        self.current_channel = None
        
        # Statistics update interval
        self.stats_interval = 60  # seconds
        self.last_stats_update = None
    
    def set_channel(self, channel):
        """Set the monitor interface to a specific channel"""
        try:
            import subprocess
            result = subprocess.run(['iwconfig', self.interface, 'channel', str(channel)], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.current_channel = channel
                logger.info(f"Monitor interface {self.interface} set to channel {channel}")
                return True
            else:
                logger.warning(f"Failed to set channel {channel} on {self.interface}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error setting channel: {e}")
            return False
    
    def start(self):
        """Start monitoring"""
        if self.running:
            logger.warning("Monitor is already running")
            return
        
        self.running = True
        logger.info(f"Starting WiFi monitoring on interface: {self.interface}")
        
        # Start packet capture in separate thread
        self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniff_thread.start()
        
        # Start statistics update thread
        stats_thread = threading.Thread(target=self._update_statistics, daemon=True)
        stats_thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        logger.info("Stopping WiFi monitoring")
        if self.pcap_writer:
            self.pcap_writer.close()
    
    def _sniff_packets(self):
        """Sniff packets from the interface"""
        try:
            # Configure Scapy to use the interface
            conf.iface = self.interface
            
            logger.info(f"Sniffing packets on {self.interface}...")
            logger.info(f"Monitor running: {self.running}, interface: {self.interface}")
            
            # Start packet capture with timeout to allow checking running status
            while self.running:
                try:
                    sniff(
                        iface=self.interface,
                        prn=self._process_packet,
                        stop_filter=lambda x: not self.running,
                        store=False,  # Don't store packets in memory
                        timeout=1  # Check every second if still running
                    )
                except Exception as sniff_error:
                    if self.running:
                        logger.error(f"Error in sniff: {sniff_error}", exc_info=True)
                        import time
                        time.sleep(0.5)
                    else:
                        break
        except Exception as e:
            logger.error(f"Error in packet capture: {e}", exc_info=True)
            self.running = False
    
    def _process_packet(self, packet):
        """Process a captured packet"""
        if not self.running:
            return
        
        try:
            self.packet_count += 1
            
            # Log first few packets to verify capture is working
            if self.packet_count <= 5:
                logger.info(f"📦 Packet #{self.packet_count} captured on {self.interface}")
            
            # Process packet through detector
            self.detector.process_packet(packet)
            
            # Log packet types for debugging (every 1000 packets)
            if self.packet_count % 1000 == 0:
                stats = self.detector.get_statistics()
                logger.info(f"📊 Stats: {self.packet_count} packets | Deauth: {stats['deauth_attacks']} | EAPOL: {stats['eapol_attacks']} | Rogue: {stats['rogue_aps']}")
            
            # Log deauth packets for debugging (every deauth packet)
            try:
                from scapy.all import Dot11Deauth
                if packet.haslayer(Dot11Deauth):
                    attacker = packet.addr2 if hasattr(packet, 'addr2') else 'Unknown'
                    victim = packet.addr1 if hasattr(packet, 'addr1') else 'Unknown'
                    logger.warning(f"🚨 DEAUTH PACKET #{self.packet_count} detected on {self.interface}! {attacker} -> {victim}")
            except Exception as e:
                logger.debug(f"Error checking deauth: {e}")
            
            # Write to PCAP file (optional, can be memory intensive)
            # Uncomment if you want to save all packets
            # if self.packet_count % 100 == 0:  # Save every 100th packet to reduce I/O
            #     wrpcap(PCAP_PATH, packet, append=True)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
    
    def _update_statistics(self):
        """Periodically update statistics in database"""
        import time
        from datetime import datetime
        
        while self.running:
            try:
                time.sleep(self.stats_interval)
                
                if not self.running:
                    break
                
                stats = self.detector.get_statistics()
                
                self.db.add_statistics(
                    deauth_count=stats.get('deauth_attacks', 0),
                    eapol_count=stats.get('eapol_attacks', 0),
                    rogue_ap_count=stats.get('rogue_aps', 0),
                    suspicious_mac_count=0,
                    total_packets=stats.get('total_packets', 0)
                )
                
                logger.debug(f"Statistics updated: {stats}")
                
            except Exception as e:
                logger.error(f"Error updating statistics: {e}")
    
    def get_status(self):
        """Get monitoring status"""
        return {
            'running': self.running,
            'interface': self.interface,
            'packet_count': self.packet_count,
            'prevention_enabled': self.prevention.is_enabled()
        }
    
    def enable_prevention(self):
        """Enable prevention mode"""
        self.prevention.enable()
    
    def disable_prevention(self):
        """Disable prevention mode"""
        self.prevention.disable()

