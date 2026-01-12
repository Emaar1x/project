"""
Flask web application for WiFi IDPS Dashboard
"""
import argparse
import threading
import time
import logging
import os
import glob
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from monitor import WiFiMonitor
from database import Database
from prevention import PreventionEngine
from adapter import AdapterController
from scanner import NetworkScanner
from attack_controller import AttackController
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG, INTERFACE

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

# Suppress werkzeug HTTP request logs (too verbose)
logging.getLogger('werkzeug').setLevel(logging.WARNING)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'widps_secret_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global monitor instance
monitor = None
db = Database()
prevention = None
adapter_controller = AdapterController()
scanner = NetworkScanner()
attack_controller = AttackController()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/testing')
def testing():
    """Testing lab page"""
    return render_template('testing.html')

@app.route('/prevention')
def prevention_dashboard():
    """Prevention dashboard page"""
    return render_template('prevention.html')

@app.route('/api/status')
def get_status():
    """Get monitoring status"""
    if monitor:
        status = monitor.get_status()
        return jsonify(status)
    return jsonify({'running': False, 'interface': INTERFACE})

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    try:
        limit = request.args.get('limit', 100, type=int)
        alerts = db.get_recent_alerts(limit=limit)
        logger.debug(f"Returning {len(alerts)} alerts (limit={limit})")
        return jsonify(alerts)
    except Exception as e:
        logger.error(f"Error getting alerts: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<alert_type>')
def get_alerts_by_type(alert_type):
    """Get alerts by type"""
    limit = request.args.get('limit', 50, type=int)
    alerts = db.get_alerts_by_type(alert_type, limit)
    return jsonify(alerts)

@app.route('/api/statistics')
def get_statistics():
    """Get statistics"""
    hours = request.args.get('hours', 24, type=int)
    stats = db.get_statistics(hours)
    return jsonify(stats)

@app.route('/api/attack-summary')
def get_attack_summary():
    """Get attack summary"""
    summary = db.get_attack_summary()
    return jsonify(summary)

@app.route('/api/devices')
def get_devices():
    """Get detected devices"""
    cursor = db.conn.cursor()
    cursor.execute('''
        SELECT * FROM devices
        ORDER BY last_seen DESC
        LIMIT 100
    ''')
    devices = [dict(row) for row in cursor.fetchall()]
    return jsonify(devices)

@app.route('/api/access-points')
def get_access_points():
    """Get access points"""
    cursor = db.conn.cursor()
    cursor.execute('''
        SELECT * FROM access_points
        ORDER BY last_seen DESC
        LIMIT 100
    ''')
    aps = [dict(row) for row in cursor.fetchall()]
    return jsonify(aps)

@app.route('/api/prevention/status')
def get_prevention_status():
    """Get prevention status"""
    global prevention
    try:
        if not prevention:
            prevention = PreventionEngine()
        stats = prevention.get_stats()
        stats['blocked_macs'] = prevention.get_blocked_macs()
        stats['block_duration'] = prevention.block_duration
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting prevention status: {e}", exc_info=True)
        return jsonify({
            'enabled': False,
            'auto_block': False,
            'blocked_macs': {},
            'block_duration': 300,
            'error': str(e)
        })

@app.route('/api/prevention/enable', methods=['POST'])
def enable_prevention():
    """Enable prevention mode"""
    global prevention
    if not prevention:
        # Get interfaces if available
        monitor_interface = None
        prevention_interface = None
        if monitor:
            monitor_interface = monitor.interface
        # Get prevention adapter from adapter controller
        assigned = adapter_controller.get_assigned_adapters()
        prevention_interface = assigned.get('prevention_adapter')
        prevention = PreventionEngine(monitor_interface=monitor_interface, 
                                    prevention_interface=prevention_interface)
    prevention.enable()
    if monitor:
        monitor.enable_prevention()
        # Update prevention interface
        prevention.set_monitor_interface(monitor.interface)
    # Update prevention adapter if assigned
    assigned = adapter_controller.get_assigned_adapters()
    if assigned.get('prevention_adapter'):
        prevention.set_prevention_interface(assigned['prevention_adapter'])
    return jsonify({'status': 'enabled', 'auto_block': prevention.auto_block})

@app.route('/api/prevention/disable', methods=['POST'])
def disable_prevention():
    """Disable prevention mode"""
    global prevention
    if not prevention:
        prevention = PreventionEngine()
    prevention.disable()
    if monitor:
        monitor.disable_prevention()
    return jsonify({'status': 'disabled'})

@app.route('/api/prevention/logs')
def get_prevention_logs():
    """Get prevention action logs"""
    try:
        logs = db.get_prevention_logs(limit=50)
        return jsonify(logs)
    except Exception as e:
        logger.error(f"Error getting prevention logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/adapter/status')
def get_adapter_status():
    """Get adapter status"""
    status = adapter_controller.get_status()
    return jsonify(status)

@app.route('/api/adapter/start', methods=['POST'])
def start_adapter():
    """Start monitor mode and begin monitoring"""
    global monitor, prevention
    
    try:
        data = request.get_json() or {}
        interface = data.get('interface', INTERFACE)
        
        # Enable monitor mode
        result = adapter_controller.enable_monitor_mode(interface)
        
        if not result['success']:
            return jsonify({'success': False, 'message': result['message']}), 400
        
        monitor_interface = result['interface']
        
        # Start monitoring if not already running
        if monitor and monitor.running:
            return jsonify({
                'success': True,
                'message': 'Monitoring already running',
                'interface': monitor_interface
            })
        
        # Create and start monitor
        monitor = WiFiMonitor(interface=monitor_interface)
        prevention = PreventionEngine(monitor_interface=monitor_interface)
        # Link prevention to monitor's detector
        monitor.detector.prevention = prevention
        monitor.start()
        
        return jsonify({
            'success': True,
            'message': 'Monitor mode enabled and monitoring started',
            'interface': monitor_interface
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/adapter/stop', methods=['POST'])
def stop_adapter():
    """Stop monitoring and disable monitor mode"""
    global monitor
    
    try:
        # Stop monitoring
        if monitor and monitor.running:
            monitor.stop()
            time.sleep(1)  # Give time for threads to stop
        
        # Get current monitor interface
        monitor_interface = None
        if monitor:
            monitor_interface = monitor.interface
        elif adapter_controller.monitor_interface:
            monitor_interface = adapter_controller.monitor_interface
        else:
            # Try to find monitor interface
            status = adapter_controller.get_status()
            if status.get('current_interface') and status['current_interface'].get('monitor_mode'):
                monitor_interface = status['current_interface']['interface']
        
        if monitor_interface:
            # Disable monitor mode
            result = adapter_controller.disable_monitor_mode(monitor_interface)
            return jsonify({
                'success': True,
                'message': 'Monitoring stopped and monitor mode disabled',
                'result': result
            })
        else:
            return jsonify({
                'success': True,
                'message': 'Monitoring stopped (no monitor interface found)'
            })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/monitor/start', methods=['POST'])
def start_monitoring():
    """Start packet capture on existing monitor interface"""
    global monitor, prevention
    
    try:
        if monitor and monitor.running:
            logger.warning("Monitoring already running, stopping first")
            monitor.stop()
            time.sleep(1)
        
        # Get monitor adapter assignment
        status = adapter_controller.get_status()
        monitor_adapter = status.get('monitor_adapter')
        
        if not monitor_adapter:
            return jsonify({'success': False, 'message': 'No monitor adapter assigned. Please assign a monitor adapter first.'}), 400
        
        logger.info(f"Starting monitoring on assigned adapter: {monitor_adapter}")
        
        # Check if monitor mode is already enabled
        if_status = adapter_controller.get_interface_status(monitor_adapter)
        if if_status['mode'] == 'monitor':
            monitor_interface = monitor_adapter
            logger.info(f"Using existing monitor interface: {monitor_interface}")
        else:
            # Enable monitor mode
            logger.info(f"Enabling monitor mode on {monitor_adapter}")
            result = adapter_controller.enable_monitor_mode(monitor_adapter)
            if not result['success']:
                return jsonify({'success': False, 'message': f"Failed to enable monitor mode: {result.get('message')}"}), 400
            monitor_interface = result['interface']
            logger.info(f"Monitor mode enabled, using interface: {monitor_interface}")
        
        # Verify interface exists and is in monitor mode
        verify_status = adapter_controller.get_interface_status(monitor_interface)
        if verify_status['mode'] != 'monitor':
            return jsonify({'success': False, 'message': f"Interface {monitor_interface} is not in monitor mode"}), 400
        
        # Create prevention engine with monitor interface
        if not prevention:
            prevention = PreventionEngine(monitor_interface=monitor_interface)
        else:
            prevention.set_monitor_interface(monitor_interface)
        
        if not verify_status['up']:
            logger.warning(f"Interface {monitor_interface} is down, bringing it up")
            subprocess.run(['ip', 'link', 'set', monitor_interface, 'up'], capture_output=True, timeout=5)
            time.sleep(1)
        
        # Start monitoring
        logger.info(f"Creating WiFiMonitor instance for interface: {monitor_interface}")
        monitor = WiFiMonitor(interface=monitor_interface)
        if not prevention:
            prevention = PreventionEngine(monitor_interface=monitor_interface)
        else:
            prevention.set_monitor_interface(monitor_interface)
        # Link prevention to monitor's detector
        monitor.detector.prevention = prevention
        logger.info("Starting monitor...")
        monitor.start()
        
        # Give it a moment to start
        time.sleep(1)
        
        if not monitor.running:
            return jsonify({'success': False, 'message': 'Monitor failed to start'}), 500
        
        logger.info(f"✅ Monitoring started successfully on {monitor_interface}")
        
        return jsonify({
            'success': True,
            'message': 'Monitoring started',
            'interface': monitor_interface
        })
        
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/monitor/stop', methods=['POST'])
def stop_monitoring():
    """Stop packet capture"""
    global monitor
    
    try:
        if monitor and monitor.running:
            monitor.stop()
            return jsonify({'success': True, 'message': 'Monitoring stopped'})
        else:
            return jsonify({'success': False, 'message': 'Monitoring not running'}), 400
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/adapters')
def get_adapters():
    """Get all available WiFi adapters with friendly names"""
    status = adapter_controller.get_status()
    
    # Log adapter query
    logger.info("Adapter list requested")
    
    return jsonify({
        'interfaces': status['interfaces'],  # Full info with friendly names
        'interface_names': status.get('interface_names', []),  # Simple names
        'monitor_adapter': status.get('monitor_adapter'),
        'attack_adapter': status.get('attack_adapter'),
        'prevention_adapter': status.get('prevention_adapter')
    })

@app.route('/api/adapters/assign', methods=['POST'])
def assign_adapters():
    """Assign adapters to monitor, attack, and prevention roles"""
    try:
        data = request.get_json() or {}
        monitor_adapter = data.get('monitor_adapter')
        attack_adapter = data.get('attack_adapter')
        prevention_adapter = data.get('prevention_adapter')
        
        # Log assignment
        logger.info(f"Adapter assignment requested: Monitor={monitor_adapter}, Attack={attack_adapter}, Prevention={prevention_adapter}")
        
        result = adapter_controller.assign_adapters(
            monitor_adapter=monitor_adapter,
            attack_adapter=attack_adapter,
            prevention_adapter=prevention_adapter
        )
        
        if result['success']:
            # Update prevention interface if prevention adapter is assigned
            try:
                global prevention
                if prevention_adapter:
                    # Initialize prevention if not exists
                    if not prevention:
                        prevention = PreventionEngine()
                    prevention.set_prevention_interface(prevention_adapter)
                    # Enable monitor mode on prevention adapter
                    adapter_controller.enable_monitor_mode(prevention_adapter)
            except Exception as e:
                logger.error(f"Error setting prevention interface: {e}")
            
            # Log successful assignment
            logger.info(f"Adapters assigned successfully: Monitor={monitor_adapter}, Attack={attack_adapter}, Prevention={prevention_adapter}")
            return jsonify(result)
        else:
            logger.warning(f"Adapter assignment failed: {result.get('message')}")
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Error assigning adapters: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/adapters/deassign', methods=['POST'])
def deassign_adapters():
    """Deassign all adapters"""
    try:
        result = adapter_controller.deassign_all_adapters()
        logger.info("All adapters deassigned")
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error deassigning adapters: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start network scan"""
    try:
        data = request.get_json() or {}
        interface = data.get('interface')
        
        if not interface:
            # Use attack adapter if available
            assigned = adapter_controller.get_assigned_adapters()
            interface = assigned.get('attack_adapter')
        
        if not interface:
            return jsonify({'success': False, 'message': 'No attack adapter assigned'}), 400
        
        # Prevent using monitor adapter for scanning
        assigned = adapter_controller.get_assigned_adapters()
        if interface == assigned.get('monitor_adapter'):
            return jsonify({'success': False, 'message': 'Cannot use monitor adapter for scanning'}), 400
        
        logger.info(f"Starting network scan on interface: {interface}")
        result = scanner.start_scan(interface)
        
        if result['success']:
            logger.info(f"Network scan started successfully on {interface}")
        else:
            logger.warning(f"Failed to start network scan: {result.get('message')}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    """Stop network scan"""
    try:
        result = scanner.stop_scan()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/scan/results')
def get_scan_results():
    """Get scan results"""
    try:
        results = scanner.get_results()
        logger.debug(f"Returning scan results: {results.get('count', 0)} networks")
        return jsonify(results)
    except Exception as e:
        logger.error(f"Error getting scan results: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/scan/debug')
def debug_scan():
    """Debug endpoint to check scan status and CSV files"""
    try:
        import glob
        csv_files = glob.glob('/tmp/widps_scan_*.csv')
        debug_info = {
            'scanning': scanner.scanning,
            'attack_adapter': scanner.attack_adapter,
            'results_count': len(scanner.scan_results),
            'csv_files': csv_files,
            'last_scan': scanner.last_scan_time
        }
        
        # Try to read the most recent CSV file
        if csv_files:
            latest_csv = max(csv_files, key=os.path.getmtime)
            try:
                with open(latest_csv, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
                    debug_info['latest_csv'] = latest_csv
                    debug_info['csv_line_count'] = len(lines)
                    debug_info['csv_first_10_lines'] = lines[:10]
                    debug_info['csv_size'] = len(content)
            except Exception as e:
                debug_info['csv_read_error'] = str(e)
        
        return jsonify(debug_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attack/start', methods=['POST'])
def start_attack():
    """Start attack (LAB ONLY)"""
    try:
        data = request.get_json() or {}
        attack_type = data.get('attack_type')
        target = data.get('target')  # {bssid, ssid, channel}
        
        if not attack_type or not target:
            return jsonify({'success': False, 'message': 'Missing attack type or target'}), 400
        
        # Get attack adapter
        assigned = adapter_controller.get_assigned_adapters()
        interface = assigned.get('attack_adapter')
        
        if not interface:
            return jsonify({'success': False, 'message': 'No attack adapter assigned'}), 400
        
        # Prevent using monitor adapter
        if interface == assigned.get('monitor_adapter'):
            return jsonify({'success': False, 'message': 'Cannot use monitor adapter for attacks'}), 400
        
        bssid = target.get('bssid')
        ssid = target.get('ssid')
        channel = target.get('channel')
        
        # Set monitor interface to same channel as attack (if monitoring is active)
        if monitor and monitor.running and channel:
            logger.info(f"Setting monitor interface to channel {channel} to capture attack packets")
            monitor.set_channel(channel)
        
        if attack_type == 'deauth':
            result = attack_controller.start_deauth_attack(interface, bssid, channel)
        elif attack_type == 'handshake':
            result = attack_controller.start_handshake_capture(interface, bssid, channel, ssid)
        elif attack_type == 'rogue_ap':
            result = attack_controller.start_rogue_ap(interface, ssid, channel, bssid)
        else:
            return jsonify({'success': False, 'message': 'Invalid attack type'}), 400
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/attack/stop', methods=['POST'])
def stop_attack():
    """Stop current attack"""
    try:
        result = attack_controller.stop_attack()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/attack/stop-all', methods=['POST'])
def stop_all_attacks():
    """Stop all active attacks"""
    try:
        result = attack_controller.stop_all_attacks()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/reset', methods=['POST'])
def reset_system():
    """Reset system to initial state"""
    try:
        # Stop all attacks
        attack_controller.stop_all_attacks()
        
        # Stop monitoring
        global monitor
        if monitor and monitor.running:
            monitor.stop()
        
        # Stop network scanner
        scanner.stop_scan()
        
        # Deassign all adapters
        adapter_controller.deassign_all_adapters()
        
        # Disable monitor mode on all interfaces
        interfaces = adapter_controller.get_wifi_interfaces()
        for iface in interfaces:
            iface_name = iface['name'] if isinstance(iface, dict) else iface
            try:
                # Check if in monitor mode
                status = adapter_controller.get_interface_status(iface_name)
                if status.get('mode') == 'monitor':
                    adapter_controller.disable_monitor_mode(iface_name)
            except:
                pass
        
        # Clear attack logs (optional - user might want to keep them)
        # db.clear_attack_logs()  # Uncomment if you want to clear logs too
        
        logger.info("System reset completed")
        return jsonify({'success': True, 'message': 'System reset completed'})
    except Exception as e:
        logger.error(f"Error resetting system: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/attack/status')
def get_attack_status():
    """Get attack status"""
    try:
        status = attack_controller.get_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/attack/logs')
def get_attack_logs():
    """Get attack logs"""
    try:
        limit = request.args.get('limit', 50, type=int)
        logs = db.get_attack_logs(limit)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    emit('connected', {'data': 'Connected to WiFi IDPS'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    pass

def background_update():
    """Background thread to send updates via WebSocket"""
    logger.info("Background update thread started")
    update_count = 0
    while True:
        try:
            time.sleep(2)  # Update every 2 seconds
            
            # Get current status
            status_data = {}
            if monitor:
                try:
                    status_data['status'] = monitor.get_status()
                except Exception as e:
                    logger.error(f"Error getting monitor status: {e}")
                    status_data['status'] = {'running': False, 'packet_count': 0}
            else:
                status_data['status'] = {'running': False, 'packet_count': 0}
            
            # Get adapter status
            try:
                adapter_status = adapter_controller.get_status()
            except Exception as e:
                logger.error(f"Error getting adapter status: {e}")
                adapter_status = {}
            
            # Get recent alerts
            try:
                alerts = db.get_recent_alerts(limit=10)
                if not alerts:
                    alerts = []
            except Exception as e:
                logger.error(f"Error getting alerts: {e}")
                alerts = []
            
            # Get statistics
            try:
                summary = db.get_attack_summary()
                if not summary:
                    summary = {}
                # Ensure summary has all expected keys with default 0
                if 'Deauthentication Attack' not in summary:
                    summary['Deauthentication Attack'] = 0
                if 'Rogue Access Point' not in summary:
                    summary['Rogue Access Point'] = 0
                if 'Handshake Capture' not in summary:
                    summary['Handshake Capture'] = 0
            except Exception as e:
                logger.error(f"Error getting attack summary: {e}")
                summary = {
                    'Deauthentication Attack': 0,
                    'Rogue Access Point': 0,
                    'Handshake Capture': 0
                }
            
            try:
                statistics = db.get_statistics(hours=1)  # Get last hour of statistics
                if not statistics:
                    statistics = []
            except Exception as e:
                logger.error(f"Error getting statistics: {e}")
                statistics = []
            
            # Prepare update data
            update_data = {
                'status': status_data.get('status', {}),
                'adapter_status': adapter_status,
                'alerts': alerts,
                'summary': summary,
                'statistics': statistics,
                'timestamp': time.time()
            }
            
            # Log update every 30 seconds for debugging
            update_count += 1
            if update_count % 15 == 0:  # Every 30 seconds (15 * 2 seconds)
                logger.debug(f"Background update #{update_count}: "
                           f"Status={status_data.get('status', {}).get('running', False)}, "
                           f"Alerts={len(alerts)}, "
                           f"Summary={summary}, "
                           f"Stats={len(statistics)}")
            
            # Send update via WebSocket (broadcast to all connected clients)
            # Note: Flask-SocketIO broadcasts by default when no 'to' parameter is specified
            socketio.emit('update', update_data)
            
            # Send prevention-specific update if prevention is enabled
            try:
                if prevention and hasattr(prevention, 'is_enabled') and prevention.is_enabled():
                    prevention_stats = prevention.get_stats()
                    prevention_logs = db.get_prevention_logs(limit=20)
                    socketio.emit('prevention_update', {
                        'status': prevention_stats,
                        'blocked_macs': prevention.get_blocked_macs(),
                        'logs': prevention_logs,
                        'timestamp': time.time()
                    })
            except Exception as e:
                logger.debug(f"Error sending prevention update: {e}")
            
        except Exception as e:
            logger.error(f"Error in background update: {e}", exc_info=True)
            time.sleep(5)  # Wait longer on error before retrying

def start_monitor(interface):
    """Start the WiFi monitor"""
    global monitor, prevention
    monitor = WiFiMonitor(interface=interface)
    if not prevention:
        prevention = PreventionEngine(monitor_interface=interface)
    else:
        prevention.set_monitor_interface(interface)
    # Link prevention to monitor's detector
    monitor.detector.prevention = prevention
    monitor.start()
    print(f"WiFi monitor started on interface: {interface}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='WiFi Intrusion Detection and Prevention System')
    parser.add_argument('--interface', '-i', default=None,
                       help='Network interface (optional - select in web UI)')
    parser.add_argument('--host', default=FLASK_HOST,
                       help=f'Flask host (default: {FLASK_HOST})')
    parser.add_argument('--port', '-p', type=int, default=FLASK_PORT,
                       help=f'Flask port (default: {FLASK_PORT})')
    parser.add_argument('--debug', action='store_true', default=FLASK_DEBUG,
                       help='Enable debug mode')
    parser.add_argument('--auto-start', action='store_true',
                       help='Automatically start monitoring on startup (requires --interface)')
    
    args = parser.parse_args()
    
    # Start background update thread
    update_thread = threading.Thread(target=background_update, daemon=True)
    update_thread.start()
    
    print(f"\n{'='*60}")
    print("WiFi Intrusion Detection and Prevention System (WIDPS)")
    print(f"{'='*60}")
    print(f"🌐 Dashboard: http://{args.host}:{args.port}")
    print(f"📡 Use the web dashboard to select adapters and start monitoring")
    if args.auto_start and args.interface:
        print(f"⚡ Auto-start enabled, starting monitor on {args.interface}...")
        monitor_thread = threading.Thread(target=start_monitor, args=(args.interface,), daemon=True)
        monitor_thread.start()
        time.sleep(2)
    elif args.auto_start:
        print(f"⚠️  Auto-start requires --interface parameter")
    print(f"{'='*60}\n")
    
    # Run Flask app
    socketio.run(app, host=args.host, port=args.port, debug=args.debug, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    main()

