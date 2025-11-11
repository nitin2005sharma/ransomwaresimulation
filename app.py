#!/usr/bin/env python3
"""
OS Security Simulator - Web Application
Flask backend with WebSocket support for real-time updates
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import sys
import json
import threading
import time
from pathlib import Path
from datetime import datetime

# Add src to path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

from core.file_monitor import AdvancedFileMonitor
from core.encrypt_engine import AdvancedEncryptor
from core.threat_detector import ThreatDetector
from core.recovery_system import RecoverySystem
from kernel.memory_manager import EncryptionMemoryManager
from kernel.system_calls import AdvancedSystemCalls
from kernel.process_manager import ProcessManager
from kernel.syscall_tracer import SystemCallTracer
from kernel.process_sandbox import ProcessSandbox
from kernel.disk_io_monitor import DiskIOMonitor
from kernel.network_simulator import NetworkPacketSimulator
from kernel.integrity_monitor import SystemIntegrityMonitor
import psutil

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(24)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

class OSSecuritySimulator:
    """Main simulator with web interface support"""
    
    def __init__(self):
        print("Initializing OS Security Simulator...")
        
        # Load configuration
        self.config = self.load_config()
        self.test_dir = Path(self.config['test_directory'])
        self.backup_dir = Path(self.config['backup_directory'])
        self.ransom_notes_dir = Path(self.config['ransom_notes_directory'])
        
        # Create directories
        self.setup_directories()
        
        # Enhanced OS components
        print("Initializing kernel components...")
        self.system_calls = AdvancedSystemCalls()
        self.memory_manager = EncryptionMemoryManager()
        self.process_manager = ProcessManager()
        
        # New OS features
        self.syscall_tracer = SystemCallTracer()
        self.process_sandbox = ProcessSandbox()
        self.disk_io_monitor = DiskIOMonitor()
        self.network_simulator = NetworkPacketSimulator()
        self.integrity_monitor = SystemIntegrityMonitor()
        
        # Register callbacks for new components
        self.syscall_tracer.register_callback(self.on_syscall_traced)
        self.disk_io_monitor.register_callback(self.on_disk_io)
        self.network_simulator.register_callback(self.on_network_packet)
        self.integrity_monitor.register_callback(self.on_integrity_violation)
        
        # Core simulation components
        self.file_monitor = AdvancedFileMonitor(self.test_dir)
        self.encryptor = AdvancedEncryptor()
        self.threat_detector = ThreatDetector()
        self.recovery_system = RecoverySystem(self.test_dir, self.backup_dir)
        
        # Simulation state
        self.simulation_active = False
        self.encryption_key = None
        self.encrypted_files = []
        self.detected_threats = []
        self.system_call_log = []
        self.disk_io_log = []
        
        # Create sandbox for simulation
        self.ransomware_sandbox = self.process_sandbox.create_sandbox(
            'ransomware_sim',
            {
                'allowed_paths': [str(self.test_dir)],
                'denied_paths': ['/etc', '/sys'],
                'network_allowed': True,  # For C2 simulation
                'file_write_allowed': True,
                'execution_allowed': False
            }
        )
        
        print("✓ OS Security Simulator initialized successfully!")
    
    def load_config(self):
        """Load configuration from JSON file"""
        config_path = Path(__file__).parent / 'config' / 'config.json'
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            print("✓ Configuration loaded")
            return config
        except Exception as e:
            print(f"⚠ Config load error: {e}, using defaults")
            return {
                "test_directory": "./data/test_files",
                "backup_directory": "./data/backups",
                "ransom_notes_directory": "./data/ransom_notes",
                "log_directory": "./data/logs"
            }
    
    def setup_directories(self):
        """Create necessary directories"""
        self.test_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.ransom_notes_dir.mkdir(parents=True, exist_ok=True)
        self.create_sample_files()
    
    def create_sample_files(self):
        """Create sample files for simulation"""
        sample_files = {
            "important_document.docx": "This is an important business document.",
            "financial_report.xlsx": "Quarterly financial report.",
            "customer_data.csv": "Customer information and contact details.",
            "project_plan.pdf": "Project timeline and resource allocation.",
            "personal_notes.txt": "Personal notes and reminders.",
            "backup_config.json": "System backup configuration.",
            "meeting_minutes.doc": "Minutes from team meeting.",
            "budget_planning.xls": "Annual budget planning."
        }
        
        created_count = 0
        for filename, content in sample_files.items():
            file_path = self.test_dir / filename
            if not file_path.exists():
                with open(file_path, 'w') as f:
                    f.write(content)
                created_count += 1
        
        print(f"✓ Created {created_count} sample files")
    
    def start_simulation(self):
        """Start the ransomware simulation"""
        if self.simulation_active:
            return {"success": False, "message": "Simulation already active"}
        
        try:
            self.simulation_active = True
            self.encryption_key = self.encryptor.generate_key()
            
            # Register files for integrity monitoring
            for file_path in self.test_dir.iterdir():
                if file_path.is_file():
                    self.integrity_monitor.register_critical_file(file_path)
            
            # Add simulation process to sandbox
            self.process_sandbox.add_process_to_sandbox(
                'ransomware_sim',
                os.getpid(),
                'ransomware_simulation'
            )
            
            # Start monitoring
            self.file_monitor.start_monitoring(self.file_event_callback)
            self.threat_detector.start_detection(self.threat_callback)
            
            # Create ransom note
            self.create_ransom_note()
            
            # Simulate initial C2 communication
            threading.Thread(target=self.simulate_c2_beacon, daemon=True).start()
            
            # Emit status update
            socketio.emit('simulation_status', {
                'status': 'started',
                'message': 'Simulation started - Creating ransom note...'
            })
            
            # Start encryption in background
            threading.Thread(target=self.encrypt_files, daemon=True).start()
            
            return {"success": True, "message": "Simulation started"}
        except Exception as e:
            self.simulation_active = False
            return {"success": False, "message": f"Error: {str(e)}"}
    
    def encrypt_files(self):
        """Encrypt files in the test directory"""
        try:
            files = [f for f in self.test_dir.iterdir() if f.is_file() and not f.name.startswith("!!!_")]
            total = len(files)
            
            for idx, file_path in enumerate(files):
                # Check sandbox permissions for write operation
                allowed, reason = self.process_sandbox.check_access(
                    'ransomware_sim', 
                    'file_write', 
                    str(file_path)
                )
                
                if not allowed:
                    socketio.emit('sandbox_violation', {
                        'operation': 'file_write',
                        'target': str(file_path),
                        'reason': reason
                    })
                    continue
                
                # Log disk I/O operation (simulated write)
                start_time = time.time()
                file_size = file_path.stat().st_size
                
                if self.encryptor.encrypt_file(file_path, self.encryption_key):
                    encrypted_path = Path(str(file_path) + ".encrypted")
                    self.encrypted_files.append(encrypted_path)
                    
                    duration_ms = (time.time() - start_time) * 1000
                    
                    # Log disk I/O
                    self.disk_io_monitor.log_io_operation(
                        'write',
                        str(file_path),
                        file_size,
                        duration_ms
                    )
                    
                    # Log system calls (read original, write encrypted)
                    self.log_system_call('read', str(file_path), 'kernel')
                    self.log_system_call('write', str(encrypted_path), 'kernel')
                    
                    # Check integrity violation
                    self.integrity_monitor.check_file_integrity(file_path)
                    
                    # Emit progress
                    socketio.emit('encryption_progress', {
                        'current': idx + 1,
                        'total': total,
                        'filename': file_path.name,
                        'progress': ((idx + 1) / total) * 100
                    })
                    
                    time.sleep(0.1)
            
            socketio.emit('simulation_status', {
                'status': 'completed',
                'message': f'Simulation complete! {len(self.encrypted_files)} files encrypted'
            })
        except Exception as e:
            print(f"Encryption error: {e}")
            socketio.emit('simulation_status', {
                'status': 'error',
                'message': f'Encryption error: {str(e)}'
            })
    
    def create_ransom_note(self):
        """Create ransom note"""
        ransom_note_content = f"""
================================================================
                       !!! WARNING !!!
                      YOUR FILES ARE ENCRYPTED
================================================================

What Happened?
-------------
Your important files have been encrypted using military-grade AES-256 encryption.

Your files (.docx, .xlsx, .pdf, .txt, etc.) are now inaccessible.
Any attempt to modify, delete, or recover files without our tool will cause PERMANENT data loss.

How to Recover Your Files?
--------------------------
This is an educational simulation for OS security research.
Use the recovery button to decrypt your files.

================================================================
No actual harm has been done to your system.
This is for educational purposes only.
================================================================
"""
        
        ransom_note_path = self.test_dir / "!!!_READ_ME_IMPORTANT_!!!.txt"
        
        # Check sandbox permissions for ransom note creation
        allowed, reason = self.process_sandbox.check_access(
            'ransomware_sim',
            'file_write',
            str(ransom_note_path)
        )
        
        if not allowed:
            socketio.emit('sandbox_violation', {
                'operation': 'file_write',
                'target': str(ransom_note_path),
                'reason': reason
            })
            return ransom_note_content
        
        # Write ransom note
        start_time = time.time()
        with open(ransom_note_path, 'w') as f:
            f.write(ransom_note_content)
        duration_ms = (time.time() - start_time) * 1000
        
        # Log disk I/O
        self.disk_io_monitor.log_io_operation(
            'write',
            str(ransom_note_path),
            len(ransom_note_content.encode()),
            duration_ms
        )
        
        # Log system call
        self.log_system_call('write', str(ransom_note_path), 'kernel')
        
        return ransom_note_content
    
    def file_event_callback(self, event):
        """Callback for file system events"""
        threat_level = self.threat_detector.analyze_file_event(event)
        
        if threat_level > 0:
            threat_info = {
                'timestamp': time.time(),
                'event': event,
                'threat_level': threat_level,
                'description': self.threat_detector.get_threat_description(event)
            }
            self.detected_threats.append(threat_info)
            
            # Emit threat detection
            socketio.emit('threat_detected', {
                'timestamp': datetime.fromtimestamp(threat_info['timestamp']).strftime('%H:%M:%S'),
                'level': ['LOW', 'MEDIUM', 'HIGH'][min(threat_level - 1, 2)],
                'filename': event.get('name', 'Unknown'),
                'description': threat_info['description']
            })
    
    def threat_callback(self, threat_info):
        """Callback for threat detection"""
        self.detected_threats.append(threat_info)
        
        socketio.emit('threat_detected', {
            'timestamp': datetime.fromtimestamp(threat_info['timestamp']).strftime('%H:%M:%S'),
            'level': 'HIGH',
            'description': threat_info['description']
        })
    
    def start_recovery(self):
        """Start recovery process"""
        if not self.encryption_key:
            return {"success": False, "message": "No encryption key available"}
        
        threading.Thread(target=self._recover_files, daemon=True).start()
        return {"success": True, "message": "Recovery started"}
    
    def _recover_files(self):
        """Recover files in background"""
        try:
            total = len(self.encrypted_files)
            recovered_count = 0
            
            for idx, file_path in enumerate(self.encrypted_files):
                if file_path.exists():
                    # Log disk I/O for decryption
                    start_time = time.time()
                    file_size = file_path.stat().st_size
                    
                    if self.encryptor.decrypt_file(file_path, self.encryption_key):
                        recovered_count += 1
                        duration_ms = (time.time() - start_time) * 1000
                        
                        # Log disk I/O
                        self.disk_io_monitor.log_io_operation(
                            'read',
                            str(file_path),
                            file_size,
                            duration_ms
                        )
                        
                        # Log system calls
                        self.log_system_call('read', str(file_path), 'kernel')
                        self.log_system_call('write', str(file_path.with_suffix('')), 'kernel')
                        
                        # Update integrity baseline (use Path object - remove .encrypted suffix)
                        recovered_file = file_path.with_suffix('')
                        self.integrity_monitor.update_baseline(recovered_file)
                        
                        # Emit progress
                        socketio.emit('recovery_progress', {
                            'current': idx + 1,
                            'total': total,
                            'filename': file_path.name,
                            'progress': ((idx + 1) / total) * 100
                        })
                        
                        time.sleep(0.05)
            
            # Remove ransom notes (with sandbox check)
            ransom_note = self.test_dir / "!!!_READ_ME_IMPORTANT_!!!.txt"
            if ransom_note.exists():
                # Check sandbox permissions
                allowed, reason = self.process_sandbox.check_access(
                    'ransomware_sim',
                    'file_write',
                    str(ransom_note)
                )
                
                if allowed:
                    ransom_note.unlink()
                    # Log system call
                    self.log_system_call('unlink', str(ransom_note), 'kernel')
                else:
                    socketio.emit('sandbox_violation', {
                        'operation': 'file_delete',
                        'target': str(ransom_note),
                        'reason': reason
                    })
            
            self.encrypted_files.clear()
            
            socketio.emit('recovery_complete', {
                'recovered_count': recovered_count,
                'message': f'Recovery complete! {recovered_count} files restored.'
            })
        except Exception as e:
            print(f"Recovery error: {e}")
            socketio.emit('recovery_status', {
                'status': 'error',
                'message': f'Recovery error: {str(e)}'
            })
    
    def log_system_call(self, syscall_type, target, mode):
        """Log system call for monitoring"""
        # Use the enhanced syscall tracer
        self.syscall_tracer.trace_call(
            syscall_type, 
            os.getpid(),
            {'target': target},
            mode
        )
    
    def on_syscall_traced(self, call_entry):
        """Callback for system call tracing"""
        # Append to system_call_log for REST API
        self.system_call_log.append(call_entry)
        if len(self.system_call_log) > 1000:
            self.system_call_log = self.system_call_log[-1000:]
        
        socketio.emit('system_call', {
            'timestamp': datetime.fromtimestamp(call_entry['timestamp']).strftime('%H:%M:%S.%f')[:-3],
            'type': call_entry['syscall'],
            'target': str(call_entry['args'].get('target', 'N/A')),
            'mode': call_entry['mode'].upper(),
            'pid': call_entry['pid'],
            'category': call_entry['category']
        })
    
    def on_disk_io(self, io_entry):
        """Callback for disk I/O operations"""
        # Append to disk_io_log for REST API
        self.disk_io_log.append(io_entry)
        if len(self.disk_io_log) > 1000:
            self.disk_io_log = self.disk_io_log[-1000:]
        
        socketio.emit('disk_io', {
            'timestamp': datetime.fromtimestamp(io_entry['timestamp']).strftime('%H:%M:%S.%f')[:-3],
            'type': io_entry['type'],
            'file': Path(io_entry['file_path']).name,
            'bytes': io_entry['bytes'],
            'throughput': round(io_entry['throughput_mbps'], 2)
        })
    
    def on_network_packet(self, packet):
        """Callback for network packet events"""
        socketio.emit('network_packet', {
            'timestamp': datetime.fromtimestamp(packet['timestamp']).strftime('%H:%M:%S.%f')[:-3],
            'protocol': packet['protocol'],
            'source': f"{packet['source_ip']}:{packet['source_port']}",
            'dest': f"{packet['dest_ip']}:{packet['dest_port']}",
            'size': packet['data_size'],
            'direction': packet['direction']
        })
    
    def on_integrity_violation(self, violation):
        """Callback for integrity violations"""
        socketio.emit('integrity_violation', {
            'timestamp': datetime.fromtimestamp(violation['timestamp']).strftime('%H:%M:%S'),
            'file': Path(violation['file_path']).name,
            'changes': violation['changes']
        })
    
    def simulate_c2_beacon(self):
        """Simulate command-and-control communication"""
        try:
            # Simulate C2 server IP
            c2_ip = '192.0.2.100'  # RFC 5737 documentation IP
            local_ip = '127.0.0.1'
            
            # Check sandbox permissions for network access
            allowed, reason = self.process_sandbox.check_access(
                'ransomware_sim',
                'network',
                f'{c2_ip}:443'
            )
            
            if not allowed:
                socketio.emit('sandbox_violation', {
                    'operation': 'network',
                    'target': f'{c2_ip}:443',
                    'reason': reason
                })
                return
            
            # Simulate ransomware C2 communication
            packets = self.network_simulator.simulate_ransomware_c2_communication(
                local_ip,
                c2_ip
            )
            
            # Log system calls for network operations
            for packet in packets:
                if packet['direction'] == 'outbound':
                    self.syscall_tracer.trace_call(
                        'send',
                        os.getpid(),
                        {'dest': f"{packet['dest_ip']}:{packet['dest_port']}"},
                        'kernel'
                    )
                else:
                    self.syscall_tracer.trace_call(
                        'recv',
                        os.getpid(),
                        {'source': f"{packet['source_ip']}:{packet['source_port']}"},
                        'kernel'
                    )
            
            print(f"✓ Simulated {len(packets)} C2 network packets")
            
        except Exception as e:
            print(f"C2 simulation error: {e}")
    
    def get_system_stats(self):
        """Get current system statistics"""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'cpu_count': psutil.cpu_count(),
                'memory_percent': psutil.virtual_memory().percent,
                'memory_used': round(psutil.virtual_memory().used / (1024**3), 2),
                'memory_total': round(psutil.virtual_memory().total / (1024**3), 2),
                'disk_percent': psutil.disk_usage('/').percent,
                'disk_used': round(psutil.disk_usage('/').used / (1024**3), 2),
                'disk_total': round(psutil.disk_usage('/').total / (1024**3), 2),
                'active_processes': len(psutil.pids()),
                'network_sent': round(psutil.net_io_counters().bytes_sent / (1024**2), 2),
                'network_recv': round(psutil.net_io_counters().bytes_recv / (1024**2), 2),
                'uptime': int(time.time() - psutil.boot_time())
            }
        except Exception as e:
            print(f"System stats error: {e}")
            return {}

# Global simulator instance
simulator = OSSecuritySimulator()

# Background thread for system metrics
def background_system_metrics():
    """Background thread to emit system metrics"""
    while True:
        try:
            stats = simulator.get_system_stats()
            socketio.emit('system_update', stats)
            socketio.sleep(2)
        except Exception as e:
            print(f"Metrics error: {e}")
            socketio.sleep(5)

# Routes
@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    """Get current simulation status"""
    return jsonify({
        'simulation_active': simulator.simulation_active,
        'encrypted_files': len(simulator.encrypted_files),
        'detected_threats': len(simulator.detected_threats),
        'system_call_log_count': len(simulator.system_call_log)
    })

@app.route('/api/simulation/start', methods=['POST'])
def start_simulation():
    """Start simulation"""
    result = simulator.start_simulation()
    return jsonify(result)

@app.route('/api/simulation/recover', methods=['POST'])
def start_recovery():
    """Start recovery"""
    result = simulator.start_recovery()
    return jsonify(result)

@app.route('/api/threats')
def get_threats():
    """Get detected threats"""
    threats = []
    for threat in simulator.detected_threats[-100:]:  # Last 100
        threats.append({
            'timestamp': datetime.fromtimestamp(threat['timestamp']).strftime('%H:%M:%S'),
            'level': threat.get('threat_level', 1),
            'description': threat.get('description', 'Unknown threat')
        })
    return jsonify(threats)

@app.route('/api/system-calls')
def get_system_calls():
    """Get system call log"""
    calls = []
    for call in simulator.system_call_log[-100:]:  # Last 100
        target = call.get('args', {}).get('target', 'N/A')
        calls.append({
            'timestamp': datetime.fromtimestamp(call['timestamp']).strftime('%H:%M:%S.%f')[:-3],
            'type': call['syscall'],
            'target': Path(target).name if target and target != 'N/A' else target,
            'mode': call['mode'],
            'pid': call['pid'],
            'category': call.get('category', 'unknown')
        })
    return jsonify(calls)

@app.route('/api/disk-io')
def get_disk_io():
    """Get disk I/O log"""
    io_ops = []
    for io_entry in simulator.disk_io_log[-100:]:  # Last 100
        io_ops.append({
            'timestamp': datetime.fromtimestamp(io_entry['timestamp']).strftime('%H:%M:%S.%f')[:-3],
            'type': io_entry['type'],
            'file': Path(io_entry['file_path']).name,
            'bytes': io_entry['bytes'],
            'throughput': round(io_entry['throughput_mbps'], 2)
        })
    return jsonify(io_ops)

@app.route('/api/network-packets')
def get_network_packets():
    """Get network packet log"""
    packets = []
    for packet in simulator.network_simulator.get_recent_packets(100):
        packets.append({
            'timestamp': datetime.fromtimestamp(packet['timestamp']).strftime('%H:%M:%S.%f')[:-3],
            'protocol': packet['protocol'],
            'source': f"{packet['source_ip']}:{packet['source_port']}",
            'dest': f"{packet['dest_ip']}:{packet['dest_port']}",
            'size': packet['data_size'],
            'direction': packet['direction']
        })
    return jsonify(packets)

@app.route('/api/integrity-violations')
def get_integrity_violations():
    """Get integrity violation log"""
    violations = []
    for violation in simulator.integrity_monitor.get_recent_violations(100):
        violations.append({
            'timestamp': datetime.fromtimestamp(violation['timestamp']).strftime('%H:%M:%S'),
            'file': Path(violation['file_path']).name,
            'changes': violation['changes']
        })
    return jsonify(violations)

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    emit('response', {'data': 'Connected to OS Security Simulator'})
    
    # Start background metrics thread
    global metrics_thread
    if 'metrics_thread' not in globals():
        metrics_thread = socketio.start_background_task(background_system_metrics)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

@socketio.on('request_stats')
def handle_stats_request():
    """Handle stats request"""
    stats = simulator.get_system_stats()
    emit('system_update', stats)

if __name__ == '__main__':
    print("🚀 Starting OS Security Simulator Web Server...")
    print("📡 Server will be available at http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
