encrypt_engine.py
import os
import time
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from pathlib import Path

class AdvancedEncryptor:
    """
    Advanced file encryption with proper error handling and file access management
    """
    
    def __init__(self):
        self.backend = default_backend()
        
    def generate_key(self):
        """Generate strong encryption key using OS random source"""
        return os.urandom(32)  # AES-256
    
    def encrypt_file(self, file_path, key):
        """
        Encrypt file with proper error handling, verification, and conflict resolution
        """
        max_retries = 3
        retry_delay = 0.1  # seconds
        
        for attempt in range(max_retries):
            try:
                file_path = Path(file_path)
                
                # Skip files that are already encrypted
                if file_path.name.endswith('.encrypted'):
                    print(f"Skipping already encrypted file: {file_path.name}")
                    return False
                
                file_size = os.path.getsize(file_path)
                
                # Skip very small or very large files for simulation
                if file_size < 10 or file_size > 10 * 1024 * 1024:  # 10MB max
                    return False
                
                with open(file_path, 'r+b') as f:
                    # Read original content
                    original_data = f.read()
                    
                    # Generate unique IV for each file
                    iv = os.urandom(16)
                    
                    # Setup cipher
                    cipher = Cipher(
                        algorithms.AES(key),
                        modes.CBC(iv),
                        backend=self.backend
                    )
                    encryptor = cipher.encryptor()
                    
                    # Pad data
                    padder = padding.PKCS7(128).padder()
                    padded_data = padder.update(original_data) + padder.finalize()
                    
                    # Encrypt
                    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                    
                    # Write IV + encrypted data
                    f.seek(0)
                    f.write(iv + encrypted_data)
                    f.truncate()
                
                # Generate encrypted filename
                encrypted_name = f"{file_path}.encrypted"
                
                # Check if encrypted file already exists and remove it
                if os.path.exists(encrypted_name):
                    os.remove(encrypted_name)
                    print(f"Removed existing encrypted file: {encrypted_name}")
                
                # Rename file to indicate encryption (with retry logic)
                for rename_attempt in range(max_retries):
                    try:
                        os.rename(file_path, encrypted_name)
                        break
                    except OSError as e:
                        if rename_attempt < max_retries - 1:
                            time.sleep(retry_delay)
                        else:
                            # If rename fails, delete the encrypted file content and restore original
                            with open(file_path, 'wb') as f:
                                f.write(original_data)
                            raise e
                
                return True
                
            except OSError as e:
                if attempt < max_retries - 1:
                    print(f"File access error for {file_path}, retrying... (Attempt {attempt + 1})")
                    time.sleep(retry_delay)
                else:
                    print(f"Encryption failed for {file_path} after {max_retries} attempts: {e}")
                    return False
            except Exception as e:
                print(f"Encryption failed for {file_path}: {e}")
                return False
        
        return False
    
    def decrypt_file(self, file_path, key):
        """
        Decrypt file and restore original name with retry logic
        """
        max_retries = 3
        retry_delay = 0.1  # seconds
        
        for attempt in range(max_retries):
            try:
                file_path = Path(file_path)
                
                # Only decrypt files with .encrypted extension
                if not file_path.name.endswith('.encrypted'):
                    print(f"Skipping non-encrypted file: {file_path.name}")
                    return False
                
                with open(file_path, 'r+b') as f:
                    # Read IV (first 16 bytes) and encrypted data
                    iv = f.read(16)
                    encrypted_data = f.read()
                    
                    # Setup cipher
                    cipher = Cipher(
                        algorithms.AES(key),
                        modes.CBC(iv),
                        backend=self.backend
                    )
                    decryptor = cipher.decryptor()
                    
                    # Decrypt
                    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
                    
                    # Unpad
                    unpadder = padding.PKCS7(128).unpadder()
                    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
                    
                    # Write decrypted data
                    f.seek(0)
                    f.write(decrypted_data)
                    f.truncate()
                
                # Restore original filename
                original_name = file_path.with_suffix('')  # Remove .encrypted
                
                # Check if original file already exists and remove it
                if os.path.exists(original_name):
                    os.remove(original_name)
                    print(f"Removed existing original file: {original_name}")
                
                # Rename back to original (with retry logic)
                for rename_attempt in range(max_retries):
                    try:
                        os.rename(file_path, original_name)
                        break
                    except OSError as e:
                        if rename_attempt < max_retries - 1:
                            time.sleep(retry_delay)
                        else:
                            raise e
                
                return True
                
            except OSError as e:
                if attempt < max_retries - 1:
                    print(f"File access error for {file_path}, retrying... (Attempt {attempt + 1})")
                    time.sleep(retry_delay)
                else:
                    print(f"Decryption failed for {file_path} after {max_retries} attempts: {e}")
                    return False
            except Exception as e:
                print(f"Decryption failed for {file_path}: {e}")
                return False
        
        return False
    
    def calculate_file_entropy(self, file_path):
        """
        Calculate file entropy to detect encryption
        High entropy suggests encrypted content
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if len(data) == 0:
                return 0
            
            # Calculate byte frequency
            frequency = [0] * 256
            for byte in data:
                frequency[byte] += 1
            
            # Calculate entropy
            entropy = 0
            for count in frequency:
                if count > 0:
                    p = count / len(data)
                    entropy -= p * (p.log2() if p > 0 else 0)
            
            return entropy
            
        except Exception:
            return 0



            filemonitor.py

            import os
import time
import threading
from pathlib import Path
import platform

class AdvancedFileMonitor:
    """
    Advanced OS-level file monitoring (Cross-platform)
    Uses different approaches for Windows vs Linux
    """
    
    def __init__(self, watch_directory):
        self.watch_directory = Path(watch_directory)
        self.monitoring = False
        self.thread = None
        self.callback = None
        self.file_states = {}
        
        # Platform-specific setup
        self.is_windows = platform.system() == "Windows"
        
        # Event constants (compatible with both platforms)
        self.IN_CREATE = 0x100
        self.IN_MODIFY = 0x2
        self.IN_DELETE = 0x200
        self.IN_ACCESS = 0x1
        
        print(f"File monitor initialized for {'Windows' if self.is_windows else 'Linux'}")

    def _update_file_states(self):
        """Update file states for polling-based detection"""
        current_states = {}
        for file_path in self.watch_directory.iterdir():
            if file_path.is_file():
                try:
                    stat = file_path.stat()
                    current_states[file_path] = {
                        'size': stat.st_size,
                        'mtime': stat.st_mtime,
                        'ctime': stat.st_ctime
                    }
                except OSError:
                    continue
        
        self.file_states = current_states
    
    def _detect_changes_polling(self):
        """Detect file changes using polling"""
        old_states = self.file_states.copy()
        self._update_file_states()
        
        events = []
        
        # Check for new files
        for file_path in self.file_states:
            if file_path not in old_states:
                events.append({
                    'name': file_path.name,
                    'mask': self.IN_CREATE,
                    'path': str(self.watch_directory)
                })
        
        # Check for deleted files
        for file_path in old_states:
            if file_path not in self.file_states:
                events.append({
                    'name': file_path.name,
                    'mask': self.IN_DELETE,
                    'path': str(self.watch_directory)
                })
        
        # Check for modified files
        for file_path in self.file_states:
            if file_path in old_states:
                old_stat = old_states[file_path]
                new_stat = self.file_states[file_path]
                
                if (old_stat['size'] != new_stat['size'] or 
                    old_stat['mtime'] != new_stat['mtime']):
                    events.append({
                        'name': file_path.name,
                        'mask': self.IN_MODIFY,
                        'path': str(self.watch_directory)
                    })
        
        return events
    
    def start_monitoring(self, callback):
        """Start monitoring file system events"""
        self.callback = callback
        self.monitoring = True
        
        # Initialize file states
        self._update_file_states()
        
        def polling_loop():
            while self.monitoring:
                try:
                    events = self._detect_changes_polling()
                    for event in events:
                        if self.callback:
                            self.callback(event)
                    time.sleep(1)  # Poll every second
                except Exception as e:
                    print(f"File monitoring error: {e}")
                    time.sleep(5)
        
        self.thread = threading.Thread(target=polling_loop)
        self.thread.daemon = True
        self.thread.start()
        
        print("File monitoring started (polling mode)")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.thread:
            self.thread.join(timeout=2.0)
        print("File monitoring stopped")




        recovery_system.py




    import os
import shutil
from pathlib import Path
import json
from datetime import datetime

class RecoverySystem:
    """
    File recovery system with backup management
    """
    
    def __init__(self, source_directory, backup_directory):
        self.source_dir = Path(source_directory)
        self.backup_dir = Path(backup_directory)
        self.recovery_log = []
        
    def create_backup(self):
        """Create backup of source directory"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / f"backup_{timestamp}"
            
            # Copy directory structure
            shutil.copytree(self.source_dir, backup_path)
            
            # Log backup creation
            self.recovery_log.append({
                'timestamp': datetime.now().isoformat(),
                'action': 'backup_created',
                'path': str(backup_path)
            })
            
            return backup_path
            
        except Exception as e:
            print(f"Backup creation failed: {e}")
            return None
    
    def restore_from_backup(self, backup_path):
        """Restore files from backup"""
        try:
            backup_path = Path(backup_path)
            
            # Clear current directory
            for item in self.source_dir.iterdir():
                if item.is_file():
                    item.unlink()
                else:
                    shutil.rmtree(item)
            
            # Copy from backup
            for item in backup_path.iterdir():
                dest = self.source_dir / item.name
                if item.is_file():
                    shutil.copy2(item, dest)
                else:
                    shutil.copytree(item, dest)
            
            # Log restoration
            self.recovery_log.append({
                'timestamp': datetime.now().isoformat(),
                'action': 'restore_from_backup',
                'backup_path': str(backup_path)
            })
            
            return True
            
        except Exception as e:
            print(f"Restore from backup failed: {e}")
            return False
    
    def get_available_backups(self):
        """Get list of available backups"""
        backups = []
        for item in self.backup_dir.iterdir():
            if item.is_dir() and item.name.startswith('backup_'):
                backups.append({
                    'path': item,
                    'name': item.name,
                    'created_time': item.stat().st_ctime
                })
        
        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x['created_time'], reverse=True)
        return backups
    
    def cleanup_old_backups(self, keep_count=5):
        """Cleanup old backups, keep only specified number"""
        backups = self.get_available_backups()
        
        if len(backups) > keep_count:
            for backup in backups[keep_count:]:
                try:
                    shutil.rmtree(backup['path'])
                    self.recovery_log.append({
                        'timestamp': datetime.now().isoformat(),
                        'action': 'backup_cleaned',
                        'backup_path': str(backup['path'])
                    })
                except Exception as e:
                    print(f"Failed to cleanup backup {backup['path']}: {e}")
    
    def save_recovery_log(self):
        """Save recovery log to file"""
        log_file = self.backup_dir / "recovery_log.json"
        with open(log_file, 'w') as f:
            json.dump(self.recovery_log, f, indent=2)    
            
system_monitor.py

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import psutil
from datetime import datetime

class SystemMonitor:
    """
    Advanced System Monitoring UI Component
    Real-time monitoring of system resources and OS-level activities
    """
    
    def __init__(self, parent, system_calls, memory_manager):
        self.parent = parent
        self.system_calls = system_calls
        self.memory_manager = memory_manager
        self.frame = None
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Monitoring data
        self.system_metrics = {}
        self.process_list = []
        self.memory_stats = {}
        self.network_stats = {}
        
        self.create_widgets()
        self.start_monitoring()
    
    def create_widgets(self):
        """Create system monitoring widgets"""
        self.frame = ttk.Frame(self.parent)
        
        # Create notebook for different monitoring sections
        self.monitor_notebook = ttk.Notebook(self.frame)
        self.monitor_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # System Overview Tab
        self.create_system_overview_tab()
        
        # Process Monitor Tab
        self.create_process_monitor_tab()
        
        # Memory Monitor Tab
        self.create_memory_monitor_tab()
        
        # Network Monitor Tab
        self.create_network_monitor_tab()
        
        # System Calls Tab
        self.create_system_calls_tab()
    
    def create_system_overview_tab(self):
        """Create system overview monitoring tab"""
        overview_frame = ttk.Frame(self.monitor_notebook)
        self.monitor_notebook.add(overview_frame, text="System Overview")
        
        # CPU Usage
        cpu_frame = ttk.LabelFrame(overview_frame, text="CPU Usage", padding=10)
        cpu_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.cpu_percent = ttk.Label(cpu_frame, text="CPU: 0.0%", font=('Arial', 12))
        self.cpu_percent.pack(anchor=tk.W)
        
        self.cpu_progress = ttk.Progressbar(cpu_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.cpu_progress.pack(fill=tk.X, pady=5)
        
        # Memory Usage
        memory_frame = ttk.LabelFrame(overview_frame, text="Memory Usage", padding=10)
        memory_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.memory_percent = ttk.Label(memory_frame, text="Memory: 0.0%", font=('Arial', 12))
        self.memory_percent.pack(anchor=tk.W)
        
        self.memory_progress = ttk.Progressbar(memory_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.memory_progress.pack(fill=tk.X, pady=5)
        
        # Disk Usage
        disk_frame = ttk.LabelFrame(overview_frame, text="Disk Usage", padding=10)
        disk_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.disk_percent = ttk.Label(disk_frame, text="Disk: 0.0%", font=('Arial', 12))
        self.disk_percent.pack(anchor=tk.W)
        
        self.disk_progress = ttk.Progressbar(disk_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.disk_progress.pack(fill=tk.X, pady=5)
        
        # System Info
        info_frame = ttk.LabelFrame(overview_frame, text="System Information", padding=10)
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.boot_time_label = ttk.Label(info_frame, text="Boot Time: --")
        self.boot_time_label.pack(anchor=tk.W)
        
        self.process_count_label = ttk.Label(info_frame, text="Running Processes: --")
        self.process_count_label.pack(anchor=tk.W)
        
        self.system_uptime_label = ttk.Label(info_frame, text="System Uptime: --")
        self.system_uptime_label.pack(anchor=tk.W)
    
    def create_process_monitor_tab(self):
        """Create process monitoring tab"""
        process_frame = ttk.Frame(self.monitor_notebook)
        self.monitor_notebook.add(process_frame, text="Process Monitor")
        
        # Process list treeview
        columns = ('PID', 'Name', 'CPU%', 'Memory%', 'Status', 'User')
        self.process_tree = ttk.Treeview(process_frame, columns=columns, show='headings', height=20)
        
        # Configure columns
        for col in columns:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=100)
        
        self.process_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Process controls
        control_frame = ttk.Frame(process_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        refresh_btn = ttk.Button(control_frame, text="Refresh Processes", 
                               command=self.refresh_process_list)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        self.auto_refresh_var = tk.BooleanVar(value=True)
        auto_refresh_cb = ttk.Checkbutton(control_frame, text="Auto Refresh", 
                                        variable=self.auto_refresh_var)
        auto_refresh_cb.pack(side=tk.LEFT, padx=5)
    
    def create_memory_monitor_tab(self):
        """Create memory monitoring tab"""
        memory_frame = ttk.Frame(self.monitor_notebook)
        self.monitor_notebook.add(memory_frame, text="Memory Monitor")
        
        # Memory statistics
        stats_frame = ttk.LabelFrame(memory_frame, text="Memory Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.total_memory_label = ttk.Label(stats_frame, text="Total Memory: --")
        self.total_memory_label.pack(anchor=tk.W)
        
        self.used_memory_label = ttk.Label(stats_frame, text="Used Memory: --")
        self.used_memory_label.pack(anchor=tk.W)
        
        self.available_memory_label = ttk.Label(stats_frame, text="Available Memory: --")
        self.available_memory_label.pack(anchor=tk.W)
        
        self.swap_memory_label = ttk.Label(stats_frame, text="Swap Usage: --")
        self.swap_memory_label.pack(anchor=tk.W)
        
        # Memory anomalies
        anomalies_frame = ttk.LabelFrame(memory_frame, text="Memory Anomalies", padding=10)
        anomalies_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.anomalies_text = scrolledtext.ScrolledText(anomalies_frame, height=8,
                                                       bg='#1e1e1e', fg='#ffffff')
        self.anomalies_text.pack(fill=tk.BOTH, expand=True)
        self.anomalies_text.insert(tk.END, "No memory anomalies detected.\n")
        self.anomalies_text.config(state=tk.DISABLED)
    
    def create_network_monitor_tab(self):
        """Create network monitoring tab"""
        network_frame = ttk.Frame(self.monitor_notebook)
        self.monitor_notebook.add(network_frame, text="Network Monitor")
        
        # Network statistics
        stats_frame = ttk.LabelFrame(network_frame, text="Network Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.bytes_sent_label = ttk.Label(stats_frame, text="Bytes Sent: --")
        self.bytes_sent_label.pack(anchor=tk.W)
        
        self.bytes_recv_label = ttk.Label(stats_frame, text="Bytes Received: --")
        self.bytes_recv_label.pack(anchor=tk.W)
        
        self.packets_sent_label = ttk.Label(stats_frame, text="Packets Sent: --")
        self.packets_sent_label.pack(anchor=tk.W)
        
        self.packets_recv_label = ttk.Label(stats_frame, text="Packets Received: --")
        self.packets_recv_label.pack(anchor=tk.W)
        
        # Network connections
        conn_frame = ttk.LabelFrame(network_frame, text="Active Connections", padding=10)
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ('Local Address', 'Remote Address', 'Status', 'PID')
        self.connections_tree = ttk.Treeview(conn_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.connections_tree.heading(col, text=col)
            self.connections_tree.column(col, width=150)
        
        self.connections_tree.pack(fill=tk.BOTH, expand=True)
    
    def create_system_calls_tab(self):
        """Create system calls monitoring tab"""
        syscall_frame = ttk.Frame(self.monitor_notebook)
        self.monitor_notebook.add(syscall_frame, text="System Calls")
        
        # System call monitoring
        monitor_frame = ttk.LabelFrame(syscall_frame, text="System Call Monitor", padding=10)
        monitor_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.syscall_text = scrolledtext.ScrolledText(monitor_frame, height=20,
                                                     bg='#1e1e1e', fg='#ffffff')
        self.syscall_text.pack(fill=tk.BOTH, expand=True)
        self.syscall_text.insert(tk.END, "System call monitoring active...\n")
        self.syscall_text.config(state=tk.DISABLED)
        
        # Controls
        control_frame = ttk.Frame(monitor_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        start_monitor_btn = ttk.Button(control_frame, text="Start Syscall Monitor",
                                     command=self.start_syscall_monitoring)
        start_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        stop_monitor_btn = ttk.Button(control_frame, text="Stop Syscall Monitor",
                                    command=self.stop_syscall_monitoring)
        stop_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        clear_monitor_btn = ttk.Button(control_frame, text="Clear Log",
                                     command=self.clear_syscall_log)
        clear_monitor_btn.pack(side=tk.LEFT, padx=5)
    
    def start_monitoring(self):
        """Start system monitoring thread"""
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self.update_system_metrics()
                self.update_memory_stats()
                self.update_network_stats()
                
                if self.auto_refresh_var.get():
                    self.refresh_process_list()
                    self.refresh_network_connections()
                
                time.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(5)
    
    def update_system_metrics(self):
        """Update system metrics in UI"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent()
            self.parent.after(0, self._update_cpu_metrics, cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.parent.after(0, self._update_memory_metrics, memory)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            self.parent.after(0, self._update_disk_metrics, disk)
            
            # System info
            boot_time = psutil.boot_time()
            process_count = len(psutil.pids())
            uptime = time.time() - boot_time
            
            self.parent.after(0, self._update_system_info, boot_time, process_count, uptime)
            
        except Exception as e:
            print(f"System metrics update error: {e}")
    
    def _update_cpu_metrics(self, cpu_percent):
        """Update CPU metrics in UI (thread-safe)"""
        self.cpu_percent.config(text=f"CPU: {cpu_percent:.1f}%")
        self.cpu_progress['value'] = cpu_percent
    
    def _update_memory_metrics(self, memory):
        """Update memory metrics in UI (thread-safe)"""
        self.memory_percent.config(text=f"Memory: {memory.percent:.1f}%")
        self.memory_progress['value'] = memory.percent
    
    def _update_disk_metrics(self, disk):
        """Update disk metrics in UI (thread-safe)"""
        self.disk_percent.config(text=f"Disk: {disk.percent:.1f}%")
        self.disk_progress['value'] = disk.percent
    
    def _update_system_info(self, boot_time, process_count, uptime):
        """Update system information in UI (thread-safe)"""
        boot_time_str = datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S')
        uptime_str = self.format_uptime(uptime)
        
        self.boot_time_label.config(text=f"Boot Time: {boot_time_str}")
        self.process_count_label.config(text=f"Running Processes: {process_count}")
        self.system_uptime_label.config(text=f"System Uptime: {uptime_str}")
    
    def update_memory_stats(self):
        """Update memory statistics"""
        try:
            if self.memory_manager:
                memory_stats = self.memory_manager.get_memory_stats()
                anomalies = self.memory_manager.detect_memory_anomalies()
                
                self.parent.after(0, self._update_memory_stats_ui, memory_stats, anomalies)
                
        except Exception as e:
            print(f"Memory stats update error: {e}")
    
    def _update_memory_stats_ui(self, memory_stats, anomalies):
        """Update memory statistics in UI (thread-safe)"""
        if memory_stats:
            total_gb = memory_stats.get('total_memory', 0) / (1024**3)
            used_gb = memory_stats.get('used_memory', 0) / (1024**3)
            available_gb = memory_stats.get('available_memory', 0) / (1024**3)
            swap_used_gb = memory_stats.get('swap_used', 0) / (1024**3)
            swap_total_gb = memory_stats.get('swap_total', 0) / (1024**3)
            
            self.total_memory_label.config(text=f"Total Memory: {total_gb:.2f} GB")
            self.used_memory_label.config(text=f"Used Memory: {used_gb:.2f} GB")
            self.available_memory_label.config(text=f"Available Memory: {available_gb:.2f} GB")
            self.swap_memory_label.config(text=f"Swap Usage: {swap_used_gb:.2f} / {swap_total_gb:.2f} GB")
        
        # Update anomalies
        self.anomalies_text.config(state=tk.NORMAL)
        self.anomalies_text.delete(1.0, tk.END)
        
        if anomalies:
            for anomaly in anomalies:
                self.anomalies_text.insert(tk.END, f"⚠️ {anomaly}\n")
        else:
            self.anomalies_text.insert(tk.END, "✅ No memory anomalies detected.\n")
        
        self.anomalies_text.config(state=tk.DISABLED)
    
    def update_network_stats(self):
        """Update network statistics"""
        try:
            net_io = psutil.net_io_counters()
            if net_io:
                self.parent.after(0, self._update_network_stats_ui, net_io)
                
        except Exception as e:
            print(f"Network stats update error: {e}")
    
    def _update_network_stats_ui(self, net_io):
        """Update network statistics in UI (thread-safe)"""
        bytes_sent_mb = net_io.bytes_sent / (1024**2)
        bytes_recv_mb = net_io.bytes_recv / (1024**2)
        
        self.bytes_sent_label.config(text=f"Bytes Sent: {bytes_sent_mb:.2f} MB")
        self.bytes_recv_label.config(text=f"Bytes Received: {bytes_recv_mb:.2f} MB")
        self.packets_sent_label.config(text=f"Packets Sent: {net_io.packets_sent}")
        self.packets_recv_label.config(text=f"Packets Received: {net_io.packets_recv}")
    
    def refresh_process_list(self):
        """Refresh process list"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by CPU usage (descending)
            processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
            
            self.parent.after(0, self._update_process_list, processes[:50])  # Top 50 processes
            
        except Exception as e:
            print(f"Process list refresh error: {e}")
    
    def _update_process_list(self, processes):
        """Update process list in UI (thread-safe)"""
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Add processes
        for proc in processes:
            self.process_tree.insert('', tk.END, values=(
                proc['pid'],
                proc['name'],
                f"{proc['cpu_percent'] or 0:.1f}",
                f"{proc['memory_percent'] or 0:.2f}",
                proc['status'],
                proc['username'] or 'N/A'
            ))
    
    def refresh_network_connections(self):
        """Refresh network connections"""
        try:
            connections = []
            for conn in psutil.net_connections():
                try:
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    
                    connections.append({
                        'local': local_addr,
                        'remote': remote_addr,
                        'status': conn.status,
                        'pid': conn.pid
                    })
                except (AttributeError, psutil.AccessDenied):
                    continue
            
            self.parent.after(0, self._update_network_connections, connections)
            
        except Exception as e:
            print(f"Network connections refresh error: {e}")
    
    def _update_network_connections(self, connections):
        """Update network connections in UI (thread-safe)"""
        # Clear existing items
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        # Add connections
        for conn in connections[:100]:  # Limit to 100 connections
            self.connections_tree.insert('', tk.END, values=(
                conn['local'],
                conn['remote'],
                conn['status'],
                conn['pid']
            ))
    
    def start_syscall_monitoring(self):
        """Start system call monitoring"""
        self.syscall_text.config(state=tk.NORMAL)
        self.syscall_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] System call monitoring started\n")
        self.syscall_text.see(tk.END)
        self.syscall_text.config(state=tk.DISABLED)
    
    def stop_syscall_monitoring(self):
        """Stop system call monitoring"""
        self.syscall_text.config(state=tk.NORMAL)
        self.syscall_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] System call monitoring stopped\n")
        self.syscall_text.see(tk.END)
        self.syscall_text.config(state=tk.DISABLED)
    
    def clear_syscall_log(self):
        """Clear system call log"""
        self.syscall_text.config(state=tk.NORMAL)
        self.syscall_text.delete(1.0, tk.END)
        self.syscall_text.config(state=tk.DISABLED)
    
    def add_syscall_event(self, syscall_info):
        """Add system call event to monitor"""
        self.parent.after(0, self._add_syscall_event_ui, syscall_info)
    
    def _add_syscall_event_ui(self, syscall_info):
        """Add system call event to UI (thread-safe)"""
        self.syscall_text.config(state=tk.NORMAL)
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        syscall_name = syscall_info.get('syscall_name', 'unknown')
        
        self.syscall_text.insert(tk.END, f"[{timestamp}] {syscall_name}\n")
        self.syscall_text.see(tk.END)
        self.syscall_text.config(state=tk.DISABLED)
    
    def format_uptime(self, seconds):
        """Format uptime to human readable string"""
        days = seconds // (24 * 3600)
        seconds = seconds % (24 * 3600)
        hours = seconds // 3600
        seconds %= 3600
        minutes = seconds // 60
        seconds %= 60
        
        if days > 0:
            return f"{int(days)}d {int(hours)}h {int(minutes)}m"
        elif hours > 0:
            return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
        else:
            return f"{int(minutes)}m {int(seconds)}s"
    
    def get_frame(self):
        """Get the main frame"""
        return self.frame


thtreat_detector.py

import time
import threading
from datetime import datetime

class ThreatDetector:
    """
    Real-time threat detection for ransomware behavior
    """
    
    def __init__(self):
        self.detection_rules = self.load_detection_rules()
        self.detection_active = False
        self.detection_thread = None
        
    def load_detection_rules(self):
        """Load threat detection rules"""
        return {
            'file_encryption_patterns': [
                '.encrypted', '.crypted', '.locked', '.ransom',
                '.aes', '.aes256', '.wncry', '.wcry'
            ],
            'suspicious_extensions': [
                '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js'
            ],
            'ransom_note_names': [
                'readme', 'decrypt', 'recover', 'help', 'instruction',
                '!!!', 'warning', 'alert', 'important'
            ],
            'mass_operation_threshold': 10,  # Files per minute
            'entropy_threshold': 7.0  # High entropy indicates encryption
        }
    
    def start_detection(self, callback):
        """Start real-time threat detection"""
        self.detection_active = True
        self.callback = callback
        
        self.detection_thread = threading.Thread(target=self._detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
    
    def stop_detection(self):
        """Stop threat detection"""
        self.detection_active = False
        if self.detection_thread:
            self.detection_thread.join(timeout=1.0)
    
    def _detection_loop(self):
        """Main detection loop"""
        file_operations = []
        
        while self.detection_active:
            # Simulate continuous monitoring
            time.sleep(1)
            
            # Analyze recent file operations for mass encryption patterns
            current_time = time.time()
            file_operations = [op for op in file_operations if current_time - op['time'] < 60]
            
            if len(file_operations) > self.detection_rules['mass_operation_threshold']:
                threat_info = {
                    'timestamp': current_time,
                    'threat_level': 3,  # High
                    'description': f"Mass file operations detected: {len(file_operations)} operations in 60 seconds"
                }
                self.callback(threat_info)
    
    def analyze_file_event(self, event):
        """Analyze file system event for threats"""
        threat_level = 0
        description = ""
        
        file_name = event.get('name', '').lower()
        event_type = self._get_event_type(event.get('mask', 0))
        
        # Check for ransom note creation
        if any(pattern in file_name for pattern in self.detection_rules['ransom_note_names']):
            threat_level = 3
            description = f"Ransom note detected: {file_name}"
        
        # Check for suspicious file extensions
        elif any(file_name.endswith(ext) for ext in self.detection_rules['suspicious_extensions']):
            threat_level = 2
            description = f"Suspicious file type: {file_name}"
        
        # Check for encryption patterns
        elif any(pattern in file_name for pattern in self.detection_rules['file_encryption_patterns']):
            threat_level = 3
            description = f"Possible encrypted file: {file_name}"
        
        # Multiple rapid modifications
        elif event_type == 'MODIFY':
            threat_level = 1
            description = f"File modification: {file_name}"
        
        if threat_level > 0:
            threat_info = {
                'timestamp': time.time(),
                'event': event,
                'threat_level': threat_level,
                'description': description
            }
            
            if hasattr(self, 'callback'):
                self.callback(threat_info)
        
        return threat_level
    
    def _get_event_type(self, mask):
        """Convert inotify mask to event type"""
        if mask & 0x100: return "CREATE"
        if mask & 0x2: return "MODIFY"
        if mask & 0x200: return "DELETE"
        if mask & 0x1: return "ACCESS"
        return "UNKNOWN"
    
    def get_threat_description(self, event):
        """Get human-readable threat description"""
        file_name = event.get('name', 'Unknown')
        event_type = self._get_event_type(event.get('mask', 0))
        
        return f"{event_type} operation on {file_name}"



        CORE 


        memory_manager.py

        import ctypes
import os
import platform
import psutil

class MemoryManager:
    """
    Cross-platform Memory Management for Ransomware Simulation
    """
    
    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        self.memory_regions = {}
        self.locked_pages = []
        
        print(f"Memory manager initialized for {'Windows' if self.is_windows else 'Linux'}")
    
    def allocate_secure_memory(self, size, description="secure_data"):
        """
        Allocate memory with enhanced security features (cross-platform)
        """
        try:
            # Use ctypes for cross-platform memory allocation
            buffer = (ctypes.c_byte * size)()
            memory_ptr = ctypes.addressof(buffer)
            
            # Store memory region info
            region_id = f"region_{len(self.memory_regions)}"
            self.memory_regions[region_id] = {
                'ptr': memory_ptr,
                'size': size,
                'description': description,
                'buffer': buffer,  # Keep reference to prevent garbage collection
                'locked': False,
                'protected': False
            }
            
            print(f"Allocated secure memory: {size} bytes for {description}")
            return memory_ptr, region_id
            
        except Exception as e:
            print(f"Memory allocation failed: {e}")
            return None, None
    
    def lock_memory_region(self, address, size):
        """Lock memory pages (simulated on Windows)"""
        try:
            # On Windows, we simulate memory locking
            # In a real implementation, you'd use VirtualLock
            self.locked_pages.append((address, size))
            return True
        except Exception as e:
            print(f"Memory locking failed: {e}")
            return False
    
    def unlock_memory_region(self, address, size):
        """Unlock memory pages"""
        try:
            # Remove from locked pages list
            self.locked_pages = [(addr, sz) for addr, sz in self.locked_pages 
                               if addr != address or sz != size]
            return True
        except Exception as e:
            print(f"Memory unlocking failed: {e}")
            return False
    
    def set_memory_protection(self, address, size, protection_flags):
        """
        Set memory protection flags (simulated on Windows)
        """
        try:
            # On Windows, we simulate memory protection
            # In a real implementation, you'd use VirtualProtect
            return True
        except Exception as e:
            print(f"Memory protection failed: {e}")
            return False
    
    def create_secure_mapping(self, file_path, size=0):
        """
        Create memory-mapped file (cross-platform simulation)
        """
        try:
            # For cross-platform compatibility, we'll use file reading
            # In a real implementation, you'd use mmap module
            with open(file_path, 'r+b') as f:
                file_data = f.read()
            
            # Create a memory buffer with the file data
            buffer_size = len(file_data) if size == 0 else size
            buffer = (ctypes.c_byte * buffer_size)()
            
            # Copy file data to buffer
            for i, byte in enumerate(file_data[:buffer_size]):
                buffer[i] = byte
            
            print(f"Created secure memory mapping for {file_path}")
            return buffer
            
        except Exception as e:
            print(f"Secure mapping failed: {e}")
            return None
    
    def free_secure_memory(self, region_id):
        """Free securely allocated memory"""
        if region_id in self.memory_regions:
            region = self.memory_regions[region_id]
            
            # Unlock memory if locked
            if region['locked']:
                self.unlock_memory_region(region['ptr'], region['size'])
            
            # Remove from tracking (buffer will be garbage collected)
            del self.memory_regions[region_id]
            
            print(f"Freed secure memory: {region['description']}")
            return True
        return False
    
    def get_memory_stats(self):
        """Get detailed memory statistics (cross-platform)"""
        try:
            virtual_memory = psutil.virtual_memory()
            swap_memory = psutil.swap_memory()
            
            return {
                'total_memory': virtual_memory.total,
                'available_memory': virtual_memory.available,
                'used_memory': virtual_memory.used,
                'memory_percent': virtual_memory.percent,
                'swap_total': swap_memory.total,
                'swap_used': swap_memory.used,
                'swap_free': swap_memory.free,
                'locked_pages_count': len(self.locked_pages),
                'active_regions': len(self.memory_regions),
                'total_locked_memory': sum(size for _, size in self.locked_pages),
                'platform': platform.system()
            }
        except Exception as e:
            print(f"Memory stats error: {e}")
            return {}
    
    def detect_memory_anomalies(self):
        """Detect potential memory-based attacks"""
        stats = self.get_memory_stats()
        anomalies = []
        
        # Check for excessive memory usage
        if stats.get('memory_percent', 0) > 90:
            anomalies.append("High memory usage detected")
        
        # Check for swap usage
        if stats.get('swap_used', 0) > stats.get('swap_total', 1) * 0.5:
            anomalies.append("High swap usage detected")
        
        return anomalies
    
    def secure_memory_cleanup(self):
        """Cleanup all secure memory regions"""
        print("Performing secure memory cleanup...")
        
        # Free all allocated regions
        for region_id in list(self.memory_regions.keys()):
            self.free_secure_memory(region_id)
        
        self.locked_pages.clear()
        print("Secure memory cleanup completed")


class EncryptionMemoryManager(MemoryManager):
    """
    Specialized memory manager for encryption operations
    """
    
    def __init__(self):
        super().__init__()
        self.encryption_buffers = {}
    
    def create_encryption_buffer(self, buffer_id, size):
        """Create secure buffer for encryption operations"""
        ptr, region_id = self.allocate_secure_memory(size, f"encryption_buffer_{buffer_id}")
        
        if ptr:
            self.encryption_buffers[buffer_id] = {
                'ptr': ptr,
                'size': size,
                'region_id': region_id
            }
            return ptr
        return None
    
    def secure_encryption_operation(self, buffer_id, data):
        """Perform secure encryption operation in protected memory"""
        if buffer_id not in self.encryption_buffers:
            return None
        
        buffer_info = self.encryption_buffers[buffer_id]
        
        try:
            # Get the buffer object
            buffer_obj = self.memory_regions[buffer_info['region_id']]['buffer']
            
            # Copy data to secure buffer
            data_bytes = data if isinstance(data, bytes) else data.encode()
            
            # Copy data to buffer (simplified approach)
            for i in range(min(len(data_bytes), buffer_info['size'])):
                buffer_obj[i] = data_bytes[i]
            
            # Simulate encryption operation
            encrypted_data = self._simulate_encryption(data_bytes)
            
            return encrypted_data
            
        except Exception as e:
            print(f"Secure encryption operation failed: {e}")
            return None
    
    def _simulate_encryption(self, data):
        """Simulate encryption operation (XOR for demonstration)"""
        # In real implementation, use proper cryptography
        key = b'encryption_key_demo'
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % len(key)])
        return bytes(encrypted)
    
    def cleanup_encryption_buffers(self):
        """Cleanup all encryption buffers"""
        for buffer_id in list(self.encryption_buffers.keys()):
            buffer_info = self.encryption_buffers[buffer_id]
            self.free_secure_memory(buffer_info['region_id'])
            del self.encryption_buffers[buffer_id]



            process_manager.py


            import os
import signal
import subprocess
import threading
import time
from pathlib import Path

class ProcessManager:
    """
    OS Process Management for ransomware simulation
    Demonstrates fork, exec, signal handling, and process monitoring
    """
    
    def __init__(self):
        self.processes = {}
        self.monitoring = False
        self.monitor_thread = None
        
    def create_process(self, command, args=None):
        """Create new process using fork/exec pattern"""
        try:
            if args is None:
                args = []
                
            # Using subprocess which internally uses fork/exec on Unix
            process = subprocess.Popen(
                [command] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group
            )
            
            pid = process.pid
            self.processes[pid] = {
                'process': process,
                'command': command,
                'start_time': time.time(),
                'status': 'running'
            }
            
            return pid
            
        except Exception as e:
            print(f"Process creation failed: {e}")
            return None
    
    def send_signal(self, pid, signal_type):
        """Send signal to process using kill system call"""
        try:
            if signal_type == 'stop':
                os.kill(pid, signal.SIGSTOP)
            elif signal_type == 'continue':
                os.kill(pid, signal.SIGCONT)
            elif signal_type == 'terminate':
                os.kill(pid, signal.SIGTERM)
            elif signal_type == 'kill':
                os.kill(pid, signal.SIGKILL)
                
            return True
        except ProcessLookupError:
            return False
    
    def monitor_processes(self):
        """Monitor processes using /proc filesystem"""
        while self.monitoring:
            for pid in list(self.processes.keys()):
                try:
                    # Check if process exists using /proc
                    proc_path = Path(f"/proc/{pid}")
                    if not proc_path.exists():
                        self.processes[pid]['status'] = 'terminated'
                        continue
                    
                    # Read process status from /proc/pid/stat
                    stat_path = proc_path / "stat"
                    if stat_path.exists():
                        with open(stat_path, 'r') as f:
                            stat_data = f.read().split()
                            status = stat_data[2]  # Process state
                            self.processes[pid]['status'] = status
                    
                    # Read memory usage
                    status_path = proc_path / "status"
                    if status_path.exists():
                        with open(status_path, 'r') as f:
                            for line in f:
                                if line.startswith('VmRSS:'):
                                    memory_kb = line.split()[1]
                                    self.processes[pid]['memory'] = f"{memory_kb} KB"
                                    break
                    
                except (PermissionError, FileNotFoundError):
                    self.processes[pid]['status'] = 'terminated'
            
            time.sleep(2)  # Monitor every 2 seconds
    
    def start_monitoring(self):
        """Start process monitoring"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_processes)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
    
    def get_process_info(self, pid):
        """Get detailed process information"""
        if pid in self.processes:
            info = self.processes[pid].copy()
            
            try:
                # Additional info from /proc
                proc_path = Path(f"/proc/{pid}")
                
                # CPU time
                stat_path = proc_path / "stat"
                if stat_path.exists():
                    with open(stat_path, 'r') as f:
                        stat_data = f.read().split()
                        info['utime'] = stat_data[13]  # user time
                        info['stime'] = stat_data[14]  # system time
                
                # Command line
                cmdline_path = proc_path / "cmdline"
                if cmdline_path.exists():
                    with open(cmdline_path, 'r') as f:
                        cmdline = f.read().replace('\x00', ' ')
                        info['cmdline'] = cmdline.strip()
                        
            except (PermissionError, FileNotFoundError):
                pass
                
            return info
        return None



        system_calls.py
        import os
import platform
import psutil

class SystemCalls:
    """
    Cross-platform System Call Interface
    Provides platform-appropriate low-level operations
    """
    
    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        print(f"System calls initialized for {'Windows' if self.is_windows else 'Linux'}")
    
    def create_process(self, program_path, args=None):
        """Create new process (cross-platform)"""
        try:
            import subprocess
            
            if args is None:
                args = []
            
            process = subprocess.Popen(
                [program_path] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            return process.pid
            
        except Exception as e:
            print(f"Process creation failed: {e}")
            return -1
    
    def allocate_memory(self, size):
        """Allocate memory (cross-platform)"""
        try:
            # Return a simulated memory pointer
            return id(bytearray(size))
        except Exception as e:
            print(f"Memory allocation failed: {e}")
            return None
    
    def open_file_direct(self, filepath, flags, mode=0o644):
        """Open file - simulation for cross-platform"""
        try:
            # For simulation, return a fake file descriptor
            fake_fd = hash(filepath) % 10000
            return fake_fd
        except Exception as e:
            print(f"File open failed: {e}")
            return -1
    
    def read_file_direct(self, fd, size):
        """Read from file - simulation"""
        try:
            # Return simulated data
            return b"Simulated file content for educational purposes"
        except Exception as e:
            print(f"File read failed: {e}")
            return None
    
    def write_file_direct(self, fd, data):
        """Write to file - simulation"""
        try:
            if isinstance(data, str):
                data = data.encode()
            return len(data)
        except Exception as e:
            print(f"File write failed: {e}")
            return -1
    
    def close_file_direct(self, fd):
        """Close file - simulation"""
        try:
            return 0
        except Exception as e:
            print(f"File close failed: {e}")
            return -1
    
    def get_process_info(self, pid=None):
        """Get process information (cross-platform)"""
        try:
            if pid is None:
                pid = os.getpid()
            
            try:
                process = psutil.Process(pid)
                info = {
                    'pid': pid,
                    'name': process.name(),
                    'status': process.status(),
                    'cpu_percent': process.cpu_percent(),
                    'memory_percent': process.memory_percent(),
                    'create_time': process.create_time(),
                    'exe': process.exe(),
                    'username': process.username()
                }
                return info
            except psutil.NoSuchProcess:
                return {'error': f'Process {pid} not found'}
                
        except Exception as e:
            print(f"Process info failed: {e}")
            return {}
    
    def get_system_metrics(self):
        """Get comprehensive system metrics (cross-platform)"""
        try:
            metrics = {
                'cpu_percent': psutil.cpu_percent(),
                'memory_info': dict(psutil.virtual_memory()._asdict()),
                'disk_usage': dict(psutil.disk_usage('/')._asdict()),
                'boot_time': psutil.boot_time(),
                'platform': platform.system(),
                'platform_version': platform.version()
            }
            
            # Add network info if available
            if psutil.net_io_counters():
                metrics['network_io'] = psutil.net_io_counters()._asdict()
            
            return metrics
            
        except Exception as e:
            print(f"System metrics failed: {e}")
            return {}


class AdvancedSystemCalls(SystemCalls):
    """
    Advanced system call operations for security monitoring
    """
    
    def __init__(self):
        super().__init__()
    
    def monitor_system_calls(self, pid=None):
        """Monitor system calls for a process"""
        try:
            if pid is None:
                pid = os.getpid()
            
            return {
                "platform": platform.system(), 
                "pid": pid, 
                "info": "System call monitoring in educational simulation mode"
            }
                    
        except Exception as e:
            return {"error": f"Monitoring failed: {e}"}



            UI


            main_window.py
            import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from datetime import datetime
from pathlib import Path  # ADD THIS IMPORT

class MainApplication:
    """
    Main application window with real-time monitoring and controls
    """
    
    def __init__(self, root, simulator):
        self.root = root
        self.simulator = simulator
        
        self.setup_window()
        self.create_widgets()
        self.setup_real_time_updates()
        
    def setup_window(self):
        """Setup the main window"""
        self.root.title("Ransomware Simulation & Recovery - OS Security Research")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
    
    def configure_styles(self):
        """Configure custom styles"""
        # Dark theme colors
        bg_color = '#2b2b2b'
        fg_color = '#ffffff'
        accent_color = '#007acc'
        warning_color = '#ff6b6b'
        success_color = '#51e3a4'
        
        self.style.configure('TFrame', background=bg_color)
        self.style.configure('TLabel', background=bg_color, foreground=fg_color, font=('Arial', 10))
        self.style.configure('Title.TLabel', font=('Arial', 14, 'bold'), foreground=accent_color)
        self.style.configure('Warning.TLabel', foreground=warning_color)
        self.style.configure('Success.TLabel', foreground=success_color)
        
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Action.TButton', background=accent_color, foreground=fg_color)
        self.style.configure('Danger.TButton', background=warning_color, foreground=fg_color)
        self.style.configure('Success.TButton', background=success_color, foreground=bg_color)
        
        self.style.configure('TNotebook', background=bg_color)
        self.style.configure('TNotebook.Tab', background=bg_color, foreground=fg_color)
        
    def create_widgets(self):
        """Create main application widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.create_header(main_frame)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create tabs
        self.create_simulation_tab()
        self.create_detection_tab()
        self.create_recovery_tab()
        self.create_system_tab()
        
        # Status bar
        self.create_status_bar(main_frame)
    
    def create_header(self, parent):
        """Create application header"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(header_frame, text="RANSOMWARE SIMULATION & RECOVERY SYSTEM", 
                               style='Title.TLabel')
        title_label.pack(side=tk.LEFT)
        
        # Simulation controls
        control_frame = ttk.Frame(header_frame)
        control_frame.pack(side=tk.RIGHT)
        
        self.simulate_btn = ttk.Button(control_frame, text="Start Simulation", 
                                      command=self.start_simulation, style='Danger.TButton')
        self.simulate_btn.pack(side=tk.LEFT, padx=5)
        
        self.recover_btn = ttk.Button(control_frame, text="Start Recovery", 
                                     command=self.start_recovery, style='Success.TButton')
        self.recover_btn.pack(side=tk.LEFT, padx=5)
        
        self.reset_btn = ttk.Button(control_frame, text="Reset Environment", 
                                   command=self.reset_environment)
        self.reset_btn.pack(side=tk.LEFT, padx=5)
    
    def create_simulation_tab(self):
        """Create simulation tab"""
        sim_frame = ttk.Frame(self.notebook)
        self.notebook.add(sim_frame, text="Simulation")
        
        # Simulation controls
        control_frame = ttk.Frame(sim_frame)
        control_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(control_frame, text="Ransomware Simulation Controls", 
                 style='Title.TLabel').pack(anchor=tk.W)
        
        # Progress frame
        progress_frame = ttk.Frame(sim_frame)
        progress_frame.pack(fill=tk.X, pady=10)
        
        self.sim_progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.sim_progress.pack(fill=tk.X, pady=5)
        
        self.sim_status = ttk.Label(progress_frame, text="Ready to start simulation")
        self.sim_status.pack(anchor=tk.W)
        
        # Ransom note preview
        ttk.Label(sim_frame, text="Ransom Note Preview", style='Title.TLabel').pack(anchor=tk.W, pady=(20, 5))
        
        self.ransom_note_text = scrolledtext.ScrolledText(sim_frame, height=15, width=100,
                                                         bg='#1e1e1e', fg='#ffffff', 
                                                         insertbackground='white')
        self.ransom_note_text.pack(fill=tk.BOTH, expand=True, pady=5)
        self.ransom_note_text.insert(tk.END, "Ransom note will appear here after simulation starts...")
        self.ransom_note_text.config(state=tk.DISABLED)
    
    def create_detection_tab(self):
        """Create threat detection tab"""
        det_frame = ttk.Frame(self.notebook)
        self.notebook.add(det_frame, text="Threat Detection")
        
        # Detection controls
        control_frame = ttk.Frame(det_frame)
        control_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(control_frame, text="Real-time Threat Detection", 
                 style='Title.TLabel').pack(anchor=tk.W)
        
        # Threat level indicator
        threat_frame = ttk.Frame(det_frame)
        threat_frame.pack(fill=tk.X, pady=10)
        
        self.threat_level = ttk.Label(threat_frame, text="THREAT LEVEL: LOW", 
                                     style='Success.TLabel', font=('Arial', 12, 'bold'))
        self.threat_level.pack(anchor=tk.W)
        
        self.threat_count = ttk.Label(threat_frame, text="Detected Threats: 0")
        self.threat_count.pack(anchor=tk.W)
        
        # Threat list
        ttk.Label(det_frame, text="Detected Threats", style='Title.TLabel').pack(anchor=tk.W, pady=(20, 5))
        
        # Treeview for threats
        columns = ('Time', 'Threat Level', 'File', 'Description')
        self.threat_tree = ttk.Treeview(det_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.threat_tree.heading(col, text=col)
            self.threat_tree.column(col, width=150)
        
        self.threat_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Scrollbar for threat tree
        scrollbar = ttk.Scrollbar(det_frame, orient=tk.VERTICAL, command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_recovery_tab(self):
        """Create recovery tab"""
        rec_frame = ttk.Frame(self.notebook)
        self.notebook.add(rec_frame, text="Recovery")
        
        # Recovery controls
        control_frame = ttk.Frame(rec_frame)
        control_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(control_frame, text="File Recovery System", 
                 style='Title.TLabel').pack(anchor=tk.W)
        
        # Recovery progress
        progress_frame = ttk.Frame(rec_frame)
        progress_frame.pack(fill=tk.X, pady=10)
        
        self.rec_progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.rec_progress.pack(fill=tk.X, pady=5)
        
        self.rec_status = ttk.Label(progress_frame, text="Ready for recovery")
        self.rec_status.pack(anchor=tk.W)
        
        # Recovery log
        ttk.Label(rec_frame, text="Recovery Log", style='Title.TLabel').pack(anchor=tk.W, pady=(20, 5))
        
        self.recovery_log = scrolledtext.ScrolledText(rec_frame, height=15, width=100,
                                                     bg='#1e1e1e', fg='#ffffff',
                                                     insertbackground='white')
        self.recovery_log.pack(fill=tk.BOTH, expand=True, pady=5)
        self.recovery_log.insert(tk.END, "Recovery log will appear here...\n")
        self.recovery_log.config(state=tk.DISABLED)
    
    def create_system_tab(self):
        """Create system monitoring tab"""
        sys_frame = ttk.Frame(self.notebook)
        self.notebook.add(sys_frame, text="System Monitor")
        
        # System stats
        stats_frame = ttk.Frame(sys_frame)
        stats_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(stats_frame, text="System Statistics", style='Title.TLabel').pack(anchor=tk.W)
        
        # Stats labels
        self.cpu_label = ttk.Label(stats_frame, text="CPU Usage: --%")
        self.cpu_label.pack(anchor=tk.W)
        
        self.memory_label = ttk.Label(stats_frame, text="Memory Usage: --%")
        self.memory_label.pack(anchor=tk.W)
        
        self.disk_label = ttk.Label(stats_frame, text="Disk Usage: --%")
        self.disk_label.pack(anchor=tk.W)
        
        self.process_label = ttk.Label(stats_frame, text="Active Processes: --")
        self.process_label.pack(anchor=tk.W)
        
        self.network_label = ttk.Label(stats_frame, text="Network Connections: --")
        self.network_label.pack(anchor=tk.W)
        
        # File system monitor
        ttk.Label(sys_frame, text="File System Activity", style='Title.TLabel').pack(anchor=tk.W, pady=(20, 5))
        
        self.file_activity_log = scrolledtext.ScrolledText(sys_frame, height=10, width=100,
                                                          bg='#1e1e1e', fg='#ffffff',
                                                          insertbackground='white')
        self.file_activity_log.pack(fill=tk.BOTH, expand=True, pady=5)
        self.file_activity_log.insert(tk.END, "File system activity will appear here...\n")
        self.file_activity_log.config(state=tk.DISABLED)
    
    def create_status_bar(self, parent):
        """Create status bar"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_label = ttk.Label(status_frame, text="Ready - Educational Simulation Active")
        self.status_label.pack(side=tk.LEFT)
        
        self.time_label = ttk.Label(status_frame, text="")
        self.time_label.pack(side=tk.RIGHT)
    
    def setup_real_time_updates(self):
        """Setup real-time updates for system monitoring"""
        def update_system_stats():
            while True:
                try:
                    stats = self.simulator.get_system_stats()
                    
                    self.cpu_label.config(text=f"CPU Usage: {stats['cpu_percent']:.1f}%")
                    self.memory_label.config(text=f"Memory Usage: {stats['memory_percent']:.1f}%")
                    self.disk_label.config(text=f"Disk Usage: {stats['disk_usage']:.1f}%")
                    self.process_label.config(text=f"Active Processes: {stats['active_processes']}")
                    self.network_label.config(text=f"Network Connections: {stats['network_connections']}")
                    
                    self.time_label.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    
                except Exception as e:
                    print(f"Stats update error: {e}")
                
                time.sleep(2)
        
        stats_thread = threading.Thread(target=update_system_stats, daemon=True)
        stats_thread.start()
    
    def start_simulation(self):
        """Start ransomware simulation"""
        self.simulate_btn.config(state=tk.DISABLED)
        self.recover_btn.config(state=tk.DISABLED)
        
        def simulation_callback(message):
            self.root.after(0, lambda: self.update_simulation_status(message))
        
        self.simulator.start_simulation(simulation_callback)
    
    def update_simulation_status(self, message):
        """Update simulation status in UI"""
        self.sim_status.config(text=message)
        self.status_label.config(text=message)
        
        if "ransom note" in message.lower():
            # Update ransom note preview
            ransom_note_path = self.simulator.test_dir / "!!!_READ_ME_IMPORTANT_!!!.txt"
            if ransom_note_path.exists():
                with open(ransom_note_path, 'r') as f:
                    note_content = f.read()
                
                self.ransom_note_text.config(state=tk.NORMAL)
                self.ransom_note_text.delete(1.0, tk.END)
                self.ransom_note_text.insert(tk.END, note_content)
                self.ransom_note_text.config(state=tk.DISABLED)
        
        if "encryption" in message.lower():
            # Update progress
            file_count = len(self.simulator.encrypted_files)
            total_files = len(list(self.simulator.test_dir.iterdir())) - 1  # Exclude ransom note
            
            if total_files > 0:
                progress = (file_count / total_files) * 100
                self.sim_progress['value'] = progress
    
    def update_encryption_status(self, file_count, file_path):
        """Update encryption progress"""
        def update():
            total_files = len(list(self.simulator.test_dir.iterdir())) - 1
            
            if total_files > 0:
                progress = (file_count / total_files) * 100
                self.sim_progress['value'] = progress
                self.sim_status.config(text=f"Encrypted {file_count}/{total_files} files: {Path(file_path).name}")
                
                if file_count >= total_files:
                    self.sim_status.config(text="Simulation complete! All files encrypted.")
                    self.simulate_btn.config(state=tk.NORMAL)
                    self.recover_btn.config(state=tk.NORMAL)
                    self.status_label.config(text="Simulation complete - Ready for recovery")
        
        self.root.after(0, update)
    
    def add_threat_detection(self, threat_info):
        """Add threat detection to UI"""
        def update():
            # Update threat count
            threat_count = len(self.simulator.detected_threats)
            self.threat_count.config(text=f"Detected Threats: {threat_count}")
            
            # Update threat level
            if threat_count > 10:
                self.threat_level.config(text="THREAT LEVEL: CRITICAL", style='Warning.TLabel')
            elif threat_count > 5:
                self.threat_level.config(text="THREAT LEVEL: HIGH", style='Warning.TLabel')
            elif threat_count > 2:
                self.threat_level.config(text="THREAT LEVEL: MEDIUM")
            else:
                self.threat_level.config(text="THREAT LEVEL: LOW", style='Success.TLabel')
            
            # Add to threat tree
            timestamp = datetime.fromtimestamp(threat_info['timestamp']).strftime('%H:%M:%S')
            level_text = {3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(threat_info['threat_level'], "UNKNOWN")
            
            self.threat_tree.insert('', 0, values=(
                timestamp,
                level_text,
                threat_info['event'].get('name', 'Unknown'),
                threat_info['description']
            ))
            
            # Update file activity log
            self.file_activity_log.config(state=tk.NORMAL)
            self.file_activity_log.insert(tk.END, 
                                         f"[{timestamp}] {threat_info['description']}\n")
            self.file_activity_log.see(tk.END)
            self.file_activity_log.config(state=tk.DISABLED)
        
        self.root.after(0, update)
    
    def start_recovery(self):
        """Start recovery process"""
        self.simulate_btn.config(state=tk.DISABLED)
        self.recover_btn.config(state=tk.DISABLED)
        
        def recovery_callback(message):
            self.root.after(0, lambda: self.update_recovery_status(message))
        
        self.simulator.start_recovery(recovery_callback)
    
    def update_recovery_status(self, message):
        """Update recovery status in UI"""
        self.rec_status.config(text=message)
        self.status_label.config(text=message)
        
        # Update recovery log
        self.recovery_log.config(state=tk.NORMAL)
        self.recovery_log.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.recovery_log.see(tk.END)
        self.recovery_log.config(state=tk.DISABLED)
    
    def update_recovery_status(self, file_count, file_path):
        """Update recovery progress"""
        def update():
            total_files = len(self.simulator.encrypted_files)
            
            if total_files > 0:
                progress = (file_count / total_files) * 100
                self.rec_progress['value'] = progress
                self.rec_status.config(text=f"Recovered {file_count}/{total_files} files: {Path(file_path).name}")
        
        self.root.after(0, update)
    
    def recovery_complete(self, recovered_count):
        """Handle recovery completion"""
        def update():
            self.rec_progress['value'] = 100
            self.rec_status.config(text=f"Recovery complete! {recovered_count} files restored.")
            self.status_label.config(text="Recovery complete - System secure")
            
            self.simulate_btn.config(state=tk.NORMAL)
            self.recover_btn.config(state=tk.NORMAL)
            
            # Show completion message
            messagebox.showinfo("Recovery Complete", 
                              f"Successfully recovered {recovered_count} files!\n"
                              "All ransom notes have been removed.\n"
                              "System is now secure.")
        
        self.root.after(0, update)
    
    def reset_environment(self):
        """Reset the test environment"""
        try:
            # Clear test directory
            for file_path in self.simulator.test_dir.iterdir():
                if file_path.is_file():
                    file_path.unlink()
            
            # Clear ransom notes
            for file_path in self.simulator.ransom_notes_dir.iterdir():
                if file_path.is_file():
                    file_path.unlink()
            
            # Recreate sample files
            self.simulator.create_sample_files()
            
            # Reset UI
            self.sim_progress['value'] = 0
            self.rec_progress['value'] = 0
            self.sim_status.config(text="Environment reset - Ready for simulation")
            self.rec_status.config(text="Ready for recovery")
            self.status_label.config(text="Environment reset - Ready")
            
            # Clear threat detection
            for item in self.threat_tree.get_children():
                self.threat_tree.delete(item)
            
            self.threat_count.config(text="Detected Threats: 0")
            self.threat_level.config(text="THREAT LEVEL: LOW", style='Success.TLabel')
            
            # Clear logs
            self.ransom_note_text.config(state=tk.NORMAL)
            self.ransom_note_text.delete(1.0, tk.END)
            self.ransom_note_text.insert(tk.END, "Ransom note will appear here after simulation starts...")
            self.ransom_note_text.config(state=tk.DISABLED)
            
            self.recovery_log.config(state=tk.NORMAL)
            self.recovery_log.delete(1.0, tk.END)
            self.recovery_log.insert(tk.END, "Recovery log will appear here...\n")
            self.recovery_log.config(state=tk.DISABLED)
            
            self.file_activity_log.config(state=tk.NORMAL)
            self.file_activity_log.delete(1.0, tk.END)
            self.file_activity_log.insert(tk.END, "File system activity will appear here...\n")
            self.file_activity_log.config(state=tk.DISABLED)
            
            # Reset simulator state
            self.simulator.encrypted_files.clear()
            self.simulator.detected_threats.clear()
            self.simulator.encryption_key = None
            
            messagebox.showinfo("Reset Complete", "Test environment has been reset successfully!")
            
        except Exception as e:
            messagebox.showerror("Reset Error", f"Failed to reset environment: {str(e)}")




            main.py 
            #!/usr/bin/env python3
"""
Ransomware Simulation & Recovery Project
Educational Cybersecurity Tool
"""

import os
import sys
import json
import threading
import time
import traceback
from pathlib import Path

# Add comprehensive error handling
def handle_exception(exc_type, exc_value, exc_traceback):
    """Global exception handler to catch all errors"""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    print("\n" + "="*60)
    print("CRITICAL ERROR - Application cannot start")
    print("="*60)
    traceback.print_exception(exc_type, exc_value, exc_traceback)
    print("="*60)
    
    input("\nPress Enter to exit...")
    sys.exit(1)

# Set global exception handler
sys.excepthook = handle_exception

print("Starting Ransomware Simulation Application...")
print(f"Python: {sys.version}")
print(f"Working directory: {os.getcwd()}")

# Add src to path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))
print(f"Source path: {src_path}")

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    print("✓ Tkinter imports successful")
except ImportError as e:
    print(f"✗ Tkinter import failed: {e}")
    input("Press Enter to exit...")
    sys.exit(1)

try:
    from core.file_monitor import AdvancedFileMonitor
    from core.encrypt_engine import AdvancedEncryptor
    from core.threat_detector import ThreatDetector
    from core.recovery_system import RecoverySystem
    from kernel.memory_manager import EncryptionMemoryManager
    from kernel.system_calls import AdvancedSystemCalls
    from ui.main_window import MainApplication
    print("✓ All application imports successful")
except ImportError as e:
    print(f"✗ Application import failed: {e}")
    traceback.print_exc()
    input("Press Enter to exit...")
    sys.exit(1)

class RansomwareSimulator:
    """
    Main controller for ransomware simulation with real-time UI
    """
    
    def __init__(self):
        print("Initializing RansomwareSimulator...")
        try:
            # Create root window first
            self.root = tk.Tk()
            self.root.title("Ransomware Simulation & Recovery")
            
            # Set window to appear in center and be always on top initially
            self.root.geometry("1200x800")
            self.root.lift()
            self.root.attributes('-topmost', True)
            self.root.after(1000, lambda: self.root.attributes('-topmost', False))
            
            self.app = None
            
            # Configuration
            self.config = self.load_config()
            self.test_dir = Path(self.config['test_directory'])
            self.backup_dir = Path(self.config['backup_directory'])
            self.ransom_notes_dir = Path(self.config['ransom_notes_directory'])
            
            # Create directories
            self.setup_directories()
            
            # Enhanced OS components (simulated for Windows)
            print("Initializing system components...")
            self.system_calls = AdvancedSystemCalls()
            self.memory_manager = EncryptionMemoryManager()
            
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
            
            print("✓ Ransomware Simulator initialized successfully!")
            
        except Exception as e:
            print(f"✗ Error during simulator initialization: {e}")
            traceback.print_exc()
            raise
        
    def load_config(self):
        """Load configuration from JSON file"""
        config_path = Path(__file__).parent / 'config' / 'config.json'
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            print("✓ Configuration loaded successfully")
            return config
        except Exception as e:
            print(f"⚠ Config load error: {e}, using defaults")
            return self.get_default_config()
    
    def get_default_config(self):
        """Get default configuration if config file is missing"""
        return {
            "test_directory": "./data/test_files",
            "backup_directory": "./data/backups", 
            "ransom_notes_directory": "./data/ransom_notes",
            "log_directory": "./data/logs"
        }
    
    def setup_directories(self):
        """Create necessary directories"""
        print("Setting up directories...")
        self.test_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.ransom_notes_dir.mkdir(parents=True, exist_ok=True)
        
        # Create sample test files
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
        
        print(f"✓ Created {created_count} sample files in {self.test_dir}")
    
    def start_simulation(self, callback=None):
        """Start the ransomware simulation"""
        try:
            print("Starting simulation...")
            self.simulation_active = True
            
            # Generate encryption key
            self.encryption_key = self.encryptor.generate_key()
            
            # Start file monitoring
            self.file_monitor.start_monitoring(self.file_event_callback)
            
            # Start threat detection
            self.threat_detector.start_detection(self.threat_callback)
            
            # Create ransom note
            self.create_ransom_note()
            
            # Encrypt files in background thread
            encryption_thread = threading.Thread(target=self.encrypt_files)
            encryption_thread.daemon = True
            encryption_thread.start()
            
            if callback:
                callback("Simulation started - Creating ransom note...")
                
        except Exception as e:
            print(f"✗ Simulation error: {e}")
            if callback:
                callback(f"Simulation error: {str(e)}")
    
    def encrypt_files(self):
        """Encrypt files in the test directory"""
        try:
            file_count = 0
            files = list(self.test_dir.iterdir())
            print(f"Found {len(files)} files to encrypt")
            
            for file_path in files:
                if file_path.is_file() and not file_path.name.startswith("!!!_"):
                    print(f"Encrypting: {file_path.name}")
                    if self.encryptor.encrypt_file(file_path, self.encryption_key):
                        self.encrypted_files.append(file_path)
                        file_count += 1
                        
                        # Update UI in thread-safe manner
                        if hasattr(self, 'app') and self.app:
                            self.app.update_encryption_status(file_count, str(file_path))
                        
                        # Small delay to simulate real encryption process
                        time.sleep(0.1)
                    else:
                        print(f"✗ Failed to encrypt: {file_path.name}")
            
            print(f"✓ Encryption completed: {file_count} files encrypted")
            
        except Exception as e:
            print(f"✗ Encryption error: {e}")
            traceback.print_exc()
    
    def create_ransom_note(self):
        """Create realistic ransom note"""
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
This is an educational simulation for cybersecurity research.
Use the recovery button to decrypt your files.

================================================================
No actual harm has been done to your system.
This is for educational purposes only.
================================================================
"""
        
        ransom_note_path = self.test_dir / "!!!_READ_ME_IMPORTANT_!!!.txt"
        with open(ransom_note_path, 'w') as f:
            f.write(ransom_note_content)
        
        # Also create desktop note
        desktop_note = self.ransom_notes_dir / "YOUR_FILES_ARE_ENCRYPTED.txt"
        with open(desktop_note, 'w') as f:
            f.write(ransom_note_content)
        
        print("✓ Ransom note created successfully")
        return ransom_note_path
    
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
            
            # Update UI
            if hasattr(self, 'app') and self.app:
                self.app.add_threat_detection(threat_info)
    
    def threat_callback(self, threat_info):
        """Callback for threat detection"""
        self.detected_threats.append(threat_info)
        
        # Update UI
        if hasattr(self, 'app') and self.app:
            self.app.add_threat_detection(threat_info)
    
    def start_recovery(self, callback=None):
        """Start recovery process"""
        try:
            if not self.encryption_key:
                if callback:
                    callback("Error: No encryption key available for recovery")
                return
            
            recovery_thread = threading.Thread(target=self._recover_files)
            recovery_thread.daemon = True
            recovery_thread.start()
            
            if callback:
                callback("Recovery started - Decrypting files...")
                
        except Exception as e:
            if callback:
                callback(f"Recovery error: {str(e)}")
    
    def _recover_files(self):
        """Recover files in background"""
        try:
            recovered_count = 0
            print(f"Starting recovery of {len(self.encrypted_files)} files")
            
            for file_path in self.encrypted_files:
                if file_path.exists():
                    print(f"Recovering: {file_path.name}")
                    if self.encryptor.decrypt_file(file_path, self.encryption_key):
                        recovered_count += 1
                        
                        # Update UI
                        if hasattr(self, 'app') and self.app:
                            self.app.update_recovery_status(recovered_count, str(file_path))
                        
                        time.sleep(0.05)
                    else:
                        print(f"✗ Failed to recover: {file_path.name}")
            
            # Remove ransom notes
            ransom_note = self.test_dir / "!!!_READ_ME_IMPORTANT_!!!.txt"
            desktop_note = self.ransom_notes_dir / "YOUR_FILES_ARE_ENCRYPTED.txt"
            
            if ransom_note.exists():
                ransom_note.unlink()
            if desktop_note.exists():
                desktop_note.unlink()
            
            # Clear encrypted files list
            self.encrypted_files.clear()
            
            print(f"✓ Recovery completed: {recovered_count} files recovered")
            
            # Show completion message
            if hasattr(self, 'app') and self.app:
                self.app.recovery_complete(recovered_count)
                
        except Exception as e:
            print(f"✗ Recovery error: {e}")
            traceback.print_exc()
    
    def get_system_stats(self):
        """Get current system statistics"""
        try:
            import psutil
            
            return {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'active_processes': len(psutil.pids()),
                'network_connections': len(psutil.net_connections())
            }
        except Exception as e:
            print(f"⚠ System stats error: {e}")
            return {
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_usage': 0,
                'active_processes': 0,
                'network_connections': 0
            }
    
    def get_os_components(self):
        """Get OS components for UI integration"""
        return {
            'system_calls': self.system_calls,
            'memory_manager': self.memory_manager
        }
    
    def cleanup(self):
        """Cleanup all resources"""
        print("Cleaning up resources...")
        self.simulation_active = False
        self.file_monitor.stop_monitoring()
        self.threat_detector.stop_detection()
        print("✓ Simulation cleanup complete")

    def run(self):
        """Start the application"""
        try:
            print("Creating main application window...")
            self.app = MainApplication(self.root, self)
            print("✓ Main application created successfully!")
            print("Starting main loop...")
            self.root.mainloop()
            print("Main loop ended.")
        except Exception as e:
            print(f"✗ Error in main loop: {e}")
            traceback.print_exc()

def main():
    """Main entry point"""
    print("🚀 Application starting...")
    
    simulator = None
    try:
        simulator = RansomwareSimulator()
        print("✓ Simulator created, starting GUI...")
        simulator.run()
    except KeyboardInterrupt:
        print("\n⚠ Application interrupted by user")
    except Exception as e:
        print(f"✗ Fatal application error: {e}")
        traceback.print_exc()
        input("Press Enter to exit...")
    finally:
        if simulator:
            simulator.cleanup()
    
    print("Application closed.")

if __name__ == "__main__":
    main()


    config.json 
    {
    "test_directory": "./data/test_files",
    "backup_directory": "./data/backups",
    "ransom_notes_directory": "./data/ransom_notes",
    "log_directory": "./data/logs",
    
    "simulation_settings": {
        "encryption_algorithm": "AES-256-CBC",
        "file_extensions_to_encrypt": [".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".png"],
        "max_file_size_mb": 10,
        "simulation_delay_ms": 100
    },
    
    "detection_settings": {
        "mass_operation_threshold": 10,
        "entropy_threshold": 7.0,
        "monitor_interval_seconds": 1
    },
    
    "recovery_settings": {
        "backup_retention_days": 7,
        "auto_backup_interval_hours": 24
    },
    
    "ui_settings": {
        "theme": "dark",
        "update_interval_ms": 1000,
        "max_log_entries": 1000
    }
}

simulation_rules.json
{
    "ransomware_patterns": {
        "file_extensions": [".encrypted", ".locked", ".crypto", ".ransom"],
        "ransom_note_names": ["READ_ME", "DECRYPT", "RECOVER", "HELP_YOUR_FILES"],
        "suspicious_processes": ["encrypt", "locker", "crypto", "ransom"]
    },
    
    "detection_thresholds": {
        "files_per_minute": 50,
        "entropy_threshold": 7.5,
        "similar_extension_changes": 10
    },
    
    "prevention_rules": {
        "protected_directories": ["/home", "/documents", "/desktop"],
        "allowed_processes": ["explorer", "notepad", "word", "excel"],
        "blocked_extensions": [".exe", ".bat", ".cmd", ".ps1"]
    }
}

this project is based on operating system   
