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