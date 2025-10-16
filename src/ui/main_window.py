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
            self.root.after(0, lambda: self.set_recovery_status(message))
        
        self.simulator.start_recovery(recovery_callback)
    
    def set_recovery_status(self, message):
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