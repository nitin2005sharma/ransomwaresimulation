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