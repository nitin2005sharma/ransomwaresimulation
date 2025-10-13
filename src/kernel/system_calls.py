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