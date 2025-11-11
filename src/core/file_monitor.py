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
