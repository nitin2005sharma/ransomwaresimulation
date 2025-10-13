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