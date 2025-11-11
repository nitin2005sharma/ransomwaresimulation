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
                        encrypted_path = Path(str(file_path) + ".encrypted")
                        self.encrypted_files.append(encrypted_path)
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
                            self.app.update_recovery_progress(recovered_count, str(file_path))
                        
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
