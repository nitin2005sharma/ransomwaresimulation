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
