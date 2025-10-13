import os
import shutil
from pathlib import Path

def cleanup_files():
    """Clean up all test files and encrypted files"""
    directories = [
        "./data/test_files",
        "./data/backups", 
        "./data/ransom_notes",
        "./data/logs"
    ]
    
    for dir_path in directories:
        dir_obj = Path(dir_path)
        if dir_obj.exists():
            print(f"Cleaning {dir_path}...")
            # Remove all files in directory
            for file_path in dir_obj.iterdir():
                if file_path.is_file():
                    file_path.unlink()
                    print(f"  Removed: {file_path.name}")
            
            # Recreate empty directory
            if dir_path != "./data":
                dir_obj.mkdir(exist_ok=True)
    
    print("Cleanup complete!")

if __name__ == "__main__":
    cleanup_files()