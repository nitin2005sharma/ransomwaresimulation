import os
import time
import math
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
                    entropy -= p * math.log2(p)
            
            return entropy
            
        except Exception:
            return 0
