import ctypes
import os
import platform
import psutil

class MemoryManager:
    """
    Cross-platform Memory Management for Ransomware Simulation
    """
    
    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        self.memory_regions = {}
        self.locked_pages = []
        
        print(f"Memory manager initialized for {'Windows' if self.is_windows else 'Linux'}")
    
    def allocate_secure_memory(self, size, description="secure_data"):
        """
        Allocate memory with enhanced security features (cross-platform)
        """
        try:
            # Use ctypes for cross-platform memory allocation
            buffer = (ctypes.c_byte * size)()
            memory_ptr = ctypes.addressof(buffer)
            
            # Store memory region info
            region_id = f"region_{len(self.memory_regions)}"
            self.memory_regions[region_id] = {
                'ptr': memory_ptr,
                'size': size,
                'description': description,
                'buffer': buffer,  # Keep reference to prevent garbage collection
                'locked': False,
                'protected': False
            }
            
            print(f"Allocated secure memory: {size} bytes for {description}")
            return memory_ptr, region_id
            
        except Exception as e:
            print(f"Memory allocation failed: {e}")
            return None, None
    
    def lock_memory_region(self, address, size):
        """Lock memory pages (simulated on Windows)"""
        try:
            # On Windows, we simulate memory locking
            # In a real implementation, you'd use VirtualLock
            self.locked_pages.append((address, size))
            return True
        except Exception as e:
            print(f"Memory locking failed: {e}")
            return False
    
    def unlock_memory_region(self, address, size):
        """Unlock memory pages"""
        try:
            # Remove from locked pages list
            self.locked_pages = [(addr, sz) for addr, sz in self.locked_pages 
                               if addr != address or sz != size]
            return True
        except Exception as e:
            print(f"Memory unlocking failed: {e}")
            return False
    
    def set_memory_protection(self, address, size, protection_flags):
        """
        Set memory protection flags (simulated on Windows)
        """
        try:
            # On Windows, we simulate memory protection
            # In a real implementation, you'd use VirtualProtect
            return True
        except Exception as e:
            print(f"Memory protection failed: {e}")
            return False
    
    def create_secure_mapping(self, file_path, size=0):
        """
        Create memory-mapped file (cross-platform simulation)
        """
        try:
            # For cross-platform compatibility, we'll use file reading
            # In a real implementation, you'd use mmap module
            with open(file_path, 'r+b') as f:
                file_data = f.read()
            
            # Create a memory buffer with the file data
            buffer_size = len(file_data) if size == 0 else size
            buffer = (ctypes.c_byte * buffer_size)()
            
            # Copy file data to buffer
            for i, byte in enumerate(file_data[:buffer_size]):
                buffer[i] = byte
            
            print(f"Created secure memory mapping for {file_path}")
            return buffer
            
        except Exception as e:
            print(f"Secure mapping failed: {e}")
            return None
    
    def free_secure_memory(self, region_id):
        """Free securely allocated memory"""
        if region_id in self.memory_regions:
            region = self.memory_regions[region_id]
            
            # Unlock memory if locked
            if region['locked']:
                self.unlock_memory_region(region['ptr'], region['size'])
            
            # Remove from tracking (buffer will be garbage collected)
            del self.memory_regions[region_id]
            
            print(f"Freed secure memory: {region['description']}")
            return True
        return False
    
    def get_memory_stats(self):
        """Get detailed memory statistics (cross-platform)"""
        try:
            virtual_memory = psutil.virtual_memory()
            swap_memory = psutil.swap_memory()
            
            return {
                'total_memory': virtual_memory.total,
                'available_memory': virtual_memory.available,
                'used_memory': virtual_memory.used,
                'memory_percent': virtual_memory.percent,
                'swap_total': swap_memory.total,
                'swap_used': swap_memory.used,
                'swap_free': swap_memory.free,
                'locked_pages_count': len(self.locked_pages),
                'active_regions': len(self.memory_regions),
                'total_locked_memory': sum(size for _, size in self.locked_pages),
                'platform': platform.system()
            }
        except Exception as e:
            print(f"Memory stats error: {e}")
            return {}
    
    def detect_memory_anomalies(self):
        """Detect potential memory-based attacks"""
        stats = self.get_memory_stats()
        anomalies = []
        
        # Check for excessive memory usage
        if stats.get('memory_percent', 0) > 90:
            anomalies.append("High memory usage detected")
        
        # Check for swap usage
        if stats.get('swap_used', 0) > stats.get('swap_total', 1) * 0.5:
            anomalies.append("High swap usage detected")
        
        return anomalies
    
    def secure_memory_cleanup(self):
        """Cleanup all secure memory regions"""
        print("Performing secure memory cleanup...")
        
        # Free all allocated regions
        for region_id in list(self.memory_regions.keys()):
            self.free_secure_memory(region_id)
        
        self.locked_pages.clear()
        print("Secure memory cleanup completed")


class EncryptionMemoryManager(MemoryManager):
    """
    Specialized memory manager for encryption operations
    """
    
    def __init__(self):
        super().__init__()
        self.encryption_buffers = {}
    
    def create_encryption_buffer(self, buffer_id, size):
        """Create secure buffer for encryption operations"""
        ptr, region_id = self.allocate_secure_memory(size, f"encryption_buffer_{buffer_id}")
        
        if ptr:
            self.encryption_buffers[buffer_id] = {
                'ptr': ptr,
                'size': size,
                'region_id': region_id
            }
            return ptr
        return None
    
    def secure_encryption_operation(self, buffer_id, data):
        """Perform secure encryption operation in protected memory"""
        if buffer_id not in self.encryption_buffers:
            return None
        
        buffer_info = self.encryption_buffers[buffer_id]
        
        try:
            # Get the buffer object
            buffer_obj = self.memory_regions[buffer_info['region_id']]['buffer']
            
            # Copy data to secure buffer
            data_bytes = data if isinstance(data, bytes) else data.encode()
            
            # Copy data to buffer (simplified approach)
            for i in range(min(len(data_bytes), buffer_info['size'])):
                buffer_obj[i] = data_bytes[i]
            
            # Simulate encryption operation
            encrypted_data = self._simulate_encryption(data_bytes)
            
            return encrypted_data
            
        except Exception as e:
            print(f"Secure encryption operation failed: {e}")
            return None
    
    def _simulate_encryption(self, data):
        """Simulate encryption operation (XOR for demonstration)"""
        # In real implementation, use proper cryptography
        key = b'encryption_key_demo'
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % len(key)])
        return bytes(encrypted)
    
    def cleanup_encryption_buffers(self):
        """Cleanup all encryption buffers"""
        for buffer_id in list(self.encryption_buffers.keys()):
            buffer_info = self.encryption_buffers[buffer_id]
            self.free_secure_memory(buffer_info['region_id'])
            del self.encryption_buffers[buffer_id]