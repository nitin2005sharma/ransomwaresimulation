import os
import hashlib
import secrets

def generate_secure_key(length=32):
    """Generate cryptographically secure random key"""
    return secrets.token_bytes(length)

def hash_password(password, salt=None):
    """Hash password with salt using PBKDF2"""
    if salt is None:
        salt = os.urandom(32)
    
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Number of iterations
    )
    
    return salt + key

def verify_password(password, hashed):
    """Verify password against stored hash"""
    salt = hashed[:32]
    stored_key = hashed[32:]
    
    computed_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    
    return secrets.compare_digest(computed_key, stored_key)

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal"""
    return "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_', '.')).rstrip()