import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

from functools import lru_cache

def _derive_keys(password: str, salt: bytes) -> tuple:
    """
    Derives a 256-bit encryption key and a 256-bit HMAC key from a password using PBKDF2.
    Uses 100,000 iterations for secure key stretching.
    Results are cached to avoid redundant computation when viewing logs.
    """
    return _derive_keys_cached(password, salt)

@lru_cache(maxsize=512)
def _derive_keys_cached(password: str, salt: bytes) -> tuple:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64, # 32 bytes for AES key, 32 bytes for HMAC key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key_material = kdf.derive(password.encode('utf-8'))
    aes_key = key_material[:32]
    hmac_key = key_material[32:]
    return aes_key, hmac_key

def encrypt_data(data: str, password: str) -> bytes:
    """
    Encrypts string data using AES-256-CBC and adds an HMAC-SHA256 tag to ensure integrity.
    
    Format of output:
    [Salt (16 bytes)] [IV (16 bytes)] [HMAC (32 bytes)] [Ciphertext]
    """
    # 1. Generate 16-byte random salt and 16-byte random IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    # 2. Derive secure keys
    aes_key, hmac_key = _derive_keys(password, salt)
    
    # 3. Pad the data using PKCS7 (Standard for AES CBC)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
    
    # 4. Encrypt with AES in CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # 5. Generate HMAC of the ciphertext for integrity
    h = HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    # Binding IV with ciphertext prevents IV manipulation
    h.update(iv + ciphertext) 
    hmac_tag = h.finalize()
    
    # 6. Return combined payload
    return salt + iv + hmac_tag + ciphertext

class SecurityException(Exception):
    """Custom exception raised during integrity or decryption failures."""
    pass

def decrypt_data(encrypted_data: bytes, password: str) -> str:
    """
    Decrypts encrypted data securely, strictly verifying HMAC-SHA256 integrity first.
    """
    if len(encrypted_data) < 16 + 16 + 32:
        raise SecurityException("Encrypted data is too short or corrupted.")
    
    # 1. Extract Salt, IV, HMAC Tag, and Ciphertext from the payload
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    hmac_tag = encrypted_data[32:64]
    ciphertext = encrypted_data[64:]
    
    # 2. Derive keys using extracted salt
    aes_key, hmac_key = _derive_keys(password, salt)
    
    # 3. Verify HMAC (integrity check) before any decryption occurs
    h = HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    try:
        h.verify(hmac_tag)
    except Exception:
        raise SecurityException("Integrity check failed: HMAC does not match. Data tampered or wrong password.")
    
    # 4. Decrypt ciphertext
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 5. Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode('utf-8')
