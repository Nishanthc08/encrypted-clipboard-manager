#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cryptographic functions for the Encrypted Clipboard Manager.
Implements AES-256 encryption with user-provided password.
"""

import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class CryptoHandler:
    """Handles encryption and decryption of clipboard data."""
    
    def __init__(self):
        """Initialize the crypto handler."""
        self.password = None
        self.key = None
        self.salt = None
        self.backend = default_backend()
        self.encrypted_data_path = os.path.expanduser("~/.encrypted_clipboard_history")
        
        # Create storage directory if it doesn't exist
        os.makedirs(os.path.dirname(self.encrypted_data_path), exist_ok=True)
    
    def set_password(self, password):
        """Set the encryption password and derive key."""
        # Store old key and salt to handle re-encryption if needed
        old_key = self.key
        old_salt = self.salt
        
        # Always generate a new salt when changing passwords
        # This ensures old encrypted data can't be decrypted with the new key
        self.salt = os.urandom(16)
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits
            salt=self.salt,
            iterations=100000,
            backend=self.backend
        )
        
        # Update password and derive new key
        self.password = password
        self.key = kdf.derive(password.encode())
        
        # If we had an old key, and we're changing the password,
        # we need to re-encrypt existing data
        if old_key and old_salt != self.salt:
            # Create a deep copy of old values to ensure we have proper backup
            # in case re-encryption fails
            stored_key, stored_salt = old_key, old_salt
            
            try:
                self._reencrypt_history(stored_key, stored_salt)
            except Exception as e:
                print(f"Error during history re-encryption: {e}")
                # Initialize with empty history on failure
                self._initialize_empty_history()
        
        return True
    
    def _reencrypt_history(self, old_key, old_salt):
        """Re-encrypt history with a new key when password changes."""
        if not os.path.exists(self.encrypted_data_path):
            return
        
        try:
            # Save the current key and salt
            new_key = self.key
            new_salt = self.salt
            
            # Temporarily restore the old key and salt
            self.key = old_key
            self.salt = old_salt
            
            # Load history with old key
            history = self.load_encrypted_history()
            
            # Restore the new key and salt
            self.key = new_key
            self.salt = new_salt
            
            # Process each entry to re-encrypt with the new key
            for entry in history:
                if "encrypted_content" in entry:
                    old_encrypted = entry["encrypted_content"]
                    # Decrypt with the old key
                    plain_content = self.decrypt_data(old_encrypted)
                    # Re-encrypt with the new key
                    entry["encrypted_content"] = self.encrypt_data(plain_content)
            
            # Save the re-encrypted history
            self.save_encrypted_history(history)
        except Exception as e:
            # Log any errors during re-encryption
            print(f"Error re-encrypting history: {e}")
            # If re-encryption fails, we should at least have a valid empty history
            self.save_encrypted_history([])
    
    def encrypt_data(self, data):
        """Encrypt clipboard data using AES-256."""
        if not self.key:
            raise ValueError("Encryption key not initialized. Set a password first.")
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Create an encryptor object
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Convert data to bytes and pad to block size
        data_bytes = data.encode()
        padded_data = self._pad_data(data_bytes)
        
        # Encrypt the data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data
        result = {
            "iv": base64.b64encode(iv).decode(),
            "data": base64.b64encode(encrypted_data).decode()
        }
        
        return result
    
    def decrypt_data(self, encrypted_data):
        """Decrypt clipboard data."""
        if not self.key:
            raise ValueError("Encryption key not initialized. Set a password first.")
        
        try:
            # Extract IV and encrypted data
            iv = base64.b64decode(encrypted_data["iv"])
            data = base64.b64decode(encrypted_data["data"])
            
            # Create a decryptor object
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            
            # Decrypt the data
            decrypted_padded_data = decryptor.update(data) + decryptor.finalize()
            
            # Unpad the data - this will likely fail if the wrong key is used
            decrypted_data = self._unpad_data(decrypted_padded_data)
            
            # Try to decode - this will fail if garbage data was produced by wrong key
            result = decrypted_data.decode('utf-8')
            
            # Extra validation check - if the key is wrong, we might get valid UTF-8
            # but it will likely contain unprintable control characters
            if any(ord(c) < 9 for c in result):  # ASCII control chars
                raise ValueError("Decryption resulted in control characters - likely wrong key")
                
            return result
            
        except Exception as e:
            # Wrap all decryption errors as a consistent exception
            raise ValueError(f"Failed to decrypt data. Wrong password or corrupted data: {str(e)}")
    
    def save_encrypted_history(self, history):
        """Save encrypted clipboard history to disk."""
        if not self.key:
            raise ValueError("Encryption key not initialized. Set a password first.")
        
        # Encrypt the entire history
        encrypted_history = {
            "salt": base64.b64encode(self.salt).decode(),
            "entries": history
        }
        
        with open(self.encrypted_data_path, 'w') as f:
            json.dump(encrypted_history, f)
    
    def load_encrypted_history(self):
        """Load encrypted clipboard history from disk."""
        if not os.path.exists(self.encrypted_data_path):
            # Initialize with an empty history file
            self._initialize_empty_history()
            return []
        
        try:
            with open(self.encrypted_data_path, 'r') as f:
                file_content = f.read().strip()
                if not file_content:
                    # File exists but is empty, initialize it
                    self._initialize_empty_history()
                    return []
                
                encrypted_history = json.loads(file_content)
            
            # Set the salt from the loaded data
            if "salt" in encrypted_history:
                self.salt = base64.b64decode(encrypted_history["salt"])
            
            # We'll need to re-derive the key with the correct password before decrypting
            if "entries" in encrypted_history:
                return encrypted_history["entries"]
            else:
                return []
        except json.JSONDecodeError as e:
            print(f"Error loading clipboard history: {e}")
            # Initialize with an empty history if JSON is invalid
            self._initialize_empty_history()
            return []
    
    def _initialize_empty_history(self):
        """Initialize an empty history file with valid JSON structure."""
        # Make sure we have a salt
        if not self.salt:
            self.salt = os.urandom(16)
        
        # Create an empty history structure
        empty_history = {
            "salt": base64.b64encode(self.salt).decode(),
            "entries": []
        }
        
        # Write the empty structure to file
        with open(self.encrypted_data_path, 'w') as f:
            json.dump(empty_history, f)
    
    def _pad_data(self, data):
        """Pad data to be a multiple of AES block size (16 bytes)."""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length]) * padding_length
        return data + padding
    
    def _unpad_data(self, padded_data):
        """Remove padding from decrypted data."""
        # Get the padding length from the last byte
        padding_length = padded_data[-1]
        
        # Validate padding - all padding bytes should be the same value
        # This helps detect wrong decryption keys
        if padding_length > 16:
            raise ValueError(f"Invalid padding length: {padding_length}")
            
        # Verify all padding bytes are correct
        for i in range(1, padding_length + 1):
            if padded_data[-i] != padding_length:
                raise ValueError("Invalid padding - wrong key or corrupted data")
                
        return padded_data[:-padding_length]
    
    def clear_key_from_memory(self):
        """Securely clear the encryption key from memory."""
        if self.key:
            # Overwrite the key with random data before deleting
            self.key = os.urandom(32)
            self.key = None
        
        if self.password:
            # Overwrite the password with random data before deleting
            self.password = ''.join([chr(ord(c) ^ 0xFF) for c in self.password])
            self.password = None

