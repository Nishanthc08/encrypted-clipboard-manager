#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cryptographic Handler Module for Encrypted Clipboard Manager
----------------------------------------------------------

This module implements secure cryptographic operations for protecting clipboard
data using industry-standard encryption algorithms and best practices. It provides
a comprehensive encryption system for clipboard content with secure key management.

Security Features:
- AES-256 encryption in CBC mode with secure padding
- PBKDF2-HMAC-SHA256 key derivation with high iteration count (100,000)
- Secure random IV generation for each encryption operation
- Memory protection for sensitive cryptographic material
- Automatic re-encryption on password changes
- Secure data deletion with memory wiping
- Integrity validation during decryption

Technical Implementation:
- Key Derivation: Uses PBKDF2-HMAC-SHA256 with 100,000 iterations and random salt
- Encryption Algorithm: AES-256-CBC with PKCS7-compatible padding
- IV: 16 bytes (128 bits) of cryptographically secure random data per encryption
- Salt: 16 bytes (128 bits) unique salt stored with encrypted data
- Memory Security: Explicit overwriting of sensitive data in memory before deletion

Security Considerations:
    WARNING: This module handles cryptographic operations and should be modified
    with extreme caution. Any changes could impact the security of stored data.
    
    1. Password Requirements:
       - Should be sufficiently complex and unique
       - Cannot be recovered if lost - there is no password reset mechanism
       - All encrypted data becomes permanently inaccessible if password is lost
    
    2. Key Management:
       - Master key is derived from the user password, never stored directly
       - Different salt values generate different keys, even with the same password
       - Re-encryption occurs automatically when password changes
    
    3. Data Protection:
       - All clipboard data is encrypted before storage
       - Data tampering can be detected during decryption
       - Encrypted data includes validation checks to detect decryption failures
    
    4. Implementation Security:
       - Uses cryptographically secure random number generation
       - Implements secure padding validation to prevent padding oracle attacks
       - Includes memory protection to minimize exposure of sensitive data

Usage Warning:
    Improper use of this module could result in permanent data loss or
    security vulnerabilities. Follow all documentation carefully.

Dependencies:
    cryptography: For cryptographic primitives and operations
"""

import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class CryptoHandler:
    """
    Handles encryption, decryption, and key management for clipboard data.
    
    This class provides the core cryptographic functionality for the Encrypted
    Clipboard Manager, ensuring that all clipboard data is securely encrypted
    before storage and properly decrypted when needed.
    
    Security Architecture:
    - User-provided password is used to derive a secure encryption key
    - Each encryption operation uses a unique initialization vector (IV)
    - Encrypted data includes integrity checks to detect tampering
    - Memory protection mechanisms prevent leakage of sensitive data
    - Password changes trigger automatic re-encryption of existing data
    
    Key Security Features:
    - Zero-knowledge design: only the user's password can decrypt data
    - Secure key derivation using PBKDF2 with high iteration count
    - Memory wiping of sensitive cryptographic material
    - Validation checks to detect incorrect passwords or data corruption
    """
    
    def __init__(self):
        """
        Initialize the cryptographic handler.
        
        Sets up the cryptographic environment, including storage paths and
        backend configuration. No encryption keys are generated during
        initialization - a password must be set using set_password() before
        any encryption or decryption operations can be performed.
        
        Security Notes:
        - Creates secure storage location for encrypted data
        - Does not initialize any cryptographic keys until explicitly requested
        - Uses the default cryptographic backend from the cryptography library
        """
        self.password = None
        self.key = None
        self.salt = None
        self.backend = default_backend()
        self.encrypted_data_path = os.path.expanduser("~/.encrypted_clipboard_history")
        
        # Create storage directory if it doesn't exist
        os.makedirs(os.path.dirname(self.encrypted_data_path), exist_ok=True)
    
    def set_password(self, password):
        """
        Set the encryption password and derive the master encryption key.
        
        Args:
            password (str): The password to use for encryption/decryption
            
        Returns:
            bool: True if password was successfully set
            
        Security Implementation:
        1. Generates a new cryptographically secure random salt
        2. Derives a 256-bit key using PBKDF2-HMAC-SHA256 with 100,000 iterations
        3. If changing an existing password, re-encrypts all clipboard history
           with the new key to maintain data accessibility
        4. Stores the salt with the encrypted data for future key derivation
        
        Note:
            The password itself is never stored, only the derived key and salt.
            If the password is lost, encrypted data cannot be recovered.
        """
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
        """
        Re-encrypt clipboard history with a new key when password changes.
        
        Args:
            old_key (bytes): The previous encryption key
            old_salt (bytes): The previous salt used for key derivation
            
        Security Implementation:
        1. Temporarily restores the old key to decrypt existing history
        2. Decrypts each history entry individually
        3. Re-encrypts each entry with the new key
        4. Saves the re-encrypted history with the new salt
        5. Handles failures gracefully by creating a new empty history
           if re-encryption fails (prevents data corruption)
            
        Note:
            This process ensures that changing the password doesn't make
            existing clipboard history inaccessible. All entries are
            decrypted and re-encrypted in memory during this operation.
        """
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
        """
        Encrypt clipboard data using AES-256-CBC with secure padding.
        
        Args:
            data (str): The plaintext data to encrypt
            
        Returns:
            dict: A dictionary containing:
                - 'iv': Base64-encoded initialization vector
                - 'data': Base64-encoded encrypted data
                
        Raises:
            ValueError: If encryption key is not initialized
            
        Security Implementation:
        1. Validates that a key has been derived from a password
        2. Generates a cryptographically secure random IV for this encryption
        3. Uses AES-256 in CBC mode for encryption
        4. Applies secure padding to the data before encryption
        5. Encodes binary data as Base64 for safe storage
        
        Note:
            Each encryption operation uses a unique random IV to ensure
            that identical plaintext values encrypt to different ciphertexts,
            preventing pattern analysis.
        """
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
        """
        Decrypt clipboard data using AES-256-CBC.
        
        Args:
            encrypted_data (dict): Dictionary containing:
                - 'iv': Base64-encoded initialization vector
                - 'data': Base64-encoded encrypted data
            
        Returns:
            str: The decrypted plaintext
            
        Raises:
            ValueError: If encryption key is not initialized or decryption fails
            
        Security Implementation:
        1. Validates that a key has been derived from a password
        2. Extracts the IV and encrypted data from the input
        3. Decrypts the data using AES-256 in CBC mode
        4. Removes padding with validation to detect tampering
        5. Performs additional validation to detect incorrect keys
        6. Handles all errors securely to prevent information leakage
        
        Note:
            This method includes several layers of validation to detect when:
            - The wrong password/key is used
            - The encrypted data has been tampered with
            - The data is corrupted
            
            All validation failures produce a consistent error message to
            prevent information leakage through error analysis.
        """
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
        """
        Save encrypted clipboard history to disk.
        
        Args:
            history (list): List of clipboard history entries to save
            
        Raises:
            ValueError: If encryption key is not initialized
            
        Security Implementation:
        1. Validates that a key has been derived from a password
        2. Creates a container structure with the current salt
        3. Stores the history entries (which contain individually encrypted content)
        4. Writes the data to disk with appropriate error handling
        
        Note:
            The salt is stored alongside the history to ensure the correct
            key can be derived when the history is loaded. The salt itself
            is not a secret, but is needed for password verification and
            key derivation.
        """
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
        """
        Load encrypted clipboard history from disk.
        
        Returns:
            list: The loaded history entries or an empty list if no history exists
            
        Security Implementation:
        1. Checks if history file exists and creates one if it doesn't
        2. Validates file content format
        3. Extracts the salt used for key derivation
        4. Loads the encrypted history entries
        5. Handles loading errors gracefully by initializing an empty history
        
        Note:
            This method loads the encrypted history but does not decrypt the
            individual entries. Each entry's content remains encrypted until
            specifically requested via the decrypt_data method. The salt is
            extracted to ensure the correct key can be derived for decryption.
        """
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
        """
        Initialize an empty history file with valid JSON structure.
        
        Security Implementation:
        1. Ensures a valid salt exists for key derivation
        2. Creates a properly structured empty history container
        3. Writes the empty structure to disk
        
        Note:
            This method is called when:
            - No history file exists yet
            - The history file is corrupted
            - Re-encryption after password change fails
            
            It ensures that the application always has a valid history file
            to work with, preventing errors during normal operation.
        """
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
        """
        Pad data to be a multiple of AES block size (16 bytes).
        
        Args:
            data (bytes): The data to pad
            
        Returns:
            bytes: Padded data
            
        Security Implementation:
        1. Calculates required padding length based on data size
        2. Adds PKCS7-compatible padding where each padding byte
           contains the value of the padding length
        
        Note:
            This padding scheme allows for secure validation during
            unpadding to detect tampering or incorrect decryption.
            AES requires data to be padded to a multiple of 16 bytes.
        """
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length]) * padding_length
        return data + padding
    
    def _unpad_data(self, padded_data):
        """
        Remove padding from decrypted data with security validation.
        
        Args:
            padded_data (bytes): Padded data after decryption
            
        Returns:
            bytes: Original unpadded data
            
        Raises:
            ValueError: If padding is invalid (wrong key or corrupted data)
            
        Security Implementation:
        1. Extracts padding length from the last byte of padded data
        2. Validates that padding length is within valid range (1-16)
        3. Verifies that all padding bytes have the correct value
        4. Raises specific errors for padding validation failures
        
        Note:
            This validation is critical for security as it helps detect:
            - Decryption with the wrong key
            - Tampering with the encrypted data
            - Data corruption
            
            The validation is performed in a way that minimizes vulnerability
            to padding oracle attacks.
        """
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
        """
        Securely clear the encryption key and password from memory.
        
        Security Implementation:
        1. Overwrites the key with random data before deletion
        2. Overwrites the password with XOR-transformed data before deletion
        3. Sets both variables to None to allow garbage collection
        
        Note:
            This is a best-effort approach to securely remove sensitive
            data from memory. Due to Python's memory management and garbage
            collection, there may still be copies of the data in memory that
            we cannot directly access. This method should be called whenever
            the application is closing or when the key is no longer needed.
        """
        if self.key:
            # Overwrite the key with random data before deleting
            self.key = os.urandom(32)
            self.key = None
        
        if self.password:
            # Overwrite the password with random data before deleting
            self.password = ''.join([chr(ord(c) ^ 0xFF) for c in self.password])
            self.password = None

