"""
Encryption Module
---------------

Implements cryptographic operations and secure key management
for the Encrypted Clipboard Manager.

Security Features:
- AES-256 encryption for all clipboard content
- PBKDF2-HMAC-SHA256 key derivation with high iteration count
- Secure memory handling for cryptographic keys
- Zero-knowledge architecture (only the user has the key)
- Authenticated encryption to prevent tampering
- Unique IV/nonce for each encryption operation
- Secure key rotation during password changes

Key Components:
- CryptoHandler: Core class that manages all cryptographic operations
  including encryption, decryption, and key management
- Secure password-based key derivation
- Encrypted history storage implementation
- Memory protection for sensitive cryptographic material

Design Principles:
- Strong encryption by default (AES-256)
- Secure key lifecycle management from generation to destruction
- Memory protection for sensitive cryptographic data
- Safe key derivation practices with high iteration counts
- Defense against cryptographic attacks via authenticated encryption
- No storage of original password, only derived keys

Implementation Notes:
    The encryption is only as strong as the user's password. While the
    implementation follows cryptographic best practices, users should be
    encouraged to use strong, unique passwords.
"""

from .crypto_handler import CryptoHandler

__all__ = ['CryptoHandler']

