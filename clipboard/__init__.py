"""
Clipboard Management Module
--------------------------

Provides secure clipboard monitoring and encrypted history management
for the Encrypted Clipboard Manager.

Security Features:
- Real-time encryption of clipboard content
- Secure history management with encryption
- Memory-safe clipboard operations
- Integration with sensitive data detection
- Protected clipboard entry handling
- Secure deletion capabilities for history entries

Key Components:
- ClipboardMonitor: Core class that monitors the system clipboard
  and manages encrypted clipboard history
- Encrypted storage of clipboard content
- Search and filtering across encrypted history
- Secure deletion operations

Design Principles:
- Immediate encryption of new clipboard content
- No plaintext storage of clipboard data
- Secure memory handling for all operations
- Safe deletion of clipboard history
- Defense-in-depth for clipboard data protection
"""

from .monitor import ClipboardMonitor

__all__ = ['ClipboardMonitor']

