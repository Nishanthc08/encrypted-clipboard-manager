"""
Graphical User Interface Module
-----------------------------

Implements the secure user interface components for the Encrypted
Clipboard Manager.

Security Features:
- Secure password entry with masking and strength indicators
- Protected content display with automatic clearing
- Real-time sensitivity indicators for clipboard content
- Secure deletion controls with confirmation
- Automatic session locking after inactivity
- Memory-safe display handling for sensitive data

Key Components:
- ClipboardManagerWindow: Main application window that provides:
  * Encrypted clipboard history management
  * Secure content viewing with sensitivity highlighting
  * Password management and authentication
  * Session security controls
  * Secure deletion operations

Design Principles:
- No sensitive data stored in widget properties
- Automatic clearing of displayed content when not in focus
- Protected clipboard operations with user confirmation
- Clear visual indicators for security status
- Fail-safe defaults for security operations
- User-friendly security controls and feedback
"""

from .main_window import ClipboardManagerWindow

__all__ = ['ClipboardManagerWindow']

