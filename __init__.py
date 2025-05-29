"""
Encrypted Clipboard Manager Package
----------------------------------
A secure clipboard management application with encryption and sensitive data detection.

Core Security Features:
- AES-256 encryption for all clipboard content
- Automatic detection of sensitive information (passwords, API keys, personal data)
- Secure memory handling to prevent data leakage
- "Shredding" capability for secure deletion of clipboard entries
- Zero-knowledge architecture (only you can decrypt your data)
- Cross-platform security measures
- Process hardening and memory protection
- Session management with automatic locking

Module Structure:
- clipboard: Provides clipboard monitoring and encrypted history management
- encryption: Implements cryptographic operations for securing clipboard content
- detection: Analyzes clipboard content for sensitive information
- gui: Provides the secure graphical user interface
- utils: Security utilities and platform-specific implementations

Security Design Principles:
- Defense in Depth: Multiple security layers protect clipboard data
- Least Privilege: Components access only what they need
- Secure by Default: All operations prioritize security
- Zero Knowledge: Only the user can decrypt their data
- Safe Failure: Security is maintained even during errors
- Memory Safety: Protected handling of sensitive data
- Platform Awareness: Security adapts to system capabilities

Security Considerations:
    1. Password Security:
       - Use strong, unique passwords for encryption
       - Password cannot be recovered if lost
       - All encrypted data becomes inaccessible if password is forgotten
       - No backdoor or recovery mechanism exists by design

    2. Platform Limitations:
       - Some security features vary in effectiveness by platform
       - Memory protection effectiveness depends on operating system
       - Secure deletion may have limitations on SSDs with wear leveling
       - File system journaling may affect secure deletion guarantees

    3. Implementation Notes:
       - Python's memory management affects some security guarantees
       - Some operations are best-effort security measures
       - External screen capture tools might bypass UI security features
       - System memory dumps could potentially contain sensitive data

Usage Warning:
    This application implements multiple layers of security but should be used
    with appropriate caution. No security system is perfect, and users should
    follow general security best practices in addition to using this tool.

Dependencies:
- PyQt6>=6.4.0: GUI framework for cross-platform interface
- cryptography>=39.0.0: Cryptographic operations and key management
- scikit-learn>=1.2.0: Machine learning for sensitive data detection
- numpy>=1.23.0: Numerical operations for data analysis
- psutil>=5.9.0: Process and memory utilities (optional)
"""

__version__ = '0.1.0'
__author__ = 'Secure Clipboard Team'
__license__ = 'MIT'
__copyright__ = 'Copyright 2025'
__status__ = 'Beta'

# Import core components
from .clipboard import ClipboardMonitor
from .encryption import CryptoHandler
from .detection import SensitiveDataAnalyzer
from .gui import ClipboardManagerWindow
from .utils import SecurityUtils

# Define public API
__all__ = [
    'ClipboardMonitor',
    'CryptoHandler',
    'SensitiveDataAnalyzer',
    'ClipboardManagerWindow',
    'SecurityUtils',
    '__version__',
    '__author__',
    '__license__',
]

