"""
Security Utilities Module
-----------------------

Provides core security operations and platform-specific implementations
for the Encrypted Clipboard Manager.

Security Features:
- Memory protection and locking to prevent swapping to disk
- Secure deletion with multiple overwrite passes
- Memory dump prevention mechanisms
- Process hardening features
- Resource access controls
- Platform-specific security optimizations
- Secure memory wiping capabilities

Key Components:
- SecurityUtils: Core security service that provides:
  * Memory protection mechanisms for sensitive data
  * Secure deletion implementations with verification
  * Platform-specific security adaptations
  * Process protection features against debugging
  * Resource cleanup utilities for sensitive data
  * Security boundary enforcement

Design Principles:
- Defense in depth for all security operations
- Platform-aware security implementations
- Safe failure modes that maintain security
- Comprehensive resource protection
- Proactive security measures
- Conservative security defaults

Implementation Notes:
    Due to platform differences and Python's memory management, some
    security features may have varying levels of effectiveness across
    different operating systems. The implementation uses best-effort
    approaches to provide maximum security within platform constraints.
"""

from .security import SecurityUtils

__all__ = ['SecurityUtils']

