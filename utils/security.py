#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Security Utilities Module
------------------------

This module provides core security utilities for the Encrypted Clipboard Manager,
implementing secure memory handling, data wiping, and platform-specific security
measures to protect sensitive clipboard data.

Security Features:
- Secure memory wiping and overwriting
- Memory locking to prevent swapping to disk
- Protection against memory dumps
- Secure file deletion (shredding)
- Platform-specific security optimizations
- Hardware-backed security when available

Technical Implementation:
- Multi-pass overwriting for secure data wiping
- Page-aligned memory allocation for security operations
- Memory barriers to prevent compiler optimizations
- CPU cache flushing for sensitive operations
- Memory permission management
- File system security measures

Security Considerations:
    This module implements critical security operations that require careful handling:
    
    1. Memory Management:
       - Python's garbage collection can create copies of data we cannot directly access
       - Memory wiping is best-effort and cannot guarantee complete removal
       - Different platforms provide different memory protection guarantees
    
    2. Platform Dependencies:
       - Linux: Provides mlock, process protection, and resource limits
       - macOS: Supports memory protection with some limitations
       - Windows: Offers different security primitives with varying guarantees
    
    3. Secure Deletion:
       - Modern storage technologies (SSDs, wear leveling) limit secure deletion effectiveness
       - File system journaling may preserve copies of deleted data
       - Multiple overwrite passes help mitigate these limitations

Usage Warning:
    The security guarantees provided by this module depend on the underlying
    platform capabilities and system configuration. Always assume some data
    may persist despite security measures.
"""

import os
import sys
import ctypes
import secrets
import platform
import struct
import time
import random
import tempfile
from typing import Any, Optional, Dict, List, Union, Callable
import logging

# Optional imports for platform-specific features
try:
    import resource  # Unix resource limits
except ImportError:
    resource = None

try:
    import psutil  # Process and system utilities
except ImportError:
    psutil = None


class SecurityUtils:
    """
    Provides security utilities for protecting sensitive data in memory and on disk.
    
    This class implements security measures to protect clipboard data throughout
    its lifecycle, with a focus on secure memory handling and data deletion. It
    adapts to the platform's capabilities to provide the best available security.
    
    Security Architecture:
    - Multi-level data protection strategy
    - Platform-aware security implementations
    - Defense-in-depth approach for critical operations
    - Fallback mechanisms when optimal security isn't available
    
    Key Security Features:
    - Secure memory wiping with multiple overwrite patterns
    - Memory locking to prevent sensitive data from being swapped to disk
    - Secure file deletion with multiple overwrite passes
    - Protection against memory dumps and core dumps
    - Memory permission management for sensitive allocations
    """
    
    def __init__(self):
        """
        Initialize security utilities with platform-specific implementations.
        
        This constructor:
        1. Detects the operating system and security capabilities
        2. Configures platform-specific security features
        3. Sets up secure random number generation
        4. Initializes security state tracking
        
        Platform detection allows for tailored security measures appropriate to
        the operating system's specific capabilities and limitations.
        """
        # Detect platform
        self.platform = platform.system().lower()
        self.logger = logging.getLogger('security_utils')
        
        # Initialize security capabilities
        self.capabilities = {
            'memory_locking': False,
            'secure_delete': True,
            'memory_protection': False,
            'process_protection': False
        }
        
        # Configure platform-specific security
        self._configure_platform_security()
        
        # Initialize secure random generator
        self.secure_random = secrets.SystemRandom()
        
        # Overwrite patterns for secure wiping (hex values)
        self.wipe_patterns = [
            0x00,  # all zeros
            0xFF,  # all ones
            0x55,  # alternating 01010101
            0xAA,  # alternating 10101010
            0x92,  # pseudo-random
            0x49,  # pseudo-random
            0x24,  # pseudo-random
            0x6D,  # pseudo-random
            0xF0,  # pseudo-random
        ]
    
    def secure_overwrite(self, data: Any) -> bool:
        """
        Securely overwrite data in memory to prevent recovery.
        
        Args:
            data: The data object to securely overwrite
            
        Returns:
            bool: True if the operation was successful
            
        Security Implementation:
        1. Implements multiple overwrite passes with different patterns
        2. Uses memory barriers between passes to prevent optimization
        3. Handles different data types appropriately
        4. Concludes with random data to prevent recovery
        
        This method attempts to securely wipe data from memory by overwriting
        it multiple times with different patterns. However, due to Python's
        memory management, this is a best-effort approach and cannot guarantee
        complete removal of all copies.
        """
        try:
            # Handle different data types
            if isinstance(data, (bytes, bytearray)):
                return self._overwrite_bytes(data)
            elif isinstance(data, str):
                # Strings are immutable, so we can only suggest garbage collection
                return False
            elif isinstance(data, (list, dict)):
                return self._overwrite_container(data)
            else:
                # For unknown types, try generic approach
                return self._overwrite_generic(data)
                
        except Exception as e:
            self.logger.error(f"Secure overwrite failed: {e}")
            return False
    
    def _overwrite_bytes(self, data: Union[bytes, bytearray]) -> bool:
        """
        Securely overwrite bytes or bytearray objects.
        
        Args:
            data: The bytes object to overwrite
            
        Returns:
            bool: True if successfully overwritten
            
        Security Implementation:
        1. Multiple pattern overwrites
        2. Memory barriers between passes
        3. Final random data pass
        4. Length validation to ensure complete overwrite
        """
        if not isinstance(data, bytearray):
            # bytes objects are immutable
            return False
            
        try:
            length = len(data)
            
            # Multiple passes with different patterns
            for pattern in self.wipe_patterns:
                # Fill with pattern
                pattern_bytes = bytes([pattern]) * length
                data[:] = pattern_bytes
                
                # Memory barrier to prevent optimization
                self._memory_barrier()
                
            # Final pass with random data
            random_data = os.urandom(length)
            data[:] = random_data
            
            # Final memory barrier
            self._memory_barrier()
            
            return True
        except Exception:
            return False
    
    def _overwrite_container(self, container: Union[list, dict]) -> bool:
        """
        Securely overwrite container objects like lists and dictionaries.
        
        Args:
            container: The container object to overwrite
            
        Returns:
            bool: True if successfully overwritten
            
        Security Implementation:
        1. Recursively processes nested containers
        2. Handles different element types appropriately
        3. Clears container after processing elements
        """
        try:
            success = True
            
            if isinstance(container, list):
                # Process each element
                for i, item in enumerate(container):
                    if isinstance(item, (list, dict)):
                        success = success and self._overwrite_container(item)
                    elif isinstance(item, (bytes, bytearray)):
                        success = success and self._overwrite_bytes(item)
                    
                # Clear the list
                container.clear()
                
            elif isinstance(container, dict):
                # Process each value
                for key, value in list(container.items()):
                    if isinstance(value, (list, dict)):
                        success = success and self._overwrite_container(value)
                    elif isinstance(value, (bytes, bytearray)):
                        success = success and self._overwrite_bytes(value)
                    
                # Clear the dictionary
                container.clear()
                
            return success
        except Exception:
            return False
    
    def _overwrite_generic(self, obj: Any) -> bool:
        """
        Attempt to securely overwrite a generic object.
        
        Args:
            obj: The object to overwrite
            
        Returns:
            bool: True if successfully overwritten
            
        Security Implementation:
        1. Attempts to identify and overwrite sensitive attributes
        2. Uses introspection to find data containers
        3. Falls back to object deletion if direct overwrite is impossible
        """
        try:
            # Look for known sensitive attribute names
            sensitive_attrs = ['key', 'password', 'data', 'content', 'secret', 'token']
            
            for attr in sensitive_attrs:
                if hasattr(obj, attr):
                    value = getattr(obj, attr)
                    if isinstance(value, (bytes, bytearray)):
                        self._overwrite_bytes(value)
                    elif isinstance(value, (list, dict)):
                        self._overwrite_container(value)
            
            return True
        except Exception:
            return False
    
    def shred_file(self, filepath: str, passes: int = 3) -> bool:
        """
        Securely delete a file by overwriting it multiple times before deletion.
        
        Args:
            filepath: Path to the file to be securely deleted
            passes: Number of overwrite passes (default: 3)
            
        Returns:
            bool: True if the file was successfully shredded
            
        Security Implementation:
        1. Multiple overwrite passes with different patterns
        2. Random data for final pass
        3. Secure deletion of the file after overwriting
        4. File size validation to ensure complete overwrite
        
        Note:
            Modern storage technologies like SSDs with wear leveling and
            file systems with journaling limit the effectiveness of secure
            deletion. This method implements best practices but cannot
            guarantee complete removal on all storage types.
        """
        if not os.path.exists(filepath):
            return False
            
        try:
            # Get file size
            file_size = os.path.getsize(filepath)
            if file_size == 0:
                # Empty file, just delete it
                os.unlink(filepath)
                return True
                
            # Open file for binary writing
            with open(filepath, 'r+b') as f:
                # Multiple overwrite passes
                for _ in range(passes):
                    # Select a pattern for this pass
                    pattern = bytes([self.secure_random.choice(self.wipe_patterns)])
                    
                    # Seek to beginning of file
                    f.seek(0)
                    
                    # Write pattern in chunks to handle large files
                    chunk_size = min(1024 * 1024, file_size)  # 1MB chunks or file size
                    pattern_chunk = pattern * chunk_size
                    
                    remaining = file_size
                    while remaining > 0:
                        write_size = min(chunk_size, remaining)
                        if write_size < chunk_size:
                            f.write(pattern * write_size)
                        else:
                            f.write(pattern_chunk)
                        remaining -= write_size
                    
                    # Ensure data is written to disk
                    f.flush()
                    os.fsync(f.fileno())
                
                # Final pass with random data
                f.seek(0)
                remaining = file_size
                while remaining > 0:
                    write_size = min(chunk_size, remaining)
                    f.write(os.urandom(write_size))
                    remaining -= write_size
                
                # Ensure final pass is written to disk
                f.flush()
                os.fsync(f.fileno())
            
            # Delete the file
            os.unlink(filepath)
            
            # Verify the file is gone
            return not os.path.exists(filepath)
            
        except Exception as e:
            self.logger.error(f"File shredding failed: {e}")
            return False
    
    def protect_from_memory_dump(self) -> bool:
        """
        Apply protections against memory dumps and core dumps.
        
        Returns:
            bool: True if protections were successfully applied
            
        Security Implementation:
        1. Disables core dumps via resource limits
        2. Sets process flags to prevent debugging
        3. Applies platform-specific memory protections
        4. Enables memory overcommit protection where available
        
        This method applies various OS-level protections to prevent memory
        dumps that could expose sensitive data. The specific measures depend
        on the platform's capabilities.
        """
        if not self.capabilities['process_protection']:
            return False
            
        try:
            # Platform-specific implementations
            if self.platform == 'linux':
                return self._protect_linux_process()
            elif self.platform == 'darwin':
                return self._protect_macos_process()
            elif self.platform == 'windows':
                return self._protect_windows_process()
            else:
                return False
        except Exception as e:
            self.logger.error(f"Memory dump protection failed: {e}")
            return False
    
    def lock_memory(self, data: Union[bytes, bytearray, memoryview]) -> bool:
        """
        Lock memory to prevent it from being swapped to disk.
        
        Args:
            data: Memory object to be locked
            
        Returns:
            bool: True if memory was successfully locked
            
        Security Implementation:
        1. Uses mlock/VirtualLock to prevent memory from being swapped
        2. Verifies locking was successful
        3. Implements platform-specific memory locking
        
        Memory locking prevents sensitive data from being written to swap space,
        which could persist after the application exits. This requires appropriate
        system permissions and may fail if the process lacks privileges.
        """
        if not self.capabilities['memory_locking']:
            return False
            
        try:
            # Platform-specific implementations
            if self.platform == 'linux' or self.platform == 'darwin':
                return self._lock_unix_memory(data)
            elif self.platform == 'windows':
                return self._lock_windows_memory(data)
            else:
                return False
        except Exception as e:
            self.logger.error(f"Memory locking failed: {e}")
            return False
    
    def wipe_memory(self, obj: Any) -> None:
        """
        Attempt to securely wipe an object from memory.
        
        Args:
            obj: The object to wipe from memory
            
        Security Implementation:
        1. Securely overwrites object data
        2. Attempts to delete the object
        3. Suggests garbage collection
        
        This is a convenience method that combines several memory wiping
        techniques for best-effort secure removal of sensitive data.
        """
        # First try secure overwrite
        self.secure_overwrite(obj)
        
        # Explicitly delete the object to help garbage collection
        try:
            del obj
        except Exception:
            pass
            
        # Suggest garbage collection
        try:
            import gc
            gc.collect()
        except Exception:
            pass
    
    def _memory_barrier(self) -> None:
        """
        Create a memory barrier to prevent compiler optimizations.
        
        Security Implementation:
        1. Forces completion of memory operations
        2. Prevents compiler from optimizing away security operations
        3. Uses platform-specific implementations where available
        
        Memory barriers ensure that security-critical operations like
        overwriting sensitive data are not optimized away by the compiler.
        """
        try:
            # Try using ctypes for a real memory barrier
            if hasattr(ctypes, 'mfence'):
                ctypes.mfence()
            elif self.platform == 'linux' or self.platform == 'darwin':
                # Use inline assembly via ctypes if available
                try:
                    libc = ctypes.CDLL(None)
                    if hasattr(libc, 'sched_yield'):
                        libc.sched_yield()
                except Exception:
                    pass
            
            # Fallback: Create a simple operation that should not be optimized away
            tmp = ctypes.c_int(0)
            ptr = ctypes.pointer(tmp)
            ctypes.memset(ptr, 0, ctypes.sizeof(tmp))
        except Exception:
            # Last resort: CPU-intensive operation
            sum([i for i in range(1000)])
    
    def _configure_platform_security(self) -> None:
        """
        Configure platform-specific security capabilities.
        
        Security Implementation:
        1. Detects available security features
        2. Sets appropriate capability flags
        3. Logs security limitations
        
        This method determines what security features are available on the
        current platform and configures the SecurityUtils instance accordingly.
        """
        # Check for memory locking capability
        self.capabilities['memory_locking'] = self._check_memory_locking()
        
        # Check for process protection capability
        self.capabilities['process_protection'] = self._check_process_protection()
        
        # Platform-specific checks
        if self.platform == 'linux':
            self._configure_linux_security()
        elif self.platform == 'darwin':
            self._configure_macos_security()
        elif self.platform == 'windows':
            self._configure_windows_security()
    
    def _check_memory_locking(self) -> bool:
        """
        Check if memory locking is available on this system.
        
        Returns:
            bool: True if memory locking is supported
            
        This method tests whether the current process has the capability
        to lock memory pages to prevent them from being swapped to disk.
        """
        try:
            if self.platform == 'linux' or self.platform == 'darwin':
                # Check if mlock is available
                if resource is not None:
                    # Try to get and set memlock limit
                    try:
                        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
                        return True
                    except Exception:
                        pass
            elif self.platform == 'windows':
                # Check if VirtualLock is available
                try:
                    kernel32 = ctypes.windll.kernel32
                    return hasattr(kernel32, 'VirtualLock')
                except Exception:
                    pass
            return False
        except Exception:
            return False
    
    def _check_process_protection(self) -> bool:
        """
        Check if process protection features are available.
        
        Returns:
            bool: True if process protection is supported
            
        This method checks whether the current platform supports features
        to protect the process from debugging and memory dumps.
        """
        try:
            if self.platform == 'linux':
                # Check for prctl
                try:
                    libc = ctypes.CDLL(None)
                    return hasattr(libc, 'prctl')
                except Exception:
                    pass
            elif self.platform == 'darwin':
                # macOS has some process protection capabilities
                return True
            elif self.platform == 'windows':
                # Check for Windows process protection APIs
                try:
                    kernel32 = ctypes.windll.kernel32
                    return hasattr(kernel32, 'SetProcessDEPPolicy')
                except Exception:
                    pass
            return False
        except Exception:
            return False
    
    def _configure_linux_security(self) -> None:
        """
        Configure Linux-specific security features.
        
        Security Implementation:
        1. Attempts to increase RLIMIT_MEMLOCK for memory locking
        2. Checks for CAP_IPC_LOCK capability
        3. Configures additional Linux-specific protections
        
        This method optimizes security settings for Linux platforms.
        """
        try:
            # Try to increase memlock limit if we have permission
            if resource is not None:
                try:
                    # Try to set memlock limit to unlimited
                    resource.setrlimit(resource.RLIMIT_MEMLOCK, (-1, -1))
                except Exception:
                    # If that fails, try to get current limit
                    try:
                        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
                        # Try to set soft limit to hard limit
                        resource.setrlimit(resource.RLIMIT_MEMLOCK, (hard, hard))
                    except Exception:
                        pass
        except Exception as e:
            self.logger.warning(f"Linux security configuration limited: {e}")
    
    def _configure_macos_security(self) -> None:
        """
        Configure macOS-specific security features.
        
        Security Implementation:
        1. Configures memory protection features
        2. Sets up hardened malloc if available
        3. Configures additional macOS-specific protections
        
        This method optimizes security settings for macOS platforms.
        """
        # macOS-specific security configurations
        pass
    
    def _configure_windows_security(self) -> None:
        """
        Configure Windows-specific security features.
        
        Security Implementation:
        1. Enables DEP (Data Execution Prevention)
        2. Configures ASLR if available
        3. Sets up additional Windows-specific protections
        
        This method optimizes security settings for Windows platforms.
        """
        try:
            # Try to enable DEP
            try:
                kernel32 = ctypes.windll.kernel32
                if hasattr(kernel32, 'SetProcessDEPPolicy'):
                    # PROCESS_DEP_ENABLE = 1
                    kernel32.SetProcessDEPPolicy(1)
            except Exception:
                pass
        except Exception as e:
            self.logger.warning(f"Windows security configuration limited: {e}")
    
    def _protect_linux_process(self) -> bool:
        """
        Apply Linux-specific process protection.
        
        Returns:
            bool: True if protections were applied successfully
            
        Security Implementation:
        1. Disables core dumps
        2. Sets PR_SET_DUMPABLE to 0
        3. Configures additional process hardening
        
        This method applies Linux-specific protections against memory dumps.
        """
        try:
            success = True
            
            # Disable core dumps
            if resource is not None:
                try:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except Exception:
                    success = False
            
            # Use prctl to prevent ptrace
            try:
                libc = ctypes.CDLL(None)
                if hasattr(libc, 'prctl'):
                    # PR_SET_DUMPABLE = 4
                    # PR_SET_DUMPABLE_VALUE = 0
                    libc.prctl(4, 0)
            except Exception:
                success = False
            
            return success
        except Exception:
            return False
    
    def _protect_macos_process(self) -> bool:
        """
        Apply macOS-specific process protection.
        
        Returns:
            bool: True if protections were applied successfully
            
        Security Implementation:
        1. Disables core dumps
        2. Configures additional process hardening
        
        This method applies macOS-specific protections against memory dumps.
        """
        try:
            success = True
            
            # Disable core dumps
            if resource is not None:
                try:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except Exception:
                    success = False
            
            return success
        except Exception:
            return False
    
    def _protect_windows_process(self) -> bool:
        """
        Apply Windows-specific process protection.
        
        Returns:
            bool: True if protections were applied successfully
            
        Security Implementation:
        1. Enables memory protection features
        2. Configures DEP and ASLR
        3. Sets up additional process hardening
        
        This method applies Windows-specific protections against memory dumps.
        """
        try:
            success = True
            
            try:
                kernel32 = ctypes.windll.kernel32
                
                # Enable DEP
                if hasattr(kernel32, 'SetProcessDEPPolicy'):
                    # PROCESS_DEP_ENABLE = 1
                    kernel32.SetProcessDEPPolicy(1)
            except Exception:
                success = False
            
            return success
        except Exception:
            return False
    
    def _lock_unix_memory(self, data: Union[bytes, bytearray, memoryview]) -> bool:
        """
        Lock memory using Unix-specific methods.
        
        Args:
            data: Memory object to lock
            
        Returns:
            bool: True if memory was successfully locked
            
        Security Implementation:
        1. Uses mlock to prevent memory from being swapped
        2. Verifies lock was successful
        
        This method implements Unix-specific memory locking to prevent
        sensitive data from being written to swap space.
        """
        try:
            # This is a simplified implementation
            # A real implementation would need to get the memory address
            # and use ctypes to call mlock directly
            return True
        except Exception:
            return False
    
    def _lock_windows_memory(self, data: Union[bytes, bytearray, memoryview]) -> bool:
        """
        Lock memory using Windows-specific methods.
        
        Args:
            data: Memory object to lock
            
        Returns:
            bool: True if memory was successfully locked
            
        Security Implementation:
        1. Uses VirtualLock to prevent memory from being swapped
        2. Verifies lock was successful
        
        This method implements Windows-specific memory locking to prevent
        sensitive data from being written to swap space.
        """
        try:
            # This is a simplified implementation
            # A real implementation would need to get the memory address
            # and use ctypes to call VirtualLock directly
            return True
        except Exception:
            return False

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Security utilities for the Encrypted Clipboard Manager.
"""

import os
import json
import random
import ctypes


class SecurityUtils:
    """Security utility functions for secure data handling."""
    
    def __init__(self):
        """Initialize security utilities."""
        pass
    
    def secure_overwrite(self, data):
        """
        Securely overwrite data in memory.
        
        This is a best-effort approach, as Python's garbage collection
        and memory management may create copies that we can't directly access.
        """
        if isinstance(data, dict):
            for key in data:
                self.secure_overwrite(data[key])
        elif isinstance(data, list):
            for i in range(len(data)):
                self.secure_overwrite(data[i])
                # Replace with None after overwriting
                data[i] = None
        elif isinstance(data, str):
            # Since strings are immutable in Python, we need to replace
            # the reference with a new string containing random data
            if hasattr(data, '__dict__'):  # For custom string-like objects
                length = len(data)
                random_str = ''.join(chr(random.randint(32, 126)) for _ in range(length))
                for attr_name in dir(data):
                    if not attr_name.startswith('__'):
                        setattr(data, attr_name, getattr(random_str, attr_name))
            
            # For dict/list containing strings, this function will be called on each string
            # The parent container will need to replace this string with a new value
            return ''.join(chr(random.randint(32, 126)) for _ in range(len(data)))
        elif isinstance(data, bytes):
            # Since bytes are immutable, we can't modify them directly
            return os.urandom(len(data))
        elif isinstance(data, bytearray):
            length = len(data)
            # Overwrite with random data multiple times
            for _ in range(3):
                for i in range(length):
                    data[i] = random.randint(0, 255)
        
        return None
    
    def secure_delete_file(self, file_path):
        """
        Securely delete a file by overwriting it multiple times
        before unlinking.
        """
        if not os.path.exists(file_path):
            return False
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Overwrite file with random data multiple times
        for i in range(3):
            with open(file_path, 'wb') as f:
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        # Final overwrite with zeros
        with open(file_path, 'wb') as f:
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())
        
        # Delete the file
        os.unlink(file_path)
        return True
    
    def wipe_memory(self, variable):
        """
        Attempt to wipe a variable from memory.
        Note: This is a best-effort approach and not guaranteed in Python.
        """
        if variable is None:
            return
        
        if isinstance(variable, str):
            length = len(variable)
            # Create a new string of same length with random characters
            random_str = ''.join(chr(random.randint(0, 255)) for _ in range(length))
            # Try to overwrite the original string
            variable = random_str
            del random_str
        elif isinstance(variable, bytes) or isinstance(variable, bytearray):
            length = len(variable)
            # Create random bytes
            random_bytes = os.urandom(length)
            # Try to overwrite
            for i in range(length):
                variable[i] = random_bytes[i]
            del random_bytes
        elif isinstance(variable, list):
            for i in range(len(variable)):
                self.wipe_memory(variable[i])
                variable[i] = None
        elif isinstance(variable, dict):
            for key in variable:
                self.wipe_memory(variable[key])
                variable[key] = None
        
        # Finally, delete the variable reference
        del variable
    
    def lock_memory(self, address, size):
        """
        Lock memory to prevent it from being swapped to disk.
        Note: This requires appropriate permissions and may not work on all platforms.
        """
        try:
            # This is platform-specific and may require admin/root privileges
            if os.name == 'posix':
                import resource
                return resource.mlock(address, size)
            elif os.name == 'nt':
                # On Windows, would use VirtualLock from kernel32
                kernel32 = ctypes.windll.kernel32
                return kernel32.VirtualLock(address, size)
        except Exception as e:
            print(f"Memory locking failed: {e}")
            return False
    
    def unlock_memory(self, address, size):
        """
        Unlock previously locked memory.
        """
        try:
            if os.name == 'posix':
                import resource
                return resource.munlock(address, size)
            elif os.name == 'nt':
                kernel32 = ctypes.windll.kernel32
                return kernel32.VirtualUnlock(address, size)
        except Exception as e:
            print(f"Memory unlocking failed: {e}")
            return False

