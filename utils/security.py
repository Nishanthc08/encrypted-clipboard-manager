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

