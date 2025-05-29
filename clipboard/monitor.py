#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Clipboard Monitoring Module
--------------------------

This module provides secure clipboard monitoring and history management with
encryption integration. It continuously monitors the system clipboard for changes
and securely stores clipboard contents with the following security features:

Key Features:
- Real-time monitoring of clipboard changes using Qt timers
- End-to-end encryption of all clipboard content before storage
- Automatic detection of sensitive information (passwords, API keys, personal data)
- Secure deletion ("shredding") of clipboard entries using memory wiping techniques
- Encrypted storage and retrieval of clipboard history
- Search and filtering capabilities across encrypted content

Technical Implementation:
- Uses PyQt6's QClipboard for cross-platform clipboard access
- Implements a polling mechanism via QTimer for reliable clipboard monitoring
- Integrates with the encryption module for secure data storage
- Provides signals for notifying the GUI of clipboard changes and analysis results

Security Considerations:
- All clipboard content is encrypted before being written to storage
- Content analysis is performed in-memory and results are not persisted unencrypted
- Sensitive data is securely wiped from memory when deleted
- History files are encrypted with AES-256 using the user's password
- Search operations decrypt data only when needed and in-memory only

Classes:
    ClipboardMonitor: Main class for monitoring clipboard changes and managing history.

Usage Example:
    crypto_handler = CryptoHandler()
    analyzer = SensitiveDataAnalyzer()
    security_utils = SecurityUtils()
    
    # Initialize the monitor with security components
    monitor = ClipboardMonitor(crypto_handler, analyzer, security_utils)
    
    # Start monitoring
    monitor.start_monitoring()
    
    # Access a history entry
    entry = monitor.get_entry(0)
    
    # Securely delete an entry
    monitor.shred_entry(0)
"""

import time
import json
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QClipboard


class ClipboardMonitor(QObject):
    """
    Monitors clipboard changes and securely manages encrypted clipboard history.
    
    This class provides the core functionality for:
    1. Detecting changes in the system clipboard
    2. Analyzing clipboard content for sensitive information
    3. Encrypting and storing clipboard history
    4. Secure retrieval and searching of clipboard entries
    5. Secure deletion ("shredding") of clipboard data
    
    The monitor uses a polling approach with QTimer to detect clipboard changes,
    which works consistently across platforms. All clipboard content is encrypted
    before storage using the provided CryptoHandler.
    """
    
    # Signal emitted when clipboard content changes
    clipboard_changed = pyqtSignal(str, dict)
    
    def __init__(self, crypto_handler, analyzer, security_utils):
        """
        Initialize the clipboard monitor with required security components.
        
        Args:
            crypto_handler: The encryption handler for securing clipboard content
            analyzer: The data analyzer for detecting sensitive information
            security_utils: Security utilities for secure operations
        
        The monitor requires these three components to function securely:
        - CryptoHandler provides encryption/decryption services
        - SensitiveDataAnalyzer detects passwords, API keys, and other sensitive data
        - SecurityUtils provides secure deletion and memory protection
        
        Note:
            No clipboard monitoring starts until explicitly called via start_monitoring()
        """
        super().__init__()
        
        self.clipboard = QApplication.clipboard()
        self.crypto_handler = crypto_handler
        self.analyzer = analyzer
        self.security_utils = security_utils
        
        self.history = []
        self.last_content = None
        self.monitoring = False
        
        # Timer for polling clipboard changes
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_clipboard)
    
    def start_monitoring(self):
        """
        Start monitoring clipboard changes.
        
        This method:
        1. Loads any existing encrypted history from storage
        2. Captures the current clipboard state as baseline
        3. Starts the timer to periodically check for clipboard changes
        
        Returns:
            None
            
        Security Notes:
            - Requires that the crypto_handler is properly initialized with a password
            - Existing history will only load if the correct password was provided
            - Monitoring begins immediately after this call
        """
        # First load any existing history
        self._load_history()
        
        # Get initial clipboard content
        self.last_content = self.clipboard.text()
        
        # Start the timer to check for changes
        self.timer.start(1000)  # Check every second
        self.monitoring = True
    
    def stop_monitoring(self):
        """
        Stop monitoring clipboard changes.
        
        This method:
        1. Stops the monitoring timer
        2. Updates the monitoring status flag
        
        Returns:
            None
            
        Security Notes:
            - Does not clear clipboard history
            - Should be called before application exit to prevent memory leaks
            - Can be restarted with start_monitoring() without data loss
        """
        self.timer.stop()
        self.monitoring = False
    
    def check_clipboard(self):
        """
        Check for changes in clipboard content.
        
        This method is called periodically by the QTimer and is responsible for:
        1. Reading the current clipboard content
        2. Determining if content has changed since last check
        3. Processing new content when detected
        
        Returns:
            None
        
        Note:
            This method ignores empty clipboard content and only processes
            changes, not repeated identical content.
        """
        current_content = self.clipboard.text()
        
        # Only process if content has changed and is not empty
        if current_content and current_content != self.last_content:
            self.last_content = current_content
            self._process_clipboard_content(current_content)
    
    def _process_clipboard_content(self, content):
        """
        Process and securely store new clipboard content.
        
        Args:
            content (str): The new clipboard content to process
            
        This method implements the core security workflow:
        1. Analyze content for sensitive data types and risk level
        2. Create metadata including timestamp and sensitivity classification
        3. Encrypt the content before storage
        4. Store the encrypted data and metadata in history
        5. Persist the encrypted history to storage
        6. Notify listeners of the new content via signal
        
        Security Measures:
        - Content is analyzed in-memory only
        - Content is encrypted before being added to history
        - Only encrypted data is persisted to storage
        - Original content is only exposed through the signal to authorized listeners
        """
        # Analyze the content for sensitive data (passwords, API keys, personal info)
        # This step is performed in memory and results are not persisted unencrypted
        analysis_result = self.analyzer.analyze(content)
        
        # Create metadata for the clipboard entry
        timestamp = datetime.now().isoformat()
        entry_metadata = {
            "timestamp": timestamp,
            "content_type": analysis_result["content_type"],
            "sensitivity": analysis_result["sensitivity"],
            "categories": analysis_result["categories"]
        }
        
        # Encrypt the content using AES-256 before storage
        # This ensures clipboard data is never stored in plaintext
        encrypted_content = self.crypto_handler.encrypt_data(content)
        
        # Create the clipboard history entry
        history_entry = {
            "metadata": entry_metadata,
            "encrypted_content": encrypted_content
        }
        
        # Add to history and save
        self.history.append(history_entry)
        self._save_history()
        
        # Emit signal about the change
        self.clipboard_changed.emit(content, analysis_result)
    
    def get_history(self):
        """
        Get the entire clipboard history.
        
        Returns:
            list: A list of history entries, each containing encrypted content
                 and unencrypted metadata.
                 
        Security Note:
            This method returns the raw history with encrypted content.
            Actual clipboard content remains encrypted and is not decrypted
            until specifically requested via get_entry().
        """
        return self.history
    
    def get_entry(self, index):
        """
        Get a specific history entry with decrypted content.
        
        Args:
            index (int): The index of the history entry to retrieve
            
        Returns:
            dict: A dictionary containing the decrypted content and metadata,
                 or None if the index is invalid.
                 
        Structure:
            {
                "content": "decrypted clipboard content",
                "metadata": {
                    "timestamp": "ISO format timestamp",
                    "content_type": "text/binary",
                    "sensitivity": "low/medium/high",
                    "categories": ["password", "api_key", etc.]
                }
            }
            
        Security Note:
            This method decrypts the content in memory. The decrypted content
            should be handled securely and wiped from memory when no longer needed.
        """
        if 0 <= index < len(self.history):
            entry = self.history[index]
            decrypted_content = self.crypto_handler.decrypt_data(entry["encrypted_content"])
            return {
                "content": decrypted_content,
                "metadata": entry["metadata"]
            }
        return None
    
    def shred_entry(self, index):
        """
        Securely delete a clipboard history entry.
        
        Args:
            index (int): The index of the history entry to shred
            
        Returns:
            bool: True if the entry was successfully shredded, False otherwise
            
        Security Implementation:
        1. Locates the history entry at the specified index
        2. Uses security_utils to securely overwrite the entry data in memory
           (this includes multiple passes of overwriting with random data)
        3. Removes the entry from the history list
        4. Updates the persistent encrypted storage
        
        This process ensures the content cannot be recovered from memory
        or from disk after deletion.
        """
        if 0 <= index < len(self.history):
            # Get the entry and securely clear its content
            entry = self.history[index]
            
            # Use security utils to securely overwrite the data in memory
            # This performs multiple overwrite passes to prevent data recovery
            self.security_utils.secure_overwrite(entry)
            
            # Remove from history
            self.history.pop(index)
            self._save_history()
            return True
        return False
    
    def shred_all(self):
        """
        Securely delete all clipboard history entries.
        
        Returns:
            bool: True if all entries were successfully shredded
            
        Security Implementation:
        1. Iterates through each entry in the history
        2. Securely overwrites each entry's data using security_utils
        3. Clears the history list
        4. Updates the persistent encrypted storage with empty history
        
        This is the most secure way to completely purge clipboard history
        while ensuring data cannot be recovered.
        """
        # Securely overwrite each entry
        for entry in self.history:
            self.security_utils.secure_overwrite(entry)
        
        # Clear the history
        self.history.clear()
        self._save_history()
        return True
    
    def search_history(self, query, filter_category=None):
        """
        Search clipboard history with optional category filter.
        
        Args:
            query (str): The search term to look for in clipboard content
            filter_category (str, optional): Category to filter by (e.g., "password")
            
        Returns:
            list: List of tuples containing (index, metadata) for matching entries
            
        Security Implementation:
        1. Filters entries first by category if specified, using metadata only
           (no decryption needed for this step)
        2. For text search, decrypts entries one by one in memory
        3. Performs case-insensitive search on the decrypted content
        4. Returns only indices and metadata, not the decrypted content
        
        Security Note:
            This method minimizes decryption operations to reduce exposure of
            sensitive data in memory, only decrypting when necessary for the search.
        """
        results = []
        
        for i, entry in enumerate(self.history):
            # Check if filter applies
            if filter_category and filter_category != "All":
                if filter_category not in entry["metadata"]["categories"]:
                    continue
            
            # Only decrypt if necessary for search to minimize exposure
            # This reduces the amount of sensitive data in memory at any time
            if query:
                try:
                    # Decrypt the content to search in it
                    decrypted_content = self.crypto_handler.decrypt_data(entry["encrypted_content"])
                    if query.lower() in decrypted_content.lower():
                        results.append((i, entry["metadata"]))
                except Exception as e:
                    print(f"Error decrypting entry: {e}")
            else:
                # If no search query, just add the entry
                results.append((i, entry["metadata"]))
        
        return results
    
    def _save_history(self):
        """
        Save clipboard history to encrypted storage.
        
        This private method:
        1. Takes the current history state (which contains already-encrypted content)
        2. Passes it to crypto_handler for secure persistent storage
        
        Security Implementation:
        - Uses the crypto_handler to handle the encryption and storage process
        - Ensures the entire history file itself is securely stored
        - Preserves metadata for searching without needing to decrypt content
        
        Exceptions:
            Catches and logs any exceptions during the save process to prevent
            application crashes while ensuring the user is informed of failures.
        """
        try:
            self.crypto_handler.save_encrypted_history(self.history)
        except Exception as e:
            print(f"Error saving clipboard history: {e}")
    
    def _load_history(self):
        """
        Load clipboard history from encrypted storage.
        
        This private method:
        1. Verifies the crypto handler has been initialized with a key
        2. Retrieves and decrypts the history file metadata (but not content)
        3. Loads the encrypted history entries into memory
        
        Security Implementation:
        - Checks for proper cryptographic initialization before attempting to load
        - Handles the case where no history exists yet
        - Initializes an empty history if decryption fails (wrong password)
        - Individual clipboard contents remain encrypted in memory until needed
        
        Note:
            The actual clipboard content remains encrypted in memory and is only
            decrypted when explicitly requested through get_entry() or search_history().
        """
        try:
            # Ensure the crypto handler has a valid key before loading
            if not self.crypto_handler.key:
                # If no password was set yet, we can't load the history
                self.history = []
                return
                
            self.history = self.crypto_handler.load_encrypted_history()
            
            # Initialize with an empty list if history is None
            if self.history is None:
                self.history = []
        except Exception as e:
            print(f"Error loading clipboard history: {e}")
            self.history = []

