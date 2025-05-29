#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Clipboard monitoring module for the Encrypted Clipboard Manager.
"""

import time
import json
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QClipboard


class ClipboardMonitor(QObject):
    """Monitors clipboard changes and manages clipboard history."""
    
    # Signal emitted when clipboard content changes
    clipboard_changed = pyqtSignal(str, dict)
    
    def __init__(self, crypto_handler, analyzer, security_utils):
        """Initialize the clipboard monitor."""
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
        """Start monitoring clipboard changes."""
        # First load any existing history
        self._load_history()
        
        # Get initial clipboard content
        self.last_content = self.clipboard.text()
        
        # Start the timer to check for changes
        self.timer.start(1000)  # Check every second
        self.monitoring = True
    
    def stop_monitoring(self):
        """Stop monitoring clipboard changes."""
        self.timer.stop()
        self.monitoring = False
    
    def check_clipboard(self):
        """Check for changes in clipboard content."""
        current_content = self.clipboard.text()
        
        # Only process if content has changed and is not empty
        if current_content and current_content != self.last_content:
            self.last_content = current_content
            self._process_clipboard_content(current_content)
    
    def _process_clipboard_content(self, content):
        """Process and store new clipboard content."""
        # Analyze the content for sensitive data
        analysis_result = self.analyzer.analyze(content)
        
        # Create metadata for the clipboard entry
        timestamp = datetime.now().isoformat()
        entry_metadata = {
            "timestamp": timestamp,
            "content_type": analysis_result["content_type"],
            "sensitivity": analysis_result["sensitivity"],
            "categories": analysis_result["categories"]
        }
        
        # Encrypt the content
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
        """Get the entire clipboard history."""
        return self.history
    
    def get_entry(self, index):
        """Get a specific history entry."""
        if 0 <= index < len(self.history):
            entry = self.history[index]
            decrypted_content = self.crypto_handler.decrypt_data(entry["encrypted_content"])
            return {
                "content": decrypted_content,
                "metadata": entry["metadata"]
            }
        return None
    
    def shred_entry(self, index):
        """Securely delete a clipboard history entry."""
        if 0 <= index < len(self.history):
            # Get the entry and securely clear its content
            entry = self.history[index]
            
            # Use security utils to securely overwrite the data
            self.security_utils.secure_overwrite(entry)
            
            # Remove from history
            self.history.pop(index)
            self._save_history()
            return True
        return False
    
    def shred_all(self):
        """Securely delete all clipboard history."""
        # Securely overwrite each entry
        for entry in self.history:
            self.security_utils.secure_overwrite(entry)
        
        # Clear the history
        self.history.clear()
        self._save_history()
        return True
    
    def search_history(self, query, filter_category=None):
        """Search clipboard history with optional category filter."""
        results = []
        
        for i, entry in enumerate(self.history):
            # Check if filter applies
            if filter_category and filter_category != "All":
                if filter_category not in entry["metadata"]["categories"]:
                    continue
            
            # Only decrypt if necessary for search
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
        """Save clipboard history to encrypted storage."""
        try:
            self.crypto_handler.save_encrypted_history(self.history)
        except Exception as e:
            print(f"Error saving clipboard history: {e}")
    
    def _load_history(self):
        """Load clipboard history from encrypted storage."""
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

