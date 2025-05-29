#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Encrypted Clipboard History Tool
--------------------------------
A secure clipboard manager that:
- Logs clipboard history in encrypted form
- Highlights sensitive data (passwords, tokens, etc.)
- Allows user to "shred" entries
"""

import sys
import os
from PyQt6.QtWidgets import QApplication

# Add the parent directory to sys.path to enable relative imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import ClipboardManagerWindow
from encryption.crypto_handler import CryptoHandler
from clipboard.monitor import ClipboardMonitor
from detection.analyzer import SensitiveDataAnalyzer
from utils.security import SecurityUtils


def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    app.setApplicationName("Encrypted Clipboard Manager")
    
    # Initialize components
    crypto_handler = CryptoHandler()
    analyzer = SensitiveDataAnalyzer()
    security_utils = SecurityUtils()
    
    # Initialize clipboard monitor
    clipboard_monitor = ClipboardMonitor(crypto_handler, analyzer, security_utils)
    
    # Initialize and show main window
    window = ClipboardManagerWindow(clipboard_monitor, crypto_handler, analyzer)
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

