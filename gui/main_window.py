#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main GUI window for the Encrypted Clipboard Manager.
"""

import os

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QSlider, QLineEdit, QLabel, 
    QListWidget, QListWidgetItem, QComboBox, QMessageBox,
    QDialog, QDialogButtonBox, QFormLayout
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon, QAction


class PasswordDialog(QDialog):
    """Dialog for entering the encryption password."""
    
    def __init__(self, parent=None, is_new_user=False):
        """Initialize the password dialog."""
        super().__init__(parent)
        
        self.password = ""
        self.is_new_user = is_new_user
        
        self.setWindowTitle("Enter Password")
        self.setMinimumWidth(300)
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the dialog UI."""
        layout = QFormLayout(self)
        
        # Password input field
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Enter Password:", self.password_input)
        
        # Confirm password field (only for new users)
        if self.is_new_user:
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
            layout.addRow("Confirm Password:", self.confirm_input)
            
            # Instructions for new users
            instructions = QLabel(
                "Please create a strong password to encrypt your clipboard data.\n"
                "This password cannot be recovered if forgotten."
            )
            instructions.setWordWrap(True)
            layout.addRow(instructions)
        
        # Dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addRow(button_box)
    
    def accept(self):
        """Handle the OK button click."""
        if self.is_new_user:
            if self.password_input.text() != self.confirm_input.text():
                QMessageBox.warning(
                    self, "Password Mismatch", 
                    "The passwords do not match. Please try again."
                )
                return
            
            if len(self.password_input.text()) < 8:
                QMessageBox.warning(
                    self, "Weak Password", 
                    "Please use a password of at least 8 characters."
                )
                return
        
        if not self.password_input.text():
            QMessageBox.warning(
                self, "Empty Password", 
                "Password cannot be empty."
            )
            return
        
        self.password = self.password_input.text()
        super().accept()
    
    def get_password(self):
        """Return the entered password."""
        return self.password

class ClipboardManagerWindow(QMainWindow):
    """Main window for the Encrypted Clipboard Manager."""
    
    def __init__(self, clipboard_monitor, crypto_handler, analyzer):
        """Initialize the main window."""
        super().__init__()
        
        self.clipboard_monitor = clipboard_monitor
        self.crypto_handler = crypto_handler
        self.analyzer = analyzer
        
        self.setWindowTitle("Encrypted Clipboard Manager")
        self.setMinimumSize(800, 600)
        
        self._init_ui()
        self._setup_connections()
        
        # Show password dialog before starting
        self._show_password_dialog()
    
    def _show_password_dialog(self):
        """Show the password dialog to get encryption key."""
        # Check if this is a first-time user
        is_new_user = not os.path.exists(self.crypto_handler.encrypted_data_path)
        
        dialog = PasswordDialog(self, is_new_user=is_new_user)
        if dialog.exec():
            # User provided a password
            password = dialog.get_password()
            
            try:
                # Set the password in the crypto handler
                self.crypto_handler.set_password(password)
                
                # Start monitoring clipboard now that we have a valid password
                self.clipboard_monitor.start_monitoring()
            except Exception as e:
                QMessageBox.critical(
                    self, "Encryption Error", 
                    f"Error initializing encryption: {str(e)}"
                )
                # Close the application if encryption fails
                self.close()
        else:
            # User canceled the password dialog
            QMessageBox.information(
                self, "Password Required",
                "A password is required to use the encrypted clipboard manager."
            )
            # Close the application if no password is provided
            self.close()
    
    def _init_ui(self):
        """Initialize the user interface."""
        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Search bar and filters
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search clipboard history...")
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All")
        self.filter_combo.addItem("Passwords")
        self.filter_combo.addItem("API Keys")
        self.filter_combo.addItem("Personal Info")
        
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.filter_combo)
        
        # Clipboard history list
        self.history_list = QListWidget()
        
        # Slider for navigating history
        slider_layout = QHBoxLayout()
        self.history_slider = QSlider(Qt.Orientation.Horizontal)
        slider_layout.addWidget(QLabel("Older"))
        slider_layout.addWidget(self.history_slider)
        slider_layout.addWidget(QLabel("Recent"))
        
        # Action buttons
        button_layout = QHBoxLayout()
        self.shred_button = QPushButton("Shred Selected")
        self.shred_all_button = QPushButton("Shred All")
        self.copy_button = QPushButton("Copy to Clipboard")
        
        button_layout.addWidget(self.shred_button)
        button_layout.addWidget(self.shred_all_button)
        button_layout.addWidget(self.copy_button)
        
        # Add all layouts to main layout
        main_layout.addLayout(search_layout)
        main_layout.addWidget(self.history_list)
        main_layout.addLayout(slider_layout)
        main_layout.addLayout(button_layout)
        
        # Setup system tray
        self._setup_system_tray()
    
    def _setup_system_tray(self):
        """Set up the system tray icon and menu."""
        # This would be implemented with QSystemTrayIcon
        pass
    
    def _setup_connections(self):
        """Connect signals and slots."""
        self.search_input.textChanged.connect(self._filter_history)
        self.filter_combo.currentIndexChanged.connect(self._filter_history)
        self.history_slider.valueChanged.connect(self._update_history_view)
        self.shred_button.clicked.connect(self._shred_selected)
        self.shred_all_button.clicked.connect(self._shred_all)
        self.copy_button.clicked.connect(self._copy_to_clipboard)
    
    def _filter_history(self):
        """Filter the clipboard history based on search text and filter."""
        # Would implement filtering logic here
        pass
    
    def _update_history_view(self, value):
        """Update the history view based on slider position."""
        # Would implement history navigation based on slider value
        pass
    
    def _shred_selected(self):
        """Securely delete selected clipboard entry."""
        # Would implement secure deletion here
        pass
    
    def _shred_all(self):
        """Securely delete all clipboard entries."""
        # Would implement secure deletion of all entries here
        pass
    
    def _copy_to_clipboard(self):
        """Copy selected item back to clipboard."""
        # Would implement copying logic here
        pass

