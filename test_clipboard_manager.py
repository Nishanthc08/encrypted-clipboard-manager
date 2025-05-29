#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script for the Encrypted Clipboard Manager.
Tests core functionalities:
- Password handling and encryption
- Clipboard monitoring
- Sensitive data detection
- History management
- Secure deletion
"""

import os
import sys
import unittest
import tempfile
import json
import base64
import time
from unittest.mock import MagicMock, patch

# Add the parent directory to sys.path to enable relative imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from encryption.crypto_handler import CryptoHandler
from clipboard.monitor import ClipboardMonitor
from detection.analyzer import SensitiveDataAnalyzer
from utils.security import SecurityUtils
from PyQt6.QtWidgets import QApplication

# Create a QApplication instance for clipboard access
app = QApplication([])


class TestCryptoHandler(unittest.TestCase):
    """Test the encryption and decryption functionality."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary file for the encrypted data
        self.temp_file_fd, self.temp_file_path = tempfile.mkstemp()
        os.close(self.temp_file_fd)
        
        # Create a CryptoHandler with a test path
        self.crypto_handler = CryptoHandler()
        self.crypto_handler.encrypted_data_path = self.temp_file_path
        
        # Set a test password
        self.test_password = "TestPassword123"
        self.crypto_handler.set_password(self.test_password)
    
    def tearDown(self):
        """Clean up after tests."""
        # Remove the temporary file
        if os.path.exists(self.temp_file_path):
            os.unlink(self.temp_file_path)
    
    def test_encrypt_decrypt(self):
        """Test encrypting and decrypting data."""
        # Test data to encrypt
        test_data = "This is a test string to encrypt"
        
        # Encrypt the data
        encrypted_data = self.crypto_handler.encrypt_data(test_data)
        
        # Check that encrypted data is different from original
        self.assertNotEqual(test_data, encrypted_data["data"])
        
        # Decrypt the data
        decrypted_data = self.crypto_handler.decrypt_data(encrypted_data)
        
        # Check that decrypted data matches original
        self.assertEqual(test_data, decrypted_data)
    
    def test_save_load_history(self):
        """Test saving and loading encrypted history."""
        # Create test history entries
        test_history = [
            {
                "metadata": {"timestamp": "2025-05-28T15:00:00"},
                "encrypted_content": self.crypto_handler.encrypt_data("Test entry 1")
            },
            {
                "metadata": {"timestamp": "2025-05-28T15:01:00"},
                "encrypted_content": self.crypto_handler.encrypt_data("Test entry 2")
            }
        ]
        
        # Save the history
        self.crypto_handler.save_encrypted_history(test_history)
        
        # Check that the file exists
        self.assertTrue(os.path.exists(self.temp_file_path))
        
        # Load the history
        loaded_history = self.crypto_handler.load_encrypted_history()
        
        # Check that the loaded history has the same length
        self.assertEqual(len(test_history), len(loaded_history))
        
        # Check that the metadata matches
        self.assertEqual(
            test_history[0]["metadata"]["timestamp"],
            loaded_history[0]["metadata"]["timestamp"]
        )
    
    def test_password_change(self):
        """Test changing the encryption password."""
        # Create test history entries
        test_data = "Testing password change"
        original_encrypted_data = self.crypto_handler.encrypt_data(test_data)
        
        # Save to history
        test_history = [
            {
                "metadata": {"timestamp": "2025-05-28T15:00:00"},
                "encrypted_content": original_encrypted_data
            }
        ]
        self.crypto_handler.save_encrypted_history(test_history)
        
        # Verify we can decrypt with original password
        decrypted_original = self.crypto_handler.decrypt_data(original_encrypted_data)
        self.assertEqual(test_data, decrypted_original)
        
        # Save the original salt and key information for comparison
        original_salt = self.crypto_handler.salt
        
        # Change the password
        new_password = "NewPassword456"
        self.crypto_handler.set_password(new_password)
        
        # Verify salt has changed
        self.assertNotEqual(original_salt, self.crypto_handler.salt)
        
        # Load history - should be re-encrypted with new key
        loaded_history = self.crypto_handler.load_encrypted_history()
        self.assertEqual(1, len(loaded_history))
        
        # Verify the re-encrypted data maintains the original content
        new_encrypted_content = loaded_history[0]["encrypted_content"]
        decrypted_reencrypted = self.crypto_handler.decrypt_data(new_encrypted_content)
        self.assertEqual(test_data, decrypted_reencrypted)
        
        # Verify new data can be encrypted and decrypted with new key
        new_test_data = "New data with new password"
        new_encrypted_data = self.crypto_handler.encrypt_data(new_test_data)
        decrypted_new = self.crypto_handler.decrypt_data(new_encrypted_data)
        self.assertEqual(new_test_data, decrypted_new)
        
        # Verify the original encrypted data is different from the re-encrypted data
        # (they should have different IVs and ciphertext)
        self.assertNotEqual(
            original_encrypted_data["data"], 
            new_encrypted_content["data"]
        )
    
    def test_clear_key_from_memory(self):
        """Test securely clearing encryption key from memory."""
        # Encrypt some data to verify the key is working
        test_data = "Test clear key"
        encrypted_data = self.crypto_handler.encrypt_data(test_data)
        
        # Clear the key
        self.crypto_handler.clear_key_from_memory()
        
        # Verify the key is cleared
        self.assertIsNone(self.crypto_handler.key)
        self.assertIsNone(self.crypto_handler.password)
        
        # Try to encrypt/decrypt - should raise an error
        with self.assertRaises(ValueError):
            self.crypto_handler.encrypt_data("This should fail")
        
        with self.assertRaises(ValueError):
            self.crypto_handler.decrypt_data(encrypted_data)


class TestSensitiveDataAnalyzer(unittest.TestCase):
    """Test the sensitive data detection functionality."""
    
    def setUp(self):
        """Set up the test environment."""
        self.analyzer = SensitiveDataAnalyzer()
    
    def test_password_detection(self):
        """Test detection of password patterns."""
        # Test strings with password patterns
        test_strings = [
            "password=MySecretPassword123",
            "pass: AnotherPassword",
            "pwd=12345",
            "Normal text with no password"
        ]
        
        # Expected results
        expected_results = [True, True, True, False]
        
        # Test each string
        for test_string, expected in zip(test_strings, expected_results):
            result = self.analyzer.analyze(test_string)
            if expected:
                self.assertIn("password", result["categories"])
            else:
                self.assertNotIn("password", result["categories"])
    
    def test_credit_card_detection(self):
        """Test detection of credit card patterns."""
        # Test strings with credit card patterns
        test_strings = [
            "My credit card is 4111-1111-1111-1111",
            "Card number: 5555555555554444",
            "Normal text with no card number"
        ]
        
        # Expected results
        expected_results = [True, True, False]
        
        # Test each string
        for test_string, expected in zip(test_strings, expected_results):
            result = self.analyzer.analyze(test_string)
            if expected:
                self.assertIn("credit_card", result["categories"])
            else:
                self.assertNotIn("credit_card", result["categories"])
    
    def test_api_key_detection(self):
        """Test detection of API key patterns."""
        # Test strings with API key patterns
        test_strings = [
            "api_key=sk_test_4eC39HqLyjWDarjtT1zdp7dc",
            "API-SECRET: abcdef12345",
            "access_token=ya29.a0Aa4xrXMjD8YLg",
            "Normal text with no API key"
        ]
        
        # Expected results
        expected_results = [True, True, True, False]
        
        # Test each string
        for test_string, expected in zip(test_strings, expected_results):
            result = self.analyzer.analyze(test_string)
            if expected:
                self.assertIn("api_key", result["categories"])
            else:
                self.assertNotIn("api_key", result["categories"])
    
    def test_sensitivity_levels(self):
        """Test the assignment of sensitivity levels."""
        # Test strings with different sensitivity levels
        test_strings = [
            # High sensitivity - contains password
            "password=MySecretPassword123",
            # Medium sensitivity - contains email
            "My email is test@example.com",
            # Low sensitivity - no sensitive data
            "This is a regular text string"
        ]
        
        # Expected sensitivity levels
        expected_levels = ["high", "medium", "low"]
        
        # Test each string
        for test_string, expected in zip(test_strings, expected_levels):
            result = self.analyzer.analyze(test_string)
            self.assertEqual(expected, result["sensitivity"])


class TestSecurityUtils(unittest.TestCase):
    """Test the security utilities functionality."""
    
    def setUp(self):
        """Set up the test environment."""
        self.security_utils = SecurityUtils()
        
        # Create a temporary file for secure deletion test
        self.temp_file_fd, self.temp_file_path = tempfile.mkstemp()
        os.write(self.temp_file_fd, b"This is test data to be securely deleted")
        os.close(self.temp_file_fd)
    
    def tearDown(self):
        """Clean up after tests."""
        # Ensure the temporary file is removed
        if os.path.exists(self.temp_file_path):
            os.unlink(self.temp_file_path)
    
    def test_secure_overwrite(self):
        """Test securely overwriting data in memory."""
        # Test with string data
        test_string = "This is sensitive data"
        # Keep a copy for comparison
        original_string = test_string
        
        # For strings, the method returns a new overwritten string
        overwritten_string = self.security_utils.secure_overwrite(test_string)
        
        # Verify the overwritten string is different from the original
        self.assertIsNotNone(overwritten_string)
        self.assertNotEqual(original_string, overwritten_string)
        
        # Verify the overwritten string has the same length
        self.assertEqual(len(original_string), len(overwritten_string))
        
        # Verify the overwritten string contains only printable characters
        import string
        for char in overwritten_string:
            self.assertIn(char, string.printable)
        
        # Test with dictionary data
        test_dict = {
            "sensitive": "This is sensitive data",
            "nested": {
                "more_sensitive": "More sensitive data"
            }
        }
        
        # Make a copy for comparison
        original_sensitive = test_dict["sensitive"]
        original_nested = test_dict["nested"]["more_sensitive"]
        
        # Process the dictionary data
        # First level string
        new_sensitive = self.security_utils.secure_overwrite(test_dict["sensitive"])
        test_dict["sensitive"] = new_sensitive or "[DATA WIPED]"
        
        # Nested string
        new_nested = self.security_utils.secure_overwrite(test_dict["nested"]["more_sensitive"])
        test_dict["nested"]["more_sensitive"] = new_nested or "[DATA WIPED]"
        
        # Check that the values have been changed
        self.assertNotEqual(original_sensitive, test_dict["sensitive"])
        self.assertNotEqual(original_nested, test_dict["nested"]["more_sensitive"])
        
        # Test with list data
        test_list = ["Secret1", "Secret2", "Secret3"]
        original_list = test_list.copy()
        
        # Process the list
        self.security_utils.secure_overwrite(test_list)
        
        # Verify the list elements are either None or different from originals
        for i, item in enumerate(test_list):
            if item is not None:
                self.assertNotEqual(original_list[i], item)
            else:
                self.assertIsNone(item)
    
    def test_secure_delete_file(self):
        """Test secure file deletion."""
        # Make sure the file exists before deletion
        self.assertTrue(os.path.exists(self.temp_file_path))
        
        # Securely delete the file
        result = self.security_utils.secure_delete_file(self.temp_file_path)
        
        # Check the result and file existence
        self.assertTrue(result)
        self.assertFalse(os.path.exists(self.temp_file_path))
    
    def test_wipe_memory(self):
        """Test wiping variables from memory."""
        # Create a test string
        test_string = "Sensitive data to wipe"
        
        # Wipe the variable
        self.security_utils.wipe_memory(test_string)
        
        # Note: We can't actually test that the memory is wiped in Python
        # because of garbage collection and references. This is more of a
        # functional test to ensure the method doesn't throw an error.
        pass


class TestClipboardMonitorIntegration(unittest.TestCase):
    """Integration tests for the clipboard monitor functionality."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary file for the encrypted data
        self.temp_file_fd, self.temp_file_path = tempfile.mkstemp()
        os.close(self.temp_file_fd)
        
        # Create components
        self.crypto_handler = CryptoHandler()
        self.crypto_handler.encrypted_data_path = self.temp_file_path
        self.crypto_handler.set_password("TestPassword123")
        
        self.analyzer = SensitiveDataAnalyzer()
        self.security_utils = SecurityUtils()
        
        # Create clipboard monitor with mocked clipboard
        self.clipboard_monitor = ClipboardMonitor(
            self.crypto_handler, self.analyzer, self.security_utils
        )
        
        # Replace the clipboard check with a mock
        self.clipboard_monitor.check_clipboard = MagicMock()
        
        # Start monitoring
        self.clipboard_monitor.start_monitoring()
    
    def tearDown(self):
        """Clean up after tests."""
        # Stop monitoring
        self.clipboard_monitor.stop_monitoring()
        
        # Remove the temporary file
        if os.path.exists(self.temp_file_path):
            os.unlink(self.temp_file_path)
    
    def test_process_clipboard_content(self):
        """Test processing clipboard content."""
        # Process some test content
        test_content = "This is test clipboard content"
        self.clipboard_monitor._process_clipboard_content(test_content)
        
        # Check that the content was added to history
        self.assertEqual(1, len(self.clipboard_monitor.history))
        
        # Process some sensitive content
        sensitive_content = "password=SecretPassword123"
        self.clipboard_monitor._process_clipboard_content(sensitive_content)
        
        # Check that the content was added to history
        self.assertEqual(2, len(self.clipboard_monitor.history))
        
        # Check that sensitive content is properly categorized
        entry = self.clipboard_monitor.get_entry(1)
        self.assertIn("password", entry["metadata"]["categories"])
        self.assertEqual("high", entry["metadata"]["sensitivity"])
    
    def test_search_history(self):
        """Test searching clipboard history."""
        # Add some test entries
        self.clipboard_monitor._process_clipboard_content("Test entry one")
        self.clipboard_monitor._process_clipboard_content("Test entry two")
        self.clipboard_monitor._process_clipboard_content("Different content")
        self.clipboard_monitor._process_clipboard_content("password=secret")
        
        # Search for "test"
        results = self.clipboard_monitor.search_history("test")
        self.assertEqual(2, len(results))
        
        # Search for "different"
        results = self.clipboard_monitor.search_history("different")
        self.assertEqual(1, len(results))
        
        # Filter by password category
        results = self.clipboard_monitor.search_history("", filter_category="password")
        self.assertEqual(1, len(results))
    
    def test_shred_entry(self):
        """Test securely deleting an entry."""
        # Add some test entries
        self.clipboard_monitor._process_clipboard_content("Entry to keep")
        self.clipboard_monitor._process_clipboard_content("Entry to shred")
        
        # Initially should have 2 entries
        self.assertEqual(2, len(self.clipboard_monitor.history))
        
        # Shred the second entry
        result = self.clipboard_monitor.shred_entry(1)
        
        # Check the result
        self.assertTrue(result)
        
        # Should now have 1 entry
        self.assertEqual(1, len(self.clipboard_monitor.history))
        
        # The remaining entry should be "Entry to keep"
        entry = self.clipboard_monitor.get_entry(0)
        self.assertEqual("Entry to keep", entry["content"])
    
    def test_shred_all(self):
        """Test securely deleting all entries."""
        # Add some test entries
        self.clipboard_monitor._process_clipboard_content("Entry one")
        self.clipboard_monitor._process_clipboard_content("Entry two")
        self.clipboard_monitor._process_clipboard_content("Entry three")
        
        # Initially should have 3 entries
        self.assertEqual(3, len(self.clipboard_monitor.history))
        
        # Shred all entries
        result = self.clipboard_monitor.shred_all()
        
        # Check the result
        self.assertTrue(result)
        
        # Should now have 0 entries
        self.assertEqual(0, len(self.clipboard_monitor.history))


def test_history_file_initialization():
    """Test proper initialization of empty history files."""
    # Create a test file path
    fd, temp_path = tempfile.mkstemp()
    os.close(fd)
    os.unlink(temp_path)  # Remove the file to test creation
    
    try:
        # Create a crypto handler with the test path
        handler = CryptoHandler()
        handler.encrypted_data_path = temp_path
        handler.set_password("TestPassword")
        
        # Attempt to load history from non-existent file
        # This should create an empty file
        history = handler.load_encrypted_history()
        
        # Verify the file was created
        assert os.path.exists(temp_path)
        
        # Verify the history is empty
        assert len(history) == 0
        
        # Open the file and verify it has valid JSON
        with open(temp_path, 'r') as f:
            content = json.load(f)
            assert "salt" in content
            assert "entries" in content
            assert isinstance(content["entries"], list)
            assert len(content["entries"]) == 0
            
        # Create an empty file
        with open(temp_path, 'w') as f:
            f.write("")
        
        # Try to load from empty file
        history = handler.load_encrypted_history()
        
        # Verify the file now has valid JSON
        with open(temp_path, 'r') as f:
            content = json.load(f)
            assert "salt" in content
            assert "entries" in content
            
        # Create a file with invalid JSON
        with open(temp_path, 'w') as f:
            f.write("This is not valid JSON")
        
        # Try to load from invalid JSON file
        history = handler.load_encrypted_history()
        
        # Verify the file now has valid JSON
        with open(temp_path, 'r') as f:
            content = json.load(f)
            assert "salt" in content
            assert "entries" in content
            
        print("History file initialization test passed!")
        
    finally:
        # Clean up
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def run_tests():
    """Run all tests."""
    # First run the standalone test for history file initialization
    print("Running history file initialization test...")
    test_history_file_initialization()
    
    # Create a test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestCryptoHandler))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestSensitiveDataAnalyzer))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestSecurityUtils))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestClipboardMonitorIntegration))
    
    # Run the tests
    unittest.TextTestRunner(verbosity=2).run(test_suite)


if __name__ == "__main__":
    run_tests()
