# Encrypted Clipboard Manager

A secure clipboard management tool that automatically encrypts your clipboard content and provides sensitive data detection capabilities, ensuring your copied information remains private and protected.

## Features

- 🔐 **End-to-end encryption** of all clipboard content using AES-256
- 🕵️ **Automatic detection** of sensitive information (passwords, tokens, personal data)
- 🧹 **Secure shredding** of clipboard entries to prevent data recovery
- 🔍 **Search functionality** across your encrypted clipboard history
- 🏷️ **Content categorization** to quickly identify different types of information
- 🖥️ **User-friendly GUI** built with PyQt6
- 🛡️ **Zero-knowledge architecture** - only you can decrypt your data

## Security Considerations

This application is designed with security as a top priority:

- All clipboard data is encrypted using AES-256 before being stored
- The encryption key is derived from your password using PBKDF2 with a high iteration count
- Sensitive data detection helps you identify when you've copied security-critical information
- The "shred" feature securely wipes data from memory and storage using multiple overwrite passes
- Memory protection techniques are employed to prevent leakage via memory dumps or swap files
- No data is ever sent to external services or cloud storage
- Password verification occurs locally without any server communication

## Installation

### Prerequisites

- Python 3.8 or newer
- PyQt6
- Additional Python libraries (see requirements.txt)

### Setup Instructions

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/encrypted_clipboard_manager.git
   cd encrypted_clipboard_manager
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Linux/macOS
   # OR
   venv\Scripts\activate     # On Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python main.py
   ```

## Usage Guide

### First Run Setup

1. On first launch, you'll be prompted to create an encryption password
   - Choose a strong password that you can remember
   - This password cannot be recovered - if forgotten, your clipboard history will be inaccessible

2. The application will start monitoring your clipboard automatically

### Daily Use

- **Copying content**: Use normal copy operations (Ctrl+C, right-click menu, etc.)
- **Viewing history**: All copied items appear in the main window
- **Searching**: Use the search bar to find specific content
- **Filtering**: Use the dropdown to filter by content type (passwords, personal info, etc.)
- **Restoring content**: Select an item and click "Copy to Clipboard"
- **Secure deletion**: Select an item and click "Shred Selected" to permanently delete it
- **Complete wipe**: Click "Shred All" to securely clear your entire clipboard history

### Security Tips

- Lock your computer when away to prevent unauthorized access
- Choose a strong, unique password for the encryption
- Regularly review and clean your clipboard history
- Use the "Shred" feature for sensitive data you no longer need

## Development Guide

### Development Environment Setup

1. Set up a development environment:
   ```bash
   git clone https://github.com/yourusername/encrypted_clipboard_manager.git
   cd encrypted_clipboard_manager
   python -m venv venv
   source venv/bin/activate  # On Linux/macOS
   pip install -r requirements.txt
   pip install -r dev-requirements.txt  # Installs development dependencies
   ```

2. Project Structure:
   ```
   encrypted_clipboard_manager/
   ├── clipboard/       # Clipboard monitoring functionality
   ├── detection/       # Sensitive data detection logic
   ├── encryption/      # Encryption/decryption handling
   ├── gui/             # PyQt6 user interface components
   ├── utils/           # Security and utility functions
   ├── __init__.py
   ├── main.py          # Application entry point
   └── test_*.py        # Test modules
   ```

### Running Tests

```bash
pytest
```

To generate a coverage report:

```bash
pytest --cov=. --cov-report=html
```

### Coding Guidelines

- Follow PEP 8 style guidelines
- Add docstrings for all modules, classes, and functions
- Include type hints for function parameters and return values
- Write unit tests for new functionality
- Update documentation when adding or changing features

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The cryptography library for secure encryption functions
- PyQt6 for the GUI framework
- scikit-learn for sensitive data detection

