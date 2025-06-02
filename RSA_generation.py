#!/usr/bin/env python3
"""
@file RSA_generation.py
@brief RSA-4096 Key Generator with AES-256 Encryption
@details This application provides a secure GUI interface for generating RSA-4096 key pairs
         with AES-256-EAX encryption for private key protection. Supports pendrive detection
         and PIN-based key derivation following cryptographic best practices.
@author PAdES Electronic Signature Project
@date 2025
@version 1.0

@section FEATURES Features
- RSA-4096 key generation with cryptographically secure random number generator
- AES-256-EAX encryption for private key protection
- PIN-based key derivation using SHA-256
- Pendrive detection for secure key storage
- Progress tracking and error handling
- Modern PyQt5 GUI interface

@section SECURITY Security Implementation
- RSA-4096: Maximum security key size meeting industry standards
- SHA-256: Secure hash algorithm for PIN-to-key derivation
- AES-256-EAX: Authenticated encryption for private key protection
- Secure Random Generation: Crypto.Random for cryptographically secure keys

@section USAGE Usage
Run with GUI: python RSA_generation.py
Run with CLI: python RSA_generation.py --cli
"""

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import sys
import time
import threading
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout,
    QWidget, QLabel, QLineEdit, QProgressBar, QMessageBox, QTextEdit,
    QGroupBox, QFileDialog
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPixmap, QIcon
import psutil

KEY_SIZE = 4096  #< RSA key size in bits for maximum security
CIPHER_MODE = AES.MODE_EAX  #< AES cipher mode with authentication

class RSAKeyGeneratorThread(QThread):
    """
    @brief Background thread for RSA key generation
    @details Handles RSA-4096 key generation, AES-256 encryption, and file operations
             in a separate thread to prevent GUI freezing during computation.
    
    @author PAdES Electronic Signature Project
    @version 1.0
    @date 2025
    
    This class implements secure key generation in a background thread with the following features:
    - RSA-4096 key generation using cryptographically secure random numbers
    - AES-256-EAX encryption for private key protection
    - SHA-256 hash function for PIN-based key derivation
    - Progress tracking and error handling
    - File I/O operations for secure key storage
    
    @par Signals:
    - progress_updated(int): Emits progress percentage (0-100)
    - key_generated(bytes, bytes, str): Emits encrypted private key, public key, and status message
    - error_occurred(str): Emits error message if generation fails
    """
    
    progress_updated = pyqtSignal(int)    #< Signal for progress updates (0-100%)
    key_generated = pyqtSignal(bytes, bytes, str)  #< Signal for successful key generation
    error_occurred = pyqtSignal(str)     #< Signal for error reporting
    
    def __init__(self, pin, output_dir):
        """
        @brief Initialize key generation thread
        @param pin User-provided PIN for key derivation (string)
        @param output_dir Directory to save generated keys (string)
        
        The PIN is immediately encoded to bytes and stored securely.
        The output directory is validated during the run() method.
        """
        super().__init__()
        self.pin = pin.encode()
        self.output_dir = output_dir
        
    def run(self):
        """
        @brief Main key generation process
        @details Generates RSA-4096 keys, encrypts private key with AES-256-EAX,
                 and saves both keys to specified directory.
        
        The process follows these steps:
        1. Derive AES key from PIN using SHA-256
        2. Generate RSA-4096 key pair
        3. Export keys in PEM format
        4. Encrypt private key with AES-256-EAX
        5. Save encrypted private key and public key to files
        
        @note All cryptographic operations use secure random number generation
        @note Private key is never stored in plaintext
        """
        try:
            # Step 1: Create AES key from PIN using SHA-256
            aes_key = SHA256.new(self.pin).digest()
            
            # Step 2: Generate RSA keys with progress tracking
            self.progress_updated.emit(20)
            rsa_key = RSA.generate(bits=KEY_SIZE)
            
            # Step 3: Export keys in PEM format
            self.progress_updated.emit(60)
            private_key = rsa_key.export_key(format='PEM')
            public_key = rsa_key.publickey().export_key(format='PEM')
            
            # Step 4: Encrypt private key with AES-256-EAX
            self.progress_updated.emit(80)
            cipher = AES.new(aes_key, CIPHER_MODE)
            encrypted_private_key, tag = cipher.encrypt_and_digest(private_key)
            
            # Step 5: Save keys to files
            self.progress_updated.emit(90)
            
            # Ensure output directory exists
            os.makedirs(self.output_dir, exist_ok=True)
            
            # Save encrypted private key with nonce and tag for authenticated decryption
            with open(os.path.join(self.output_dir, "rsa_private.bin"), "wb") as f:
                f.write(cipher.nonce + tag + encrypted_private_key)
            
            # Save public key in PEM format
            with open(os.path.join(self.output_dir, "rsa_public.pem"), "wb") as f:
                f.write(public_key)
            
            self.progress_updated.emit(100)
            self.key_generated.emit(encrypted_private_key, public_key, 
                                  f"Keys successfully generated and saved to {self.output_dir}")
            
        except Exception as e:
            self.error_occurred.emit(f"Error generating keys: {str(e)}")


class RSAKeyGeneratorGUI(QMainWindow):
    """
    @brief Main GUI window for RSA key generation
    @details Provides a user-friendly interface for generating RSA-4096 key pairs with
             AES-256-EAX encryption. Features include PIN validation, pendrive detection,
             progress tracking, and comprehensive error handling.
    
    @author PAdES Electronic Signature Project
    @version 1.0
    @date 2025
    
    The GUI provides the following features:
    - Secure PIN input with confirmation
    - Output directory selection with browse functionality
    - Automatic pendrive detection for secure key storage
    - Real-time progress tracking during key generation
    - Input validation and comprehensive error handling
    - Modern styling with color-coded status indicators
    
    @par Key Components:
    - PIN input fields with password masking
    - Output directory selection with validation
    - Pendrive detection and listing
    - Progress bar with percentage tracking
    - Status label with success/error indicators
    """
    
    def __init__(self):
        """
        @brief Initialize the RSA Key Generator GUI
        @details Sets up the main window and initializes the user interface components
        
        Creates the main window with proper title, geometry, and calls initUI()
        to set up all interface components.
        """
        super().__init__()
        self.initUI()
        
    def initUI(self):
        """
        @brief Initialize the user interface components
        @details Creates and configures all GUI elements including:
                 - Title and instruction labels with styling
                 - PIN input fields with validation
                 - Output directory selection with browse button
                 - Pendrive detection interface
                 - Progress bar and status indicators
                 - Key generation button with modern styling
        
        All components are organized in a vertical layout with proper spacing
        and grouped in logical sections for better user experience.
        """
        self.setWindowTitle("RSA Key Generator - PAdES Signature Tool")
        self.setGeometry(300, 300, 600, 500)
        
        # Central widget setup
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout()
          # Title section
        title = QLabel("RSA Key Generator for PAdES Electronic Signature")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        # Instructions section
        instructions = QLabel(
            "This tool generates a 4096-bit RSA key pair for electronic document signing. "
            "The private key will be encrypted with AES using your PIN and stored on a pendrive."
        )
        instructions.setWordWrap(True)
        instructions.setStyleSheet("color: #34495e; margin: 10px; padding: 10px; background-color: #ecf0f1; border-radius: 5px;")
        layout.addWidget(instructions)
        
        # PIN input group
        pin_group = QGroupBox("Security Settings")
        pin_layout = QVBoxLayout()
        
        pin_label = QLabel("Enter PIN (will be used to encrypt your private key):")
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.setPlaceholderText("Enter a strong PIN...")
        
        pin_confirm_label = QLabel("Confirm PIN:")
        self.pin_confirm_input = QLineEdit()
        self.pin_confirm_input.setEchoMode(QLineEdit.Password)
        self.pin_confirm_input.setPlaceholderText("Re-enter your PIN...")
        
        pin_layout.addWidget(pin_label)
        pin_layout.addWidget(self.pin_input)
        pin_layout.addWidget(pin_confirm_label)
        pin_layout.addWidget(self.pin_confirm_input)
        pin_group.setLayout(pin_layout)
        layout.addWidget(pin_group)
        
        # Output directory selection
        output_group = QGroupBox("Output Location")
        output_layout = QHBoxLayout()
        
        self.output_path = QLabel("keys/")
        self.output_path.setStyleSheet("padding: 5px; background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 3px;")
        
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_output_dir)
        
        output_layout.addWidget(self.output_path)
        output_layout.addWidget(self.browse_button)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Pendrive detection
        pendrive_group = QGroupBox("Pendrive Detection")
        pendrive_layout = QVBoxLayout()
        
        self.detect_button = QPushButton("Detect Available Pendrives")
        self.detect_button.clicked.connect(self.detect_pendrives)
        
        self.pendrive_info = QTextEdit()
        self.pendrive_info.setMaximumHeight(100)
        self.pendrive_info.setReadOnly(True)
        
        pendrive_layout.addWidget(self.detect_button)
        pendrive_layout.addWidget(self.pendrive_info)
        pendrive_group.setLayout(pendrive_layout)
        layout.addWidget(pendrive_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Generate button
        self.generate_button = QPushButton("Generate RSA Key Pair")
        self.generate_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
        """)
        self.generate_button.clicked.connect(self.generate_keys)
        layout.addWidget(self.generate_button)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #27ae60; font-weight: bold; margin: 10px;")
        layout.addWidget(self.status_label)
        
        central_widget.setLayout(layout)
        
    def browse_output_dir(self):
        """
        @brief Open a dialog to select the output directory
        @details Uses QFileDialog to allow user selection of output directory.
                 Updates the output_path label with the selected directory.
        
        If user cancels the dialog, no changes are made to the current path.
        """
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory", self.output_path.text())
        if directory:
            self.output_path.setText(directory)
    
    def detect_pendrives(self):
        """
        @brief Detect and list available pendrives
        @details Uses psutil to scan for removable drives and displays them in the info area.
                 Provides helpful tips for secure key storage on pendrives.
          The detection process:
        1. Clear previous results
        2. Scan all disk partitions
        3. Filter for removable drives
        4. Display drive information with mount points
        5. Provide user guidance
        """
        self.pendrive_info.clear()
        partitions = psutil.disk_partitions(all=False)
        pendrives_found = False
        
        for partition in partitions:
            if 'removable' in partition.opts.lower():
                self.pendrive_info.append(f"📱 {partition.device} - mounted at {partition.mountpoint}")
                pendrives_found = True
        
        if not pendrives_found:
            self.pendrive_info.append("❌ No removable drives detected.")
        else:
            self.pendrive_info.append("")
            self.pendrive_info.append("💡 Tip: You can save your keys directly to a pendrive for security.")
    
    def generate_keys(self):
        """
        @brief Validate inputs and start the RSA key generation process
        @details Performs comprehensive input validation and initiates background key generation.
        
        Validation steps:
        1. Check PIN is provided
        2. Verify PIN confirmation matches
        3. Ensure minimum PIN length (4 characters)
        4. Optional security warning for short PINs
        5. Validate output directory accessibility
        
        If validation passes, starts RSAKeyGeneratorThread in background.
        """        # Input validation
        pin = self.pin_input.text()
        pin_confirm = self.pin_confirm_input.text()
        
        if not pin:
            QMessageBox.warning(self, "Warning", "Please enter a PIN.")
            return
            
        if pin != pin_confirm:
            QMessageBox.warning(self, "Warning", "PINs do not match.")
            return
            
        if len(pin) < 4:
            QMessageBox.warning(self, "Warning", "PIN must be at least 4 characters long.")
            return
            
        # Security recommendation for PIN length
        if len(pin) < 8:
            reply = QMessageBox.question(self, "PIN Security", 
                "Your PIN is shorter than 8 characters. For better security, consider using a longer PIN. "
                "Continue with current PIN?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                return
        
        # Prepare for key generation
        self.generate_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Generating RSA keys...")
        
        output_dir = self.output_path.text()
        
        # Validate and create output directory
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Cannot create output directory: {str(e)}")
                self.generate_button.setEnabled(True)
                self.progress_bar.setVisible(False)
                return
        
        # Start background key generation
        self.key_thread = RSAKeyGeneratorThread(pin, output_dir)
        self.key_thread.progress_updated.connect(self.update_progress)
        self.key_thread.key_generated.connect(self.on_keys_generated)
        self.key_thread.error_occurred.connect(self.on_error)
        self.key_thread.start()
    
    def update_progress(self, value):
        """
        @brief Update the progress bar value
        @param value Progress percentage (0-100)
        
        Updates the GUI progress bar to reflect current key generation progress.
        """
        self.progress_bar.setValue(value)
    
    def on_keys_generated(self, encrypted_private_key, public_key, message):
        """
        @brief Handle successful key generation
        @param encrypted_private_key The encrypted private key (bytes)
        @param public_key The public key in PEM format (bytes)
        @param message Success message from the generation thread (string)
          Resets the GUI state and displays success information to the user.
        Provides guidance on key usage and security.
        """
        self.progress_bar.setVisible(False)
        self.generate_button.setEnabled(True)
        self.status_label.setText("✅ " + message)
        
        QMessageBox.information(self, "Success", 
            f"{message} "
            f"Private key: encrypted and saved to rsa_private.bin "
            f"Public key: saved to rsa_public.pem "
            f"Keep your PIN safe - you'll need it to sign documents!")
    
    def on_error(self, error_message):
        """
        @brief Handle errors during key generation
        @param error_message Error description from the generation thread (string)
        
        Resets the GUI state and displays error information to the user.
        """
        self.progress_bar.setVisible(False)
        self.generate_button.setEnabled(True)
        self.status_label.setText("❌ Error occurred")
        QMessageBox.critical(self, "Error", error_message)


def create_rsa_keys():
    """
    @brief Legacy command-line interface for key generation
    @details Provides command-line interface for key generation when GUI is not desired.
             Uses the same cryptographic operations as the GUI version.
    
    @deprecated This function is maintained for backward compatibility.
                Use the GUI version for better user experience.
    
    The CLI process:
    1. Prompt user for PIN
    2. Generate RSA-4096 key pair
    3. Encrypt private key with AES-256-EAX
    4. Save keys to default 'keys/' directory
    """
    pin = input("Enter PIN: ").encode()
    aes_key = SHA256.new(pin).digest()

    print("Generating RSA keys...")
    
    try:
        rsa_key = RSA.generate(bits=KEY_SIZE)
        private_key = rsa_key.export_key(format='PEM')
        public_key = rsa_key.publickey().export_key(format='PEM')

        cipher = AES.new(aes_key, CIPHER_MODE)
        encrypted_private_key, tag = cipher.encrypt_and_digest(private_key)
        
        # Ensure keys directory exists
        os.makedirs("keys", exist_ok=True)
        
        # Save encrypted private key with nonce and tag
        with open("keys/rsa_private.bin", "wb") as f:
            f.write(cipher.nonce + tag + encrypted_private_key)

        with open("keys/rsa_public.pem", "wb") as f:
            f.write(public_key)

        print("Keys saved to files in the keys folder.")
        
    except Exception as e:
        print(f"Error generating keys: {e}")


if __name__ == "__main__":
    """
    @brief Main entry point for the application
    @details Supports both GUI and CLI modes based on command line arguments.
    
    Usage:
    - GUI mode (default): python RSA_generation.py
    - CLI mode: python RSA_generation.py --cli
    """
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        create_rsa_keys()
    else:
        app = QApplication(sys.argv)
        window = RSAKeyGeneratorGUI()
        window.show()
        sys.exit(app.exec_())
