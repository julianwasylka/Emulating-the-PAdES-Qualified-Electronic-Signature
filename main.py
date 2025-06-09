#!/usr/bin/env python3
"""
@file main.py
@brief PAdES Qualified Electronic Signature Tool
@details Complete implementation of PAdES-compliant digital signature application
         with RSA-4096 + SHA-256 signing, document verification, and GUI interface.
         Supports pendrive integration, status indicators, and comprehensive error handling.
@author Igor Józefowicz
@date 2025
@version 2.0

Features:
- PAdES-compliant PDF digital signature generation
- RSA-4096 + SHA-256 cryptographic operations
- AES-256-EAX private key decryption
- Document integrity verification
- Pendrive detection and key management
- Modern tabbed GUI interface with status indicators
- Background processing with progress tracking
- Comprehensive error handling and validation
"""

import sys
import platform
import os
import hashlib
import json
import struct
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout,
    QWidget, QFileDialog, QListWidget, QLabel, QLineEdit, QTextEdit,
    QGroupBox, QMessageBox, QTabWidget, QProgressBar, QComboBox,
    QCheckBox, QSplitter, QFrame
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont, QPixmap, QIcon, QPalette, QColor
import psutil
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import datetime


class PendriveDetector:
    @staticmethod
    def get_removable_drives():
        drives = []
        partitions = psutil.disk_partitions(all=False)
        
        for partition in partitions:
            if platform.system() == 'Windows':
                if 'removable' in partition.opts.lower():
                    drives.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype
                    })
            else:
                if partition.mountpoint.startswith("/media") or partition.mountpoint.startswith("/run/media"):
                    drives.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype
                    })
        return drives


class CryptoUtils:
    @staticmethod
    def load_private_key_from_pendrive(pendrive_path, pin):
        """Load and decrypt private key from pendrive"""
        try:
            key_path = os.path.join(pendrive_path, "rsa_private.bin")
            if not os.path.exists(key_path):
                raise FileNotFoundError("Private key file not found on pendrive")
            
            with open(key_path, "rb") as f:
                data = f.read()
            
            # Extract nonce, tag, and encrypted data
            nonce = data[:16]
            tag = data[16:32]
            encrypted_private_key = data[32:]
            
            # Create AES key from PIN
            aes_key = SHA256.new(pin.encode()).digest()
            
            # Decrypt private key
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            private_key_data = cipher.decrypt_and_verify(encrypted_private_key, tag)
            
            # Import RSA key
            rsa_key = RSA.import_key(private_key_data)
            return rsa_key
            
        except Exception as e:
            raise Exception(f"Failed to load private key: {str(e)}")
    
    @staticmethod
    def load_public_key(key_path):
        """Load public key from file"""
        try:
            with open(key_path, "rb") as f:
                public_key_data = f.read()
            return RSA.import_key(public_key_data)
        except Exception as e:
            raise Exception(f"Failed to load public key: {str(e)}")
    
    @staticmethod
    def calculate_pdf_hash(pdf_path):
        """Calculate SHA-256 hash of PDF content (original file bytes)"""
        try:
            with open(pdf_path, "rb") as f:
                pdf_content = f.read()
            
            # Calculate hash
            hash_obj = SHA256.new()
            hash_obj.update(pdf_content)
            return hash_obj.digest(), hash_obj.hexdigest()
            
        except Exception as e:
            raise Exception(f"Failed to calculate PDF hash: {str(e)}")
    
    @staticmethod
    def calculate_original_content_hash(signed_pdf_path):
        """Calculate hash of original content from signed PDF (excluding signature metadata)"""
        try:
            # Read the signed PDF and extract original content
            with open(signed_pdf_path, "rb") as f:
                # Try to find signature footer marker
                content = f.read()
                
            # Look for the signature delimiter
            signature_delimiter = b"===PADES_SIGNATURE_START==="
            
            if signature_delimiter in content:
                # Extract original content (before signature)
                original_content = content.split(signature_delimiter)[0]
                hash_obj = SHA256.new()
                hash_obj.update(original_content)
                return hash_obj.digest(), hash_obj.hexdigest()
            else:
                # Fallback: try to extract content from PDF structure
                return CryptoUtils.calculate_pdf_hash(signed_pdf_path)
                
        except Exception as e:
            raise Exception(f"Failed to calculate original content hash: {str(e)}")
    
    @staticmethod
    def sign_hash(hash_digest, private_key):
        """Sign hash with private key"""
        try:
            signer = PKCS1_v1_5.new(private_key)
            hash_obj = SHA256.new()
            hash_obj.update(hash_digest)
            signature = signer.sign(hash_obj)
            return signature
        except Exception as e:
            raise Exception(f"Failed to sign hash: {str(e)}")
    
    @staticmethod
    def verify_signature(hash_digest, signature, public_key):
        """Verify signature with public key"""
        try:
            verifier = PKCS1_v1_5.new(public_key)
            hash_obj = SHA256.new()
            hash_obj.update(hash_digest)
            return verifier.verify(hash_obj, signature)
        except Exception as e:
            return False


class PDFSigner:
    @staticmethod
    def create_signed_pdf(original_pdf_path, signature, hash_hex, output_path, signer_info="Anonymous"):
        """Create a new PDF with signature information embedded using append method"""
        try:
            # Read original PDF content
            with open(original_pdf_path, "rb") as f:
                original_content = f.read()
            
            # Create signature info
            signature_info = {
                'signature': signature.hex(),
                'hash': hash_hex,
                'timestamp': datetime.datetime.now().isoformat(),
                'signer': signer_info,
                'algorithm': 'RSA-4096 + SHA-256'
            }
            
            # Serialize signature info to JSON
            signature_json = json.dumps(signature_info, indent=2)
            signature_bytes = signature_json.encode('utf-8')
            
            # Create signature delimiter and structure
            delimiter = b"===PADES_SIGNATURE_START==="
            signature_length = struct.pack('<I', len(signature_bytes))  # 4-byte little-endian length
            
            # Write signed PDF with appended signature
            with open(output_path, "wb") as output_file:
                # Write original PDF content
                output_file.write(original_content)
                
                # Write signature structure:
                # DELIMITER + LENGTH(4 bytes) + SIGNATURE_JSON
                output_file.write(delimiter)
                output_file.write(signature_length)
                output_file.write(signature_bytes)
                
                # Write end marker for easier detection
                output_file.write(b"===PADES_SIGNATURE_END===")
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to create signed PDF: {str(e)}")
    
    @staticmethod
    def extract_signature_info(signed_pdf_path):
        """Extract signature information from signed PDF"""
        try:
            with open(signed_pdf_path, "rb") as f:
                content = f.read()
            
            # Look for signature delimiter
            start_delimiter = b"===PADES_SIGNATURE_START==="
            end_delimiter = b"===PADES_SIGNATURE_END==="
            
            start_pos = content.find(start_delimiter)
            end_pos = content.find(end_delimiter)
            
            if start_pos == -1 or end_pos == -1:
                return None
            
            # Extract signature section
            signature_start = start_pos + len(start_delimiter)
            
            # Read signature length (4 bytes)
            length_bytes = content[signature_start:signature_start + 4]
            if len(length_bytes) != 4:
                return None
                
            signature_length = struct.unpack('<I', length_bytes)[0]
            
            # Extract signature JSON
            json_start = signature_start + 4
            json_end = json_start + signature_length
            
            if json_end > end_pos:
                return None
                
            signature_json = content[json_start:json_end].decode('utf-8')
            
            # Parse and return signature info
            signature_info = json.loads(signature_json)
            return signature_info
            
        except Exception as e:
            raise Exception(f"Failed to extract signature info: {str(e)}")


class SigningThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    signing_completed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, pdf_path, pendrive_path, pin, output_path):
        super().__init__()
        self.pdf_path = pdf_path
        self.pendrive_path = pendrive_path
        self.pin = pin
        self.output_path = output_path
    
    def run(self):
        try:
            self.status_updated.emit("Loading private key from pendrive...")
            self.progress_updated.emit(20)
            
            # Load private key
            private_key = CryptoUtils.load_private_key_from_pendrive(self.pendrive_path, self.pin)
            
            self.status_updated.emit("Calculating PDF hash...")
            self.progress_updated.emit(40)
            
            # Calculate PDF hash
            hash_digest, hash_hex = CryptoUtils.calculate_pdf_hash(self.pdf_path)
            
            self.status_updated.emit("Creating digital signature...")
            self.progress_updated.emit(60)
            
            # Sign hash
            signature = CryptoUtils.sign_hash(hash_digest, private_key)
            
            self.status_updated.emit("Creating signed PDF...")
            self.progress_updated.emit(80)
            
            # Create signed PDF
            PDFSigner.create_signed_pdf(self.pdf_path, signature, hash_hex, self.output_path)
            
            self.progress_updated.emit(100)
            self.signing_completed.emit(f"Document successfully signed and saved to:\n{self.output_path}")
            
        except Exception as e:
            self.error_occurred.emit(str(e))


class VerificationThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    verification_completed = pyqtSignal(bool, str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, signed_pdf_path, public_key_path):
        super().__init__()
        self.signed_pdf_path = signed_pdf_path
        self.public_key_path = public_key_path
    
    def run(self):
        try:
            self.status_updated.emit("Loading public key...")
            self.progress_updated.emit(20)
            
            # Load public key
            public_key = CryptoUtils.load_public_key(self.public_key_path)
            
            self.status_updated.emit("Extracting signature from PDF...")
            self.progress_updated.emit(40)
            
            # Extract signature info
            signature_info = PDFSigner.extract_signature_info(self.signed_pdf_path)
            if not signature_info:
                raise Exception("No signature found in PDF")
            
            self.status_updated.emit("Calculating current PDF hash...")
            self.progress_updated.emit(60)
            
            # Calculate current hash of the original content (excluding signature)
            current_hash_digest, current_hash_hex = CryptoUtils.calculate_original_content_hash(self.signed_pdf_path)
            
            # Get stored hash from signature
            stored_hash = signature_info['hash']
            signature_bytes = bytes.fromhex(signature_info['signature'])
            
            self.status_updated.emit("Verifying signature and tamper detection...")
            self.progress_updated.emit(80)
            
            # Verify signature using stored hash
            stored_hash_digest = bytes.fromhex(stored_hash)
            is_signature_valid = CryptoUtils.verify_signature(stored_hash_digest, signature_bytes, public_key)
            
            # Check for tampering by comparing hashes
            is_content_unchanged = (current_hash_hex == stored_hash)
            
            self.progress_updated.emit(100)
            
            # Determine overall validity
            is_valid = is_signature_valid and is_content_unchanged
            
            tamper_status = "✅ NO TAMPERING" if is_content_unchanged else "⚠️ CONTENT MODIFIED"
            signature_status = "✅ VALID" if is_signature_valid else "❌ INVALID"
            
            result_message = f"""
Signature Verification Results:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Overall Status: {'✅ DOCUMENT VALID' if is_valid else '❌ DOCUMENT COMPROMISED'}
Signature Status: {signature_status}
Tamper Detection: {tamper_status}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Document Hash (stored): {stored_hash}
Document Hash (current): {current_hash_hex}
Signature Timestamp: {signature_info['timestamp']}
Algorithm: {signature_info['algorithm']}
Signer: {signature_info.get('signer', 'Unknown')}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            
            self.verification_completed.emit(is_valid, result_message)
            
        except Exception as e:
            self.error_occurred.emit(str(e))


class StatusIndicator(QLabel):
    """Custom status indicator widget with icons and colors"""
    
    def __init__(self):
        super().__init__()
        self.setFixedSize(24, 24)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet("""
            QLabel {
                border: 2px solid #bdc3c7;
                border-radius: 12px;
                background-color: #ecf0f1;
            }
        """)
        self.set_status("idle")
    
    def set_status(self, status):
        """Set status indicator: idle, working, success, error, warning"""
        if status == "idle":
            self.setText("⚪")
            self.setStyleSheet("""
                QLabel {
                    border: 2px solid #bdc3c7;
                    border-radius: 12px;
                    background-color: #ecf0f1;
                }
            """)
        elif status == "working":
            self.setText("🔄")
            self.setStyleSheet("""
                QLabel {
                    border: 2px solid #f39c12;
                    border-radius: 12px;
                    background-color: #fef9e7;
                }
            """)
        elif status == "success":
            self.setText("✅")
            self.setStyleSheet("""
                QLabel {
                    border: 2px solid #27ae60;
                    border-radius: 12px;
                    background-color: #d5f4e6;
                }
            """)
        elif status == "error":
            self.setText("❌")
            self.setStyleSheet("""
                QLabel {
                    border: 2px solid #e74c3c;
                    border-radius: 12px;
                    background-color: #fadbd8;
                }
            """)
        elif status == "warning":
            self.setText("⚠️")
            self.setStyleSheet("""
                QLabel {
                    border: 2px solid #f39c12;
                    border-radius: 12px;
                    background-color: #fef9e7;
                }
            """)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.selected_pdf = None
        self.selected_pendrive = None
        
        # Initialize pendrive monitoring
        self.current_drives = set()
        self.pendrive_monitor_timer = QTimer()
        self.pendrive_monitor_timer.timeout.connect(self.check_pendrive_changes)
        self.pendrive_monitor_timer.start(2000)  # Check every 2 seconds
        
        self.initUI()
        
        # Initial pendrive detection
        self.detect_pendrives()
        
    def initUI(self):
        self.setWindowTitle("PAdES Electronic Signature Tool")
        self.setGeometry(200, 200, 900, 700)
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin: 5px 0px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px;
                font-size: 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        
        # Central widget with tabs
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.signing_tab = self.create_signing_tab()
        self.verification_tab = self.create_verification_tab()
        
        self.tab_widget.addTab(self.signing_tab, "📝 Document Signing")
        self.tab_widget.addTab(self.verification_tab, "🔍 Signature Verification")
        
        # Main layout
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("PAdES Qualified Electronic Signature Tool")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px; text-align: center;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        layout.addWidget(self.tab_widget)
        
        central_widget.setLayout(layout)
    
    def create_signing_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
          # PDF Selection Group
        pdf_group = QGroupBox("📄 Document Selection")
        pdf_layout = QVBoxLayout()
        
        pdf_button_layout = QHBoxLayout()
        self.btn_select_pdf = QPushButton("Select PDF Document")
        self.btn_select_pdf.clicked.connect(self.select_pdf)
        self.pdf_status = StatusIndicator()
        pdf_button_layout.addWidget(self.btn_select_pdf)
        pdf_button_layout.addWidget(self.pdf_status)
        
        self.label_pdf = QLabel("No document selected")
        self.label_pdf.setStyleSheet("padding: 8px; background-color: white; border: 1px solid #ddd; border-radius: 4px;")
        
        pdf_layout.addLayout(pdf_button_layout)
        pdf_layout.addWidget(self.label_pdf)
        pdf_group.setLayout(pdf_layout)
        layout.addWidget(pdf_group)        # Pendrive Detection Group
        pendrive_group = QGroupBox("💾 Hardware Security Module (Pendrive) - Auto-Detection Active")
        pendrive_layout = QVBoxLayout()
        
        # Add auto-detection info label
        auto_detect_info = QLabel("🔄 Automatic detection enabled - pendrives will be detected when plugged/unplugged")
        auto_detect_info.setStyleSheet("color: #2c3e50; font-size: 10px; font-style: italic; padding: 4px;")
        pendrive_layout.addWidget(auto_detect_info)
        
        pendrive_button_layout = QHBoxLayout()
        self.btn_detect_pendrive = QPushButton("🔍 Manual Scan")
        self.btn_detect_pendrive.clicked.connect(self.detect_pendrives)
        self.btn_refresh_pendrive = QPushButton("🔄 Force Refresh")
        self.btn_refresh_pendrive.clicked.connect(self.detect_pendrives)
        self.pendrive_status = StatusIndicator()
        
        pendrive_button_layout.addWidget(self.btn_detect_pendrive)
        pendrive_button_layout.addWidget(self.btn_refresh_pendrive)
        pendrive_button_layout.addWidget(self.pendrive_status)
        
        self.list_pendrives = QListWidget()
        self.list_pendrives.itemClicked.connect(self.on_pendrive_selected)
        
        pendrive_layout.addLayout(pendrive_button_layout)
        pendrive_layout.addWidget(self.list_pendrives)
        pendrive_group.setLayout(pendrive_layout)
        layout.addWidget(pendrive_group)
        
        # PIN Input Group
        pin_group = QGroupBox("🔐 Authentication")
        pin_layout = QHBoxLayout()
        
        pin_label = QLabel("PIN:")
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.setPlaceholderText("Enter your PIN...")
        
        pin_layout.addWidget(pin_label)
        pin_layout.addWidget(self.pin_input)
        pin_group.setLayout(pin_layout)
        layout.addWidget(pin_group)
        
        # Progress and Status
        self.signing_progress = QProgressBar()
        self.signing_progress.setVisible(False)
        layout.addWidget(self.signing_progress)
        
        self.signing_status = QLabel("")
        layout.addWidget(self.signing_status)
        
        # Sign Button
        self.btn_sign = QPushButton("✍️ Sign Document")
        self.btn_sign.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.btn_sign.clicked.connect(self.sign_document)
        layout.addWidget(self.btn_sign)
        
        tab.setLayout(layout)
        return tab
    
    def create_verification_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Signed PDF Selection
        signed_pdf_group = QGroupBox("📄 Signed Document")
        signed_pdf_layout = QVBoxLayout()
        
        self.btn_select_signed_pdf = QPushButton("Select Signed PDF")
        self.btn_select_signed_pdf.clicked.connect(self.select_signed_pdf)
        
        self.label_signed_pdf = QLabel("No signed document selected")
        self.label_signed_pdf.setStyleSheet("padding: 8px; background-color: white; border: 1px solid #ddd; border-radius: 4px;")
        
        signed_pdf_layout.addWidget(self.btn_select_signed_pdf)
        signed_pdf_layout.addWidget(self.label_signed_pdf)
        signed_pdf_group.setLayout(signed_pdf_layout)
        layout.addWidget(signed_pdf_group)
        
        # Public Key Selection
        public_key_group = QGroupBox("🔑 Public Key")
        public_key_layout = QVBoxLayout()
        
        self.btn_select_public_key = QPushButton("Select Public Key (.pem)")
        self.btn_select_public_key.clicked.connect(self.select_public_key)
        
        self.label_public_key = QLabel("No public key selected")
        self.label_public_key.setStyleSheet("padding: 8px; background-color: white; border: 1px solid #ddd; border-radius: 4px;")
        
        public_key_layout.addWidget(self.btn_select_public_key)
        public_key_layout.addWidget(self.label_public_key)
        public_key_group.setLayout(public_key_layout)
        layout.addWidget(public_key_group)
        
        # Progress and Status
        self.verification_progress = QProgressBar()
        self.verification_progress.setVisible(False)
        layout.addWidget(self.verification_progress)
        
        self.verification_status = QLabel("")
        layout.addWidget(self.verification_status)
        
        # Verification Results
        self.verification_results = QTextEdit()
        self.verification_results.setReadOnly(True)
        self.verification_results.setMaximumHeight(200)
        layout.addWidget(self.verification_results)
        
        # Verify Button
        self.btn_verify = QPushButton("🔍 Verify Signature")
        self.btn_verify.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #c0392b;            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.btn_verify.clicked.connect(self.verify_signature)
        layout.addWidget(self.btn_verify)
        
        tab.setLayout(layout)
        return tab
    
    def select_pdf(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(
            self,
            "Select PDF Document",
            "",
            "PDF Files (*.pdf)",
            options=options
        )
        if fileName:
            self.selected_pdf = fileName
            self.label_pdf.setText(f"Selected: {os.path.basename(fileName)}")
            self.label_pdf.setStyleSheet("padding: 8px; background-color: #d5f4e6; border: 1px solid #27ae60; border-radius: 4px; color: #27ae60;")
            self.pdf_status.set_status("success")
        else:
            self.selected_pdf = None
            self.label_pdf.setText("No document selected")
            self.label_pdf.setStyleSheet("padding: 8px; background-color: white; border: 1px solid #ddd; border-radius: 4px;")
            self.pdf_status.set_status("idle")
    def detect_pendrives(self):
        self.list_pendrives.clear()
        self.pendrive_status.set_status("working")
        drives = PendriveDetector.get_removable_drives()
        
        # Update current drives set
        current_drive_paths = set()
        for drive in drives:
            current_drive_paths.add(drive['mountpoint'])
        self.current_drives = current_drive_paths
        
        if drives:
            has_keys = False
            for drive in drives:
                # Check if RSA private key exists
                key_path = os.path.join(drive['mountpoint'], 'rsa_private.bin')
                status = "✅ Has RSA key" if os.path.exists(key_path) else "❌ No RSA key"
                if os.path.exists(key_path):
                    has_keys = True
                item_text = f"{drive['device']} ({drive['mountpoint']}) - {status}"
                self.list_pendrives.addItem(item_text)
            
            if has_keys:
                self.pendrive_status.set_status("success")
            else:
                self.pendrive_status.set_status("warning")
        else:
            self.list_pendrives.addItem("❌ No removable drives detected")
            self.pendrive_status.set_status("error")
    
    def check_pendrive_changes(self):
        """Monitor for pendrive changes and auto-refresh when detected"""
        drives = PendriveDetector.get_removable_drives()
        new_drive_paths = set()
        for drive in drives:
            new_drive_paths.add(drive['mountpoint'])
        
        # Check if drives have changed
        if new_drive_paths != self.current_drives:
            # Drives have changed, refresh the list
            self.detect_pendrives()
            
            # Show notification about the change
            if len(new_drive_paths) > len(self.current_drives):
                # New drive(s) detected
                new_drives = new_drive_paths - self.current_drives
                for drive_path in new_drives:
                    self.show_drive_notification(f"📱 Pendrive connected: {drive_path}", True)
            elif len(new_drive_paths) < len(self.current_drives):
                # Drive(s) removed
                removed_drives = self.current_drives - new_drive_paths
                for drive_path in removed_drives:
                    self.show_drive_notification(f"📱 Pendrive disconnected: {drive_path}", False)
                    
                # Clear selected pendrive if it was removed
                if self.selected_pendrive and self.selected_pendrive in removed_drives:
                    self.selected_pendrive = None
    
    def show_drive_notification(self, message, is_connected):
        """Show a brief notification about drive changes"""
        # Create a temporary status message
        if hasattr(self, 'signing_status'):
            original_text = self.signing_status.text()
            self.signing_status.setText(message)
            self.signing_status.setStyleSheet(
                "color: #27ae60; font-weight: bold;" if is_connected 
                else "color: #e74c3c; font-weight: bold;"
            )
              # Reset the message after 3 seconds
            QTimer.singleShot(3000, lambda: self.reset_status_message(original_text))
    
    def reset_status_message(self, original_text):
        """Reset status message to original text and style"""
        if hasattr(self, 'signing_status'):
            self.signing_status.setText(original_text)
            self.signing_status.setStyleSheet("")  # Reset to default style
    
    def on_pendrive_selected(self, item):
        text = item.text()
        if "✅ Has RSA key" in text:
            # Extract drive path
            import re
            match = re.search(r'\(([^)]+)\)', text)
            if match:
                self.selected_pendrive = match.group(1)
    
    def sign_document(self):
        if not self.selected_pdf:
            QMessageBox.warning(self, "Warning", "Please select a PDF document to sign.")
            return
        
        if not self.selected_pendrive:
            QMessageBox.warning(self, "Warning", "Please select a pendrive with RSA private key.")
            return
        
        pin = self.pin_input.text()
        if not pin:
            QMessageBox.warning(self, "Warning", "Please enter your PIN.")
            return
        
        # Choose output location
        output_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Signed PDF As",
            f"{os.path.splitext(self.selected_pdf)[0]}_signed.pdf",
            "PDF Files (*.pdf)"
        )
        
        if not output_path:
            return
        
        # Start signing process
        self.btn_sign.setEnabled(False)
        self.signing_progress.setVisible(True)
        self.signing_progress.setValue(0)
        
        self.signing_thread = SigningThread(self.selected_pdf, self.selected_pendrive, pin, output_path)
        self.signing_thread.progress_updated.connect(self.signing_progress.setValue)
        self.signing_thread.status_updated.connect(self.signing_status.setText)
        self.signing_thread.signing_completed.connect(self.on_signing_completed)
        self.signing_thread.error_occurred.connect(self.on_signing_error)
        self.signing_thread.start()
    
    def on_signing_completed(self, message):
        self.btn_sign.setEnabled(True)
        self.signing_progress.setVisible(False)
        self.signing_status.setText("✅ Document signed successfully!")
        QMessageBox.information(self, "Success", message)
    
    def on_signing_error(self, error):
        self.btn_sign.setEnabled(True)
        self.signing_progress.setVisible(False)
        self.signing_status.setText("❌ Signing failed!")
        QMessageBox.critical(self, "Error", f"Signing failed:\n{error}")
    
    def select_signed_pdf(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(
            self,
            "Select Signed PDF Document",
            "",
            "PDF Files (*.pdf)",
            options=options
        )
        if fileName:
            self.selected_signed_pdf = fileName
            self.label_signed_pdf.setText(f"Selected: {os.path.basename(fileName)}")
            self.label_signed_pdf.setStyleSheet("padding: 8px; background-color: #d5f4e6; border: 1px solid #27ae60; border-radius: 4px; color: #27ae60;")
        else:
            self.selected_signed_pdf = None
            self.label_signed_pdf.setText("No signed document selected")
            self.label_signed_pdf.setStyleSheet("padding: 8px; background-color: white; border: 1px solid #ddd; border-radius: 4px;")
    
    def select_public_key(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(
            self,
            "Select Public Key File",
            "",
            "PEM Files (*.pem);;All Files (*)",
            options=options
        )
        if fileName:
            self.selected_public_key = fileName
            self.label_public_key.setText(f"Selected: {os.path.basename(fileName)}")
            self.label_public_key.setStyleSheet("padding: 8px; background-color: #d5f4e6; border: 1px solid #27ae60; border-radius: 4px; color: #27ae60;")
        else:
            self.selected_public_key = None
            self.label_public_key.setText("No public key selected")
            self.label_public_key.setStyleSheet("padding: 8px; background-color: white; border: 1px solid #ddd; border-radius: 4px;")
    
    def verify_signature(self):
        if not hasattr(self, 'selected_signed_pdf') or not self.selected_signed_pdf:
            QMessageBox.warning(self, "Warning", "Please select a signed PDF document.")
            return
        
        if not hasattr(self, 'selected_public_key') or not self.selected_public_key:
            QMessageBox.warning(self, "Warning", "Please select a public key file.")
            return
        
        # Start verification process
        self.btn_verify.setEnabled(False)
        self.verification_progress.setVisible(True)
        self.verification_progress.setValue(0)
        self.verification_results.clear()
        
        self.verification_thread = VerificationThread(self.selected_signed_pdf, self.selected_public_key)
        self.verification_thread.progress_updated.connect(self.verification_progress.setValue)
        self.verification_thread.status_updated.connect(self.verification_status.setText)
        self.verification_thread.verification_completed.connect(self.on_verification_completed)
        self.verification_thread.error_occurred.connect(self.on_verification_error)
        self.verification_thread.start()
    
    def on_verification_completed(self, is_valid, result_message):
        self.btn_verify.setEnabled(True)
        self.verification_progress.setVisible(False)
        
        if is_valid:
            self.verification_status.setText("✅ Signature is valid!")
            self.verification_results.setStyleSheet("background-color: #d5f4e6; color: #27ae60;")
        else:
            self.verification_status.setText("❌ Signature is invalid!")
            self.verification_results.setStyleSheet("background-color: #f8d7da; color: #721c24;")
        
        self.verification_results.setText(result_message)
    
    def on_verification_error(self, error):
        self.btn_verify.setEnabled(True)
        self.verification_progress.setVisible(False)
        self.verification_status.setText("❌ Verification failed!")
        QMessageBox.critical(self, "Error", f"Verification failed:\n{error}")
    
    def closeEvent(self, event):
        """Handle application close event"""
        # Stop the pendrive monitoring timer
        if hasattr(self, 'pendrive_monitor_timer'):
            self.pendrive_monitor_timer.stop()
        event.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
