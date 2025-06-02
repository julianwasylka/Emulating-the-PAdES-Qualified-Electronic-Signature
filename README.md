# 🔐 PAdES Qualified Electronic Signature Tool

A complete implementation of PAdES (PDF Advanced Electronic Signatures) qualified electronic signature tool with RSA-4096 encryption, AES-256 private key protection, and modern GUI interface.

## ✨ Project Status: COMPLETE ✅

**All requirements have been successfully implemented and tested:**
- ✅ RSA-4096 key generation with cryptographically secure random generator
- ✅ AES-256-EAX private key encryption with PIN-derived keys
- ✅ PAdES-compliant digital signature generation and verification
- ✅ Modern GUI interfaces for both applications
- ✅ Pendrive detection and hardware integration
- ✅ Comprehensive status indicators and error handling
- ✅ Complete documentation and testing infrastructure

## 🚀 Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Generate RSA keys:**
   ```bash
   python RSA_generation.py
   ```

3. **Sign and verify documents:**
   ```bash
   python pythonProject/main.py
   ```

## 🎯 Project Overview

This project implements a complete PAdES electronic signature solution consisting of two main applications:

1. **RSA Key Generator** (`RSA_generation.py`) - Auxiliary application for generating RSA key pairs
2. **PAdES Signature Tool** (`pythonProject/main.py`) - Main application for document signing and verification

## 🔧 Key Features

### RSA Key Generator
- ✅ **4096-bit RSA key generation** using cryptographically secure random number generator
- ✅ **AES-256 encryption** of private keys using PIN-derived keys (SHA-256)
- ✅ **Pendrive storage support** for secure key storage
- ✅ **Modern GUI interface** with progress tracking
- ✅ **Key validation** and security checks

### PAdES Signature Tool
- ✅ **PDF document signing** with RSA-4096 + SHA-256
- ✅ **Automatic pendrive detection** for hardware security modules
- ✅ **Digital signature verification** with public key validation
- ✅ **PAdES-compliant metadata embedding** in signed PDFs
- ✅ **Status indicators** for all operations
- ✅ **Tabbed interface** for signing and verification workflows

## 🛠️ Technical Specifications

- **Encryption**: RSA-4096 for digital signatures, AES-256-EAX for private key protection
- **Hash Algorithm**: SHA-256 for document integrity and PIN key derivation
- **File Format**: PAdES-compliant PDF with embedded signature metadata
- **Hardware Support**: USB pendrive detection and automatic key loading
- **GUI Framework**: PyQt5 with modern responsive design

## 🚀 Installation & Setup

### Prerequisites
- Python 3.7+ (tested with Python 3.13.2)
- USB pendrive for key storage

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Manual Installation
```bash
pip install pycryptodome PyQt5 psutil PyPDF2 reportlab
```

## 📖 Usage Guide

### 1. Generate RSA Keys
```bash
python RSA_generation.py
```
1. Launch the RSA Key Generator
2. Enter a secure PIN (minimum 4 characters)
3. Select output directory (preferably on pendrive)
4. Click "Generate RSA Key Pair"
5. Keys will be saved as:
   - `rsa_private.bin` (encrypted with your PIN)
   - `rsa_public.pem` (public key for verification)

### 2. Sign PDF Documents
```bash
cd pythonProject
python main.py
```
1. Open the main PAdES application
2. Go to "Document Signing" tab
3. Select PDF document to sign
4. Detect and select your pendrive with RSA keys
5. Enter your PIN
6. Choose output location for signed PDF
7. Click "Sign Document"

### 3. Verify Signatures
1. Go to "Signature Verification" tab
2. Select the signed PDF document
3. Select the corresponding public key file
4. Click "Verify Signature"
5. Review verification results

## 🔒 Security Features

- **PIN-based encryption**: Private keys encrypted with AES-256 using SHA-256(PIN)
- **Hardware isolation**: Private keys stored only on removable media
- **Signature integrity**: RSA-PKCS#1 v1.5 with SHA-256 hashing
- **Tamper detection**: Verification detects any document modifications
- **Metadata protection**: Signature information embedded in PDF structure

## 📁 Project Structure

```
├── RSA_generation.py          # RSA key generator (auxiliary app)
├── pythonProject/
│   └── main.py               # Main PAdES signing application
├── keys/                     # Generated key storage
│   ├── rsa_private.bin       # Encrypted private key
│   └── rsa_public.pem        # Public key
├── docs/                     # Project documentation
├── requirements.txt          # Python dependencies
└── README.md                # This file
```

## 🧪 Testing Scenarios

The application has been tested with the following scenarios:
- ✅ RSA key generation with various PIN lengths
- ✅ Document signing with different PDF sizes and formats
- ✅ Signature verification with valid signatures
- ✅ Tamper detection with modified documents
- ✅ Pendrive detection across different USB devices
- ✅ Error handling for invalid PINs and missing keys

## 📋 Requirements Compliance

This implementation fulfills all project requirements:
- [x] GUI interface for document selection and signing
- [x] RSA-4096 signature algorithm implementation
- [x] Pseudorandom number generator for key generation
- [x] AES-256 private key encryption with PIN-derived keys
- [x] Mandatory pendrive usage for private key storage
- [x] Automatic hardware detection and key loading
- [x] Public key storage and transfer capabilities
- [x] Status/message icons for application state indication
- [x] Single-user signing capability
- [x] External library usage (pycryptodome, PyQt5, etc.)
- [x] Comprehensive testing and validation
- [x] Code documentation and GitHub repository

## 🔗 Repository

GitHub Repository: [\[Emulating-the-PAdES-Qualified-Electronic-Signature\]](https://github.com/julianwasylka/Emulating-the-PAdES-Qualified-Electronic-Signature)
