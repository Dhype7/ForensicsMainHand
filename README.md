# ForensicsMainHand 🔍

> **Credit:** Project by Dhype7 (NYX team)

A comprehensive digital forensics toolkit with a modern GUI, designed for image, file, and cryptography analysis. Built for CTFs, security research, and forensic investigations.

---

## 📥 How to Download, Install, and Run

### 1. Download
Clone the repository:
```bash
git clone https://github.com/YOUR-USERNAME/YOUR-PRIVATE-REPO.git
cd ForensicsMainHand
```

### 2. Install (Recommended)
Run the provided installation script to install **all system tools and Python libraries**:
```bash
chmod +x install.sh
sudo ./install.sh
```
This will install all dependencies: Python libraries, tesseract-ocr, steghide, exiftool, binwalk, zsteg (Ruby gem), hashcat, hash-identifier/hashid, and more.

### 3. Run
```bash
sudo python3 main.py
```

---

## 🌟 Features

### 🖼️ Photo Analyzer
- **EXIF Data Extraction**: Device info, timestamps, GPS
- **Location Analysis**: Reverse geocoding of coordinates
- **Metadata Analysis**: Deep metadata with ExifTool
- **String Extraction**: Find readable strings in files
- **Binwalk Integration**: Hidden file and binary analysis
- **Steghide Integration**: Hide/extract data in images
- **OCR**: Extract text from images (Tesseract)
- **QR/Barcode Analysis**: Decode embedded codes
- **File Carving**: Recover embedded files
- **Hex Viewer**: Inspect file bytes visually

### 🔐 Cryptography Module
- **Classical Ciphers**: Affine, Atbash, Bacon, Caesar, Playfair, Rail Fence, Rot13, Scytale, Substitution, Vigenère, XOR, Binary, and more (encrypt/decrypt, file input/output, parameter presets)
- **Advanced Crypto**: RSA, AES, Blowfish, DES, RC4, OTP, Base64/32/16, SHA-256, MD5, HMAC, Substitution, Playfair, Rail Fence, XOR, and more
- **Magic Hasher**: Identify hash types (hash-identifier/hashid) and crack hashes with hashcat from the GUI
- **Modern UI**: Split view for classical/advanced crypto, user-friendly grid, back navigation
- **File Import/Export**: Work with text or files
- **Dynamic Parameters**: Only relevant options shown
- **Status Bar**: Real-time feedback and error handling

### 📁 File Analyzer
- **File Carving**: Recover files from binary blobs
- **String Analysis**: Extract readable strings
- **Binary Analysis**: Inspect file structure
- **Format Detection**: Identify file types

### 🎨 Modern GUI
- **Dark/Light Theme**: Professional, switchable
- **Intuitive Layout**: User-friendly, clear sections
- **Real-time Results**: Instant feedback
- **File Browser**: Easy file selection
- **Accessibility**: Clear fonts, good contrast

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- Kali Linux (recommended) or any Linux distribution
- **Required system tools:**
  - `tesseract-ocr`, `steghide`, `exiftool`, `binwalk`, `zsteg` (Ruby gem), `hashcat`, `hash-identifier` (or `hashid`), `ruby-full` (for zsteg)

### Install All Dependencies (Recommended)
```bash
chmod +x install.sh
sudo ./install.sh
```

### Manual Installation (Not Recommended)
You must install all system tools and Python libraries yourself. See `install.sh` for the full list.

## 📖 Usage

### Basic Usage
```bash
sudo python3 main.py
```

### Features Guide

#### 1. Image Selection
- Click "Select Image" to browse and load an image
- Or enter the file path directly in the text field

#### 2. EXIF Analysis
- **Simple Data**: Extract basic EXIF information
- **Location**: Extract GPS coordinates and address information

#### 3. Steganography
- **Inject Text**: Hide text messages in images
- **Inject File**: Hide files within images
- **Extract**: Extract hidden data from images

#### 4. Advanced Analysis
- **Detail ExifTool**: Comprehensive metadata analysis
- **Show All Strings**: Extract readable strings from files
- **Binwalk**: Advanced file analysis and hidden file extraction

#### 5. Cryptography
- **Classical/Advanced Split**: Choose between classical and advanced crypto
- **Magic Hasher**: Identify hash types and crack hashes with hashcat from the GUI

## 🛠️ System Requirements

### Required System Tools
- **tesseract-ocr**: OCR engine
- **steghide**: Steganography tool for hiding data in images
- **exiftool**: Metadata extraction and manipulation
- **binwalk**: Binary analysis and hidden file extraction
- **zsteg**: PNG/BMP steganography analysis (Ruby gem)
- **hashcat**: Password/hash cracking
- **hash-identifier** or **hashid**: Hash type identification
- **ruby-full**: Required for zsteg

### Python Dependencies
- See `requirements.txt` for the full list (includes Pillow, geopy, tkinter-tooltip, cryptography, pycryptodome, numpy, opencv-python, matplotlib, scikit-image, pytesseract, pypng, pyzbar, qrcode, stegano, exifread, etc.)

## 🔧 Configuration

### Kali Linux Specific
The tool is optimized for Kali Linux and includes:
- Automatic tool detection
- Proper file permissions handling
- Integration with Kali's security tools

### Customization
You can customize the interface by modifying:
- Color schemes in `src/ui/theme.py`
- Tool configurations in `src/config/settings.py`
- Analysis parameters in respective modules

## 📁 Project Structure

```
ForensicsMainHand/
├── main.py                      # Main application entry point
├── requirements.txt             # Python dependencies
├── install.sh                   # Installation script
├── README.md                    # This file
├── LICENSE                      # License information
└── src/
    ├── __init__.py
    ├── config/
    │   ├── __init__.py
    │   └── settings.py          # Application settings
    ├── core/
    │   ├── exif_analyzer.py     # EXIF data analysis
    │   ├── location_analyzer.py # GPS and location analysis
    │   ├── string_analyzer.py   # String extraction
    │   └── zsteg_analyzer.py    # Zsteg analysis
    ├── forensics_main.py        # Main forensics application
    ├── forensics_toolkit.py     # Forensics toolkit
    ├── modules/
    │   ├── __init__.py
    │   ├── cryptography/
    │   │   ├── __init__.py
    │   │   ├── advanced_crypto.py      # Advanced cryptography module
    │   │   ├── classical_ciphers.py    # Classical ciphers
    │   │   ├── classical_crypto_gui.py # Classical crypto GUI
    │   │   └── crypto_main.py          # Main crypto application
    │   ├── file_analyzer/
    │   │   ├── __init__.py
    │   │   └── file_main.py            # File analyzer module
    │   └── photo_analyzer/
    │       ├── __init__.py
    │       ├── binwalk_analyzer.py     # Binwalk analysis
    │       ├── crypto_analyzer.py      # Crypto analysis
    │       ├── exif_analyzer.py        # EXIF analysis
    │       ├── file_carving_analyzer.py # File carving
    │       ├── file_utils.py           # File utilities
    │       ├── hex_viewer.py           # Hex viewer
    │       ├── location_analyzer.py    # Location analysis
    │       ├── main_window.py          # Photo analyzer main window
    │       ├── metadata_analyzer.py    # Metadata analysis
    │       ├── ocr_analyzer.py         # OCR analysis
    │       ├── qr_barcode_analyzer.py  # QR/Barcode analysis
    │       ├── settings.py             # Settings
    │       ├── steganography.py        # Steganography
    │       ├── string_analyzer.py      # String analysis
    │       ├── theme.py                # Theme configuration
    │       ├── validation.py           # Validation utilities
    │       ├── widgets.py              # Custom widgets
    │       └── zsteg_analyzer.py       # Zsteg analysis
    ├── ui/
    │   ├── __init__.py
    │   ├── theme.py                    # UI theme configuration
    │   └── widgets.py                  # Custom widgets
    └── utils/
        ├── __init__.py
        ├── file_utils.py               # File handling utilities
        └── validation.py               # Input validation
```

## 🎯 Use Cases

### Digital Forensics
- Extract metadata from evidence images
- Analyze GPS coordinates for location tracking
- Detect hidden data in suspicious files

### CTF Challenges
- Solve steganography, cryptography, and hash cracking challenges
- Use Magic Hasher for hash identification and automated cracking

## ⚠️ Troubleshooting
- If `hashcat` or `hash-identifier` are not found, ensure they are installed and in your PATH. On some systems, you may need to install `hashid` via pip as a fallback.
- For `zsteg`, ensure Ruby and the `zsteg` gem are installed.
- If you encounter missing Python modules, re-run `install.sh` or manually install from `requirements.txt`.

---

For more information, see the code and comments, or open an issue.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for educational and legitimate security analysis purposes only. Users are responsible for ensuring they have proper authorization before analyzing any files or images.

## 📞 Support

For support, please open an issue on GitHub or contact the development team. 