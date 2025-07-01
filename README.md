# ForensicsMainHand 🔍

> **Credit:** Project by Dhype7 (NYX team)

A comprehensive digital forensics toolkit with a modern GUI, designed for image, file, and cryptography analysis. Built for CTFs, security research, and forensic investigations.

---

## 🚀 Quick Start

### 1. Download
```bash
git clone https://github.com/Dhype7/ForensicsMainHand.git
cd ForensicsMainHand
```

### 2. Install
```bash
sudo chmod +x install.sh run.sh
sudo ./install.sh
```
This automatically installs all dependencies and sets up the environment.

### 3. Run
```bash
./run.sh
```
Or use the desktop shortcut created during installation.

---

## 📥 Detailed Installation Guide

### Prerequisites
- **Operating System**: Kali Linux (recommended) or any Debian/Ubuntu-based Linux distribution
- **Python**: 3.8 or higher (automatically installed by the script)
- **Root Access**: Required for installing system tools

### Automatic Installation (Recommended)
The `install.sh` script handles everything automatically:

```bash
# 1. Make the script executable
chmod +x install.sh

# 2. Run the installation (requires sudo)
sudo ./install.sh
```

**What the installer does:**
- Updates package repositories
- Installs system tools: `tesseract-ocr`, `steghide`, `exiftool`, `binwalk`, `hashcat`, `zsteg`, `hash-identifier`
- Creates Python virtual environment
- Installs all Python dependencies from `requirements.txt`
- Sets up desktop shortcut
- Verifies all installations

### Manual Installation (Advanced Users)
If you prefer manual installation, you'll need to install:

**System Tools:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-tk python3-pil.imagetk tesseract-ocr steghide exiftool binwalk hashcat hash-identifier ruby-full
sudo gem install zsteg
```

**Python Dependencies:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🎯 How to Run

### Method 1: Using the Launcher Script (Recommended)
```bash
./run.sh
```
This script automatically:
- Activates the virtual environment
- Checks for required files
- Launches the application

### Method 2: Desktop Shortcut
After installation, a desktop shortcut is created. Simply double-click it to run.

### Method 3: Manual Launch
```bash
source venv/bin/activate
python main.py
```

### Method 4: Direct Python Execution
```bash
python3 main.py
```
To launch the web analyzer, run:
```bash
python main.py --web
```

*Note: This requires all dependencies to be installed system-wide.*

### 🌐 Web Analyzer (Flask Web App)

#### Prerequisites
- **Operating System**: Linux (Kali recommended), Ubuntu, Debian, or Windows with Python 3.8+
- **Python**: 3.8 or higher
- **pip**: Python package manager

#### Python Dependencies
The web analyzer requires the following Python packages (see `src/modules/web_analyzer_project/requirements.txt`):

```bash
flask
requests
python-whois
beautifulsoup4
dnspython
```

You can install them manually with:
```bash
pip install flask requests python-whois beautifulsoup4 dnspython
```

#### How to Run

To launch the web analyzer, run:
```bash
python main.py --web
```

- This will start a local web server (default: http://127.0.0.1:5000/)
- Open your browser and navigate to the address to use the web interface

#### Usage Notes
- The web analyzer is for educational and CTF use. Do not use brute force or scanning features on unauthorized targets.
- Some features (like brute force) are hardcoded for demo.testfire.net and may need adjustment for other sites.
- For best results, ensure all dependencies are installed and your firewall allows local connections.

---

## 🌟 Features

### 🖼️ Photo Analyzer
- **EXIF Data Extraction**: Device info, timestamps, GPS coordinates
- **Location Analysis**: Reverse geocoding with address lookup
- **Metadata Analysis**: Comprehensive metadata with ExifTool
- **String Extraction**: Find readable strings in files
- **Binwalk Integration**: Hidden file and binary analysis
- **Steghide Integration**: Hide/extract data in images
- **OCR**: Extract text from images using Tesseract
- **QR/Barcode Analysis**: Decode embedded QR codes and barcodes
- **File Carving**: Recover embedded files from binary data
- **Hex Viewer**: Visual byte-level file inspection

### 🔐 Cryptography Module
- **Classical Ciphers**: Affine, Atbash, Bacon, Caesar, Playfair, Rail Fence, Rot13, Scytale, Substitution, Vigenère, XOR, Binary, and more
- **Advanced Crypto**: RSA, AES, Blowfish, DES, RC4, OTP, Base64/32/16, SHA-256, MD5, HMAC
- **Magic Hasher**: Identify hash types and crack hashes with hashcat integration
- **Modern UI**: Split view for classical/advanced crypto, user-friendly interface
- **File Import/Export**: Work with text files or binary files
- **Dynamic Parameters**: Context-sensitive options
- **Real-time Feedback**: Status bar with progress and error handling

### 📁 File Analyzer
- **File Carving**: Recover files from binary blobs
- **String Analysis**: Extract readable strings with encoding detection
- **Binary Analysis**: Inspect file structure and headers
- **Format Detection**: Identify file types and signatures

### 🌐 Web Analyzer (Flask Web App)
- **HTTP Header Analysis**: View all HTTP headers for a given URL.
- **IP/Domain Resolver**: Resolve domains to IP addresses.
- **XSS Scanner**: Basic detection of reflected XSS vulnerabilities.
- **Port Scanner**: Scan common ports on a target domain.
- **Security Headers Check**: Check for missing or weak HTTP security headers.
- **Login Page Discovery**: Find login forms/pages on a target website.
- **Brute Force Login**: Attempt login brute force (for demo.testfire.net or similar forms).

### 🎨 Modern GUI
- **Dark/Light Theme**: Professional themes with easy switching
- **Intuitive Layout**: User-friendly interface with clear sections
- **Real-time Results**: Instant feedback and progress indicators
- **File Browser**: Easy file selection with drag-and-drop support
- **Accessibility**: Clear fonts, good contrast, keyboard navigation

---

## 📖 Usage Guide

### Getting Started
1. **Launch the Application**: Run `./run.sh` or use the desktop shortcut
2. **Select a File**: Click "Select Image" or enter a file path
3. **Choose Analysis**: Select the type of analysis you want to perform
4. **View Results**: Results appear in real-time in the interface

### Common Use Cases

#### Image Analysis
1. Load an image file
2. Use "EXIF Data" to extract metadata
3. Use "Location" to get GPS coordinates and address
4. Use "Steganography" to check for hidden data

#### Cryptography
1. Navigate to the Cryptography module
2. Choose between Classical or Advanced crypto
3. Select your cipher/algorithm
4. Enter text or load a file
5. Use Magic Hasher for hash identification and cracking

#### File Forensics
1. Load any file type
2. Use "String Analysis" to extract readable text
3. Use "Binwalk" to find embedded files
4. Use "Hex Viewer" for byte-level analysis

#### Web Analysis
1. Use "Web Analyzer" to perform web analysis

---

## 🛠️ System Requirements

### Required System Tools (Auto-installed)
- **tesseract-ocr**: OCR engine for text extraction
- **steghide**: Steganography tool for data hiding/extraction
- **exiftool**: Metadata extraction and manipulation
- **binwalk**: Binary analysis and hidden file extraction
- **zsteg**: PNG/BMP steganography analysis
- **hashcat**: Password/hash cracking
- **hash-identifier**: Hash type identification
- **ruby-full**: Required for zsteg

### Python Dependencies (Auto-installed)
- **Core**: Pillow, numpy, opencv-python, matplotlib
- **Forensics**: pytesseract, exifread, stegano, pyzbar
- **Cryptography**: cryptography, pycryptodome
- **Utilities**: geopy, qrcode, pypng, requests
- **GUI**: tkinter-tooltip

---

## 🔧 Configuration

### Theme Customization
Edit `src/ui/theme.py` to customize colors and appearance.

### Tool Configuration
Modify `src/config/settings.py` to adjust analysis parameters.

### Adding Custom Tools
Extend the toolkit by adding new modules in the `src/modules/` directory.

---

## 📁 Project Structure

```
ForensicsMainHand/
├── main.py                      # Main application entry point
├── run.sh                       # Launcher script
├── install.sh                   # Installation script
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── LICENSE                      # License information
├── webanalyzer.py               # Flask web analyzer app
├── static/
│   └── img/
│       └── nyx_logo.png
└── src/
    ├── config/
    │   ├── __init__.py
    │   └── settings.py
    ├── core/
    │   ├── exif_analyzer.py
    │   ├── location_analyzer.py
    │   ├── string_analyzer.py
    │   └── zsteg_analyzer.py
    ├── modules/
    │   ├── cryptography/
    │   │   ├── __init__.py
    │   │   ├── advanced_crypto.py
    │   │   ├── classical_ciphers.py
    │   │   ├── classical_crypto_gui.py
    │   │   └── crypto_main.py
    │   ├── file_analyzer/
    │   │   ├── __init__.py
    │   │   ├── file_main.py
    │   │   └── file_utils.py
    │   ├── photo_analyzer/
    │   │   ├── __init__.py
    │   │   ├── binwalk_analyzer.py
    │   │   ├── crypto_analyzer.py
    │   │   ├── exif_analyzer.py
    │   │   ├── file_carving_analyzer.py
    │   │   ├── file_utils.py
    │   │   ├── hex_viewer.py
    │   │   ├── location_analyzer.py
    │   │   ├── main_window.py
    │   │   ├── metadata_analyzer.py
    │   │   ├── ocr_analyzer.py
    │   │   ├── qr_barcode_analyzer.py
    │   │   ├── settings.py
    │   │   ├── steganography.py
    │   │   ├── string_analyzer.py
    │   │   ├── theme.py
    │   │   ├── validation.py
    │   │   ├── widgets.py
    │   │   └── zsteg_analyzer.py
    │   └── web_analyzer_project/
    │       ├── requirements.txt
    │       ├── templates/
    │       │   ├── index.html
    │       │   └── result.html
    │       └── web_tools/
    │           └── tools.py
    ├── forensics_main.py
    ├── forensics_toolkit.py
    ├── ui/
    │   ├── __init__.py
    │   ├── theme.py
    │   └── widgets.py
    └── utils/
        ├── __init__.py
        ├── file_utils.py
        └── validation.py
```
---

## 🎯 Use Cases

### Digital Forensics
- Extract metadata from evidence images
- Analyze GPS coordinates for location tracking
- Detect hidden data in suspicious files
- Perform file carving on binary evidence

### CTF Challenges
- Solve steganography challenges
- Crack classical and modern ciphers
- Identify and crack hash types
- Analyze binary files for hidden data
- **Web CTFs**: Scan for XSS, enumerate login pages, brute force demo logins, check HTTP headers, and perform basic web reconnaissance

### Security Research
- Analyze suspicious images and files
- Extract embedded data and metadata
- Perform cryptographic analysis
- Reverse engineer file formats
- **Web Security**: Check for missing security headers, scan open ports, resolve domains, and test for basic XSS vulnerabilities

---

## ⚠️ Troubleshooting

### Common Issues

**Installation Problems:**
```bash
# If install.sh fails, try:
sudo apt update
sudo apt install -y python3-venv
sudo ./install.sh
```

**Missing Dependencies:**
```bash
# Re-run installation
sudo ./install.sh

# Or manually install Python packages
source venv/bin/activate
pip install -r requirements.txt
```

**Permission Issues:**
```bash
# Make scripts executable
chmod +x install.sh run.sh
```

**GUI Issues:**
- Ensure you're running in a graphical environment
- Install `python3-tk` if tkinter is missing
- Try running with `DISPLAY=:0 ./run.sh`

### Getting Help
1. Check the troubleshooting section above
2. Review the installation logs
3. Open an issue on GitHub with error details
4. Ensure all system requirements are met

---

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is designed for educational and legitimate security analysis purposes only. Users are responsible for ensuring they have proper authorization before analyzing any files or images. Always comply with local laws and regulations.

---

## 📞 Support

- **GitHub Issues**: Open an issue for bugs or feature requests
- **Documentation**: Check this README and code comments
- **Community**: Join discussions in the repository

**Happy Forensics! 🔍** 