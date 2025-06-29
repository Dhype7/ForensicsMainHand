# DemoAnalyzer 🔍

> **Credit:** Project by Dhype7 (NYX team)

A comprehensive digital forensics toolkit with a modern GUI, designed for image, file, and cryptography analysis. Built for CTFs, security research, and forensic investigations.

---

## 📥 How to Download, Install, and Run

### 1. Download
Clone the repository:
```bash
git clone https://github.com/YOUR-USERNAME/YOUR-PRIVATE-REPO.git
cd DemoAnalyzer
```

### 2. Install
Run the provided installation script (recommended):
```bash
chmod +x install.sh
sudo ./install.sh
```
This will install all system and Python dependencies automatically.

Or, install manually:
```bash
sudo apt update
sudo apt install -y steghide exiftool binwalk tesseract-ocr zsteg xxd
pip install -r requirements.txt
```

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
- **Classical Ciphers**: Affine, Atbash, Bacon, Caesar, Playfair, Rail Fence, Rot13, Scytale, Substitution, Vigenère (encrypt/decrypt, file input/output, parameter presets)
- **Modern UI**: Split view for classical/advanced crypto
- **File Import/Export**: Work with text or files
- **Dynamic Parameters**: Only relevant options shown
- **Status Bar**: Real-time feedback and error handling
- **Advanced Crypto**: (Coming soon)

### 📁 File Analyzer (Early Preview)
- **File Carving**: Recover files from binary blobs
- **String Analysis**: Extract readable strings
- **Binary Analysis**: Inspect file structure
- **Format Detection**: Identify file types
- **Memory Analysis**: (Planned)

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
- Required system tools: `steghide`, `exiftool`, `strings`, `binwalk`

### System Dependencies (Kali Linux)
```bash
# Update package list
sudo apt update

# Install required tools
sudo apt install -y steghide exiftool binwalk

# Install Python dependencies
pip install -r requirements.txt
```

### Manual Installation
```bash
# Clone or download the project
cd DemoAnalyzer

# Install Python dependencies
pip install -r requirements.txt

# Make sure system tools are available
which steghide exiftool binwalk strings
```

## 📖 Usage

### Basic Usage
```bash
python src/main.py
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

## 🛠️ System Requirements

### Required System Tools
- **steghide**: Steganography tool for hiding data in images
- **exiftool**: Metadata extraction and manipulation
- **strings**: Extract printable strings from files
- **binwalk**: Binary analysis and hidden file extraction

### Python Dependencies
- **Pillow**: Image processing and EXIF extraction
- **geopy**: Geocoding and reverse geocoding
- **tkinter**: GUI framework (included with Python)

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
DemoAnalyzer/
├── src/
│   ├── main.py                 # Main application entry point
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── main_window.py      # Main GUI window
│   │   ├── theme.py           # UI theme configuration
│   │   └── widgets.py         # Custom widgets
│   ├── core/
│   │   ├── __init__.py
│   │   ├── exif_analyzer.py   # EXIF data analysis
│   │   ├── location_analyzer.py # GPS and location analysis
│   │   ├── steganography.py   # Steghide integration
│   │   ├── metadata_analyzer.py # ExifTool analysis
│   │   ├── string_analyzer.py # String extraction
│   │   └── binwalk_analyzer.py # Binwalk analysis
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── file_utils.py      # File handling utilities
│   │   └── validation.py      # Input validation
│   └── config/
│       ├── __init__.py
│       └── settings.py        # Application settings
├── requirements.txt           # Python dependencies
├── README.md                 # This file
└── LICENSE                   # License information
```

## 🎯 Use Cases

### Digital Forensics
- Extract metadata from evidence images
- Analyze GPS coordinates for location tracking
- Detect hidden data in suspicious files

### CTF Challenges
- Solve steganography challenges
- Extract flags from images
- Analyze binary files for hidden content

### Security Analysis
- Investigate suspicious images
- Detect data exfiltration attempts
- Analyze malware samples

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for educational and legitimate security analysis purposes only. Users are responsible for ensuring they have proper authorization before analyzing any files or images.

## 🐛 Troubleshooting

### Common Issues

#### Tool Not Found
```bash
# Check if tools are installed
which steghide exiftool binwalk strings

# Install missing tools
sudo apt install -y steghide exiftool binwalk
```

#### Permission Errors
```bash
# Ensure proper permissions
chmod +x src/main.py
```

#### GUI Issues
```bash
# Install tkinter if missing
sudo apt install python3-tk
```

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review existing issues
3. Create a new issue with detailed information

---

**Made with ❤️ for the security community** 