#!/bin/bash

# DemoAnalyzer Forensics Toolkit Installation Script
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}🔍 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

echo "🔍 DemoAnalyzer Forensics Toolkit Installation Script"
echo "=================================================="

if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

if ! command -v apt &> /dev/null; then
    print_error "This script is designed for Debian/Ubuntu/Kali Linux systems"
    exit 1
fi

print_status "Updating package list..."
# Try to fix Kali repository key issue
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 827C8569F2518CC677FECA1AED65462EC8D5E4C5 2>/dev/null || true
sudo apt update || print_warning "Package list update had issues, continuing..."

print_status "Installing system dependencies..."
# Install core dependencies first
sudo apt install -y \
    steghide \
    libimage-exiftool-perl \
    binwalk \
    python3-pip \
    python3-tk \
    tesseract-ocr \
    tesseract-ocr-eng \
    xxd

# Try to install zsteg if available
if apt search zsteg 2>/dev/null | grep -q zsteg; then
    sudo apt install -y zsteg
    print_success "zsteg installed"
else
    print_warning "zsteg not available in repositories, skipping"
fi

print_status "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt --break-system-packages
else
    pip3 install --break-system-packages \
        Pillow>=10.0.0 geopy>=2.3.0 tkinter-tooltip>=2.0.0 \
        cryptography>=41.0.0 numpy>=1.24.0 opencv-python>=4.8.0 \
        matplotlib>=3.7.0 scikit-image>=0.21.0 pytesseract>=0.3.10 \
        pypng>=0.20220715.0 pyzbar>=0.1.9 qrcode>=7.4.0 stegano>=0.9.9 exifread
fi

print_status "Verifying dependencies..."
if command -v tesseract &> /dev/null; then
    print_success "Tesseract OCR: $(tesseract --version | head -n 1)"
else
    print_error "Tesseract OCR not found"
    exit 1
fi

for tool in steghide exiftool binwalk; do
    if command -v $tool &> /dev/null; then
        print_success "$tool: Found"
    else
        print_warning "$tool: Not found"
    fi
done

# Check zsteg separately since it's optional
if command -v zsteg &> /dev/null; then
    print_success "zsteg: Found"
else
    print_warning "zsteg: Not found (optional dependency)"
fi

print_status "Testing Python imports..."
python3 -c "
modules = ['PIL', 'pytesseract', 'exifread', 'stegano', 'pyzbar', 'requests', 'tkinter']
failed = []
for module in modules:
    try:
        __import__(module)
        print(f'✅ {module}')
    except ImportError as e:
        print(f'❌ {module}: {e}')
        failed.append(module)
if failed:
    print(f'\\n❌ Failed to import: {failed}')
    exit(1)
else:
    print('\\n✅ All Python modules imported successfully')
"

print_status "Setting executable permissions..."
[ -f "demoanalyzer.py" ] && chmod +x demoanalyzer.py && print_success "demoanalyzer.py is executable"
[ -f "src/forensics_main.py" ] && chmod +x src/forensics_main.py && print_success "forensics_main.py is executable"

print_status "Creating desktop shortcut..."
if [ -d "$HOME/Desktop" ]; then
    cat > "$HOME/Desktop/DemoAnalyzer.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=DemoAnalyzer
Comment=Forensics Toolkit - Image Analysis and Steganography Tool
Exec=$(pwd)/demoanalyzer.py
Icon=applications-graphics
Terminal=false
Categories=Graphics;Security;Forensics;
EOF
    chmod +x "$HOME/Desktop/DemoAnalyzer.desktop"
    print_success "Desktop shortcut created"
fi

echo ""
print_success "Installation completed successfully!"
echo ""
echo "🚀 To run DemoAnalyzer:"
echo "   ./demoanalyzer.py"
echo ""
echo "📖 For more information, see README.md" 