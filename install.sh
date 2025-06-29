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

print_status "Installing system dependencies (Python, pip, build tools, tesseract, steghide, exiftool, binwalk, hashcat, hash-identifier, etc.)..."
sudo apt install -y python3 python3-pip python3-tk python3-pil.imagetk tesseract-ocr steghide exiftool binwalk hashcat hash-identifier

# zsteg is a Ruby gem
if ! command -v zsteg &> /dev/null; then
    print_status "Installing Ruby and zsteg (Ruby gem)..."
    sudo apt install -y ruby-full
    sudo gem install zsteg
else
    print_success "zsteg: Found"
fi

# Fallback for hash-identifier: try hashid (pip) if not found
if ! command -v hash-identifier &> /dev/null; then
    print_warning "hash-identifier not found, trying to install hashid (pip)..."
    pip3 install hashid || print_error "Failed to install hashid. Please install a hash identifier tool manually."
else
    print_success "hash-identifier: Found"
fi

print_status "Installing Python libraries from requirements.txt..."
if ! python3 -m pip install --upgrade pip; then
    echo "[!] pip upgrade failed. Retrying with --break-system-packages..."
    python3 -m pip install --break-system-packages --upgrade pip
fi

if ! python3 -m pip install -r requirements.txt; then
    echo "[!] Standard pip install failed. Retrying with --break-system-packages..."
    python3 -m pip install --break-system-packages -r requirements.txt
fi

# Ensure critical packages are installed and visible
python3 -m pip uninstall -y scikit-image pypng pycryptodome || true
python3 -m pip install --break-system-packages scikit-image pypng pycryptodome

echo -e "\033[1;33m[!] If you run the app with sudo, you may need to set PYTHONPATH to your user site-packages.\033[0m"
echo -e "\033[1;33m[!] Example: sudo PYTHONPATH=\$PYTHONPATH:/home/$USER/.local/lib/python3.13/site-packages python3 main.py\033[0m"

print_status "Verifying dependencies..."
for tool in tesseract steghide exiftool binwalk hashcat zsteg; do
    if command -v $tool &> /dev/null; then
        print_success "$tool: Found"
    else
        print_warning "$tool: Not found"
    fi
done

print_status "Testing Python imports..."
python3 -c "
modules = ['PIL', 'pytesseract', 'exifread', 'stegano', 'pyzbar', 'requests', 'tkinter', 'numpy', 'cv2', 'matplotlib', 'scikit-image', 'qrcode', 'pypng', 'cryptography', 'pycryptodome', 'geopy']
failed = []
for module in modules:
    try:
        __import__(module)
        print(f'✅ {module}')
    except ImportError as e:
        print(f'❌ {module}: {e}')
        failed.append(module)
if failed:
    print(f'\n❌ Failed to import: {failed}')
    exit(1)
else:
    print('\n✅ All Python modules imported successfully')
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