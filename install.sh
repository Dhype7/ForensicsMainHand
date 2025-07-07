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
print_warning() { echo -e "${YELLOW}⚠  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

echo "🔍 DemoAnalyzer Forensics Toolkit Installation Script"
echo "=================================================="

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "\033[1;31m❌ This script must be run as root. Please use sudo ./install.sh\033[0m"
  exit 1
fi

if ! command -v apt &> /dev/null; then
    print_error "This script is designed for Debian/Ubuntu/Kali Linux systems"
    exit 1
fi

print_status "Updating package list..."
# Remove deprecated apt-key usage and use modern approach
sudo apt update || print_warning "Package list update had issues, continuing..."

print_status "Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-tk python3-pil.imagetk tesseract-ocr steghide exiftool binwalk hashcat \
    unzip p7zip-full p7zip-rar unrar tar gzip bzip2 xz-utils lzma zstd lz4 arj rar || print_warning "Some archive tools may not be available on all systems."

print_status "Installing audio playback utility (alsa-utils for aplay)..."
sudo apt install -y alsa-utils

# Install hash-identifier if available, otherwise use hashid
if apt list --installed | grep -q hash-identifier; then
    print_success "hash-identifier: Already installed"
elif apt list | grep -q hash-identifier; then
    sudo apt install -y hash-identifier
    print_success "hash-identifier: Installed"
else
    print_warning "hash-identifier not available, will use hashid instead"
fi

if ! command -v zsteg &> /dev/null; then
    print_status "Installing Ruby and zsteg..."
    sudo apt install -y ruby-full
    sudo gem install zsteg
else
    print_success "zsteg: Found"
fi

# Install hashid as fallback if hash-identifier is not available
if ! command -v hash-identifier &> /dev/null; then
    print_warning "hash-identifier not found, installing hashid..."
    pip3 install hashid || print_error "Failed to install hashid."
else
    print_success "hash-identifier: Found"
fi

print_status "Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

print_status "Upgrading pip in the virtual environment..."
pip install --upgrade pip

print_status "Installing Python libraries from requirements.txt..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_success "All Python dependencies from requirements.txt installed"
else
    print_error "requirements.txt not found! Please ensure the file exists."
    exit 1
fi

print_status "Installing Python modules for advanced archive support..."
pip install --upgrade python-magic rarfile py7zr zstandard lz4 || print_warning "Some Python archive modules failed to install."

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
module_map = {
    'PIL': 'PIL',
    'pytesseract': 'pytesseract',
    'exifread': 'exifread',
    'stegano': 'stegano',
    'pyzbar': 'pyzbar',
    'requests': 'requests',
    'tkinter': 'tkinter',
    'numpy': 'numpy',
    'cv2': 'cv2',
    'matplotlib': 'matplotlib',
    'scikit-image': 'skimage',
    'qrcode': 'qrcode',
    'pypng': 'png',
    'cryptography': 'cryptography',
    'pycryptodome': 'Crypto',
    'geopy': 'geopy',

    'python-magic': 'magic',
    'rarfile': 'rarfile',
    'py7zr': 'py7zr',
    'zstandard': 'zstandard',
    'lz4': 'lz4',
    'pyperclip': 'pyperclip',
    'flask': 'flask',
    'python-whois': 'whois',
    'beautifulsoup4': 'bs4',
    'dnspython': 'dns',
}

failed = []

for name, import_name in module_map.items():
    try:
        __import__(import_name)
        print(f'✅ {name}')
    except ImportError as e:
        print(f'❌ {name}: {e}')
        failed.append(name)

if failed:
    print(f'\n❌ Failed to import: {failed}')
    exit(1)
else:
    print('\n✅ All Python modules imported successfully')
"

print_status "Setting executable permissions..."
# Fix: Use main.py instead of demoanalyzer.py since that's the actual entry point
[ -f "main.py" ] && chmod +x main.py && print_success "main.py is executable"
[ -f "run.sh" ] && chmod +x run.sh && print_success "run.sh is executable"
[ -f "src/forensics_main.py" ] && chmod +x src/forensics_main.py && print_success "forensics_main.py is executable"

print_status "Creating desktop shortcut..."
# Fix: Use the correct user's home directory and the launcher script
if [ -d "/home/$SUDO_USER/Desktop" ]; then
    cat > "/home/$SUDO_USER/Desktop/DemoAnalyzer.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=DemoAnalyzer
Comment=Forensics Toolkit - Image Analysis and Steganography Tool
Exec=$(pwd)/run.sh
Icon=applications-graphics
Terminal=true
Categories=Graphics;Security;Forensics;
EOF
    chmod +x "/home/$SUDO_USER/Desktop/DemoAnalyzer.desktop"
    print_success "Desktop shortcut created"
elif [ -d "$HOME/Desktop" ]; then
    cat > "$HOME/Desktop/DemoAnalyzer.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=DemoAnalyzer
Comment=Forensics Toolkit - Image Analysis and Steganography Tool
Exec=$(pwd)/run.sh
Icon=applications-graphics
Terminal=true
Categories=Graphics;Security;Forensics;
EOF
    chmod +x "$HOME/Desktop/DemoAnalyzer.desktop"
    print_success "Desktop shortcut created"
else
    print_warning "Desktop directory not found, skipping desktop shortcut"
fi

echo -e "\033[1;32m[!] Installation complete!\033[0m"
echo -e "\033[1;33m[!] To use the toolkit, you can either:\033[0m"
echo -e "\033[1;33m[!] 1. Use the desktop shortcut (if created)\033[0m"
echo -e "\033[1;33m[!] 2. Run the launcher script:\033[0m"
echo -e "\033[1;32m./run.sh\033[0m"
echo -e "\033[1;33m[!] 3. Or manually activate the virtual environment and run:\033[0m"
echo -e "\033[1;32msource venv/bin/activate && python main.py\033[0m"

# Fix: Use the correct user for the final module check
if [ -n "$SUDO_USER" ]; then
    USER_HOME="/home/$SUDO_USER"
else
    USER_HOME="$HOME"
fi

PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
USER_SITE="$USER_HOME/.local/lib/python${PYVER}/site-packages"

print_status "Checking for missing critical Python modules..."

declare -A critical_modules=(
    [scikit-image]=skimage
    [pypng]=png
    [pycryptodome]=Crypto
    [requests]=requests

    [python-magic]=magic
    [rarfile]=rarfile
    [py7zr]=py7zr
    [zstandard]=zstandard
    [lz4]=lz4
    [pyperclip]=pyperclip
    [flask]=flask
    [python-whois]=whois
    [beautifulsoup4]=bs4
    [dnspython]=dns
)

for pkg in "${!critical_modules[@]}"; do
    mod="${critical_modules[$pkg]}"
    if ! python3 -c "import $mod" &>/dev/null; then
        echo -e "\033[1;33m[!] '$pkg' missing. Attempting to install it in the virtual environment...\033[0m"
        pip install "$pkg" || {
            echo -e "\033[1;31m[!] Failed to install $pkg. You may need to install it manually.\033[0m"
        }
    else
        print_success "$pkg (import: $mod): OK"
    fi
done

print_success "Installation completed successfully!"

echo "[+] Checking/installing additional system dependencies..."
if ! command -v unrar &> /dev/null; then
    echo "[!] 'unrar' not found. Installing (Debian/Ubuntu)..."
    sudo apt-get update && sudo apt-get install -y unrar
fi
if ! command -v 7z &> /dev/null; then
    echo "[!] 'p7zip-full' not found. Installing (Debian/Ubuntu)..."
    sudo apt-get update && sudo apt-get install -y p7zip-full
fi

echo "[+] All dependencies installed."
