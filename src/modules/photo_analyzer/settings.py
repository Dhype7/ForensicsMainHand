"""
Application settings and configuration
"""
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

class Settings:
    """Application settings and configuration management"""
    
    # Application info
    APP_NAME = "DemoAnalyzer"
    APP_VERSION = "3.0.0"
    APP_DESCRIPTION = "Advanced CTF Image Analysis and Steganography Tool"
    
    # Window settings
    WINDOW_WIDTH = 1400
    WINDOW_HEIGHT = 900
    MIN_WINDOW_WIDTH = 1200
    MIN_WINDOW_HEIGHT = 700
    
    # File settings
    SUPPORTED_IMAGE_FORMATS = [
        "*.jpg", "*.jpeg", "*.png", "*.bmp", 
        "*.gif", "*.tiff", "*.ico", "*.webp", "*.svg",
        "*.ppm", "*.pgm", "*.pbm", "*.xpm", "*.xbm"
    ]
    
    SUPPORTED_FILE_FORMATS = [
        "*.jpg", "*.jpeg", "*.png", "*.bmp", 
        "*.gif", "*.tiff", "*.ico", "*.webp", "*.svg",
        "*.pdf", "*.doc", "*.docx", "*.txt",
        "*.zip", "*.rar", "*.7z", "*.tar.gz", "*.tar",
        "*.exe", "*.dll", "*.so", "*.dylib", "*.bin",
        "*.ppm", "*.pgm", "*.pbm", "*.xpm", "*.xbm"
    ]
    
    # CTF-specific file patterns
    CTF_PATTERNS = [
        r'flag\{.*?\}',
        r'FLAG\{.*?\}',
        r'ctf\{.*?\}',
        r'CTF\{.*?\}',
        r'key\{.*?\}',
        r'KEY\{.*?\}',
        r'secret\{.*?\}',
        r'SECRET\{.*?\}',
        r'password.*?=.*?[\w\d]+',
        r'passwd.*?=.*?[\w\d]+',
        r'admin.*?=.*?[\w\d]+',
        r'root.*?=.*?[\w\d]+',
        r'[a-zA-Z0-9]{32}',  # MD5 hashes
        r'[a-fA-F0-9]{40}',  # SHA1 hashes
        r'[a-fA-F0-9]{64}',  # SHA256 hashes
        r'[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',  # Base64
        r'[A-Z2-7]{32}',  # Base32
        r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',  # UUID
    ]
    
    # Tool paths and availability
    TOOLS: Dict[str, Optional[str]] = {
        'steghide': None,
        'exiftool': None,
        'strings': None,
        'binwalk': None,
        'zsteg': None,
        'tesseract': None,
        'identify': None,
        'convert': None,
        'file': None,
        'hexdump': None,
        'xxd': None,
        'grep': None,
        'sed': None,
        'awk': None,
        'tr': None,
        'base64': None,
        'base32': None,
        'openssl': None,
        'gpg': None,
        'unzip': None,
        'tar': None,
        '7z': None,
        'unrar': None
    }
    
    @classmethod
    def check_tools(cls) -> None:
        """Check availability of required system tools"""
        tool_names = list(cls.TOOLS.keys())
        
        for tool in tool_names:
            try:
                result = subprocess.run(['which', tool], 
                                      capture_output=True, text=True, check=True)
                cls.TOOLS[tool] = result.stdout.strip()
            except subprocess.CalledProcessError:
                cls.TOOLS[tool] = None
    
    @classmethod
    def get_missing_tools(cls) -> List[str]:
        """Get list of missing tools"""
        return [tool for tool, path in cls.TOOLS.items() if path is None]
    
    @classmethod
    def is_tool_available(cls, tool_name: str) -> bool:
        """Check if a specific tool is available"""
        return cls.TOOLS.get(tool_name) is not None
    
    @classmethod
    def get_essential_tools(cls) -> List[str]:
        """Get list of essential tools for basic functionality"""
        return ['strings', 'file', 'grep']
    
    @classmethod
    def get_advanced_tools(cls) -> List[str]:
        """Get list of advanced tools for enhanced analysis"""
        return ['steghide', 'exiftool', 'binwalk', 'zsteg', 'tesseract']

# Initialize tool availability
Settings.check_tools() 