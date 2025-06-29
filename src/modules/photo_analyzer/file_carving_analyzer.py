"""
File Carving Analysis Module - File Extraction from Binary Data
"""
import os
import subprocess
import re
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class FileCarvingAnalyzer:
    """File carving analysis for extracting files from binary data"""
    
    def __init__(self):
        self.extracted_files = []
        self.file_signatures = []
    
    def check_foremost_available(self) -> bool:
        """Check if Foremost is available on the system"""
        try:
            result = subprocess.run(['which', 'foremost'], 
                                  capture_output=True, text=True, check=True)
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False
    
    def check_binwalk_available(self) -> bool:
        """Check if Binwalk is available on the system"""
        try:
            result = subprocess.run(['which', 'binwalk'], 
                                  capture_output=True, text=True, check=True)
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False
    
    def extract_with_foremost(self, file_path: str, output_dir: str = None) -> Dict[str, Any]:
        """
        Extract files using Foremost
        
        Args:
            file_path: Path to the file to analyze
            output_dir: Output directory for extracted files
            
        Returns:
            Dictionary containing extraction results
        """
        result = {
            'success': False,
            'files_found': [],
            'total_files': 0,
            'output_directory': '',
            'error': None
        }
        
        if not self.check_foremost_available():
            result['error'] = "Foremost is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Create output directory
            if output_dir is None:
                output_dir = f"foremost_output_{os.path.basename(file_path)}"
            
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            result['output_directory'] = output_dir
            
            # Run foremost
            cmd = ['foremost', '-i', file_path, '-o', output_dir]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if process.returncode == 0:
                result['success'] = True
                
                # Parse foremost output
                output_lines = process.stdout.split('\n')
                files_found = []
                
                for line in output_lines:
                    if 'File:' in line and 'Size:' in line:
                        # Extract file information
                        file_match = re.search(r'File: (.+?) Size: (\d+)', line)
                        if file_match:
                            filename = file_match.group(1)
                            size = int(file_match.group(2))
                            files_found.append({
                                'filename': filename,
                                'size': size,
                                'path': os.path.join(output_dir, filename)
                            })
                
                result['files_found'] = files_found
                result['total_files'] = len(files_found)
                
            else:
                result['error'] = f"Foremost failed: {process.stderr}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Foremost operation timed out"
        except Exception as e:
            result['error'] = f"Error during foremost extraction: {str(e)}"
            logger.error(f"Foremost extraction error: {e}")
        
        return result
    
    def extract_with_binwalk(self, file_path: str, output_dir: str = None) -> Dict[str, Any]:
        """
        Extract files using Binwalk
        
        Args:
            file_path: Path to the file to analyze
            output_dir: Output directory for extracted files
            
        Returns:
            Dictionary containing extraction results
        """
        result = {
            'success': False,
            'files_found': [],
            'total_files': 0,
            'output_directory': '',
            'error': None
        }
        
        if not self.check_binwalk_available():
            result['error'] = "Binwalk is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Create output directory
            if output_dir is None:
                output_dir = f"binwalk_output_{os.path.basename(file_path)}"
            
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            result['output_directory'] = output_dir
            
            # Run binwalk extraction
            cmd = ['binwalk', '--extract', '--directory', output_dir, file_path]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if process.returncode == 0:
                result['success'] = True
                
                # Parse binwalk output
                output_lines = process.stdout.split('\n')
                files_found = []
                
                for line in output_lines:
                    if 'extracted:' in line.lower():
                        # Extract file information
                        file_match = re.search(r'extracted: (.+)', line, re.IGNORECASE)
                        if file_match:
                            filename = file_match.group(1).strip()
                            file_path_full = os.path.join(output_dir, filename)
                            if os.path.exists(file_path_full):
                                size = os.path.getsize(file_path_full)
                                files_found.append({
                                    'filename': filename,
                                    'size': size,
                                    'path': file_path_full
                                })
                
                result['files_found'] = files_found
                result['total_files'] = len(files_found)
                
            else:
                result['error'] = f"Binwalk failed: {process.stderr}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Binwalk operation timed out"
        except Exception as e:
            result['error'] = f"Error during binwalk extraction: {str(e)}"
            logger.error(f"Binwalk extraction error: {e}")
        
        return result
    
    def scan_file_signatures(self, file_path: str) -> Dict[str, Any]:
        """
        Scan for file signatures in binary data
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing signature scan results
        """
        result = {
            'success': False,
            'signatures_found': [],
            'total_signatures': 0,
            'error': None
        }
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Common file signatures
            signatures = {
                'JPEG': b'\xff\xd8\xff',
                'PNG': b'\x89PNG\r\n\x1a\n',
                'GIF': b'GIF87a',
                'GIF89a': b'GIF89a',
                'BMP': b'BM',
                'ZIP': b'PK\x03\x04',
                'RAR': b'Rar!\x1a\x07',
                'PDF': b'%PDF',
                'ELF': b'\x7fELF',
                'PE': b'MZ',
                'GZIP': b'\x1f\x8b',
                'BZIP2': b'BZ',
                'TAR': b'ustar',
                '7ZIP': b'7z\xbc\xaf\x27\x1c',
                'EXE': b'MZ',
                'DLL': b'MZ',
                'JAR': b'PK\x03\x04',
                'WAR': b'PK\x03\x04',
                'EAR': b'PK\x03\x04',
                'CLASS': b'\xca\xfe\xba\xbe',
                'PYC': b'\x03\xf3\r\n',
                'PYO': b'\x03\xf3\r\n',
                'SWF': b'FWS',
                'FLV': b'FLV',
                'MP4': b'ftyp',
                'AVI': b'RIFF',
                'WAV': b'RIFF',
                'MP3': b'ID3',
                'OGG': b'OggS',
                'FLAC': b'fLaC',
                'TXT': b'',
                'HTML': b'<html',
                'XML': b'<?xml',
                'JSON': b'{',
                'SQLITE': b'SQLite format 3',
                'MYSQL': b'\xfe\xfe\xfe\xfe',
                'POSTGRES': b'PGCOPY\n',
                'ORACLE': b'\x00\x00\x00\x00',
                'SQLSERVER': b'\x04\x01\x00\x00',
                'ACCESS': b'\x00\x01\x00\x00',
                'EXCEL': b'\xd0\xcf\x11\xe0',
                'WORD': b'\xd0\xcf\x11\xe0',
                'POWERPOINT': b'\xd0\xcf\x11\xe0',
                'VISIO': b'\xd0\xcf\x11\xe0',
                'OUTLOOK': b'\xd0\xcf\x11\xe0',
                'ONENOTE': b'\xe4\x52\x5c\x7b',
                'PUBLISHER': b'\xd0\xcf\x11\xe0',
                'PROJECT': b'\xd0\xcf\x11\xe0',
                'INFOPATH': b'\xd0\xcf\x11\xe0',
                'SHAREPOINT': b'\xd0\xcf\x11\xe0',
                'GROOVE': b'\xd0\xcf\x11\xe0',
                'ACCESS': b'\xd0\xcf\x11\xe0',
                'EXCEL': b'\xd0\xcf\x11\xe0',
                'WORD': b'\xd0\xcf\x11\xe0',
                'POWERPOINT': b'\xd0\xcf\x11\xe0',
                'VISIO': b'\xd0\xcf\x11\xe0',
                'OUTLOOK': b'\xd0\xcf\x11\xe0',
                'ONENOTE': b'\xe4\x52\x5c\x7b',
                'PUBLISHER': b'\xd0\xcf\x11\xe0',
                'PROJECT': b'\xd0\xcf\x11\xe0',
                'INFOPATH': b'\xd0\xcf\x11\xe0',
                'SHAREPOINT': b'\xd0\xcf\x11\xe0',
                'GROOVE': b'\xd0\xcf\x11\xe0'
            }
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            signatures_found = []
            
            for file_type, signature in signatures.items():
                if signature:  # Skip empty signatures
                    positions = []
                    start = 0
                    while True:
                        pos = data.find(signature, start)
                        if pos == -1:
                            break
                        positions.append(pos)
                        start = pos + 1
                    
                    if positions:
                        signatures_found.append({
                            'type': file_type,
                            'signature': signature.hex(),
                            'positions': positions,
                            'count': len(positions)
                        })
            
            result['success'] = True
            result['signatures_found'] = signatures_found
            result['total_signatures'] = len(signatures_found)
            
        except Exception as e:
            result['error'] = f"Error during signature scan: {str(e)}"
            logger.error(f"Signature scan error: {e}")
        
        return result
    
    def auto_carve(self, file_path: str) -> Dict[str, Any]:
        """
        Automatically carve files using multiple methods
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing carving results
        """
        result = {
            'success': False,
            'foremost_results': None,
            'binwalk_results': None,
            'signature_results': None,
            'total_files_extracted': 0,
            'error': None
        }
        
        try:
            # Scan for signatures first
            signature_results = self.scan_file_signatures(file_path)
            result['signature_results'] = signature_results
            
            # Try foremost extraction
            foremost_results = self.extract_with_foremost(file_path)
            result['foremost_results'] = foremost_results
            
            # Try binwalk extraction
            binwalk_results = self.extract_with_binwalk(file_path)
            result['binwalk_results'] = binwalk_results
            
            # Calculate total files extracted
            total_files = 0
            if foremost_results.get('success'):
                total_files += foremost_results.get('total_files', 0)
            if binwalk_results.get('success'):
                total_files += binwalk_results.get('total_files', 0)
            
            result['total_files_extracted'] = total_files
            result['success'] = True
            
        except Exception as e:
            result['error'] = f"Error during auto-carving: {str(e)}"
            logger.error(f"Auto-carving error: {e}")
        
        return result
    
    def export_to_text(self, carving_result: Dict[str, Any]) -> str:
        """Export carving results to formatted text"""
        if not carving_result.get('success'):
            return f"File Carving Analysis failed: {carving_result.get('error', 'Unknown error')}"
        
        output = []
        output.append("=" * 60)
        output.append("FILE CARVING ANALYSIS RESULTS")
        output.append("=" * 60)
        output.append("")
        
        # Signature scan results
        if carving_result.get('signature_results'):
            sig_results = carving_result['signature_results']
            if sig_results.get('success'):
                output.append("🔍 File Signatures Found:")
                output.append("-" * 30)
                output.append(f"Total Signatures: {sig_results.get('total_signatures', 0)}")
                output.append("")
                
                for sig in sig_results.get('signatures_found', []):
                    output.append(f"📄 {sig['type']}:")
                    output.append(f"   Signature: {sig['signature']}")
                    output.append(f"   Count: {sig['count']}")
                    output.append(f"   Positions: {sig['positions'][:5]}{'...' if len(sig['positions']) > 5 else ''}")
                    output.append("")
        
        # Foremost results
        if carving_result.get('foremost_results'):
            fore_results = carving_result['foremost_results']
            if fore_results.get('success'):
                output.append("🗜️ Foremost Extraction:")
                output.append("-" * 25)
                output.append(f"Files Extracted: {fore_results.get('total_files', 0)}")
                output.append(f"Output Directory: {fore_results.get('output_directory', 'N/A')}")
                output.append("")
                
                for file_info in fore_results.get('files_found', [])[:10]:  # Show first 10
                    output.append(f"  📁 {file_info['filename']} ({file_info['size']} bytes)")
                
                if len(fore_results.get('files_found', [])) > 10:
                    output.append(f"  ... and {len(fore_results.get('files_found', [])) - 10} more files")
                output.append("")
        
        # Binwalk results
        if carving_result.get('binwalk_results'):
            bin_results = carving_result['binwalk_results']
            if bin_results.get('success'):
                output.append("🔧 Binwalk Extraction:")
                output.append("-" * 25)
                output.append(f"Files Extracted: {bin_results.get('total_files', 0)}")
                output.append(f"Output Directory: {bin_results.get('output_directory', 'N/A')}")
                output.append("")
                
                for file_info in bin_results.get('files_found', [])[:10]:  # Show first 10
                    output.append(f"  📁 {file_info['filename']} ({file_info['size']} bytes)")
                
                if len(bin_results.get('files_found', [])) > 10:
                    output.append(f"  ... and {len(bin_results.get('files_found', [])) - 10} more files")
                output.append("")
        
        output.append(f"📊 Total Files Extracted: {carving_result.get('total_files_extracted', 0)}")
        
        return "\n".join(output) 