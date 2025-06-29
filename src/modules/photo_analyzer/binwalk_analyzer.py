"""
Binwalk Analysis Module
"""
import subprocess
import os
import shutil
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class BinwalkAnalyzer:
    """Binwalk file analysis and hidden file extraction"""
    
    def __init__(self):
        self.scan_results = {}
        self.extracted_files = []
    
    def check_binwalk_available(self) -> bool:
        """Check if Binwalk is available on the system"""
        try:
            result = subprocess.run(['which', 'binwalk'], 
                                  capture_output=True, text=True, check=True)
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False
    
    def basic_scan(self, file_path: str) -> Dict[str, Any]:
        """
        Perform basic Binwalk scan
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing scan results
        """
        result = {
            'success': False,
            'output': '',
            'signatures_found': 0,
            'error': None
        }
        
        if not self.check_binwalk_available():
            result['error'] = "Binwalk is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Run basic binwalk scan
            command = ['binwalk', file_path]
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if process.returncode == 0:
                result['success'] = True
                result['output'] = process.stdout
                
                # Count signatures found
                lines = process.stdout.strip().split('\n')
                signature_lines = [line for line in lines if 'DECIMAL' in line or 'HEXADECIMAL' in line]
                result['signatures_found'] = len(signature_lines)
                
                self.scan_results['basic'] = result
            else:
                result['error'] = f"Binwalk error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Basic scan timed out"
        except Exception as e:
            result['error'] = f"Error during basic scan: {e}"
            logger.error(f"Basic scan error: {e}")
        
        return result
    
    def deep_scan(self, file_path: str) -> Dict[str, Any]:
        """
        Perform deep Binwalk analysis with entropy and hexdump
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing deep scan results
        """
        result = {
            'success': False,
            'output': '',
            'entropy_analysis': '',
            'hexdump': '',
            'error': None
        }
        
        if not self.check_binwalk_available():
            result['error'] = "Binwalk is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Run deep binwalk analysis
            command = [
                'binwalk',
                '--entropy',
                '--hexdump',
                '--matryoshka',
                file_path
            ]
            
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if process.returncode == 0:
                result['success'] = True
                result['output'] = process.stdout
                
                # Parse different sections
                output_lines = process.stdout.split('\n')
                current_section = 'main'
                
                for line in output_lines:
                    if 'ENTROPY ANALYSIS' in line:
                        current_section = 'entropy'
                    elif 'HEXDUMP' in line:
                        current_section = 'hexdump'
                    elif current_section == 'entropy':
                        result['entropy_analysis'] += line + '\n'
                    elif current_section == 'hexdump':
                        result['hexdump'] += line + '\n'
                
                self.scan_results['deep'] = result
            else:
                result['error'] = f"Binwalk deep scan error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Deep scan timed out"
        except Exception as e:
            result['error'] = f"Error during deep scan: {e}"
            logger.error(f"Deep scan error: {e}")
        
        return result
    
    def extract_files(self, file_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract hidden files using Binwalk
        
        Args:
            file_path: Path to the file to extract from
            output_dir: Directory to extract files to (optional)
            
        Returns:
            Dictionary containing extraction results
        """
        result = {
            'success': False,
            'extracted_files': [],
            'extraction_dir': '',
            'error': None
        }
        
        if not self.check_binwalk_available():
            result['error'] = "Binwalk is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Determine output directory
            if not output_dir:
                base_name = os.path.splitext(os.path.basename(file_path))[0]
                output_dir = f"_{base_name}.extracted"
            
            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
            
            # Run binwalk extraction
            command = [
                'binwalk',
                '-e',
                '-D', '.*',
                '--run-as=root',
                '-C', output_dir,
                file_path
            ]
            
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            if process.returncode == 0:
                result['success'] = True
                result['extraction_dir'] = os.path.abspath(output_dir)
                
                # List extracted files
                if os.path.exists(output_dir):
                    extracted_files = []
                    for root, dirs, files in os.walk(output_dir):
                        for file in files:
                            file_path_full = os.path.join(root, file)
                            extracted_files.append({
                                'path': file_path_full,
                                'name': file,
                                'size': os.path.getsize(file_path_full)
                            })
                    result['extracted_files'] = extracted_files
                    self.extracted_files = extracted_files
                
            else:
                result['error'] = f"Binwalk extraction error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "File extraction timed out"
        except Exception as e:
            result['error'] = f"Error during file extraction: {e}"
            logger.error(f"File extraction error: {e}")
        
        return result
    
    def signature_scan(self, file_path: str) -> Dict[str, Any]:
        """
        Perform signature-based scan
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing signature scan results
        """
        result = {
            'success': False,
            'signatures': [],
            'error': None
        }
        
        if not self.check_binwalk_available():
            result['error'] = "Binwalk is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Run signature scan
            command = ['binwalk', '--signature', file_path]
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if process.returncode == 0:
                result['success'] = True
                
                # Parse signatures
                lines = process.stdout.strip().split('\n')
                signatures = []
                
                for line in lines:
                    if 'DECIMAL' in line or 'HEXADECIMAL' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            signatures.append({
                                'offset': parts[0],
                                'type': parts[1],
                                'description': ' '.join(parts[2:])
                            })
                
                result['signatures'] = signatures
                
            else:
                result['error'] = f"Signature scan error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Signature scan timed out"
        except Exception as e:
            result['error'] = f"Error during signature scan: {e}"
            logger.error(f"Signature scan error: {e}")
        
        return result
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Complete Binwalk analysis of a file
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing complete analysis results
        """
        result = {
            'success': False,
            'basic_scan': {},
            'deep_scan': {},
            'signature_scan': {},
            'extraction': {},
            'summary': {},
            'error': None
        }
        
        # Perform basic scan
        basic_result = self.basic_scan(file_path)
        if basic_result['success']:
            result['basic_scan'] = basic_result
        else:
            result['error'] = basic_result['error']
            return result
        
        # Perform signature scan
        signature_result = self.signature_scan(file_path)
        if signature_result['success']:
            result['signature_scan'] = signature_result
        
        # Perform deep scan
        deep_result = self.deep_scan(file_path)
        if deep_result['success']:
            result['deep_scan'] = deep_result
        
        # Generate summary
        result['summary'] = {
            'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            'signatures_found': basic_result.get('signatures_found', 0),
            'has_entropy_analysis': deep_result.get('success', False),
            'extraction_available': basic_result.get('signatures_found', 0) > 0
        }
        
        result['success'] = True
        return result
    
    def export_to_text(self, analysis_result: Dict[str, Any]) -> str:
        """
        Export Binwalk analysis as formatted text
        
        Args:
            analysis_result: Result from analyze_file method
            
        Returns:
            Formatted text string
        """
        text_lines = []
        text_lines.append("=== Binwalk Analysis ===\n")
        
        if not analysis_result['success']:
            text_lines.append(f"Error: {analysis_result['error']}")
            return "\n".join(text_lines)
        
        # Summary
        summary = analysis_result['summary']
        text_lines.append("--- Summary ---")
        text_lines.append(f"File size: {summary['file_size']} bytes")
        text_lines.append(f"Signatures found: {summary['signatures_found']}")
        text_lines.append(f"Entropy analysis: {'Yes' if summary['has_entropy_analysis'] else 'No'}")
        text_lines.append(f"Extraction available: {'Yes' if summary['extraction_available'] else 'No'}")
        text_lines.append("")
        
        # Basic scan results
        if analysis_result['basic_scan']:
            text_lines.append("--- Basic Scan Results ---")
            text_lines.append(analysis_result['basic_scan']['output'])
            text_lines.append("")
        
        # Signature scan results
        if analysis_result['signature_scan'] and analysis_result['signature_scan']['signatures']:
            text_lines.append("--- Signature Analysis ---")
            for sig in analysis_result['signature_scan']['signatures']:
                text_lines.append(f"Offset {sig['offset']}: {sig['type']} - {sig['description']}")
            text_lines.append("")
        
        # Deep scan results (entropy)
        if (analysis_result['deep_scan'] and 
            analysis_result['deep_scan'].get('entropy_analysis')):
            text_lines.append("--- Entropy Analysis ---")
            text_lines.append(analysis_result['deep_scan']['entropy_analysis'])
            text_lines.append("")
        
        # Extraction results
        if analysis_result['extraction'] and analysis_result['extraction']['success']:
            text_lines.append("--- Extracted Files ---")
            text_lines.append(f"Extraction directory: {analysis_result['extraction']['extraction_dir']}")
            for file_info in analysis_result['extraction']['extracted_files']:
                text_lines.append(f"  {file_info['name']} ({file_info['size']} bytes)")
            text_lines.append("")
        
        return "\n".join(text_lines) 