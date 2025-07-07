"""
Metadata Analysis Module - ExifTool Integration
"""
import subprocess
import re
import os
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class MetadataAnalyzer:
    """Metadata extraction and analysis using ExifTool"""
    
    def __init__(self):
        self.metadata = {}
        self.flags_found = []
    
    def check_exiftool_available(self) -> bool:
        """Check if ExifTool is available on the system"""
        try:
            result = subprocess.run(['which', 'exiftool'], 
                                  capture_output=True, text=True, check=True)
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False
    
    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Extract metadata from file using ExifTool
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing metadata
        """
        result = {
            'success': False,
            'metadata': {},
            'error': None
        }
        
        if not self.check_exiftool_available():
            result['error'] = "ExifTool is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Run ExifTool command
            command = ['exiftool', file_path]
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if process.returncode == 0:
                result['success'] = True
                result['metadata'] = self._parse_exiftool_output(process.stdout)
                self.metadata = result['metadata']
            else:
                result['error'] = f"ExifTool error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Metadata extraction timed out"
        except Exception as e:
            result['error'] = f"Error during metadata extraction: {e}"
            logger.error(f"Metadata extraction error: {e}")
        
        return result
    
    def _parse_exiftool_output(self, output: str) -> Dict[str, str]:
        """
        Parse ExifTool output into a dictionary
        
        Args:
            output: Raw ExifTool output
            
        Returns:
            Dictionary of metadata key-value pairs
        """
        metadata = {}
        
        for line in output.strip().split('\n'):
            if ':' in line:
                # Split on first colon
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    metadata[key] = value
        
        return metadata
    
    def find_flags(self, data: str) -> List[str]:
        """
        Find CTF flags in the data
        
        Args:
            data: String data to search
            
        Returns:
            List of found flags
        """
        flags = []
        
        # Common CTF flag patterns
        flag_patterns = [
            r'FLAG\{[^}]*\}',           # FLAG{...}
            r'flag\{[^}]*\}',           # flag{...}
            r'CTF\{[^}]*\}',            # CTF{...}
            r'ctf\{[^}]*\}',            # ctf{...}
            r'KEY\{[^}]*\}',            # KEY{...}
            r'key\{[^}]*\}',            # key{...}
            r'PASSWORD\{[^}]*\}',       # PASSWORD{...}
            r'password\{[^}]*\}',       # password{...}
            r'[A-Z0-9]{32}',            # 32-character hex strings
            r'[A-Z0-9]{64}',            # 64-character hex strings
        ]
        
        for pattern in flag_patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            flags.extend(matches)
        
        # Remove duplicates while preserving order
        unique_flags = []
        for flag in flags:
            if flag not in unique_flags:
                unique_flags.append(flag)
        
        self.flags_found = unique_flags
        return unique_flags
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Complete metadata analysis of a file
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        result = {
            'success': False,
            'metadata': {},
            'flags': [],
            'summary': {},
            'error': None
        }
        
        # Extract metadata
        metadata_result = self.extract_metadata(file_path)
        
        if not metadata_result['success']:
            result['error'] = metadata_result['error']
            return result
        
        result['success'] = True
        result['metadata'] = metadata_result['metadata']
        
        # Convert metadata to string for flag search
        metadata_text = '\n'.join([
            f"{key}: {value}" for key, value in metadata_result['metadata'].items()
        ])
        
        # Find flags
        flags = self.find_flags(metadata_text)
        result['flags'] = flags
        
        # Generate summary
        result['summary'] = {
            'total_metadata_fields': len(metadata_result['metadata']),
            'flags_found': len(flags),
            'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            'file_type': self._get_file_type(metadata_result['metadata'])
        }
        
        return result
    
    def _get_file_type(self, metadata: Dict[str, str]) -> str:
        """Extract file type from metadata"""
        file_type_keys = [
            'File Type', 'MIME Type', 'Format', 'Image Type',
            'File Type Extension', 'File Format'
        ]
        
        for key in file_type_keys:
            if key in metadata:
                return metadata[key]
        
        return "Unknown"
    
    def export_to_text(self, analysis_result: Dict[str, Any]) -> str:
        """
        Export metadata analysis as formatted text
        
        Args:
            analysis_result: Result from analyze_file method
            
        Returns:
            Formatted text string
        """
        text_lines = []
        text_lines.append("=== Metadata Analysis ===\n")
        
        if not analysis_result['success']:
            text_lines.append(f"Error: {analysis_result['error']}")
            return "\n".join(text_lines)
        
        # Summary
        summary = analysis_result['summary']
        text_lines.append("--- Summary ---")
        text_lines.append(f"Total metadata fields: {summary['total_metadata_fields']}")
        text_lines.append(f"Flags found: {summary['flags_found']}")
        text_lines.append(f"File size: {summary['file_size']} bytes")
        text_lines.append(f"File type: {summary['file_type']}")
        text_lines.append("")
        
        # Flags
        if analysis_result['flags']:
            text_lines.append("--- FLAGS FOUND ---")
            for i, flag in enumerate(analysis_result['flags'], 1):
                text_lines.append(f"{i}. {flag}")
            text_lines.append("")
        
        # Metadata
        if analysis_result['metadata']:
            text_lines.append("--- Metadata ---")
            for key, value in analysis_result['metadata'].items():
                text_lines.append(f"{key}: {value}")
            text_lines.append("")
        
        return "\n".join(text_lines)
    
    def search_metadata(self, search_term: str) -> List[Dict[str, str]]:
        """
        Search metadata for specific terms
        
        Args:
            search_term: Term to search for
            
        Returns:
            List of matching metadata entries
        """
        if not self.metadata:
            return []
        
        matches = []
        search_term_lower = search_term.lower()
        
        for key, value in self.metadata.items():
            if (search_term_lower in key.lower() or 
                search_term_lower in str(value).lower()):
                matches.append({'key': key, 'value': value})
        
        return matches 