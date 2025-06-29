"""
String Analysis Module
"""
import subprocess
import re
import os
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class StringAnalyzer:
    """String extraction and analysis"""
    
    def __init__(self):
        self.extracted_strings = []
        self.search_results = []
    
    def check_strings_available(self) -> bool:
        """Check if strings command is available on the system"""
        try:
            result = subprocess.run(['which', 'strings'], 
                                  capture_output=True, text=True, check=True)
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False
    
    def extract_strings(self, file_path: str, min_length: int = 4) -> Dict[str, Any]:
        """
        Extract printable strings from a file
        
        Args:
            file_path: Path to the file to analyze
            min_length: Minimum string length to extract
            
        Returns:
            Dictionary containing extraction results
        """
        result = {
            'success': False,
            'strings': [],
            'total_count': 0,
            'error': None
        }
        
        if not self.check_strings_available():
            result['error'] = "Strings command is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Run strings command
            command = ['strings', '-n', str(min_length), file_path]
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if process.returncode == 0:
                strings = process.stdout.strip().split('\n')
                # Filter out empty strings
                strings = [s for s in strings if s.strip()]
                
                result['success'] = True
                result['strings'] = strings
                result['total_count'] = len(strings)
                self.extracted_strings = strings
            else:
                result['error'] = f"Strings command error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "String extraction timed out"
        except Exception as e:
            result['error'] = f"Error during string extraction: {e}"
            logger.error(f"String extraction error: {e}")
        
        return result
    
    def search_strings(self, search_term: str, case_sensitive: bool = False) -> Dict[str, Any]:
        """
        Search extracted strings for a specific term
        
        Args:
            search_term: Term to search for
            case_sensitive: Whether search should be case sensitive
            
        Returns:
            Dictionary containing search results
        """
        result = {
            'success': False,
            'matches': [],
            'total_matches': 0,
            'search_term': search_term,
            'error': None
        }
        
        if not self.extracted_strings:
            result['error'] = "No strings extracted. Run extract_strings first."
            return result
        
        try:
            matches = []
            
            for string in self.extracted_strings:
                if case_sensitive:
                    if search_term in string:
                        matches.append(string)
                else:
                    if search_term.lower() in string.lower():
                        matches.append(string)
            
            result['success'] = True
            result['matches'] = matches
            result['total_matches'] = len(matches)
            self.search_results = matches
            
        except Exception as e:
            result['error'] = f"Error during string search: {e}"
            logger.error(f"String search error: {e}")
        
        return result
    
    def search_with_grep(self, file_path: str, search_term: str, 
                        case_sensitive: bool = False) -> Dict[str, Any]:
        """
        Search file using grep (more efficient for large files)
        
        Args:
            file_path: Path to the file to search
            search_term: Term to search for
            case_sensitive: Whether search should be case sensitive
            
        Returns:
            Dictionary containing search results
        """
        result = {
            'success': False,
            'matches': [],
            'total_matches': 0,
            'search_term': search_term,
            'error': None
        }
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Build grep command
            command = ['grep']
            
            if not case_sensitive:
                command.append('-i')
            
            command.extend(['-n', search_term, file_path])
            
            # Run grep command
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if process.returncode == 0:
                matches = process.stdout.strip().split('\n')
                matches = [m for m in matches if m.strip()]
                
                result['success'] = True
                result['matches'] = matches
                result['total_matches'] = len(matches)
            elif process.returncode == 1:
                # No matches found (grep returns 1 when no matches)
                result['success'] = True
                result['matches'] = []
                result['total_matches'] = 0
            else:
                result['error'] = f"Grep command error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Grep search timed out"
        except Exception as e:
            result['error'] = f"Error during grep search: {e}"
            logger.error(f"Grep search error: {e}")
        
        return result
    
    def find_patterns(self, pattern: str, regex: bool = False) -> Dict[str, Any]:
        """
        Find strings matching a specific pattern
        
        Args:
            pattern: Pattern to search for
            regex: Whether pattern is a regex
            
        Returns:
            Dictionary containing pattern matches
        """
        result = {
            'success': False,
            'matches': [],
            'total_matches': 0,
            'pattern': pattern,
            'error': None
        }
        
        if not self.extracted_strings:
            result['error'] = "No strings extracted. Run extract_strings first."
            return result
        
        try:
            matches = []
            
            if regex:
                # Use regex pattern
                try:
                    regex_pattern = re.compile(pattern, re.IGNORECASE)
                    for string in self.extracted_strings:
                        if regex_pattern.search(string):
                            matches.append(string)
                except re.error as e:
                    result['error'] = f"Invalid regex pattern: {e}"
                    return result
            else:
                # Use simple pattern matching
                pattern_lower = pattern.lower()
                for string in self.extracted_strings:
                    if pattern_lower in string.lower():
                        matches.append(string)
            
            result['success'] = True
            result['matches'] = matches
            result['total_matches'] = len(matches)
            
        except Exception as e:
            result['error'] = f"Error during pattern search: {e}"
            logger.error(f"Pattern search error: {e}")
        
        return result
    
    def categorize_strings(self) -> Dict[str, List[str]]:
        """
        Categorize extracted strings by type
        
        Returns:
            Dictionary with categorized strings
        """
        if not self.extracted_strings:
            return {}
        
        categories = {
            'URLs': [],
            'Email Addresses': [],
            'IP Addresses': [],
            'File Paths': [],
            'Commands': [],
            'Flags': [],
            'Hex Strings': [],
            'Base64': [],
            'Other': []
        }
        
        # URL pattern
        url_pattern = re.compile(r'https?://[^\s]+', re.IGNORECASE)
        
        # Email pattern
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        # IP address pattern
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        # File path patterns
        file_path_patterns = [
            r'/[^\s]+',  # Unix paths
            r'[A-Za-z]:\\[^\s]+',  # Windows paths
        ]
        
        # Command patterns
        command_patterns = [
            r'\b(ls|cd|pwd|cat|grep|find|chmod|chown|sudo|su|ssh|scp|wget|curl)\b',
            r'\b(if|for|while|do|done|then|else|fi|case|esac)\b',
            r'\b(function|def|class|import|from|return|print|echo)\b'
        ]
        
        # Flag patterns
        flag_patterns = [
            r'FLAG\{[^}]*\}',
            r'flag\{[^}]*\}',
            r'CTF\{[^}]*\}',
            r'ctf\{[^}]*\}'
        ]
        
        # Hex string pattern
        hex_pattern = re.compile(r'\b[A-Fa-f0-9]{8,}\b')
        
        # Base64 pattern
        base64_pattern = re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b')
        
        for string in self.extracted_strings:
            categorized = False
            
            # Check URLs
            if url_pattern.search(string):
                categories['URLs'].append(string)
                categorized = True
            
            # Check emails
            if email_pattern.search(string):
                categories['Email Addresses'].append(string)
                categorized = True
            
            # Check IP addresses
            if ip_pattern.search(string):
                categories['IP Addresses'].append(string)
                categorized = True
            
            # Check file paths
            for pattern in file_path_patterns:
                if re.search(pattern, string):
                    categories['File Paths'].append(string)
                    categorized = True
                    break
            
            # Check commands
            for pattern in command_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    categories['Commands'].append(string)
                    categorized = True
                    break
            
            # Check flags
            for pattern in flag_patterns:
                if re.search(pattern, string):
                    categories['Flags'].append(string)
                    categorized = True
                    break
            
            # Check hex strings
            if hex_pattern.search(string):
                categories['Hex Strings'].append(string)
                categorized = True
            
            # Check base64
            if base64_pattern.search(string):
                categories['Base64'].append(string)
                categorized = True
            
            # Add to Other if not categorized
            if not categorized:
                categories['Other'].append(string)
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def export_to_text(self, extraction_result: Dict[str, Any], 
                      search_result: Dict[str, Any] = None) -> str:
        """
        Export string analysis as formatted text
        
        Args:
            extraction_result: Result from extract_strings method
            search_result: Optional result from search methods
            
        Returns:
            Formatted text string
        """
        text_lines = []
        text_lines.append("=== String Analysis ===\n")
        
        if not extraction_result['success']:
            text_lines.append(f"Error: {extraction_result['error']}")
            return "\n".join(text_lines)
        
        # Extraction summary
        text_lines.append("--- String Extraction ---")
        text_lines.append(f"Total strings extracted: {extraction_result['total_count']}")
        text_lines.append("")
        
        # Search results
        if search_result and search_result['success']:
            text_lines.append(f"--- Search Results for '{search_result['search_term']}' ---")
            text_lines.append(f"Total matches: {search_result['total_matches']}")
            text_lines.append("")
            
            for i, match in enumerate(search_result['matches'][:50], 1):  # Limit to first 50
                text_lines.append(f"{i}. {match}")
            
            if len(search_result['matches']) > 50:
                text_lines.append(f"... and {len(search_result['matches']) - 50} more matches")
            text_lines.append("")
        
        # Categorized strings (first 20 of each category)
        categories = self.categorize_strings()
        if categories:
            text_lines.append("--- Categorized Strings ---")
            for category, strings in categories.items():
                text_lines.append(f"{category} ({len(strings)}):")
                for string in strings[:20]:  # Limit to first 20
                    text_lines.append(f"  {string}")
                if len(strings) > 20:
                    text_lines.append(f"  ... and {len(strings) - 20} more")
                text_lines.append("")
        
        return "\n".join(text_lines) 