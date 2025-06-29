"""
Crypto Analysis Module - Encoding and Cipher Decoding
"""
import base64
import binascii
import re
import string
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class CryptoAnalyzer:
    """Crypto analysis for various encodings and ciphers"""
    
    def __init__(self):
        self.decoded_results = []
        self.encoding_types = []
    
    def decode_base64(self, data: str) -> Dict[str, Any]:
        """
        Decode Base64 data
        
        Args:
            data: Base64 encoded string
            
        Returns:
            Dictionary containing decode results
        """
        result = {
            'success': False,
            'decoded': '',
            'encoding': 'base64',
            'error': None
        }
        
        try:
            # Try standard base64
            decoded = base64.b64decode(data).decode('utf-8')
            result['success'] = True
            result['decoded'] = decoded
        except Exception as e:
            try:
                # Try with padding
                data += '=' * (4 - len(data) % 4)
                decoded = base64.b64decode(data).decode('utf-8')
                result['success'] = True
                result['decoded'] = decoded
            except Exception as e2:
                result['error'] = f"Base64 decode failed: {str(e2)}"
        
        return result
    
    def decode_base32(self, data: str) -> Dict[str, Any]:
        """
        Decode Base32 data
        
        Args:
            data: Base32 encoded string
            
        Returns:
            Dictionary containing decode results
        """
        result = {
            'success': False,
            'decoded': '',
            'encoding': 'base32',
            'error': None
        }
        
        try:
            decoded = base64.b32decode(data.upper()).decode('utf-8')
            result['success'] = True
            result['decoded'] = decoded
        except Exception as e:
            result['error'] = f"Base32 decode failed: {str(e)}"
        
        return result
    
    def decode_hex(self, data: str) -> Dict[str, Any]:
        """
        Decode hexadecimal data
        
        Args:
            data: Hex encoded string
            
        Returns:
            Dictionary containing decode results
        """
        result = {
            'success': False,
            'decoded': '',
            'encoding': 'hex',
            'error': None
        }
        
        try:
            # Remove common hex prefixes
            data = data.replace('0x', '').replace('0X', '')
            decoded = binascii.unhexlify(data).decode('utf-8')
            result['success'] = True
            result['decoded'] = decoded
        except Exception as e:
            result['error'] = f"Hex decode failed: {str(e)}"
        
        return result
    
    def decode_rot13(self, data: str) -> Dict[str, Any]:
        """
        Decode ROT13 cipher
        
        Args:
            data: ROT13 encoded string
            
        Returns:
            Dictionary containing decode results
        """
        result = {
            'success': False,
            'decoded': '',
            'encoding': 'rot13',
            'error': None
        }
        
        try:
            decoded = data.translate(str.maketrans(
                string.ascii_lowercase + string.ascii_uppercase,
                string.ascii_lowercase[13:] + string.ascii_lowercase[:13] +
                string.ascii_uppercase[13:] + string.ascii_uppercase[:13]
            ))
            result['success'] = True
            result['decoded'] = decoded
        except Exception as e:
            result['error'] = f"ROT13 decode failed: {str(e)}"
        
        return result
    
    def decode_caesar(self, data: str, shift: Optional[int] = None) -> Dict[str, Any]:
        """
        Decode Caesar cipher with automatic shift detection
        
        Args:
            data: Caesar encoded string
            shift: Specific shift value (if None, tries all shifts)
            
        Returns:
            Dictionary containing decode results
        """
        result = {
            'success': False,
            'decoded': '',
            'encoding': 'caesar',
            'shift': shift,
            'error': None
        }
        
        try:
            if shift is not None:
                # Use specific shift
                decoded = self._caesar_shift(data, shift)
                result['success'] = True
                result['decoded'] = decoded
                result['shift'] = shift
            else:
                # Try all shifts and find the most likely one
                best_result = None
                best_score = 0
                
                for test_shift in range(26):
                    decoded = self._caesar_shift(data, test_shift)
                    score = self._score_text(decoded)
                    
                    if score > best_score:
                        best_score = score
                        best_result = {
                            'decoded': decoded,
                            'shift': test_shift
                        }
                
                if best_result:
                    result['success'] = True
                    result['decoded'] = best_result['decoded']
                    result['shift'] = best_result['shift']
                else:
                    result['error'] = "Could not find valid Caesar shift"
                    
        except Exception as e:
            result['error'] = f"Caesar decode failed: {str(e)}"
        
        return result
    
    def _caesar_shift(self, text: str, shift: int) -> str:
        """Apply Caesar shift to text"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - ascii_offset + shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        return result
    
    def _score_text(self, text: str) -> float:
        """Score text based on common English letter frequencies"""
        # Common English letter frequencies
        frequencies = {
            'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
            'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
            'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
            'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
            'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
        }
        
        score = 0.0
        text_lower = text.lower()
        
        for char in text_lower:
            if char in frequencies:
                score += frequencies[char]
        
        return score
    
    def decode_binary(self, data: str) -> Dict[str, Any]:
        """
        Decode binary data
        
        Args:
            data: Binary string (0s and 1s)
            
        Returns:
            Dictionary containing decode results
        """
        result = {
            'success': False,
            'decoded': '',
            'encoding': 'binary',
            'error': None
        }
        
        try:
            # Remove spaces and ensure it's binary
            data = data.replace(' ', '').replace('\n', '')
            if not all(bit in '01' for bit in data):
                result['error'] = "Invalid binary data"
                return result
            
            # Convert to bytes
            if len(data) % 8 != 0:
                result['error'] = "Binary data length must be multiple of 8"
                return result
            
            # Convert binary to bytes
            bytes_data = bytes(int(data[i:i+8], 2) for i in range(0, len(data), 8))
            
            # Try to decode as UTF-8
            decoded = bytes_data.decode('utf-8')
            result['success'] = True
            result['decoded'] = decoded
            
        except Exception as e:
            result['error'] = f"Binary decode failed: {str(e)}"
        
        return result
    
    def decode_morse(self, data: str) -> Dict[str, Any]:
        """
        Decode Morse code
        
        Args:
            data: Morse code string
            
        Returns:
            Dictionary containing decode results
        """
        result = {
            'success': False,
            'decoded': '',
            'encoding': 'morse',
            'error': None
        }
        
        # Morse code dictionary
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
            '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?', '-.-.--': '!',
            '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+', '-....-': '-',
            '..--.-': '_', '.-..-.': '"', '.----.': "'", '-..-.': '/', '-.--.': '(',
            '-.--.-': ')', '...-.-': 'End', '.-...': 'Wait'
        }
        
        try:
            # Normalize input
            data = data.replace('_', '-').replace('—', '-').replace('–', '-')
            data = data.replace('·', '.').replace('•', '.')
            
            # Split into words
            words = data.split('   ')  # Three spaces between words
            decoded_words = []
            
            for word in words:
                if not word.strip():
                    continue
                    
                # Split into letters
                letters = word.split(' ')
                decoded_letters = []
                
                for letter in letters:
                    if letter in morse_dict:
                        decoded_letters.append(morse_dict[letter])
                    else:
                        decoded_letters.append('?')
                
                decoded_words.append(''.join(decoded_letters))
            
            decoded = ' '.join(decoded_words)
            result['success'] = True
            result['decoded'] = decoded
            
        except Exception as e:
            result['error'] = f"Morse decode failed: {str(e)}"
        
        return result
    
    def auto_decode(self, data: str) -> Dict[str, Any]:
        """
        Automatically detect and decode various encodings
        
        Args:
            data: Data to decode
            
        Returns:
            Dictionary containing all decode attempts
        """
        result = {
            'success': False,
            'results': [],
            'best_match': None,
            'error': None
        }
        
        try:
            # Clean the data
            data = data.strip()
            
            # Try different decoding methods
            decode_attempts = []
            
            # Base64
            base64_result = self.decode_base64(data)
            if base64_result['success']:
                decode_attempts.append(base64_result)
            
            # Base32
            base32_result = self.decode_base32(data)
            if base32_result['success']:
                decode_attempts.append(base32_result)
            
            # Hex
            if re.match(r'^[0-9a-fA-F]+$', data.replace('0x', '').replace('0X', '')):
                hex_result = self.decode_hex(data)
                if hex_result['success']:
                    decode_attempts.append(hex_result)
            
            # ROT13
            rot13_result = self.decode_rot13(data)
            if rot13_result['success']:
                decode_attempts.append(rot13_result)
            
            # Caesar (only if it looks like text)
            if data.isalpha():
                caesar_result = self.decode_caesar(data)
                if caesar_result['success']:
                    decode_attempts.append(caesar_result)
            
            # Binary
            if re.match(r'^[01\s\n]+$', data):
                binary_result = self.decode_binary(data)
                if binary_result['success']:
                    decode_attempts.append(binary_result)
            
            # Morse
            if re.match(r'^[.\-_\s]+$', data):
                morse_result = self.decode_morse(data)
                if morse_result['success']:
                    decode_attempts.append(morse_result)
            
            if decode_attempts:
                result['success'] = True
                result['results'] = decode_attempts
                
                # Find best match (highest score for text-based decodings)
                best_score = 0
                for attempt in decode_attempts:
                    if attempt['encoding'] in ['caesar', 'rot13']:
                        score = self._score_text(attempt['decoded'])
                        if score > best_score:
                            best_score = score
                            result['best_match'] = attempt
                
                # If no best match found, use first successful result
                if not result['best_match'] and decode_attempts:
                    result['best_match'] = decode_attempts[0]
            else:
                result['error'] = "No successful decodings found"
                
        except Exception as e:
            result['error'] = f"Auto-decode failed: {str(e)}"
        
        return result
    
    def search_for_flags(self, decoded_text: str) -> List[str]:
        """
        Search decoded text for potential CTF flags
        
        Args:
            decoded_text: Text to search
            
        Returns:
            List of potential flags found
        """
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'key\{[^}]+\}',
            r'KEY\{[^}]+\}',
            r'picoctf\{[^}]+\}',
            r'PICOCTF\{[^}]+\}',
            r'flag:[^\s]+',
            r'FLAG:[^\s]+',
            r'ctf:[^\s]+',
            r'CTF:[^\s]+'
        ]
        
        flags_found = []
        for pattern in flag_patterns:
            flags = re.findall(pattern, decoded_text, re.IGNORECASE)
            flags_found.extend(flags)
        
        return flags_found
    
    def export_to_text(self, decode_result: Dict[str, Any]) -> str:
        """Export decode results to formatted text"""
        if not decode_result.get('success'):
            return f"Crypto Analysis failed: {decode_result.get('error', 'Unknown error')}"
        
        output = []
        output.append("=" * 60)
        output.append("CRYPTO ANALYSIS RESULTS")
        output.append("=" * 60)
        output.append("")
        
        if decode_result.get('best_match'):
            best = decode_result['best_match']
            output.append(f"🎯 Best Match: {best['encoding'].upper()}")
            if 'shift' in best:
                output.append(f"   Shift: {best['shift']}")
            output.append(f"   Decoded: {best['decoded']}")
            output.append("")
        
        output.append("📋 All Decode Attempts:")
        output.append("-" * 30)
        
        for i, attempt in enumerate(decode_result.get('results', []), 1):
            output.append(f"{i}. {attempt['encoding'].upper()}")
            if 'shift' in attempt:
                output.append(f"   Shift: {attempt['shift']}")
            output.append(f"   Result: {attempt['decoded']}")
            output.append("")
        
        return "\n".join(output) 