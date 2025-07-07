"""
Input Validation Utilities
"""
import re
from typing import Any, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class ValidationUtils:
    """Input validation utilities"""
    
    @classmethod
    def validate_file_path(cls, file_path: str) -> Tuple[bool, str]:
        """
        Validate file path
        
        Args:
            file_path: Path to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not file_path:
            return False, "File path is empty"
        
        if not isinstance(file_path, str):
            return False, "File path must be a string"
        
        # Check for basic path validity
        if len(file_path) > 4096:  # Maximum path length on most systems
            return False, "File path is too long"
        
        # Check for invalid characters (basic check)
        invalid_chars = ['<', '>', ':', '"', '|', '?', '*']
        for char in invalid_chars:
            if char in file_path:
                return False, f"File path contains invalid character: {char}"
        
        return True, ""
    
    @classmethod
    def validate_password(cls, password: str) -> Tuple[bool, str]:
        """
        Validate password strength
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not password:
            return False, "Password is empty"
        
        if len(password) < 3:
            return False, "Password must be at least 3 characters long"
        
        if len(password) > 100:
            return False, "Password is too long"
        
        return True, ""
    
    @classmethod
    def validate_search_term(cls, search_term: str) -> Tuple[bool, str]:
        """
        Validate search term
        
        Args:
            search_term: Search term to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not search_term:
            return False, "Search term is empty"
        
        if len(search_term) < 1:
            return False, "Search term must be at least 1 character long"
        
        if len(search_term) > 200:
            return False, "Search term is too long"
        
        return True, ""
    
    @classmethod
    def validate_coordinates(cls, latitude: float, longitude: float) -> Tuple[bool, str]:
        """
        Validate GPS coordinates
        
        Args:
            latitude: Latitude value
            longitude: Longitude value
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            lat = float(latitude)
            lon = float(longitude)
            
            if not (-90 <= lat <= 90):
                return False, "Latitude must be between -90 and 90 degrees"
            
            if not (-180 <= lon <= 180):
                return False, "Longitude must be between -180 and 180 degrees"
            
            return True, ""
            
        except (ValueError, TypeError):
            return False, "Coordinates must be valid numbers"
    
    @classmethod
    def validate_email(cls, email: str) -> Tuple[bool, str]:
        """
        Validate email address format
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not email:
            return False, "Email address is empty"
        
        # Basic email regex pattern
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(pattern, email):
            return False, "Invalid email address format"
        
        return True, ""
    
    @classmethod
    def validate_url(cls, url: str) -> Tuple[bool, str]:
        """
        Validate URL format
        
        Args:
            url: URL to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url:
            return False, "URL is empty"
        
        # Basic URL regex pattern
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        
        if not re.match(pattern, url):
            return False, "Invalid URL format"
        
        return True, ""
    
    @classmethod
    def sanitize_input(cls, input_str: str, max_length: int = 1000) -> str:
        """
        Sanitize user input
        
        Args:
            input_str: Input string to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not input_str:
            return ""
        
        # Convert to string if needed
        input_str = str(input_str)
        
        # Truncate if too long
        if len(input_str) > max_length:
            input_str = input_str[:max_length]
        
        # Remove or replace potentially dangerous characters
        # This is a basic sanitization - adjust based on your needs
        dangerous_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        }
        
        for char, replacement in dangerous_chars.items():
            input_str = input_str.replace(char, replacement)
        
        return input_str
    
    @classmethod
    def validate_form_data(cls, form_data: Dict[str, Any], 
                          required_fields: List[str]) -> Tuple[bool, Dict[str, str]]:
        """
        Validate form data
        
        Args:
            form_data: Dictionary of form data
            required_fields: List of required field names
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = {}
        
        # Check required fields
        for field in required_fields:
            if field not in form_data or not form_data[field]:
                errors[field] = f"{field} is required"
        
        # Additional validation can be added here based on field types
        
        return len(errors) == 0, errors
    
    @classmethod
    def validate_file_size(cls, file_size: int, max_size_mb: int = 100) -> Tuple[bool, str]:
        """
        Validate file size
        
        Args:
            file_size: File size in bytes
            max_size_mb: Maximum allowed size in MB
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        max_size_bytes = max_size_mb * 1024 * 1024
        
        if file_size <= 0:
            return False, "File size must be greater than 0"
        
        if file_size > max_size_bytes:
            return False, f"File size exceeds maximum allowed size of {max_size_mb} MB"
        
        return True, ""
    
    @classmethod
    def validate_hex_string(cls, hex_string: str) -> Tuple[bool, str]:
        """
        Validate hex string format
        
        Args:
            hex_string: Hex string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not hex_string:
            return False, "Hex string is empty"
        
        # Check if string contains only hex characters
        if not re.match(r'^[0-9A-Fa-f]+$', hex_string):
            return False, "Hex string contains invalid characters"
        
        # Check if length is even (hex pairs)
        if len(hex_string) % 2 != 0:
            return False, "Hex string length must be even"
        
        return True, ""
    
    @classmethod
    def validate_base64_string(cls, base64_string: str) -> Tuple[bool, str]:
        """
        Validate base64 string format
        
        Args:
            base64_string: Base64 string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not base64_string:
            return False, "Base64 string is empty"
        
        # Basic base64 pattern (allows padding)
        pattern = r'^[A-Za-z0-9+/]*={0,2}$'
        
        if not re.match(pattern, base64_string):
            return False, "Invalid base64 string format"
        
        # Check padding
        if len(base64_string) % 4 != 0:
            return False, "Base64 string length must be divisible by 4"
        
        return True, ""
    
    @classmethod
    def validate_integer_range(cls, value: Any, min_val: int, max_val: int) -> Tuple[bool, str]:
        """
        Validate integer value within range
        
        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            int_value = int(value)
            
            if int_value < min_val:
                return False, f"Value must be at least {min_val}"
            
            if int_value > max_val:
                return False, f"Value must be at most {max_val}"
            
            return True, ""
            
        except (ValueError, TypeError):
            return False, "Value must be a valid integer" 