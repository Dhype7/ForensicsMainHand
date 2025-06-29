"""Classical Cryptography Ciphers Implementation"""

class BinaryCipher:
    """Binary cipher for text/binary/ASCII/hex conversions"""
    
    @staticmethod
    def text_to_binary(text: str) -> str:
        """Convert text to binary representation"""
        binary = ""
        for char in text:
            binary += format(ord(char), '08b') + " "
        return binary.strip()
    
    @staticmethod
    def binary_to_text(binary: str) -> str:
        """Convert binary representation back to text"""
        # Remove spaces and newlines
        binary = binary.replace(" ", "").replace("\n", "")
        
        # Check if input is empty
        if not binary:
            return "Error: Empty binary input"
        
        # Check if input contains only 0s and 1s
        if not all(bit in '01' for bit in binary):
            return "Error: Invalid binary input (must contain only 0s and 1s)"
        
        # Check if length is multiple of 8
        if len(binary) % 8 != 0:
            return f"Error: Binary length ({len(binary)}) is not a multiple of 8"
        
        text = ""
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            try:
                char_code = int(byte, 2)
                # Check if character code is valid
                if 0 <= char_code <= 255:
                    text += chr(char_code)
                else:
                    text += f"[INVALID:{char_code}]"
            except ValueError:
                text += "[ERROR]"
        
        return text
    
    @staticmethod
    def text_to_ascii(text: str) -> str:
        """Convert text to ASCII decimal representation"""
        ascii_values = []
        for char in text:
            ascii_values.append(str(ord(char)))
        return " ".join(ascii_values)
    
    @staticmethod
    def ascii_to_text(ascii_str: str) -> str:
        """Convert ASCII decimal representation back to text"""
        try:
            ascii_values = ascii_str.split()
            text = ""
            for value in ascii_values:
                try:
                    char_code = int(value)
                    if 0 <= char_code <= 255:
                        text += chr(char_code)
                    else:
                        text += "?"
                except ValueError:
                    text += "?"
            return text
        except:
            return "Invalid ASCII input"
    
    @staticmethod
    def text_to_hex(text: str) -> str:
        """Convert text to hexadecimal representation"""
        hex_values = []
        for char in text:
            hex_values.append(format(ord(char), '02x'))
        return " ".join(hex_values)
    
    @staticmethod
    def hex_to_text(hex_str: str) -> str:
        """Convert hexadecimal representation back to text"""
        try:
            hex_values = hex_str.replace(" ", "").replace("\n", "")
            text = ""
            
            for i in range(0, len(hex_values), 2):
                if i + 2 <= len(hex_values):
                    hex_byte = hex_values[i:i+2]
                    try:
                        char_code = int(hex_byte, 16)
                        text += chr(char_code)
                    except ValueError:
                        text += "?"
            
            return text
        except UnicodeDecodeError:
            return "Decryption failed - invalid data"
        except ValueError:
            return "Invalid hex input"
    
    @staticmethod
    def binary_to_hex(binary: str) -> str:
        """Convert binary to hexadecimal"""
        # First convert binary to text, then to hex
        text = BinaryCipher.binary_to_text(binary)
        return BinaryCipher.text_to_hex(text)
    
    @staticmethod
    def hex_to_binary(hex_str: str) -> str:
        """Convert hexadecimal to binary"""
        # First convert hex to text, then to binary
        text = BinaryCipher.hex_to_text(hex_str)
        return BinaryCipher.text_to_binary(text)
    
    @staticmethod
    def ascii_to_binary(ascii_str: str) -> str:
        """Convert ASCII to binary"""
        # First convert ASCII to text, then to binary
        text = BinaryCipher.ascii_to_text(ascii_str)
        return BinaryCipher.text_to_binary(text)
    
    @staticmethod
    def binary_to_ascii(binary: str) -> str:
        """Convert binary to ASCII"""
        # First convert binary to text, then to ASCII
        text = BinaryCipher.binary_to_text(binary)
        return BinaryCipher.text_to_ascii(text)

class XORCipher:
    """XOR cipher for text encryption/decryption"""
    
    @staticmethod
    def xor_encrypt(text: str, key: str) -> str:
        """Encrypt text using XOR with a key"""
        if not key:
            raise ValueError("Key cannot be empty")
        
        # Convert text and key to bytes
        text_bytes = text.encode('utf-8')
        key_bytes = key.encode('utf-8')
        
        # Perform XOR operation
        encrypted_bytes = bytearray()
        for i, byte in enumerate(text_bytes):
            key_byte = key_bytes[i % len(key_bytes)]  # Repeat key if needed
            encrypted_bytes.append(byte ^ key_byte)
        
        # Convert back to hex string for display
        return ' '.join(f'{b:02x}' for b in encrypted_bytes)
    
    @staticmethod
    def xor_decrypt(hex_text: str, key: str) -> str:
        """Decrypt XOR encrypted text using a key"""
        if not key:
            raise ValueError("Key cannot be empty")
        
        try:
            # Convert hex string back to bytes
            hex_values = hex_text.replace(" ", "").replace("\n", "")
            encrypted_bytes = bytes.fromhex(hex_values)
            
            # Convert key to bytes
            key_bytes = key.encode('utf-8')
            
            # Perform XOR operation (same as encryption)
            decrypted_bytes = bytearray()
            for i, byte in enumerate(encrypted_bytes):
                key_byte = key_bytes[i % len(key_bytes)]  # Repeat key if needed
                decrypted_bytes.append(byte ^ key_byte)
            
            # Convert back to text
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return "Decryption failed - invalid data"
        except ValueError:
            return "Invalid hex input"
    
    @staticmethod
    def xor_single_char_encrypt(text: str, key_char: str) -> str:
        """Encrypt text using XOR with a single character key"""
        if not key_char:
            raise ValueError("Key character cannot be empty")
        
        key_byte = ord(key_char)
        encrypted_bytes = bytearray()
        
        for char in text:
            encrypted_bytes.append(ord(char) ^ key_byte)
        
        # Convert to hex string
        return ' '.join(f'{b:02x}' for b in encrypted_bytes)
    
    @staticmethod
    def xor_single_char_decrypt(hex_text: str, key_char: str) -> str:
        """Decrypt XOR encrypted text using a single character key"""
        if not key_char:
            raise ValueError("Key character cannot be empty")
        
        try:
            # Convert hex string back to bytes
            hex_values = hex_text.replace(" ", "").replace("\n", "")
            encrypted_bytes = bytes.fromhex(hex_values)
            
            key_byte = ord(key_char)
            decrypted_chars = []
            
            for byte in encrypted_bytes:
                decrypted_chars.append(chr(byte ^ key_byte))
            
            return ''.join(decrypted_chars)
        except UnicodeDecodeError:
            return "Decryption failed - invalid data"
        except ValueError:
            return "Invalid hex input"
