"""
Cryptography Module Main Window
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import sys
import re
import math
from typing import Dict, List, Tuple, Optional

from src.ui.theme import Theme
from src.ui.widgets import ModernButton
from src.config.settings import Settings
from src.modules.cryptography.classical_ciphers import BinaryCipher, XORCipher

class ClassicalCiphers:
    """Collection of classical cryptography ciphers"""
    
    @staticmethod
    def affine_encrypt(text: str, a: int, b: int) -> str:
        """Affine cipher encryption: E(x) = (ax + b) mod 26"""
        if math.gcd(a, 26) != 1:
            raise ValueError("'a' must be coprime with 26")
        
        result = ""
        for char in text.upper():
            if char.isalpha():
                x = ord(char) - ord('A')
                encrypted = (a * x + b) % 26
                result += chr(encrypted + ord('A'))
            else:
                result += char
        return result
    
    @staticmethod
    def affine_decrypt(text: str, a: int, b: int) -> str:
        """Affine cipher decryption: D(x) = a^(-1)(x - b) mod 26"""
        if math.gcd(a, 26) != 1:
            raise ValueError("'a' must be coprime with 26")
        
        # Find modular multiplicative inverse of a
        a_inv = pow(a, -1, 26)
        
        result = ""
        for char in text.upper():
            if char.isalpha():
                x = ord(char) - ord('A')
                decrypted = (a_inv * (x - b)) % 26
                result += chr(decrypted + ord('A'))
            else:
                result += char
        return result
    
    @staticmethod
    def atbash_encrypt(text: str) -> str:
        """Atbash cipher encryption/decryption (self-inverse)"""
        result = ""
        for char in text:
            if char.isupper():
                result += chr(90 - (ord(char) - 65))  # Z - (char - A)
            elif char.islower():
                result += chr(122 - (ord(char) - 97))  # z - (char - a)
            else:
                result += char
        return result
    
    @staticmethod
    def atbash_decrypt(text: str) -> str:
        """Atbash cipher decryption (same as encryption)"""
        return ClassicalCiphers.atbash_encrypt(text)
    
    @staticmethod
    def bacon_encrypt(text: str) -> str:
        """Bacon cipher encryption"""
        bacon_dict = {
            'A': 'aaaaa', 'B': 'aaaab', 'C': 'aaaba', 'D': 'aaabb', 'E': 'aabaa',
            'F': 'aabab', 'G': 'aabba', 'H': 'aabbb', 'I': 'abaaa', 'J': 'abaab',
            'K': 'ababa', 'L': 'ababb', 'M': 'abbaa', 'N': 'abbab', 'O': 'abbba',
            'P': 'abbbb', 'Q': 'baaaa', 'R': 'baaab', 'S': 'baaba', 'T': 'baabb',
            'U': 'babaa', 'V': 'babab', 'W': 'babba', 'X': 'babbb', 'Y': 'bbaaa',
            'Z': 'bbaab'
        }
        
        result = ""
        for char in text.upper():
            if char.isalpha():
                result += bacon_dict.get(char, char)
            else:
                result += char
        return result
    
    @staticmethod
    def bacon_decrypt(text: str) -> str:
        """Bacon cipher decryption"""
        bacon_dict = {
            'aaaaa': 'A', 'aaaab': 'B', 'aaaba': 'C', 'aaabb': 'D', 'aabaa': 'E',
            'aabab': 'F', 'aabba': 'G', 'aabbb': 'H', 'abaaa': 'I', 'abaab': 'J',
            'ababa': 'K', 'ababb': 'L', 'abbaa': 'M', 'abbab': 'N', 'abbba': 'O',
            'abbbb': 'P', 'baaaa': 'Q', 'baaab': 'R', 'baaba': 'S', 'baabb': 'T',
            'babaa': 'U', 'babab': 'V', 'babba': 'W', 'babbb': 'X', 'bbaaa': 'Y',
            'bbaab': 'Z'
        }
        
        # Remove non-a/b characters and group by 5
        clean_text = re.sub(r'[^abAB]', '', text.lower())
        result = ""
        
        for i in range(0, len(clean_text), 5):
            group = clean_text[i:i+5]
            if len(group) == 5:
                result += bacon_dict.get(group, '?')
            else:
                break
        return result
    
    @staticmethod
    def caesar_encrypt(text: str, shift: int) -> str:
        """Caesar cipher encryption"""
        result = ""
        for char in text:
            if char.isupper():
                result += chr((ord(char) - 65 + shift) % 26 + 65)
            elif char.islower():
                result += chr((ord(char) - 97 + shift) % 26 + 97)
            else:
                result += char
        return result
    
    @staticmethod
    def caesar_decrypt(text: str, shift: int) -> str:
        """Caesar cipher decryption"""
        return ClassicalCiphers.caesar_encrypt(text, -shift)
    
    @staticmethod
    def playfair_encrypt(text: str, key: str) -> str:
        """Playfair cipher encryption"""
        # Create Playfair matrix
        matrix = ClassicalCiphers._create_playfair_matrix(key)
        
        # Prepare text (remove spaces, add X for double letters)
        text = re.sub(r'[^A-Za-z]', '', text.upper())
        if len(text) % 2 == 1:
            text += 'X'
        
        # Process text in pairs
        result = ""
        for i in range(0, len(text), 2):
            pair = text[i:i+2]
            if len(pair) == 2:
                encrypted_pair = ClassicalCiphers._playfair_encrypt_pair(pair, matrix)
                result += encrypted_pair
        
        return result
    
    @staticmethod
    def playfair_decrypt(text: str, key: str) -> str:
        """Playfair cipher decryption"""
        matrix = ClassicalCiphers._create_playfair_matrix(key)
        
        result = ""
        for i in range(0, len(text), 2):
            pair = text[i:i+2]
            if len(pair) == 2:
                decrypted_pair = ClassicalCiphers._playfair_decrypt_pair(pair, matrix)
                result += decrypted_pair
        
        return result
    
    @staticmethod
    def _create_playfair_matrix(key: str) -> List[List[str]]:
        """Create Playfair matrix from key"""
        # Remove duplicates and J, replace I with J
        key = re.sub(r'[^A-Za-z]', '', key.upper()).replace('J', 'I')
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No J
        
        # Fill matrix
        matrix = []
        used_chars = set()
        
        # Add key characters first
        for char in key:
            if char not in used_chars:
                matrix.append(char)
                used_chars.add(char)
        
        # Add remaining alphabet
        for char in alphabet:
            if char not in used_chars:
                matrix.append(char)
                used_chars.add(char)
        
        # Convert to 5x5 matrix
        return [matrix[i:i+5] for i in range(0, 25, 5)]
    
    @staticmethod
    def _playfair_encrypt_pair(pair: str, matrix: List[List[str]]) -> str:
        """Encrypt a pair of letters using Playfair rules"""
        a, b = pair[0], pair[1]
        if a == 'J': a = 'I'
        if b == 'J': b = 'I'
        
        # Find positions
        pos_a = ClassicalCiphers._find_in_matrix(a, matrix)
        pos_b = ClassicalCiphers._find_in_matrix(b, matrix)
        
        row_a, col_a = pos_a
        row_b, col_b = pos_b
        
        if row_a == row_b:  # Same row
            return matrix[row_a][(col_a + 1) % 5] + matrix[row_b][(col_b + 1) % 5]
        elif col_a == col_b:  # Same column
            return matrix[(row_a + 1) % 5][col_a] + matrix[(row_b + 1) % 5][col_b]
        else:  # Rectangle
            return matrix[row_a][col_b] + matrix[row_b][col_a]
    
    @staticmethod
    def _playfair_decrypt_pair(pair: str, matrix: List[List[str]]) -> str:
        """Decrypt a pair of letters using Playfair rules"""
        a, b = pair[0], pair[1]
        
        # Find positions
        pos_a = ClassicalCiphers._find_in_matrix(a, matrix)
        pos_b = ClassicalCiphers._find_in_matrix(b, matrix)
        
        row_a, col_a = pos_a
        row_b, col_b = pos_b
        
        if row_a == row_b:  # Same row
            return matrix[row_a][(col_a - 1) % 5] + matrix[row_b][(col_b - 1) % 5]
        elif col_a == col_b:  # Same column
            return matrix[(row_a - 1) % 5][col_a] + matrix[(row_b - 1) % 5][col_b]
        else:  # Rectangle
            return matrix[row_a][col_b] + matrix[row_b][col_a]
    
    @staticmethod
    def _find_in_matrix(char: str, matrix: List[List[str]]) -> Tuple[int, int]:
        """Find character position in matrix"""
        for i, row in enumerate(matrix):
            for j, cell in enumerate(row):
                if cell == char:
                    return i, j
        return 0, 0
    
    @staticmethod
    def rail_fence_encrypt(text: str, rails: int) -> str:
        """Rail fence cipher encryption"""
        if rails <= 1:
            return text
        
        # Create rails
        fence = [[''] * len(text) for _ in range(rails)]
        
        # Fill the fence
        rail = 0
        direction = 1
        
        for i, char in enumerate(text):
            fence[rail][i] = char
            rail += direction
            
            if rail == rails - 1:
                direction = -1
            elif rail == 0:
                direction = 1
        
        # Read the fence
        result = ""
        for row in fence:
            result += ''.join(row)
        
        return result
    
    @staticmethod
    def rail_fence_decrypt(text: str, rails: int) -> str:
        """Rail fence cipher decryption"""
        if rails <= 1:
            return text
        
        # Create fence pattern
        fence = [[''] * len(text) for _ in range(rails)]
        
        # Mark positions
        rail = 0
        direction = 1
        
        for i in range(len(text)):
            fence[rail][i] = '*'
            rail += direction
            
            if rail == rails - 1:
                direction = -1
            elif rail == 0:
                direction = 1
        
        # Fill with text
        text_index = 0
        for row_idx, row in enumerate(fence):
            for j, cell in enumerate(row):
                if cell == '*':
                    fence[row_idx][j] = text[text_index]
                    text_index += 1
        
        # Read the fence
        result = ""
        rail = 0
        direction = 1
        
        for i in range(len(text)):
            result += fence[rail][i]
            rail += direction
            
            if rail == rails - 1:
                direction = -1
            elif rail == 0:
                direction = 1
        
        return result
    
    @staticmethod
    def rot13_encrypt(text: str) -> str:
        """ROT13 encryption (self-inverse)"""
        return ClassicalCiphers.caesar_encrypt(text, 13)
    
    @staticmethod
    def rot13_decrypt(text: str) -> str:
        """ROT13 decryption (same as encryption)"""
        return ClassicalCiphers.rot13_encrypt(text)
    
    @staticmethod
    def scytale_encrypt(text: str, diameter: int) -> str:
        """Scytale cipher encryption"""
        if diameter <= 1:
            return text
        
        # Remove spaces and pad if necessary
        text = re.sub(r'\s', '', text)
        while len(text) % diameter != 0:
            text += 'X'
        
        # Create matrix
        rows = len(text) // diameter
        matrix = [[''] * diameter for _ in range(rows)]
        
        # Fill matrix row by row
        for i, char in enumerate(text):
            row = i // diameter
            col = i % diameter
            matrix[row][col] = char
        
        # Read column by column
        result = ""
        for col in range(diameter):
            for row in range(rows):
                result += matrix[row][col]
        
        return result
    
    @staticmethod
    def scytale_decrypt(text: str, diameter: int) -> str:
        """Scytale cipher decryption"""
        if diameter <= 1:
            return text
        
        # Calculate rows
        rows = len(text) // diameter
        if len(text) % diameter != 0:
            rows += 1
        
        # Create matrix
        matrix = [[''] * diameter for _ in range(rows)]
        
        # Fill matrix column by column
        text_index = 0
        for col in range(diameter):
            for row in range(rows):
                if text_index < len(text):
                    matrix[row][col] = text[text_index]
                    text_index += 1
        
        # Read row by row
        result = ""
        for row in matrix:
            result += ''.join(row)
        
        return result.rstrip('X')
    
    @staticmethod
    def substitution_encrypt(text: str, key: str) -> str:
        """Simple substitution cipher encryption"""
        if len(key) != 26:
            raise ValueError("Key must be exactly 26 characters")
        
        # Create mapping
        mapping = {}
        for i, char in enumerate(key.upper()):
            mapping[chr(65 + i)] = char
        
        result = ""
        for char in text:
            if char.isupper():
                result += mapping.get(char, char)
            elif char.islower():
                result += mapping.get(char.upper(), char).lower()
            else:
                result += char
        
        return result
    
    @staticmethod
    def substitution_decrypt(text: str, key: str) -> str:
        """Simple substitution cipher decryption"""
        if len(key) != 26:
            raise ValueError("Key must be exactly 26 characters")
        
        # Create reverse mapping
        mapping = {}
        for i, char in enumerate(key.upper()):
            mapping[char] = chr(65 + i)
        
        result = ""
        for char in text:
            if char.isupper():
                result += mapping.get(char, char)
            elif char.islower():
                result += mapping.get(char.upper(), char).lower()
            else:
                result += char
        
        return result
    
    @staticmethod
    def vigenere_encrypt(text: str, key: str) -> str:
        """Vigenère cipher encryption"""
        key = key.upper()
        result = ""
        key_index = 0
        
        for char in text:
            if char.isalpha():
                key_char = key[key_index % len(key)]
                shift = ord(key_char) - ord('A')
                
                if char.isupper():
                    result += chr((ord(char) - 65 + shift) % 26 + 65)
                else:
                    result += chr((ord(char) - 97 + shift) % 26 + 97)
                
                key_index += 1
            else:
                result += char
        
        return result
    
    @staticmethod
    def vigenere_decrypt(text: str, key: str) -> str:
        """Vigenère cipher decryption"""
        key = key.upper()
        result = ""
        key_index = 0
        
        for char in text:
            if char.isalpha():
                key_char = key[key_index % len(key)]
                shift = ord(key_char) - ord('A')
                
                if char.isupper():
                    result += chr((ord(char) - 65 - shift) % 26 + 65)
                else:
                    result += chr((ord(char) - 97 - shift) % 26 + 97)
                
                key_index += 1
            else:
                result += char
        
        return result

class CryptoMainWindow:
    """Main window for Cryptography module"""
    
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.theme_var = tk.StringVar(value=Theme.get_current_theme())
        self.ciphers = ClassicalCiphers()
        self.current_cipher = tk.StringVar(value="caesar")
        self.output_font_size = 10
        self.main_frame = None
        self.content_frame = None
        self.current_view = None
        self.status_label: Optional[tk.Label] = None
        self.cipher_desc_label: Optional[tk.Label] = None
        self.theme_combo = None
        self.footer_frame = None
        self.setup_window()
        self.show_main_choice()
        self.create_footer()
        self.apply_theme()
        
    def setup_window(self):
        """Setup main window properties"""
        self.root.title(f"Cryptography - {Settings.APP_NAME} v{Settings.APP_VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Configure window
        self.root.configure(bg=Theme.get_color('primary'))
        
        # Center window on screen
        self.center_window()
        
    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def clear_content(self):
        if self.content_frame:
            self.content_frame.destroy()
        self.content_frame = tk.Frame(self.root, bg=Theme.get_color('primary'))
        self.content_frame.pack(fill='both', expand=True)
        # Always keep footer at the bottom
        if self.footer_frame is not None:
            self.footer_frame.lift()

    def show_main_choice(self):
        self.clear_content()
        self.current_view = 'main_choice'
        label = tk.Label(self.content_frame, text="Choose Cryptography Type", font=Theme.get_font('title'), fg=Theme.get_color('accent'), bg=Theme.get_color('primary'))
        label.pack(pady=60)
        btn_frame = tk.Frame(self.content_frame, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=40)
        classical_btn = tk.Button(btn_frame, text="Classical", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), width=20, height=3, command=self.show_classical)
        classical_btn.pack(side='left', padx=40)
        advanced_btn = tk.Button(btn_frame, text="Advanced", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), width=20, height=3, command=self.show_advanced)
        advanced_btn.pack(side='left', padx=40)

    def show_classical(self):
        self.clear_content()
        self.current_view = 'classical'
        back_btn = tk.Button(self.content_frame, text="← Back", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'), command=self.show_main_choice)
        back_btn.pack(anchor='nw', padx=20, pady=20)
        self.create_classical_section(self.content_frame)

    def show_advanced(self):
        self.clear_content()
        self.current_view = 'advanced'
        self.create_advanced_section(self.content_frame)

    def create_classical_section(self, parent_frame):
        """Create classical ciphers section"""
        # Title with better styling
        title_frame = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        title_frame.pack(fill='x', padx=10, pady=(10, 5))
        
        title_label = tk.Label(title_frame, 
                              text="🔐 Classical Ciphers",
                              font=Theme.get_font('title'),
                              bg=Theme.get_color('secondary'),
                              fg=Theme.get_color('accent'))
        title_label.pack(side='left')
        
        # Cipher selection with better layout
        cipher_frame = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        cipher_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        tk.Label(cipher_frame, text="Select Cipher:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=Theme.get_font('default')).pack(anchor='w', pady=(0, 5))
        
        cipher_combo = ttk.Combobox(cipher_frame, 
                                   textvariable=self.current_cipher,
                                   values=[
                                       "caesar", "affine", "atbash", "bacon", "binary",
                                       "playfair", "rail_fence", "rot13", 
                                       "scytale", "substitution", "vigenere", "xor"
                                   ],
                                   state='readonly',
                                   width=20,
                                   font=('Arial', 10))
        cipher_combo.pack(anchor='w')
        cipher_combo.bind('<<ComboboxSelected>>', self.on_cipher_change)
        
        # Description label
        self.cipher_desc_label = tk.Label(cipher_frame, 
                                         text="",
                                         bg=Theme.get_color('secondary'), 
                                         fg=Theme.get_color('text_secondary'),
                                         font=('Arial', 9),
                                         wraplength=300,
                                         justify='left')
        self.cipher_desc_label.pack(anchor='w', pady=(5, 0))
        
        # Parameters frame with better styling
        params_container = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        params_container.pack(fill='x', padx=10, pady=(0, 10))
        
        params_title = tk.Label(params_container, text="Parameters:", 
                               bg=Theme.get_color('secondary'), 
                               fg=Theme.get_color('text_primary'),
                               font=Theme.get_font('default'))
        params_title.pack(anchor='w', pady=(0, 5))
        
        self.params_frame = tk.Frame(params_container, bg=Theme.get_color('secondary'))
        self.params_frame.pack(fill='x')
        
        # Input/Output frame with better organization
        io_container = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        io_container.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Input section
        self.input_container = tk.Frame(io_container, bg=Theme.get_color('secondary'))
        self.input_container.pack(side='left', fill='both', expand=True, padx=(0, 5))
        # Input header
        input_header = tk.Frame(self.input_container, bg=Theme.get_color('secondary'))
        input_header.pack(fill='x', pady=(0, 5))
        tk.Label(input_header, text="📝 Input Text", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=Theme.get_font('default')).pack(side='left')
        # Input buttons with better styling
        input_buttons_frame = tk.Frame(self.input_container, bg=Theme.get_color('secondary'))
        input_buttons_frame.pack(fill='x', pady=(0, 5))
        ModernButton(input_buttons_frame, text="📁 Load File", 
                    command=self.load_file, style='secondary').pack(side='left', padx=(0, 5))
        ModernButton(input_buttons_frame, text="🧹 Clear", 
                    command=self.clear_input, style='secondary').pack(side='left', padx=(0, 5))
        ModernButton(input_buttons_frame, text="💡 Example", 
                    command=self.load_example, style='secondary').pack(side='left')
        # Input text area with better styling
        self.input_text_area = scrolledtext.ScrolledText(self.input_container, 
                                                        height=10, 
                                                        width=30,
                                                        font=('Courier', 10),
                                                        bg='white',
                                                        fg='black',
                                                        insertbackground='black',
                                                        selectbackground='lightblue')
        self.input_text_area.pack(fill='both', expand=True)
        
        # Output section
        output_container = tk.Frame(io_container, bg=Theme.get_color('secondary'))
        output_container.pack(side='right', fill='both', expand=True, padx=(5, 0))
        
        # Output header
        output_header = tk.Frame(output_container, bg=Theme.get_color('secondary'))
        output_header.pack(fill='x', pady=(0, 5))
        
        tk.Label(output_header, text="🔓 Output Text", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=Theme.get_font('default')).pack(side='left')
        
        # Output buttons with better styling
        output_buttons_frame = tk.Frame(output_container, bg=Theme.get_color('secondary'))
        output_buttons_frame.pack(fill='x', pady=(0, 5))
        
        ModernButton(output_buttons_frame, text="💾 Save File", 
                    command=self.save_file, style='secondary').pack(side='left', padx=(0, 5))
        ModernButton(output_buttons_frame, text="🧹 Clear", 
                    command=self.clear_output, style='secondary').pack(side='left', padx=(0, 5))
        ModernButton(output_buttons_frame, text="📋 Copy", 
                    command=self.copy_output, style='secondary').pack(side='left', padx=(0, 5))
        ModernButton(output_buttons_frame, text="🔍 Zoom In", 
                    command=self.zoom_in, style='secondary').pack(side='left', padx=(0, 5))
        ModernButton(output_buttons_frame, text="🔍 Zoom Out", 
                    command=self.zoom_out, style='secondary').pack(side='left')
        
        # Output text area with better styling - ALWAYS visible
        self.output_text_area = scrolledtext.ScrolledText(output_container, 
                                                         height=10, 
                                                         width=30,
                                                         font=('Courier', 10),
                                                         bg='white',
                                                         fg='black',
                                                         insertbackground='black',
                                                         selectbackground='lightblue')
        self.output_text_area.pack(fill='both', expand=True)
        
        # Action buttons with better styling
        self.action_frame = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        self.action_frame.pack(fill='x', padx=10, pady=(0, 10))
        ModernButton(self.action_frame, text="🔒 Encrypt", 
                    command=self.encrypt, style='primary').pack(side='left', padx=(0, 10))
        ModernButton(self.action_frame, text="🔓 Decrypt", 
                    command=self.decrypt, style='primary').pack(side='left', padx=(0, 10))
        ModernButton(self.action_frame, text="🔄 Swap", 
                    command=self.swap_text, style='secondary').pack(side='left')
        
        # Initialize parameters for first cipher
        self.on_cipher_change()
        
    def create_advanced_section(self, parent_frame):
        """Create advanced cryptography section with direct type selection"""
        # Title
        title_label = tk.Label(parent_frame, 
                              text="🔓 Advanced Crypto",
                              font=Theme.get_font('heading'),
                              bg=Theme.get_color('secondary'),
                              fg=Theme.get_color('accent'))
        title_label.pack(pady=(10, 20))

        # Button grid for advanced types
        btn_frame = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        btn_frame.pack(pady=10, padx=20, fill='both', expand=True)

        # List of (name, class) tuples for advanced types
        types = [
            ("RSA", "RSACryptoWindow"),
            ("AES", "AESCryptoWindow"),
            ("Blowfish", "BlowfishCryptoWindow"),
            ("DES", "DESCryptoWindow"),
            ("RC4", "RC4CryptoWindow"),
            ("Rail Fence", "RailFenceCryptoWindow"),
            ("Substitution", "SubstitutionCryptoWindow"),
            ("XOR", "XORCryptoWindow"),
            ("Playfair", "PlayfairCryptoWindow"),
            ("OTP", "OTPCryptoWindow"),
            ("Base64/32/16", "BaseCryptoWindow"),
            ("SHA-256", "SHA256CryptoWindow"),
            ("MD5", "MD5CryptoWindow"),
            ("HMAC", "HMACCryptoWindow"),
            ("Magic Hasher", "MagicHasherWindow"),
        ]

        # Dynamically import the advanced crypto classes
        import importlib
        adv_mod = importlib.import_module('modules.cryptography.advanced_crypto')

        # Create buttons in a grid
        columns = 3
        for idx, (name, cls_name) in enumerate(types):
            row = idx // columns
            col = idx % columns
            cls = getattr(adv_mod, cls_name)
            btn = tk.Button(
                btn_frame,
                text=name,
                font=Theme.get_font('button'),
                fg=Theme.get_color('text_primary'),
                bg=Theme.get_color('accent'),
                relief='flat',
                bd=0,
                padx=20,
                pady=15,
                width=18,
                command=lambda c=cls: c(self.root)
            )
            btn.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            btn_frame.grid_columnconfigure(col, weight=1)
        for r in range((len(types) + columns - 1) // columns):
            btn_frame.grid_rowconfigure(r, weight=1)

    def on_cipher_change(self, event=None):
        """Handle cipher selection change"""
        cipher = self.current_cipher.get()
        self.update_parameters(cipher)
        self.update_cipher_description(cipher)
        if self.status_label is not None:
            self.status_label.config(text=f"Selected {cipher} cipher - Ready to encrypt/decrypt")
    
    def update_cipher_description(self, cipher):
        """Update cipher description"""
        descriptions = {
            "caesar": "Simple substitution cipher that shifts each letter by a fixed number of positions in the alphabet.",
            "affine": "Advanced substitution cipher using the formula E(x) = (ax + b) mod 26. 'a' must be coprime with 26.",
            "atbash": "Simple substitution cipher that replaces each letter with its reverse in the alphabet (A↔Z, B↔Y, etc.).",
            "bacon": "Steganographic cipher that hides messages using binary patterns (A/B or 0/1).",
            "binary": "Binary conversion cipher that converts between text, binary, ASCII, and hexadecimal representations.",
            "playfair": "Digraphic substitution cipher using a 5x5 matrix. Handles letter pairs and is more secure than simple substitution.",
            "rail_fence": "Transposition cipher that writes the message in a zigzag pattern across multiple rails.",
            "rot13": "Simple substitution cipher that rotates the alphabet by 13 positions (A↔N, B↔O, etc.).",
            "scytale": "Ancient transposition cipher using a cylinder with a specific diameter to scramble text.",
            "substitution": "Simple substitution cipher where each letter is replaced by another letter from a 26-character key.",
            "vigenere": "Polyalphabetic substitution cipher using a repeating keyword to shift letters.",
            "xor": "Exclusive OR cipher that performs bitwise XOR operation on the input text."
        }
        if self.cipher_desc_label is not None:
            self.cipher_desc_label.config(text=descriptions.get(cipher, ""))
    
    def load_example(self):
        """Load example text for the selected cipher"""
        examples = {
            "caesar": "HELLO WORLD",
            "affine": "HELLO WORLD",
            "atbash": "HELLO WORLD",
            "bacon": "HELLO",
            "binary": "HELLO",
            "playfair": "HELLO WORLD",
            "rail_fence": "HELLO WORLD",
            "rot13": "HELLO WORLD",
            "scytale": "HELLO WORLD",
            "substitution": "HELLO WORLD",
            "vigenere": "HELLO WORLD",
            "xor": "HELLO WORLD"
        }
        
        cipher = self.current_cipher.get()
        example_text = examples.get(cipher, "Enter your text here...")
        self.input_text_area.delete(1.0, tk.END)
        self.input_text_area.insert(1.0, example_text)
    
    def clear_input(self):
        """Clear input text area"""
        self.input_text_area.delete(1.0, tk.END)
    
    def clear_output(self):
        """Clear output text area"""
        self.output_text_area.delete(1.0, tk.END)
    
    def copy_output(self):
        """Copy output text to clipboard"""
        output_text = self.output_text_area.get(1.0, tk.END).strip()
        if output_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(output_text)
            messagebox.showinfo("Copied", "Output text copied to clipboard!")
    
    def swap_text(self):
        """Swap input and output text"""
        input_text = self.input_text_area.get(1.0, tk.END).strip()
        output_text = self.output_text_area.get(1.0, tk.END).strip()
        
        self.input_text_area.delete(1.0, tk.END)
        self.output_text_area.delete(1.0, tk.END)
        
        self.input_text_area.insert(1.0, output_text)
        self.output_text_area.insert(1.0, input_text)

    def encrypt(self):
        """Encrypt the input text"""
        try:
            cipher = self.current_cipher.get()
            if self.status_label is not None:
                self.status_label.config(text=f"Encrypting with {cipher} cipher...")
            self.root.update()
            
            # Handle XOR cipher specially
            if cipher == "xor":
                # Check if XOR input areas exist
                if not hasattr(self, 'xor_input1_area') or not hasattr(self, 'xor_input2_area'):
                    messagebox.showerror("Error", "XOR input areas not found. Please select XOR cipher again.")
                    return
                
                # Get input from XOR areas
                input1 = self.xor_input1_area.get(1.0, tk.END).strip()
                input2 = self.xor_input2_area.get(1.0, tk.END).strip()
                
                # Validate inputs
                if not input1 or not input2:
                    messagebox.showwarning("Warning", "Please enter text in both XOR input areas.")
                    return
                
                try:
                    # Convert to bytes and perform XOR
                    b1 = input1.encode('utf-8')
                    b2 = input2.encode('utf-8')
                    min_len = min(len(b1), len(b2))
                    
                    if min_len == 0:
                        messagebox.showwarning("Warning", "At least one input is empty.")
                        return
                    
                    xor_bytes = bytes([x ^ y for x, y in zip(b1[:min_len], b2[:min_len])])
                    
                    # Always show hex for XOR results since they often contain non-printable characters
                    result = ' '.join(f'{b:02x}' for b in xor_bytes)
                    
                    # If all bytes are printable ASCII, also show the text version
                    try:
                        text_result = xor_bytes.decode('ascii')
                        if text_result.isprintable():
                            result = f"Text: {text_result}\nHex: {result}"
                    except:
                        pass  # Keep hex-only result
                    
                    # Update output
                    self.set_output_text(result)
                    if self.status_label is not None:
                        self.status_label.config(text=f"Successfully XORed inputs ({len(xor_bytes)} bytes)")
                    
                except Exception as e:
                    error_msg = f"XOR operation failed: {str(e)}"
                    self.set_output_text(error_msg)
                    if self.status_label is not None:
                        self.status_label.config(text="XOR operation failed")
                    messagebox.showerror("Error", error_msg)
                return
            
            # Handle other ciphers
            input_text = self.get_input_text()
            if not input_text:
                messagebox.showwarning("Warning", "Please enter some text to encrypt.")
                return
            
            result = ""
            if cipher == "caesar":
                shift = int(self.caesar_shift.get())
                result = self.ciphers.caesar_encrypt(input_text, shift)
            elif cipher == "affine":
                a = int(self.affine_a.get())
                b = int(self.affine_b.get())
                result = self.ciphers.affine_encrypt(input_text, a, b)
            elif cipher == "atbash":
                result = self.ciphers.atbash_encrypt(input_text)
            elif cipher == "bacon":
                result = self.ciphers.bacon_encrypt(input_text)
            elif cipher == "binary":
                result = self.handle_binary_conversion(input_text, "encrypt")
            elif cipher == "playfair":
                key = self.playfair_key.get()
                result = self.ciphers.playfair_encrypt(input_text, key)
            elif cipher == "rail_fence":
                rails = int(self.rail_fence_rails.get())
                result = self.ciphers.rail_fence_encrypt(input_text, rails)
            elif cipher == "rot13":
                result = self.ciphers.rot13_encrypt(input_text)
            elif cipher == "scytale":
                diameter = int(self.scytale_diameter.get())
                result = self.ciphers.scytale_encrypt(input_text, diameter)
            elif cipher == "substitution":
                key = self.substitution_key.get()
                result = self.ciphers.substitution_encrypt(input_text, key)
            elif cipher == "vigenere":
                key = self.vigenere_key.get()
                result = self.ciphers.vigenere_encrypt(input_text, key)
            
            self.set_output_text(result)
            if self.status_label is not None:
                self.status_label.config(text=f"Successfully encrypted with {cipher} cipher")
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid parameter: {str(e)}")
            if self.status_label is not None:
                self.status_label.config(text="Encryption failed - Invalid parameters")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            if self.status_label is not None:
                self.status_label.config(text="Encryption failed - Check input and parameters")
    
    def decrypt(self):
        """Decrypt the input text"""
        try:
            cipher = self.current_cipher.get()
            if self.status_label is not None:
                self.status_label.config(text=f"Decrypting with {cipher} cipher...")
            self.root.update()
            
            # For XOR, decryption is the same as encryption
            if cipher == "xor":
                self.encrypt()  # XOR is self-inverse
                return
            
            input_text = self.get_input_text()
            if not input_text:
                messagebox.showwarning("Warning", "Please enter some text to decrypt.")
                return
            
            result = ""
            if cipher == "caesar":
                shift = int(self.caesar_shift.get())
                result = self.ciphers.caesar_decrypt(input_text, shift)
            elif cipher == "affine":
                a = int(self.affine_a.get())
                b = int(self.affine_b.get())
                result = self.ciphers.affine_decrypt(input_text, a, b)
            elif cipher == "atbash":
                result = self.ciphers.atbash_decrypt(input_text)
            elif cipher == "bacon":
                result = self.ciphers.bacon_decrypt(input_text)
            elif cipher == "binary":
                result = self.handle_binary_conversion(input_text, "decrypt")
            elif cipher == "playfair":
                key = self.playfair_key.get()
                result = self.ciphers.playfair_decrypt(input_text, key)
            elif cipher == "rail_fence":
                rails = int(self.rail_fence_rails.get())
                result = self.ciphers.rail_fence_decrypt(input_text, rails)
            elif cipher == "rot13":
                result = self.ciphers.rot13_decrypt(input_text)
            elif cipher == "scytale":
                diameter = int(self.scytale_diameter.get())
                result = self.ciphers.scytale_decrypt(input_text, diameter)
            elif cipher == "substitution":
                key = self.substitution_key.get()
                result = self.ciphers.substitution_decrypt(input_text, key)
            elif cipher == "vigenere":
                key = self.vigenere_key.get()
                result = self.ciphers.vigenere_decrypt(input_text, key)
            
            self.set_output_text(result)
            if self.status_label is not None:
                self.status_label.config(text=f"Successfully decrypted with {cipher} cipher")
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid parameter: {str(e)}")
            if self.status_label is not None:
                self.status_label.config(text="Decryption failed - Invalid parameters")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            if self.status_label is not None:
                self.status_label.config(text="Decryption failed - Check input and parameters")

    def show_cipher_info(self):
        """Show information about the selected cipher"""
        # Implement the logic to show cipher information
        pass

    def get_input_text(self):
        """Get text from input area"""
        return self.input_text_area.get(1.0, tk.END).strip()
    
    def set_output_text(self, text):
        """Set text in output area"""
        self.output_text_area.delete(1.0, tk.END)
        self.output_text_area.insert(1.0, text)

    def update_parameters(self, cipher):
        """Update parameters for the selected cipher"""
        # Clear existing parameters
        for widget in self.params_frame.winfo_children():
            widget.destroy()
        
        # Handle XOR mode specially
        if cipher == "xor":
            # Hide the main input container for XOR mode
            if hasattr(self, 'input_container'):
                self.input_container.pack_forget()
            self.create_xor_vertical_input()
            return
        
        # For non-XOR ciphers, show regular input area
        if hasattr(self, 'input_container'):
            self.input_container.pack(side='left', fill='both', expand=True, padx=(0, 5))
        
        # Create parameters for other ciphers
        if cipher == "caesar":
            self.create_caesar_params()
        elif cipher == "affine":
            self.create_affine_params()
        elif cipher == "atbash":
            self.create_atbash_params()
        elif cipher == "bacon":
            self.create_bacon_params()
        elif cipher == "binary":
            self.create_binary_params()
        elif cipher == "playfair":
            self.create_playfair_params()
        elif cipher == "rail_fence":
            self.create_rail_fence_params()
        elif cipher == "rot13":
            self.create_rot13_params()
        elif cipher == "scytale":
            self.create_scytale_params()
        elif cipher == "substitution":
            self.create_substitution_params()
        elif cipher == "vigenere":
            self.create_vigenere_params()

    def create_caesar_params(self):
        """Create Caesar cipher parameters"""
        self.caesar_shift = tk.StringVar(value="3")
        
        param_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Shift:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        shift_entry = tk.Entry(param_frame, textvariable=self.caesar_shift, 
                              width=10, font=('Arial', 9))
        shift_entry.pack(side='left')
        
        # Add quick shift buttons
        for shift in [1, 3, 5, 13]:
            btn = tk.Button(param_frame, text=str(shift), 
                           command=lambda s=shift: self.caesar_shift.set(str(s)),
                           bg=Theme.get_color('accent'), fg='white',
                           font=('Arial', 8), relief='flat', padx=3)
            btn.pack(side='left', padx=2)
    
    def create_affine_params(self):
        """Create Affine cipher parameters"""
        self.affine_a = tk.StringVar(value="5")
        self.affine_b = tk.StringVar(value="8")
        
        param_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="a:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        a_entry = tk.Entry(param_frame, textvariable=self.affine_a, 
                          width=8, font=('Arial', 9))
        a_entry.pack(side='left', padx=(0, 10))
        
        tk.Label(param_frame, text="b:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        b_entry = tk.Entry(param_frame, textvariable=self.affine_b, 
                          width=8, font=('Arial', 9))
        b_entry.pack(side='left')
        
        # Add common values
        common_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        common_frame.pack(fill='x', pady=2)
        
        tk.Label(common_frame, text="Common values:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_secondary'),
                font=('Arial', 8)).pack(side='left', padx=(0, 5))
        
        for a, b in [(1, 3), (3, 5), (5, 8), (7, 11)]:
            btn = tk.Button(common_frame, text=f"({a},{b})", 
                           command=lambda a_val=a, b_val=b: (self.affine_a.set(str(a_val)), self.affine_b.set(str(b_val))),
                           bg=Theme.get_color('accent'), fg='white',
                           font=('Arial', 7), relief='flat', padx=3)
            btn.pack(side='left', padx=1)
    
    def create_atbash_params(self):
        """Create Atbash cipher parameters (none needed)"""
        info_label = tk.Label(self.params_frame, 
                             text="No parameters needed - self-inverse cipher",
                             bg=Theme.get_color('secondary'), 
                             fg=Theme.get_color('text_secondary'),
                             font=('Arial', 9, 'italic'))
        info_label.pack(pady=5)
    
    def create_bacon_params(self):
        """Create Bacon cipher parameters"""
        self.bacon_variant = tk.StringVar(value="standard")
        
        param_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Variant:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        variant_combo = ttk.Combobox(param_frame, textvariable=self.bacon_variant,
                                    values=["standard", "binary"],
                                    state='readonly', width=10, font=('Arial', 9))
        variant_combo.pack(side='left')
    
    def create_binary_params(self):
        """Create Binary cipher parameters"""
        self.binary_variant = tk.StringVar(value="text_to_binary")
        
        param_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Conversion Type:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        variant_combo = ttk.Combobox(param_frame, textvariable=self.binary_variant,
                                    values=[
                                        "text_to_binary", "binary_to_text",
                                        "text_to_ascii", "ascii_to_text",
                                        "text_to_hex", "hex_to_text",
                                        "binary_to_hex", "hex_to_binary",
                                        "ascii_to_binary", "binary_to_ascii"
                                    ],
                                    state='readonly', width=15, font=('Arial', 9))
        variant_combo.pack(side='left')
    
    def create_playfair_params(self):
        """Create Playfair cipher parameters"""
        self.playfair_key = tk.StringVar(value="MONARCHY")
        
        param_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Key:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        key_entry = tk.Entry(param_frame, textvariable=self.playfair_key, 
                            width=15, font=('Arial', 9))
        key_entry.pack(side='left')
        
        # Add common keys
        common_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        common_frame.pack(fill='x', pady=2)
        
        tk.Label(common_frame, text="Common keys:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_secondary'),
                font=('Arial', 8)).pack(side='left', padx=(0, 5))
        
        for key in ["MONARCHY", "PLAYFAIR", "SECRET"]:
            btn = tk.Button(common_frame, text=key, 
                           command=lambda k=key: self.playfair_key.set(k),
                           bg=Theme.get_color('accent'), fg='white',
                           font=('Arial', 7), relief='flat', padx=3)
            btn.pack(side='left', padx=1)
    
    def create_rail_fence_params(self):
        """Create Rail Fence cipher parameters"""
        self.rail_fence_rails = tk.StringVar(value="3")
        
        param_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Rails:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        rails_entry = tk.Entry(param_frame, textvariable=self.rail_fence_rails, 
                              width=8, font=('Arial', 9))
        rails_entry.pack(side='left')
        
        # Add common rail counts
        for rails in [2, 3, 4, 5]:
            btn = tk.Button(param_frame, text=str(rails), 
                           command=lambda r=rails: self.rail_fence_rails.set(str(r)),
                           bg=Theme.get_color('accent'), fg='white',
                           font=('Arial', 8), relief='flat', padx=3)
            btn.pack(side='left', padx=2)
    
    def create_rot13_params(self):
        """Create ROT13 cipher parameters (none needed)"""
        info_label = tk.Label(self.params_frame, 
                             text="No parameters needed - fixed 13-position shift",
                             bg=Theme.get_color('secondary'), 
                             fg=Theme.get_color('text_secondary'),
                             font=('Arial', 9, 'italic'))
        info_label.pack(pady=5)
    
    def create_scytale_params(self):
        """Create Scytale cipher parameters"""
        self.scytale_diameter = tk.StringVar(value="3")
        
        param_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Diameter:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        diameter_entry = tk.Entry(param_frame, textvariable=self.scytale_diameter, 
                                 width=8, font=('Arial', 9))
        diameter_entry.pack(side='left')
        
        # Add common diameters
        for diameter in [2, 3, 4, 5]:
            btn = tk.Button(param_frame, text=str(diameter), 
                           command=lambda d=diameter: self.scytale_diameter.set(str(d)),
                           bg=Theme.get_color('accent'), fg='white',
                           font=('Arial', 8), relief='flat', padx=3)
            btn.pack(side='left', padx=2)
    
    def create_substitution_params(self):
        """Create Substitution cipher parameters"""
        self.substitution_key = tk.StringVar(value="QWERTYUIOPASDFGHJKLZXCVBNM")
        
        param_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Key (26 chars):", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        key_entry = tk.Entry(param_frame, textvariable=self.substitution_key, 
                            width=30, font=('Arial', 9))
        key_entry.pack(side='left')
        
        # Add preset keys
        common_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        common_frame.pack(fill='x', pady=2)
        
        tk.Label(common_frame, text="Preset keys:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_secondary'),
                font=('Arial', 8)).pack(side='left', padx=(0, 5))
        
        preset_keys = [
            ("QWERTY", "QWERTYUIOPASDFGHJKLZXCVBNM"),
            ("REVERSE", "ZYXWVUTSRQPONMLKJIHGFEDCBA"),
            ("SHIFT+1", "BCDEFGHIJKLMNOPQRSTUVWXYZA")
        ]
        
        for name, key in preset_keys:
            btn = tk.Button(common_frame, text=name, 
                           command=lambda k=key: self.substitution_key.set(k),
                           bg=Theme.get_color('accent'), fg='white',
                           font=('Arial', 7), relief='flat', padx=3)
            btn.pack(side='left', padx=1)
    
    def create_vigenere_params(self):
        """Create Vigenère cipher parameters"""
        self.vigenere_key = tk.StringVar(value="KEY")
        
        param_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Key:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        key_entry = tk.Entry(param_frame, textvariable=self.vigenere_key, 
                            width=15, font=('Arial', 9))
        key_entry.pack(side='left')
        
        # Add common keys
        common_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        common_frame.pack(fill='x', pady=2)
        
        tk.Label(common_frame, text="Common keys:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_secondary'),
                font=('Arial', 8)).pack(side='left', padx=(0, 5))
        
        for key in ["KEY", "SECRET", "PASSWORD", "CRYPTO"]:
            btn = tk.Button(common_frame, text=key, 
                           command=lambda k=key: self.vigenere_key.set(k),
                           bg=Theme.get_color('accent'), fg='white',
                           font=('Arial', 7), relief='flat', padx=3)
            btn.pack(side='left', padx=1)

    def create_xor_vertical_input(self):
        """Create XOR input areas with two text inputs and file load buttons"""
        # Main XOR frame
        self.xor_input_frame = tk.Frame(self.params_frame, bg=Theme.get_color('secondary'))
        self.xor_input_frame.pack(fill='x', pady=(0, 10))
        
        # Input 1 section
        input1_frame = tk.Frame(self.xor_input_frame, bg=Theme.get_color('secondary'))
        input1_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(input1_frame, text="Input 1:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 10, 'bold')).pack(anchor='w', pady=(0, 5))
        
        self.xor_input1_area = scrolledtext.ScrolledText(
            input1_frame, 
            height=4, 
            width=50, 
            font=('Courier', 10),
            bg='white',
            fg='black',
            insertbackground='black',
            selectbackground='lightblue'
        )
        self.xor_input1_area.pack(fill='x', expand=True)
        
        ModernButton(input1_frame, text="📁 Load File", 
                    command=lambda: self.load_xor_file(self.xor_input1_area), 
                    style='secondary').pack(anchor='w', pady=(5, 0))
        
        # Input 2 section
        input2_frame = tk.Frame(self.xor_input_frame, bg=Theme.get_color('secondary'))
        input2_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(input2_frame, text="Input 2:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 10, 'bold')).pack(anchor='w', pady=(0, 5))
        
        self.xor_input2_area = scrolledtext.ScrolledText(
            input2_frame, 
            height=4, 
            width=50, 
            font=('Courier', 10),
            bg='white',
            fg='black',
            insertbackground='black',
            selectbackground='lightblue'
        )
        self.xor_input2_area.pack(fill='x', expand=True)
        
        ModernButton(input2_frame, text="📁 Load File", 
                    command=lambda: self.load_xor_file(self.xor_input2_area), 
                    style='secondary').pack(anchor='w', pady=(5, 0))
        
        # Result button
        result_frame = tk.Frame(self.xor_input_frame, bg=Theme.get_color('secondary'))
        result_frame.pack(fill='x', pady=(10, 0))
        
        ModernButton(result_frame, text="🔍 XOR Result", 
                    command=self.xor_result, 
                    style='primary').pack(anchor='w')

    def load_xor_file(self, text_area):
        file_path = filedialog.askopenfilename(title="Select File for XOR Input")
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                # Try to decode as text, fallback to hex
                try:
                    text = data.decode('utf-8')
                except UnicodeDecodeError:
                    text = ' '.join(f'{b:02x}' for b in data)
                text_area.delete(1.0, tk.END)
                text_area.insert(1.0, text)
            except Exception as e:
                messagebox.showerror("Error", f"Could not load file: {str(e)}")

    def xor_result(self):
        """Perform XOR operation and display result"""
        try:
            # Check if XOR input areas exist
            if not hasattr(self, 'xor_input1_area') or not hasattr(self, 'xor_input2_area'):
                messagebox.showerror("Error", "XOR input areas not found. Please select XOR cipher again.")
                return
            
            # Get input from XOR areas
            input1 = self.xor_input1_area.get(1.0, tk.END).strip()
            input2 = self.xor_input2_area.get(1.0, tk.END).strip()
            
            # Validate inputs
            if not input1 or not input2:
                messagebox.showwarning("Warning", "Please enter text in both XOR input areas.")
                return
            
            # Convert to bytes and perform XOR
            b1 = input1.encode('utf-8')
            b2 = input2.encode('utf-8')
            min_len = min(len(b1), len(b2))
            
            if min_len == 0:
                messagebox.showwarning("Warning", "At least one input is empty.")
                return
            
            xor_bytes = bytes([x ^ y for x, y in zip(b1[:min_len], b2[:min_len])])
            
            # Always show hex for XOR results since they often contain non-printable characters
            result = ' '.join(f'{b:02x}' for b in xor_bytes)
            
            # If all bytes are printable ASCII, also show the text version
            try:
                text_result = xor_bytes.decode('ascii')
                if text_result.isprintable():
                    result = f"Text: {text_result}\nHex: {result}"
            except:
                pass  # Keep hex-only result
            
            # Update output using the standard method
            self.set_output_text(result)
            if self.status_label is not None:
                self.status_label.config(text=f"XOR result computed ({len(xor_bytes)} bytes)")
            
        except Exception as e:
            error_msg = f"XOR operation failed: {str(e)}"
            self.set_output_text(error_msg)
            if self.status_label is not None:
                self.status_label.config(text="XOR operation failed")
            messagebox.showerror("Error", error_msg)

    def load_file(self):
        """Load text from file"""
        file_path = filedialog.askopenfilename(
            title="Load text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                self.input_text_area.delete(1.0, tk.END)
                self.input_text_area.insert(1.0, content)
                messagebox.showinfo("Success", "File loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Could not load file: {str(e)}")

    def save_file(self):
        """Save output text to file"""
        file_path = filedialog.asksaveasfilename(
            title="Save output text",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                content = self.output_text_area.get(1.0, tk.END)
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(content)
                messagebox.showinfo("Success", "File saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file: {str(e)}")

    def handle_binary_conversion(self, text, operation):
        """Handle binary conversion"""
        try:
            variant = getattr(self, 'binary_variant', tk.StringVar(value="text_to_binary")).get()
            
            if variant == "text_to_binary":
                result = BinaryCipher.text_to_binary(text)
            elif variant == "binary_to_text":
                result = BinaryCipher.binary_to_text(text)
            elif variant == "text_to_ascii":
                result = BinaryCipher.text_to_ascii(text)
            elif variant == "ascii_to_text":
                result = BinaryCipher.ascii_to_text(text)
            elif variant == "text_to_hex":
                result = BinaryCipher.text_to_hex(text)
            elif variant == "hex_to_text":
                result = BinaryCipher.hex_to_text(text)
            elif variant == "binary_to_hex":
                result = BinaryCipher.binary_to_hex(text)
            elif variant == "hex_to_binary":
                result = BinaryCipher.hex_to_binary(text)
            elif variant == "ascii_to_binary":
                result = BinaryCipher.ascii_to_binary(text)
            elif variant == "binary_to_ascii":
                result = BinaryCipher.binary_to_ascii(text)
            else:
                result = "Invalid conversion type"
            return result
        except Exception as e:
            error_msg = f"Conversion error: {str(e)}"
            return error_msg

    def zoom_in(self):
        """Increase output text font size by 1"""
        self.output_font_size += 1
        self.output_text_area.configure(font=('Courier', self.output_font_size))
    
    def zoom_out(self):
        """Decrease output text font size by 1"""
        if self.output_font_size > 6:  # Minimum font size of 6
            self.output_font_size -= 1
            self.output_text_area.configure(font=('Courier', self.output_font_size))

    def create_footer(self):
        self.footer_frame = tk.Frame(self.root, bg=Theme.get_color('primary'), height=30)
        self.footer_frame.pack(side='bottom', fill='x')
        self.footer_frame.pack_propagate(False)
        self.status_label = tk.Label(self.footer_frame, 
                                    text="Ready - Select a cipher to begin",
                                    bg=Theme.get_color('primary'),
                                    fg=Theme.get_color('text_primary'),
                                    font=('Arial', 9),
                                    anchor='w')
        self.status_label.pack(side='left', padx=10, pady=5)
        theme_frame = tk.Frame(self.footer_frame, bg=Theme.get_color('primary'))
        theme_frame.pack(side='right', padx=10, pady=5)
        tk.Label(theme_frame, text="Theme:", 
                bg=Theme.get_color('primary'),
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        self.theme_combo = ttk.Combobox(theme_frame, 
                                  textvariable=self.theme_var,
                                  values=Theme.get_available_themes(),
                                  state='readonly',
                                  width=10,
                                  font=('Arial', 9))
        self.theme_combo.pack(side='left')
        self.theme_combo.bind('<<ComboboxSelected>>', self.on_theme_change)

    def apply_theme(self):
        def update_widget_colors(widget):
            try:
                if isinstance(widget, tk.Label):
                    if widget.cget('bg') == Theme.get_color('secondary'):
                        widget.configure(bg=Theme.get_color('secondary'))
                    else:
                        widget.configure(bg=Theme.get_color('primary'))
                elif isinstance(widget, tk.Frame):
                    if widget.cget('bg') == Theme.get_color('secondary'):
                        widget.configure(bg=Theme.get_color('secondary'))
                    else:
                        widget.configure(bg=Theme.get_color('primary'))
            except tk.TclError:
                pass
            for child in widget.winfo_children():
                update_widget_colors(child)
        update_widget_colors(self.root)
        # Update footer colors
        if self.status_label is not None:
            self.status_label.configure(bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary'))
        if self.footer_frame is not None:
            self.footer_frame.configure(bg=Theme.get_color('primary'))
        if self.theme_combo is not None:
            self.theme_combo.configure(background=Theme.get_color('primary'), foreground=Theme.get_color('text_primary'))

    def on_theme_change(self, event=None):
        """Handle theme change from the theme combo box."""
        Theme.set_theme(self.theme_var.get())
        self.apply_theme()


def main():
    """Main function to run the crypto application"""
    root = tk.Tk()
    app = CryptoMainWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main() 