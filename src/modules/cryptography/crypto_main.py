"""
Cryptography Module Main Window
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import sys
import re
import math
from typing import Dict, List, Tuple, Optional, Callable

from src.ui.theme import Theme
from src.ui.widgets import ModernButton
from src.config.settings import Settings
from src.modules.cryptography.classical_ciphers import BinaryCipher, XORCipher

# Advanced crypto imports
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import binascii
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
import hashlib
import hmac
import string
from collections import Counter
import random
import secrets

try:
    from Crypto.Cipher import DES, Blowfish, ARC4  # type: ignore
    DES_AVAILABLE = True
except ImportError:
    DES_AVAILABLE = False

import string
import secrets
import wave
import numpy as np

MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
    '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
    ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
    '"': '.-..-.', '$': '...-..-', '@': '.--.-.', ' ': '/'
}
MORSE_CODE_DICT_REVERSE = {v: k for k, v in MORSE_CODE_DICT.items()}

def random_uppercase_word(length):
    return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(length))

def xor_brute_force_single_byte(ciphertext):
    results = []
    for key in range(256):
        pt = bytes([b ^ key for b in ciphertext])
        try:
            text = pt.decode('utf-8')
        except Exception:
            text = pt.decode('latin1', errors='replace')
        score = sum(32 <= c <= 126 for c in pt)  # printable ASCII
        results.append((key, text, score))
    results.sort(key=lambda x: -x[2])
    return results[:10]  # Top 10

def playfair_dictionary_attack(ciphertext, wordlist):
    results = []
    for key in wordlist:
        try:
            pt = ClassicalCiphers.playfair_decrypt(ciphertext, key)
            score = sum(c in string.ascii_letters + ' ' for c in pt)
            results.append((key, pt, score))
        except Exception:
            continue
    results.sort(key=lambda x: -x[2])
    return results[:10]

# Helper functions from advanced_crypto.py
def random_bytes(length):
    return os.urandom(length)

def random_ascii(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def random_alpha(length):
    return ''.join(random.choices(string.ascii_uppercase, k=length))

def random_substitution_key():
    alpha = list(string.ascii_uppercase)
    random.shuffle(alpha)
    return ''.join(alpha)

def frequency_analysis(text):
    text = ''.join(filter(str.isalpha, text.upper()))
    freq = Counter(text)
    total = sum(freq.values())
    return sorted([(char, count, count/total) for char, count in freq.items()], key=lambda x: -x[1])

def caesar_brute_force(ciphertext):
    results = []
    for shift in range(1, 26):
        decrypted = ''
        for char in ciphertext:
            if char.isupper():
                decrypted += chr((ord(char) - 65 - shift) % 26 + 65)
            elif char.islower():
                decrypted += chr((ord(char) - 97 - shift) % 26 + 97)
            else:
                decrypted += char
        results.append((shift, decrypted))
    return results

def rail_fence_brute_force(ciphertext, max_rails=10):
    results = []
    for rails in range(2, max_rails+1):
        try:
            results.append((rails, rail_fence_decrypt(ciphertext, rails)))
        except Exception:
            continue
    return results

def rail_fence_decrypt(text, rails):
    if rails <= 1:
        return text
    fence = [[''] * len(text) for _ in range(rails)]
    rail = 0
    direction = 1
    for i in range(len(text)):
        fence[rail][i] = '*'
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1
    text_index = 0
    for row_idx, row in enumerate(fence):
        for j, cell in enumerate(row):
            if cell == '*':
                fence[row_idx][j] = text[text_index]
                text_index += 1
    result = ''
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

class CryptoMainWindow(tk.Frame):
    """Main frame for Cryptography module"""
    def __init__(self, parent, back_callback: Callable[[], None], theme_change_callback=None, theme_var=None, *args, **kwargs) -> None:
        super().__init__(parent, *args, **kwargs)
        self.back_callback = back_callback
        self.theme_change_callback = theme_change_callback
        if theme_var is None:
            self.theme_var = tk.StringVar(value=Theme.get_current_theme())
        else:
            self.theme_var = theme_var
        self.theme_var.trace_add('write', self._on_external_theme_change)
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
        self.adv_font_size = 12  # Default font size for advanced section
        self.show_main_choice()
        self.create_footer()
        self.apply_theme()

    def clear_content(self):
        if self.content_frame:
            self.content_frame.destroy()
        self.content_frame = tk.Frame(self, bg=Theme.get_color('primary'))
        self.content_frame.pack(fill='both', expand=True)
        # Always keep footer at the bottom
        if self.footer_frame is not None:
            self.footer_frame.lift()

    def show_main_choice(self):
        self.clear_content()
        self.current_view = 'main_choice'
        # Back button at the top
        back_btn = tk.Button(self.content_frame, text="← Back", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'), command=self.back_callback)
        back_btn.pack(anchor='nw', padx=20, pady=20)
        # Title
        label = tk.Label(self.content_frame, text="Choose Cryptography Type", font=Theme.get_font('title'), fg=Theme.get_color('accent'), bg=Theme.get_color('primary'))
        label.pack(pady=(20, 10))
        # Large NYX logo between title and buttons
        try:
            from PIL import Image, ImageTk
            logo_img = Image.open("pics/Picsart_25-07-01_17-15-32-191.png")
            logo_img = logo_img.resize((140, 170), Image.Resampling.LANCZOS)
            logo = ImageTk.PhotoImage(logo_img)
            logo_label = tk.Label(self.content_frame, image=logo, bg=Theme.get_color('primary'))
            setattr(logo_label, "image", logo)
            logo_label.pack(pady=(0, 32))
        except Exception:
            logo_label = tk.Label(self.content_frame, text="NYX", font=("Arial", 54, "bold"), fg="#FFD600", bg=Theme.get_color('primary'))
            logo_label.pack(pady=(0, 32))
        # Card layout for buttons
        card_frame = tk.Frame(self.content_frame, bg=Theme.get_color('primary'))
        card_frame.pack(expand=True)
        # Classical Card
        classical_card = tk.Frame(card_frame, bg=Theme.get_color('secondary'), bd=2, relief='ridge', padx=30, pady=30)
        classical_card.grid(row=0, column=0, padx=40, pady=10, sticky='nsew')
        classical_emoji = tk.Label(classical_card, text="🏛️", font=("Arial", 48), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        classical_emoji.pack(pady=(0, 10))
        classical_btn = tk.Button(classical_card, text="Classical", font=("Segoe UI", 18, "bold"), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), width=12, height=2, command=self.show_classical, relief='raised', bd=2, cursor='hand2')
        classical_btn.pack(pady=(0, 10))
        classical_desc = tk.Label(classical_card, text="Explore classic ciphers like Caesar, Vigenère, Atbash, and more. Great for learning and CTFs!", font=("Segoe UI", 11), fg=Theme.get_color('text_secondary'), bg=Theme.get_color('secondary'), wraplength=260, justify='center')
        classical_desc.pack()
        # Advanced Card
        advanced_card = tk.Frame(card_frame, bg=Theme.get_color('secondary'), bd=2, relief='ridge', padx=30, pady=30)
        advanced_card.grid(row=0, column=1, padx=40, pady=10, sticky='nsew')
        advanced_emoji = tk.Label(advanced_card, text="🚀", font=("Arial", 48), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        advanced_emoji.pack(pady=(0, 10))
        advanced_btn = tk.Button(advanced_card, text="Advanced", font=("Segoe UI", 18, "bold"), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), width=12, height=2, command=self.show_advanced, relief='raised', bd=2, cursor='hand2')
        advanced_btn.pack(pady=(0, 10))
        advanced_desc = tk.Label(advanced_card, text="Modern crypto tools: AES, RSA, hashes, attacks, and more. For advanced users and real-world scenarios.", font=("Segoe UI", 11), fg=Theme.get_color('text_secondary'), bg=Theme.get_color('secondary'), wraplength=260, justify='center')
        advanced_desc.pack()
        # Make cards expand equally
        card_frame.grid_columnconfigure(0, weight=1)
        card_frame.grid_columnconfigure(1, weight=1)
        card_frame.grid_rowconfigure(0, weight=1)

    def show_classical(self):
        self.clear_content()
        self.current_view = 'classical'
        self.create_classical_section(self.content_frame)

    def show_advanced(self):
        self.clear_content()
        self.current_view = 'advanced'
        self.create_advanced_section(self.content_frame)

    def create_classical_section(self, parent_frame):
        """Create classical ciphers section (user-friendly redesign)"""
        # Back button
        back_btn = tk.Button(parent_frame, text="← Back", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'), command=self.show_main_choice)
        back_btn.pack(anchor='nw', padx=10, pady=10)
        # Title
        title_frame = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        title_frame.pack(fill='x', padx=10, pady=(10, 5))
        # NYX logo and Title (for main choice and section headers)
        from PIL import Image, ImageTk
        try:
            logo_img = Image.open("pics/Picsart_25-07-01_17-15-32-191.png")
            logo_img = logo_img.resize((32, 32), Image.Resampling.LANCZOS)
            logo = ImageTk.PhotoImage(logo_img)
            logo_label = tk.Label(title_frame, image=logo, bg=Theme.get_color('primary'))
            setattr(logo_label, "image", logo)  # Keep reference
            logo_label.pack(side='left', padx=(0, 8))
        except Exception:
            logo_label = tk.Label(title_frame, text="NYX", font=("Arial", 16, "bold"), fg="#FFD600", bg=Theme.get_color('primary'))
            logo_label.pack(side='left', padx=(0, 8))
        title_label = tk.Label(title_frame, 
                              text="🔐 Classical Ciphers",
                              font=Theme.get_font('title'),
                              bg=Theme.get_color('primary'),
                              fg=Theme.get_color('accent'))
        title_label.pack(side='left')
        # Cipher selection grid
        cipher_grid_frame = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        cipher_grid_frame.pack(fill='x', padx=10, pady=(10, 20))
        cipher_info = [
            ("caesar", "Caesar", "🔤", "Shifts each letter by a fixed number of positions."),
            ("affine", "Affine", "🔢", "Uses a linear function for substitution."),
            ("atbash", "Atbash", "🔁", "Reverses the alphabet (A↔Z, B↔Y, ...)."),
            ("bacon", "Bacon", "🥓", "Encodes text as binary patterns (A/B)."),
            ("binary", "Binary", "💾", "Converts between text, binary, ASCII, hex."),
            ("playfair", "Playfair", "🔲", "Digraph substitution using a 5x5 matrix."),
            ("rail_fence", "Rail Fence", "🚆", "Zigzag transposition cipher."),
            ("rot13", "Rot13", "🔄", "Shifts letters by 13 positions."),
            ("scytale", "Scytale", "🌀", "Transposition using a cylinder."),
            ("substitution", "Substitution", "🔀", "Each letter replaced by another from a key."),
            ("vigenere", "Vigenère", "🗝️", "Polyalphabetic substitution with a keyword."),
            ("xor", "XOR", "❌", "Bitwise XOR of two texts."),
        ]
        self.cipher_buttons = {}
        columns = 4
        for idx, (key, name, icon, shortdesc) in enumerate(cipher_info):
            row = idx // columns
            col = idx % columns
            btn = tk.Button(
                cipher_grid_frame,
                text=f"{icon}\n{name}",
                font=("Arial", 14, "bold"),
                width=10,
                height=2,
                relief='solid',
                bd=2,
                bg=Theme.get_color('primary'),
                fg=Theme.get_color('accent'),
                activebackground=Theme.get_color('accent'),
                activeforeground=Theme.get_color('primary'),
                command=lambda k=key: self.select_cipher_grid(k)
            )
            btn.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            self.cipher_buttons[key] = btn
            # Tooltip on hover
            btn.bind("<Enter>", lambda e, d=shortdesc: self.status_label.config(text=d) if self.status_label else None)
            btn.bind("<Leave>", lambda e: self.status_label.config(text="Ready - Select a cipher to begin") if self.status_label else None)
        for c in range(columns):
            cipher_grid_frame.grid_columnconfigure(c, weight=1)
        # Cipher parameter card area
        self.param_card_frame = tk.Frame(parent_frame, bg=Theme.get_color('primary'), bd=2, relief='groove')
        self.param_card_frame.pack(fill='x', padx=30, pady=(0, 20))
        # Input/Output/Action layout (unchanged, but with more spacing)
        io_container = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        io_container.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        # Input section
        self.input_container = tk.Frame(io_container, bg=Theme.get_color('secondary'))
        self.input_container.pack(side='left', fill='both', expand=True, padx=(0, 5))
        input_header = tk.Frame(self.input_container, bg=Theme.get_color('secondary'))
        input_header.pack(fill='x', pady=(0, 5))
        tk.Label(input_header, text="📝 Input Text", bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'), font=Theme.get_font('default')).pack(side='left')
        input_buttons_frame = tk.Frame(self.input_container, bg=Theme.get_color('secondary'))
        input_buttons_frame.pack(fill='x', pady=(0, 5))
        ModernButton(input_buttons_frame, text="📁 Load File", command=self.load_file, style='secondary').pack(side='left', padx=(0, 5))
        ModernButton(input_buttons_frame, text="🧹 Clear", command=self.clear_input, style='secondary').pack(side='left', padx=(0, 5))
        ModernButton(input_buttons_frame, text="💡 Example", command=self.load_example, style='secondary').pack(side='left')
        self.input_text_area = scrolledtext.ScrolledText(self.input_container, height=10, width=30, font=('Courier', 10), bg='white', fg='black', insertbackground='black', selectbackground='lightblue')
        self.input_text_area.pack(fill='both', expand=True)
        # Output section
        output_container = tk.Frame(io_container, bg=Theme.get_color('secondary'))
        output_container.pack(side='right', fill='both', expand=True, padx=(5, 0))
        output_header = tk.Frame(output_container, bg=Theme.get_color('secondary'))
        output_header.pack(fill='x', pady=(0, 5))
        tk.Label(output_header, text="🔓 Output Text", bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'), font=Theme.get_font('default')).pack(side='left')
        output_buttons_frame = tk.Frame(output_container, bg=Theme.get_color('secondary'))
        output_buttons_frame.pack(fill='x', pady=(0, 5))
        ModernButton(output_buttons_frame, text="💾 Save File", command=self.save_file, style='secondary').pack(side='left', padx=(0, 5))
        ModernButton(output_buttons_frame, text="🧹 Clear", command=self.clear_output, style='secondary').pack(side='left', padx=(0, 5))
        ModernButton(output_buttons_frame, text="📋 Copy", command=self.copy_output, style='secondary').pack(side='left', padx=(0, 5))
        self.output_text_area = scrolledtext.ScrolledText(output_container, height=10, width=30, font=('Courier', 10), bg='white', fg='black', insertbackground='black', selectbackground='lightblue')
        self.output_text_area.pack(fill='both', expand=True)
        # Action buttons
        self.action_frame = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        self.action_frame.pack(fill='x', padx=10, pady=(0, 10))
        ModernButton(self.action_frame, text="🔒 Encrypt", command=self.encrypt, style='primary').pack(side='left', padx=(0, 10))
        ModernButton(self.action_frame, text="🔓 Decrypt", command=self.decrypt, style='primary').pack(side='left', padx=(0, 10))
        ModernButton(self.action_frame, text="🔄 Swap", command=self.swap_text, style='secondary').pack(side='left')
        # Initialize with first cipher
        self.select_cipher_grid('caesar')

    def select_cipher_grid(self, cipher_key):
        """Handle cipher selection from the grid, update highlight and parameter card"""
        self.current_cipher.set(cipher_key)
        # Highlight selected button
        for key, btn in self.cipher_buttons.items():
            if key == cipher_key:
                btn.config(bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), relief='sunken')
            else:
                btn.config(bg=Theme.get_color('primary'), fg=Theme.get_color('accent'), relief='solid')
        # Update parameter card
        for widget in self.param_card_frame.winfo_children():
            widget.destroy()
        desc = next((d for k, n, i, d in [
            ("caesar", "Caesar", "🔤", "Shifts each letter by a fixed number of positions."),
            ("affine", "Affine", "🔢", "Uses a linear function for substitution."),
            ("atbash", "Atbash", "🔁", "Reverses the alphabet (A↔Z, B↔Y, ...)."),
            ("bacon", "Bacon", "🥓", "Encodes text as binary patterns (A/B)."),
            ("binary", "Binary", "💾", "Converts between text, binary, ASCII, hex."),
            ("playfair", "Playfair", "🔲", "Digraph substitution using a 5x5 matrix."),
            ("rail_fence", "Rail Fence", "🚆", "Zigzag transposition cipher."),
            ("rot13", "Rot13", "🔄", "Shifts letters by 13 positions."),
            ("scytale", "Scytale", "🌀", "Transposition using a cylinder."),
            ("substitution", "Substitution", "🔀", "Each letter replaced by another from a key."),
            ("vigenere", "Vigenère", "🗝️", "Polyalphabetic substitution with a keyword."),
            ("xor", "XOR", "❌", "Bitwise XOR of two texts.")
        ] if k == cipher_key), "")
        tk.Label(self.param_card_frame, text=desc, bg=Theme.get_color('primary'), fg=Theme.get_color('text_secondary'), font=('Arial', 11, 'italic'), wraplength=600, justify='left').pack(anchor='w', padx=10, pady=(10, 5))
        # Show parameters for the selected cipher
        self.update_parameters(cipher_key)

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
        for widget in self.param_card_frame.winfo_children():
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
        
        param_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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
        
        param_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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
        common_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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
        info_label = tk.Label(self.param_card_frame, 
                             text="No parameters needed - self-inverse cipher",
                             bg=Theme.get_color('secondary'), 
                             fg=Theme.get_color('text_secondary'),
                             font=('Arial', 9, 'italic'))
        info_label.pack(pady=5)
    
    def create_bacon_params(self):
        """Create Bacon cipher parameters"""
        self.bacon_variant = tk.StringVar(value="standard")
        
        param_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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
        
        param_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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
        
        param_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Key:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        key_entry = tk.Entry(param_frame, textvariable=self.playfair_key, 
                            width=15, font=('Arial', 9))
        key_entry.pack(side='left')
        
        # Add common keys
        common_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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
        
        param_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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
        info_label = tk.Label(self.param_card_frame, 
                             text="No parameters needed - fixed 13-position shift",
                             bg=Theme.get_color('secondary'), 
                             fg=Theme.get_color('text_secondary'),
                             font=('Arial', 9, 'italic'))
        info_label.pack(pady=5)
    
    def create_scytale_params(self):
        """Create Scytale cipher parameters"""
        self.scytale_diameter = tk.StringVar(value="3")
        
        param_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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
        
        param_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Key (26 chars):", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        key_entry = tk.Entry(param_frame, textvariable=self.substitution_key, 
                            width=30, font=('Arial', 9))
        key_entry.pack(side='left')
        
        # Add preset keys
        common_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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
        # Add random key button
        tk.Button(common_frame, text="Random Key", 
                  command=lambda: self.substitution_key.set(random_substitution_key()),
                  bg=Theme.get_color('accent'), fg='white', font=('Arial', 7), relief='flat', padx=3).pack(side='left', padx=1)
    
    def create_vigenere_params(self):
        """Create Vigenère cipher parameters"""
        self.vigenere_key = tk.StringVar(value="KEY")
        
        param_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
        param_frame.pack(fill='x', pady=2)
        
        tk.Label(param_frame, text="Key:", 
                bg=Theme.get_color('secondary'), 
                fg=Theme.get_color('text_primary'),
                font=('Arial', 9)).pack(side='left', padx=(0, 5))
        
        key_entry = tk.Entry(param_frame, textvariable=self.vigenere_key, 
                            width=15, font=('Arial', 9))
        key_entry.pack(side='left')
        
        # Add common keys
        common_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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

        def random_uppercase_word(length):
            return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(length))
        # Add random key button
        tk.Button(common_frame, text="Random Key", 
                  command=lambda: self.vigenere_key.set(random_uppercase_word(secrets.choice(range(6,13)))),
                  bg=Theme.get_color('accent'), fg='white', font=('Arial', 7), relief='flat', padx=3).pack(side='left', padx=1)

    def create_xor_vertical_input(self):
        """Create XOR input areas with two text inputs and file load buttons"""
        # Main XOR frame
        self.xor_input_frame = tk.Frame(self.param_card_frame, bg=Theme.get_color('secondary'))
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
        self.footer_frame = tk.Frame(self, bg=Theme.get_color('primary'), height=30)
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
        # Add universal zoom buttons next to theme
        zoom_frame = tk.Frame(self.footer_frame, bg=Theme.get_color('primary'))
        zoom_frame.pack(side='right', padx=(0, 10))
        tk.Button(zoom_frame, text="🔍 Zoom In", command=self.universal_zoom_in, font=('Arial', 9), bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary')).pack(side='left', padx=(0, 5))
        tk.Button(zoom_frame, text="🔍 Zoom Out", command=self.universal_zoom_out, font=('Arial', 9), bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary')).pack(side='left')

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
        update_widget_colors(self)
        # Update footer colors
        if self.status_label is not None:
            self.status_label.configure(bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary'))
        if self.footer_frame is not None:
            self.footer_frame.configure(bg=Theme.get_color('primary'))
        if self.theme_combo is not None:
            self.theme_combo.configure(background=Theme.get_color('primary'), foreground=Theme.get_color('text_primary'))

    def on_theme_change(self, event=None):
        if self.theme_change_callback:
            self.theme_change_callback()
        else:
            Theme.set_theme(self.theme_var.get())
            self.apply_theme()
        # No need to call update_idletasks here, main window will handle it

    def universal_zoom_in(self):
        """Increase font size for input and output in classical and advanced sections"""
        if self.current_view == 'classical' and hasattr(self, 'input_text_area') and hasattr(self, 'output_text_area'):
            current_font = self.input_text_area.cget('font')
            size = int(str(current_font).split()[-1]) + 1
            self.input_text_area.configure(font=("Courier", size))
            self.output_text_area.configure(font=("Courier", size))
        elif self.current_view == 'advanced':
            self.adv_font_size += 1
            self._update_advanced_font_size()

    def universal_zoom_out(self):
        """Decrease font size for input and output in classical and advanced sections"""
        if self.current_view == 'classical' and hasattr(self, 'input_text_area') and hasattr(self, 'output_text_area'):
            current_font = self.input_text_area.cget('font')
            size = int(str(current_font).split()[-1])
            if size > 6:
                size -= 1
                self.input_text_area.configure(font=("Courier", size))
                self.output_text_area.configure(font=("Courier", size))
        elif self.current_view == 'advanced':
            if self.adv_font_size > 6:
                self.adv_font_size -= 1
                self._update_advanced_font_size()

    def _update_advanced_font_size(self):
        """Update font size for all input/output widgets in the advanced section."""
        # Try to update all known advanced widgets if they exist
        # RSA
        if hasattr(self, 'rsa_input'):
            try:
                self.rsa_input.configure(font=("Courier", self.adv_font_size))
            except Exception:
                pass
        if hasattr(self, 'rsa_output'):
            try:
                self.rsa_output.configure(font=("Courier", self.adv_font_size))
            except Exception:
                pass
        if hasattr(self, 'rsa_pub_key'):
            try:
                self.rsa_pub_key.configure(font=("Courier", self.adv_font_size - 2))
            except Exception:
                pass
        if hasattr(self, 'rsa_priv_key'):
            try:
                self.rsa_priv_key.configure(font=("Courier", self.adv_font_size - 2))
            except Exception:
                pass
        # AES
        if hasattr(self, 'aes_input'):
            try:
                self.aes_input.configure(font=("Courier", self.adv_font_size))
            except Exception:
                pass
        if hasattr(self, 'aes_output'):
            try:
                self.aes_output.configure(font=("Courier", self.adv_font_size))
            except Exception:
                pass
        # Blowfish
        if hasattr(self, 'blowfish_input'):
            try:
                self.blowfish_input.configure(font=("Courier", self.adv_font_size))
            except Exception:
                pass
        if hasattr(self, 'blowfish_output'):
            try:
                self.blowfish_output.configure(font=("Courier", self.adv_font_size))
            except Exception:
                pass
        # DES
        if hasattr(self, 'des_input'):
            try:
                self.des_input.configure(font=("Courier", self.adv_font_size))
            except Exception:
                pass
        if hasattr(self, 'des_output'):
            try:
                self.des_output.configure(font=("Courier", self.adv_font_size))
            except Exception:
                pass
        # RC4
        if hasattr(self, 'rc4_input'):
            try:
                self.rc4_input.configure(font=("Courier", self.adv_font_size))
            except Exception:
                pass
        if hasattr(self, 'rc4_output'):
            try:
                self.rc4_output.configure(font=("Courier", self.adv_font_size))
            except Exception:
                pass
        # Substitution, Caesar, OTP, Base, SHA256, MD5, HMAC, Magic Hasher, etc.
        # Add similar blocks for other advanced ciphers as needed
        # For generic update, loop through all children of adv_param_frame and update Text widgets
        if hasattr(self, 'adv_param_frame'):
            for widget in self.adv_param_frame.winfo_children():
                if isinstance(widget, tk.Text):
                    try:
                        widget.configure(font=("Courier", self.adv_font_size))
                    except Exception:
                        pass
                # Recursively update children
                for child in widget.winfo_children() if hasattr(widget, 'winfo_children') else []:
                    if isinstance(child, tk.Text):
                        try:
                            child.configure(font=("Courier", self.adv_font_size))
                        except Exception:
                            pass

    def create_advanced_section(self, parent_frame):
        """Full-featured, user-friendly Advanced Crypto GUI with advanced attacks and Magic Hasher."""
        # Back button
        back_btn = tk.Button(parent_frame, text=" Back", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'), command=self.show_main_choice)
        back_btn.pack(anchor='nw', padx=10, pady=10)
        # Title
        title_frame = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        title_frame.pack(fill='x', padx=10, pady=(10, 5))
        # NYX logo and Title (for main choice and section headers)
        from PIL import Image, ImageTk
        try:
            logo_img = Image.open("pics/Picsart_25-07-01_17-15-32-191.png")
            logo_img = logo_img.resize((32, 32), Image.Resampling.LANCZOS)
            logo = ImageTk.PhotoImage(logo_img)
            logo_label = tk.Label(title_frame, image=logo, bg=Theme.get_color('primary'))
            setattr(logo_label, "image", logo)  # Keep reference
            logo_label.pack(side='left', padx=(0, 8))
        except Exception:
            logo_label = tk.Label(title_frame, text="NYX", font=("Arial", 16, "bold"), fg="#FFD600", bg=Theme.get_color('primary'))
            logo_label.pack(side='left', padx=(0, 8))
        title_label = tk.Label(title_frame, 
                              text=" Advanced Crypto",
                              font=Theme.get_font('title'),
                              bg=Theme.get_color('primary'),
                              fg=Theme.get_color('accent'))
        title_label.pack(side='left')
        # Cipher selection grid
        cipher_info = [
            ("rsa", "RSA", "🔑", "Asymmetric encryption (public/private key)."),
            ("aes", "AES", "🔒", "Symmetric block cipher (128/192/256-bit)."),
            ("blowfish", "Blowfish", "🐡", "Symmetric block cipher (variable key size)."),
            ("des", "DES", "🔐", "Symmetric block cipher (56-bit key)."),
            ("rc4", "RC4", "💧", "Stream cipher (variable key size)."),
            ("rail_fence", "Rail Fence (Adv)", "🚆", "Zigzag cipher with brute force attack."),
            ("substitution", "Substitution (Adv)", "🔀", "Substitution with frequency analysis."),
            ("caesar", "Caesar (Adv)", "🔤", "Caesar with brute force/frequency analysis."),
            ("otp", "OTP", "🗝️", "One-Time Pad (perfect secrecy)."),
            ("base", "Base64/32/16", "🔢", "Base encoding/decoding."),
            ("sha256", "SHA-256", "🧮", "Secure hash algorithm (256-bit)."),
            ("md5", "MD5", "🧩", "Hash function (128-bit, not secure)."),
            ("hmac", "HMAC", "✉️", "Keyed-hash message authentication code."),
            ("magic_hasher", "Magic Hasher", "🪄", "Identify and crack hashes with Hashcat."),
            ("dots", "Dots", "⚫", "Convert spaces to 0 and other chars to 1 (Dots cipher)."),
            ("morse", "Morse Code", "•-", "Encode/decode Morse code from text or audio."),
        ]
        self.adv_cipher_buttons = {}
        adv_grid = tk.Frame(parent_frame, bg=Theme.get_color('secondary'))
        adv_grid.pack(fill='x', padx=10, pady=(10, 20))
        columns = 4
        for idx, (key, name, icon, desc) in enumerate(cipher_info):
            row = idx // columns
            col = idx % columns
            btn = tk.Button(
                adv_grid,
                text=f"{icon}\n{name}",
                font=("Arial", 14, "bold"),
                width=16,
                height=2,
                relief='solid',
                bd=2,
                bg=Theme.get_color('primary'),
                fg=Theme.get_color('accent'),
                activebackground=Theme.get_color('accent'),
                activeforeground=Theme.get_color('primary'),
                command=lambda k=key: self.select_adv_cipher(k)
            )
            btn.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            self.adv_cipher_buttons[key] = btn
            btn.bind("<Enter>", lambda e, d=desc: self.status_label.config(text=d) if self.status_label else None)
            btn.bind("<Leave>", lambda e: self.status_label.config(text="Ready - Select an advanced cipher") if self.status_label else None)
        for c in range(columns):
            adv_grid.grid_columnconfigure(c, weight=1)
        # --- Scrollable parameter/result panel ---
        adv_param_outer = tk.Frame(parent_frame, bg=Theme.get_color('primary'))
        adv_param_outer.pack(fill='both', expand=True, padx=5, pady=(0, 20))
        # Canvas + Scrollbar
        self.adv_param_canvas = tk.Canvas(adv_param_outer, bg=Theme.get_color('primary'), highlightthickness=0, borderwidth=0)
        self.adv_param_canvas.pack(side='left', fill='both', expand=True)
        adv_param_scrollbar = tk.Scrollbar(adv_param_outer, orient='vertical', command=self.adv_param_canvas.yview)
        adv_param_scrollbar.pack(side='right', fill='y')
        self.adv_param_canvas.configure(yscrollcommand=adv_param_scrollbar.set)
        # Frame inside canvas (no border, no relief)
        self.adv_param_frame = tk.Frame(self.adv_param_canvas, bg=Theme.get_color('primary'))
        self.adv_param_window = self.adv_param_canvas.create_window((0, 0), window=self.adv_param_frame, anchor='nw')
        # Make scrolling work and frame width match canvas
        def _on_frame_configure(event):
            self.adv_param_canvas.configure(scrollregion=self.adv_param_canvas.bbox('all'))
            self.adv_param_canvas.itemconfig(self.adv_param_window, width=self.adv_param_canvas.winfo_width())
        self.adv_param_frame.bind('<Configure>', _on_frame_configure)
        def _on_canvas_configure(event):
            self.adv_param_canvas.itemconfig(self.adv_param_window, width=event.width)
        self.adv_param_canvas.bind('<Configure>', _on_canvas_configure)
        # Mousewheel scrolling
        def _on_mousewheel(event):
            self.adv_param_canvas.yview_scroll(int(-1*(event.delta/120)), 'units')
        self.adv_param_canvas.bind_all('<MouseWheel>', _on_mousewheel)
        # Show a friendly message until a cipher is selected
        for widget in self.adv_param_frame.winfo_children():
            widget.destroy()
        msg = tk.Label(self.adv_param_frame, text="Select a cipher to begin", font=("Arial", 16, "italic"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        msg.pack(expand=True, pady=40)
        # Do NOT auto-select any cipher
        # self.select_adv_cipher('rsa')

    def select_adv_cipher(self, cipher_key):
        """Update advanced crypto parameter/result panel for selected cipher."""
        # Highlight selected button
        for key, btn in self.adv_cipher_buttons.items():
            if key == cipher_key:
                btn.config(bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), relief='sunken')
            else:
                btn.config(bg=Theme.get_color('primary'), fg=Theme.get_color('accent'), relief='solid')
        # Clear param/result frame
        for widget in self.adv_param_frame.winfo_children():
            widget.destroy()
        # --- Cipher-specific UI ---
        if cipher_key == 'rsa':
            self._adv_rsa_ui()
        elif cipher_key == 'aes':
            self._adv_aes_ui()
        elif cipher_key == 'blowfish':
            self._adv_blowfish_ui()
        elif cipher_key == 'des':
            self._adv_des_ui()
        elif cipher_key == 'rc4':
            self._adv_rc4_ui()
        elif cipher_key == 'rail_fence':
            self._adv_rail_fence_ui()
        elif cipher_key == 'substitution':
            self._adv_substitution_ui()
        elif cipher_key == 'caesar':
            self._adv_caesar_ui()
        elif cipher_key == 'otp':
            self._adv_otp_ui()
        elif cipher_key == 'base':
            self._adv_base_ui()
        elif cipher_key == 'sha256':
            self._adv_sha256_ui()
        elif cipher_key == 'md5':
            self._adv_md5_ui()
        elif cipher_key == 'hmac':
            self._adv_hmac_ui()
        elif cipher_key == 'magic_hasher':
            self._adv_magic_hasher_ui()
        elif cipher_key == 'dots':
            self._adv_dots_ui()
        elif cipher_key == 'morse':
            self._adv_morse_ui()

    # --- Cipher-specific UI methods (scaffolded, you can add crypto logic later) ---
    def _adv_rsa_ui(self):
        frame = self.adv_param_frame
        # Title
        tk.Label(frame, text="RSA Encryption/Decryption", font=("Arial", 16, "bold"), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        # Key management section
        key_frame = tk.LabelFrame(frame, text="Key Management", font=("Arial", 12, "bold"),
                                 bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        key_frame.pack(fill='x', padx=10, pady=5)
        # Key size selection
        key_size_frame = tk.Frame(key_frame, bg=Theme.get_color('primary'))
        key_size_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(key_size_frame, text="Key Size:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.rsa_key_size = tk.StringVar(value="2048")
        key_size_menu = tk.OptionMenu(key_size_frame, self.rsa_key_size, "1024", "2048", "4096")
        key_size_menu.config(bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        key_size_menu.pack(side='left', padx=5)
        tk.Button(key_size_frame, text="Generate New Keys", font=("Arial", 10, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._rsa_generate_keys).pack(side='left', padx=10)
        # Public key
        pub_frame = tk.Frame(key_frame, bg=Theme.get_color('primary'))
        pub_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(pub_frame, text="Public Key:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.rsa_pub_key = tk.Text(pub_frame, height=6, font=("Courier", 10),
                                  bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.rsa_pub_key.pack(fill='x', pady=2)
        pub_btn_frame = tk.Frame(pub_frame, bg=Theme.get_color('primary'))
        pub_btn_frame.pack(fill='x')
        tk.Button(pub_btn_frame, text="Load Public Key", font=("Arial", 9),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._rsa_load_public_key).pack(side='left', padx=2)
        tk.Button(pub_btn_frame, text="Save Public Key", font=("Arial", 9),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._rsa_save_public_key).pack(side='left', padx=2)
        # Private key
        priv_frame = tk.Frame(key_frame, bg=Theme.get_color('primary'))
        priv_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(priv_frame, text="Private Key:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.rsa_priv_key = tk.Text(priv_frame, height=6, font=("Courier", 10),
                                   bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.rsa_priv_key.pack(fill='x', pady=2)
        priv_btn_frame = tk.Frame(priv_frame, bg=Theme.get_color('primary'))
        priv_btn_frame.pack(fill='x')
        tk.Button(priv_btn_frame, text="Load Private Key", font=("Arial", 9),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._rsa_load_private_key).pack(side='left', padx=2)
        tk.Button(priv_btn_frame, text="Save Private Key", font=("Arial", 9),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._rsa_save_private_key).pack(side='left', padx=2)
        # Input/Output section
        io_frame = tk.LabelFrame(frame, text="Input/Output", font=("Arial", 12, "bold"),
                                bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        io_frame.pack(fill='both', expand=True, padx=10, pady=5)
        # Input
        input_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        input_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(input_frame, text="Input Text:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.rsa_input = tk.Text(input_frame, height=8, font=("Courier", 12),
                                bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.rsa_input.pack(fill='x', pady=2)
        # Action buttons
        action_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        action_frame.pack(fill='x', padx=10, pady=5)
        tk.Button(action_frame, text="🔒 Encrypt", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._rsa_encrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="🔓 Decrypt", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._rsa_decrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="Clear", font=("Arial", 10),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._rsa_clear).pack(side='left', padx=5)
        # Output
        output_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        tk.Label(output_frame, text="Output:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.rsa_output = tk.Text(output_frame, height=10, font=("Courier", 12),
                                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.rsa_output.pack(fill='both', expand=True, pady=2)
        # Do NOT auto-generate keys here

    def _rsa_generate_keys(self):
        """Generate new RSA key pair"""
        try:
            key_size = int(self.rsa_key_size.get())
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Update UI
            self.rsa_priv_key.delete(1.0, tk.END)
            self.rsa_priv_key.insert(1.0, private_pem.decode())
            self.rsa_pub_key.delete(1.0, tk.END)
            self.rsa_pub_key.insert(1.0, public_pem.decode())
            
            messagebox.showinfo("Success", f"Generated {key_size}-bit RSA key pair")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys: {e}")

    def _rsa_load_public_key(self):
        """Load public key from file"""
        try:
            filename = filedialog.askopenfilename(
                title="Load Public Key",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'r') as f:
                    key_data = f.read()
                self.rsa_pub_key.delete(1.0, tk.END)
                self.rsa_pub_key.insert(1.0, key_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load public key: {e}")

    def _rsa_save_public_key(self):
        """Save public key to file"""
        try:
            filename = filedialog.asksaveasfilename(
                title="Save Public Key",
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if filename:
                key_data = self.rsa_pub_key.get(1.0, tk.END).strip()
                with open(filename, 'w') as f:
                    f.write(key_data)
                messagebox.showinfo("Success", "Public key saved")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save public key: {e}")

    def _rsa_load_private_key(self):
        """Load private key from file"""
        try:
            filename = filedialog.askopenfilename(
                title="Load Private Key",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'r') as f:
                    key_data = f.read()
                self.rsa_priv_key.delete(1.0, tk.END)
                self.rsa_priv_key.insert(1.0, key_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load private key: {e}")

    def _rsa_save_private_key(self):
        """Save private key to file"""
        try:
            filename = filedialog.asksaveasfilename(
                title="Save Private Key",
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if filename:
                key_data = self.rsa_priv_key.get(1.0, tk.END).strip()
                with open(filename, 'w') as f:
                    f.write(key_data)
                messagebox.showinfo("Success", "Private key saved")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save private key: {e}")

    def _rsa_encrypt(self):
        """Encrypt data using RSA public key"""
        try:
            # Get public key
            pub_key_data = self.rsa_pub_key.get(1.0, tk.END).strip()
            if not pub_key_data:
                messagebox.showerror("Error", "Please provide a public key")
                return
            
            public_key = serialization.load_pem_public_key(
                pub_key_data.encode(),
                backend=default_backend()
            )
            
            # Ensure it's an RSA public key
            if not isinstance(public_key, rsa.RSAPublicKey):
                messagebox.showerror("Error", "Invalid RSA public key")
                return
            
            # Get input data
            data = self.rsa_input.get(1.0, tk.END).strip()
            if not data:
                messagebox.showerror("Error", "Please provide input data")
                return
            
            # Encrypt
            encrypted = public_key.encrypt(
                data.encode(),
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Display result
            self.rsa_output.delete(1.0, tk.END)
            self.rsa_output.insert(1.0, base64.b64encode(encrypted).decode())
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def _rsa_decrypt(self):
        """Decrypt data using RSA private key"""
        try:
            # Get private key
            priv_key_data = self.rsa_priv_key.get(1.0, tk.END).strip()
            if not priv_key_data:
                messagebox.showerror("Error", "Please provide a private key")
                return
            
            private_key = serialization.load_pem_private_key(
                priv_key_data.encode(),
                password=None,
                backend=default_backend()
            )
            
            # Ensure it's an RSA private key
            if not isinstance(private_key, rsa.RSAPrivateKey):
                messagebox.showerror("Error", "Invalid RSA private key")
                return
            
            # Get input data
            data = self.rsa_input.get(1.0, tk.END).strip()
            if not data:
                messagebox.showerror("Error", "Please provide input data")
                return
            
            # Decrypt
            encrypted_data = base64.b64decode(data)
            decrypted = private_key.decrypt(
                encrypted_data,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Display result
            self.rsa_output.delete(1.0, tk.END)
            self.rsa_output.insert(1.0, decrypted.decode())
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def _rsa_clear(self):
        # Clear input and output fields
        self.rsa_input.delete(1.0, tk.END)
        self.rsa_output.delete(1.0, tk.END)

    def _adv_aes_ui(self):
        frame = self.adv_param_frame
        
        # Title
        tk.Label(frame, text="AES Encryption/Decryption", font=("Arial", 16, "bold"), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        
        # Parameters section
        param_frame = tk.LabelFrame(frame, text="Parameters", font=("Arial", 12, "bold"),
                                   bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        param_frame.pack(fill='x', padx=10, pady=5)
        
        # Key management
        key_frame = tk.Frame(param_frame, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(key_frame, text="Key Size:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.aes_key_size = tk.StringVar(value="16")
        key_size_menu = tk.OptionMenu(key_frame, self.aes_key_size, "16", "24", "32")
        key_size_menu.config(bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        key_size_menu.pack(side='left', padx=5)
        
        key_input_frame = tk.Frame(param_frame, bg=Theme.get_color('primary'))
        key_input_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(key_input_frame, text="Key (Base64):", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.aes_key = tk.Entry(key_input_frame, font=("Courier", 10), width=40,
                               bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.aes_key.pack(side='left', padx=5)
        tk.Button(key_input_frame, text="Random Key", font=("Arial", 9),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._aes_random_key).pack(side='left', padx=5)
        
        # IV management
        iv_frame = tk.Frame(param_frame, bg=Theme.get_color('primary'))
        iv_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(iv_frame, text="IV (Base64):", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.aes_iv = tk.Entry(iv_frame, font=("Courier", 10), width=40,
                              bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.aes_iv.pack(side='left', padx=5)
        tk.Button(iv_frame, text="Random IV", font=("Arial", 9),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._aes_random_iv).pack(side='left', padx=5)
        
        # Input/Output section
        io_frame = tk.LabelFrame(frame, text="Input/Output", font=("Arial", 12, "bold"),
                                bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        io_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Input
        input_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        input_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(input_frame, text="Input Text:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.aes_input = tk.Text(input_frame, height=4, font=("Courier", 10),
                                bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.aes_input.pack(fill='x', pady=2)
        
        # Action buttons
        action_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        action_frame.pack(fill='x', padx=10, pady=5)
        tk.Button(action_frame, text="🔒 Encrypt", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._aes_encrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="🔓 Decrypt", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._aes_decrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="Clear", font=("Arial", 10),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._aes_clear).pack(side='left', padx=5)
        
        # Output
        output_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        tk.Label(output_frame, text="Output:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.aes_output = tk.Text(output_frame, height=6, font=("Courier", 10),
                                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.aes_output.pack(fill='both', expand=True, pady=2)
        
        # Initialize with random key and IV
        self._aes_random_key()
        self._aes_random_iv()

    def _aes_random_key(self):
        key_size = int(self.aes_key_size.get())
        key = secrets.token_bytes(key_size)
        self.aes_key.delete(0, tk.END)
        self.aes_key.insert(0, base64.b64encode(key).decode())

    def _aes_random_iv(self):
        iv = secrets.token_bytes(16)
        self.aes_iv.delete(0, tk.END)
        self.aes_iv.insert(0, base64.b64encode(iv).decode())

    def _aes_encrypt(self):
        try:
            key = base64.b64decode(self.aes_key.get())
            iv = base64.b64decode(self.aes_iv.get())
            msg = self.aes_input.get('1.0', tk.END).strip().encode()

            if len(key) not in (16, 24, 32):
                messagebox.showerror("Error", "Key must be 16, 24, or 32 bytes.")
                return
            if len(iv) != 16:
                messagebox.showerror("Error", "IV must be 16 bytes.")
                return

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(msg) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_data) + encryptor.finalize()

            self.aes_output.delete('1.0', tk.END)
            self.aes_output.insert('1.0', base64.b64encode(ct).decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def _aes_decrypt(self):
        try:
            key = base64.b64decode(self.aes_key.get())
            iv = base64.b64decode(self.aes_iv.get())
            ct = base64.b64decode(self.aes_input.get('1.0', tk.END).strip())

            if len(key) not in (16, 24, 32):
                messagebox.showerror("Error", "Key must be 16, 24, or 32 bytes.")
                return
            if len(iv) != 16:
                messagebox.showerror("Error", "IV must be 16 bytes.")
                return

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()

            self.aes_output.delete('1.0', tk.END)
            try:
                self.aes_output.insert('1.0', data.decode('utf-8'))
            except Exception:
                self.aes_output.insert('1.0', f"<non-UTF8 output>\n{data.hex()}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def _aes_clear(self):
        self.aes_input.delete('1.0', tk.END)
        self.aes_output.delete('1.0', tk.END)

    def _adv_blowfish_ui(self):
        frame = self.adv_param_frame
        
        # Title
        tk.Label(frame, text="Blowfish Encryption/Decryption", font=("Arial", 16, "bold"), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        
        # Parameters section
        param_frame = tk.LabelFrame(frame, text="Parameters", font=("Arial", 12, "bold"),
                                   bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        param_frame.pack(fill='x', padx=10, pady=5)
        
        # Key management
        key_frame = tk.Frame(param_frame, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(key_frame, text="Key Size:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.blowfish_key_size = tk.StringVar(value="16")
        key_size_menu = tk.OptionMenu(key_frame, self.blowfish_key_size, "8", "16", "24", "32", "40", "48", "56")
        key_size_menu.config(bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        key_size_menu.pack(side='left', padx=5)
        
        key_input_frame = tk.Frame(param_frame, bg=Theme.get_color('primary'))
        key_input_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(key_input_frame, text="Key (Base64):", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.blowfish_key = tk.Entry(key_input_frame, font=("Courier", 10), width=40,
                                    bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.blowfish_key.pack(side='left', padx=5)
        tk.Button(key_input_frame, text="Random Key", font=("Arial", 9),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._blowfish_random_key).pack(side='left', padx=5)
        
        # IV management
        iv_frame = tk.Frame(param_frame, bg=Theme.get_color('primary'))
        iv_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(iv_frame, text="IV (Base64):", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.blowfish_iv = tk.Entry(iv_frame, font=("Courier", 10), width=40,
                                   bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.blowfish_iv.pack(side='left', padx=5)
        tk.Button(iv_frame, text="Random IV", font=("Arial", 9),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._blowfish_random_iv).pack(side='left', padx=5)
        
        # Input/Output section
        io_frame = tk.LabelFrame(frame, text="Input/Output", font=("Arial", 12, "bold"),
                                bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        io_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Input
        input_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        input_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(input_frame, text="Input Text:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.blowfish_input = tk.Text(input_frame, height=4, font=("Courier", 10),
                                     bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.blowfish_input.pack(fill='x', pady=2)
        
        # Action buttons
        action_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        action_frame.pack(fill='x', padx=10, pady=5)
        tk.Button(action_frame, text="🔒 Encrypt", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._blowfish_encrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="🔓 Decrypt", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._blowfish_decrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="Clear", font=("Arial", 10),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._blowfish_clear).pack(side='left', padx=5)
        
        # Output
        output_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        tk.Label(output_frame, text="Output:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.blowfish_output = tk.Text(output_frame, height=6, font=("Courier", 10),
                                      bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.blowfish_output.pack(fill='both', expand=True, pady=2)
        
        # Initialize with random key and IV
        self._blowfish_random_key()
        self._blowfish_random_iv()

    def _blowfish_random_key(self):
        key_size = int(self.blowfish_key_size.get())
        # Blowfish key must be 4-56 bytes
        key_size = max(4, min(56, key_size))
        key = secrets.token_bytes(key_size)
        self.blowfish_key.delete(0, tk.END)
        self.blowfish_key.insert(0, base64.b64encode(key).decode())

    def _blowfish_random_iv(self):
        iv = secrets.token_bytes(8)
        self.blowfish_iv.delete(0, tk.END)
        self.blowfish_iv.insert(0, base64.b64encode(iv).decode())

    def _blowfish_encrypt(self):
        try:
            key = base64.b64decode(self.blowfish_key.get())
            iv = base64.b64decode(self.blowfish_iv.get())
            msg = self.blowfish_input.get('1.0', tk.END).strip().encode()

            if not (4 <= len(key) <= 56):
                messagebox.showerror("Error", "Key must be 4-56 bytes for Blowfish.")
                return
            if len(iv) != 8:
                messagebox.showerror("Error", "IV must be 8 bytes for Blowfish.")
                return

            padder = padding.PKCS7(64).padder()
            padded_data = padder.update(msg) + padder.finalize()
            cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_data) + encryptor.finalize()

            self.blowfish_output.delete('1.0', tk.END)
            self.blowfish_output.insert('1.0', base64.b64encode(ct).decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def _blowfish_decrypt(self):
        try:
            key = base64.b64decode(self.blowfish_key.get())
            iv = base64.b64decode(self.blowfish_iv.get())
            ct = base64.b64decode(self.blowfish_input.get('1.0', tk.END).strip())

            if not (4 <= len(key) <= 56):
                messagebox.showerror("Error", "Key must be 4-56 bytes for Blowfish.")
                return
            if len(iv) != 8:
                messagebox.showerror("Error", "IV must be 8 bytes for Blowfish.")
                return

            cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(64).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()

            self.blowfish_output.delete('1.0', tk.END)
            try:
                self.blowfish_output.insert('1.0', data.decode('utf-8'))
            except Exception:
                self.blowfish_output.insert('1.0', f"<non-UTF8 output>\n{data.hex()}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def _blowfish_clear(self):
        self.blowfish_input.delete('1.0', tk.END)
        self.blowfish_output.delete('1.0', tk.END)

    def _adv_des_ui(self):
        frame = self.adv_param_frame
        # Title
        tk.Label(frame, text="DES Encryption/Decryption", font=("Arial", 16, "bold"), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        # Parameters section
        param_frame = tk.LabelFrame(frame, text="Parameters", font=("Arial", 12, "bold"),
                                   bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        param_frame.pack(fill='x', padx=10, pady=5)
        # Key management
        key_frame = tk.Frame(param_frame, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(key_frame, text="Key (8 bytes, Base64):", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.des_key = tk.Entry(key_frame, font=("Courier", 10), width=24,
                               bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.des_key.pack(side='left', padx=5)
        tk.Button(key_frame, text="Random Key", font=("Arial", 9),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._des_random_key).pack(side='left', padx=5)
        # IV management
        iv_frame = tk.Frame(param_frame, bg=Theme.get_color('primary'))
        iv_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(iv_frame, text="IV (8 bytes, Base64):", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.des_iv = tk.Entry(iv_frame, font=("Courier", 10), width=24,
                              bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.des_iv.pack(side='left', padx=5)
        tk.Button(iv_frame, text="Random IV", font=("Arial", 9),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._des_random_iv).pack(side='left', padx=5)
        # Input/Output section
        io_frame = tk.LabelFrame(frame, text="Input/Output", font=("Arial", 12, "bold"),
                                bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        io_frame.pack(fill='both', expand=True, padx=10, pady=5)
        # Input
        input_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        input_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(input_frame, text="Input Text:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.des_input = tk.Text(input_frame, height=4, font=("Courier", 10),
                                bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.des_input.pack(fill='x', pady=2)
        # Action buttons
        action_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        action_frame.pack(fill='x', padx=10, pady=5)
        tk.Button(action_frame, text="🔒 Encrypt", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._des_encrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="🔓 Decrypt", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._des_decrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="Clear", font=("Arial", 10),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._des_clear).pack(side='left', padx=5)
        # Output
        output_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        tk.Label(output_frame, text="Output (hex):", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.des_output = tk.Text(output_frame, height=6, font=("Courier", 10),
                                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.des_output.pack(fill='both', expand=True, pady=2)
        # Copy Output button
        tk.Button(output_frame, text="Copy Output", font=("Arial", 10),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._des_copy_output).pack(anchor='e', pady=5, padx=5)
        # Initialize with random key and IV
        self._des_random_key()
        self._des_random_iv()

    def _des_random_key(self):
        key = secrets.token_bytes(8)
        self.des_key.delete(0, tk.END)
        self.des_key.insert(0, base64.b64encode(key).decode())

    def _des_random_iv(self):
        iv = secrets.token_bytes(8)
        self.des_iv.delete(0, tk.END)
        self.des_iv.insert(0, base64.b64encode(iv).decode())

    def _des_encrypt(self):
        try:
            if not DES_AVAILABLE:
                messagebox.showerror("Error", "pycryptodome is not installed. DES is unavailable.")
                return
            import base64
            from Crypto.Util.Padding import pad
            key = base64.b64decode(self.des_key.get())
            iv = base64.b64decode(self.des_iv.get())
            msg = self.des_input.get('1.0', tk.END).strip().encode()
            if len(key) != 8:
                messagebox.showerror("Error", "DES key must be exactly 8 bytes.")
                return
            if len(iv) != 8:
                messagebox.showerror("Error", "DES IV must be exactly 8 bytes.")
                return
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded_data = pad(msg, 8)
            ct = cipher.encrypt(padded_data)
            self.des_output.delete('1.0', tk.END)
            self.des_output.insert('1.0', base64.b64encode(ct).decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def _des_decrypt(self):
        try:
            if not DES_AVAILABLE:
                messagebox.showerror("Error", "pycryptodome is not installed. DES is unavailable.")
                return
            import base64
            from Crypto.Util.Padding import unpad
            key = base64.b64decode(self.des_key.get())
            iv = base64.b64decode(self.des_iv.get())
            ct = base64.b64decode(self.des_input.get('1.0', tk.END).strip())
            if len(key) != 8:
                messagebox.showerror("Error", "DES key must be exactly 8 bytes.")
                return
            if len(iv) != 8:
                messagebox.showerror("Error", "DES IV must be exactly 8 bytes.")
                return
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded_data = cipher.decrypt(ct)
            try:
                data = unpad(padded_data, 8)
            except Exception as e:
                messagebox.showerror("Error", f"Unpadding failed: {e}")
                return
            self.des_output.delete('1.0', tk.END)
            try:
                self.des_output.insert('1.0', data.decode('utf-8'))
            except Exception:
                self.des_output.insert('1.0', f"<non-UTF8 output>\n{data.hex()}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def _des_clear(self):
        self.des_input.delete('1.0', tk.END)
        self.des_output.delete('1.0', tk.END)

    def _des_copy_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.des_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")

    def _adv_rc4_ui(self):
        frame = self.adv_param_frame
        tk.Label(frame, text="RC4 Encryption/Decryption", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        param_frame = tk.LabelFrame(frame, text="Parameters", font=("Arial", 12, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        param_frame.pack(fill='x', padx=10, pady=5)
        key_frame = tk.Frame(param_frame, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(key_frame, text="Key (1-256 bytes, Base64):", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.rc4_key = tk.Entry(key_frame, font=("Courier", 10), width=32, bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.rc4_key.pack(side='left', padx=5)
        tk.Button(key_frame, text="Random Key", font=("Arial", 9), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=self._rc4_random_key).pack(side='left', padx=5)
        io_frame = tk.LabelFrame(frame, text="Input/Output", font=("Arial", 12, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        io_frame.pack(fill='both', expand=True, padx=10, pady=5)
        input_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        input_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(input_frame, text="Input Text:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.rc4_input = tk.Text(input_frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.rc4_input.pack(fill='x', pady=2)
        action_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        action_frame.pack(fill='x', padx=10, pady=5)
        tk.Button(action_frame, text="🔒 Encrypt", font=("Arial", 12, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=self._rc4_encrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="🔓 Decrypt", font=("Arial", 12, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=self._rc4_decrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="Clear", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=self._rc4_clear).pack(side='left', padx=5)
        output_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        tk.Label(output_frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.rc4_output = tk.Text(output_frame, height=8, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.rc4_output.pack(fill='both', expand=True, pady=2)

    def _adv_substitution_ui(self):
        frame = self.adv_param_frame
        # Title
        tk.Label(frame, text="Substitution (Advanced)", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        # Key entry
        key_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(key_frame, text="Key (26 uppercase letters):", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.subst_key_var = tk.StringVar(value="QWERTYUIOPASDFGHJKLZXCVBNM")
        key_entry = tk.Entry(key_frame, textvariable=self.subst_key_var, font=("Courier", 10), width=30, bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        key_entry.pack(side='left', padx=5)
        def set_random_key():
            import random, string
            k = list(string.ascii_uppercase)
            random.shuffle(k)
            self.subst_key_var.set(''.join(k))
        tk.Button(key_frame, text="Random Key", font=("Arial", 9), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=set_random_key).pack(side='left', padx=5)
        tk.Label(frame, text="Key must be 26 unique uppercase letters (A-Z).", font=("Arial", 9, "italic"), bg=Theme.get_color('primary'), fg=Theme.get_color('text_secondary')).pack(anchor='w', padx=15)
        # Input area
        input_label = tk.Label(frame, text="Input Text:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        input_label.pack(anchor='w', padx=10)
        self.subst_input = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.subst_input.pack(fill='x', padx=10, pady=2)
        # Action buttons
        btn_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        btn_frame.pack(fill='x', padx=10, pady=5)
        def encrypt():
            key = self.subst_key_var.get().upper()
            msg = self.subst_input.get('1.0', tk.END).strip()
            if len(key) != 26 or len(set(key)) != 26 or not key.isupper():
                self.subst_output.delete('1.0', tk.END)
                self.subst_output.insert('1.0', 'Error: Key must be 26 unique uppercase letters.')
                return
            result = self.ciphers.substitution_encrypt(msg, key)
            self.subst_output.delete('1.0', tk.END)
            self.subst_output.insert('1.0', result)
        def decrypt():
            key = self.subst_key_var.get().upper()
            msg = self.subst_input.get('1.0', tk.END).strip()
            if len(key) != 26 or len(set(key)) != 26 or not key.isupper():
                self.subst_output.delete('1.0', tk.END)
                self.subst_output.insert('1.0', 'Error: Key must be 26 unique uppercase letters.')
                return
            result = self.ciphers.substitution_decrypt(msg, key)
            self.subst_output.delete('1.0', tk.END)
            self.subst_output.insert('1.0', result)
        def clear():
            self.subst_input.delete('1.0', tk.END)
            self.subst_output.delete('1.0', tk.END)
        def freq_analysis():
            from collections import Counter
            msg = self.subst_input.get('1.0', tk.END).strip().upper()
            letters = [c for c in msg if c.isalpha()]
            freq = Counter(letters)
            total = sum(freq.values())
            lines = [f"{ch}: {freq[ch]} ({freq[ch]/total:.2%})" for ch in sorted(freq)] if total else ["No letters in input."]
            self.subst_output.delete('1.0', tk.END)
            self.subst_output.insert('1.0', "Frequency Analysis:\n" + "\n".join(lines))
        tk.Button(btn_frame, text="Encrypt", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=encrypt).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Decrypt", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=decrypt).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Frequency Analysis", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=freq_analysis).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=clear).pack(side='left', padx=5)
        # Output area
        output_label = tk.Label(frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        output_label.pack(anchor='w', padx=10)
        self.subst_output = tk.Text(frame, height=6, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.subst_output.pack(fill='x', padx=10, pady=2)
        def copy_output():
            self.clipboard_clear()
            self.clipboard_append(self.subst_output.get('1.0', tk.END).strip())
        tk.Button(frame, text="Copy Output", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=copy_output).pack(anchor='e', pady=5, padx=10)

    def _adv_caesar_ui(self):
        frame = self.adv_param_frame
        tk.Label(frame, text="Caesar (Advanced)", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        shift_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        shift_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(shift_frame, text="Shift:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.caesar_shift_var = tk.StringVar(value="3")
        shift_entry = tk.Entry(shift_frame, textvariable=self.caesar_shift_var, font=("Courier", 10), width=5, bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        shift_entry.pack(side='left', padx=5)
        tk.Label(frame, text="Input Text:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.caesar_input = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.caesar_input.pack(fill='x', padx=10, pady=2)
        btn_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        btn_frame.pack(fill='x', padx=10, pady=5)
        def encrypt():
            try:
                shift = int(self.caesar_shift_var.get())
            except Exception:
                self.caesar_output.delete('1.0', tk.END)
                self.caesar_output.insert('1.0', 'Error: Shift must be an integer.')
                return
            msg = self.caesar_input.get('1.0', tk.END).strip()
            result = self.ciphers.caesar_encrypt(msg, shift)
            self.caesar_output.delete('1.0', tk.END)
            self.caesar_output.insert('1.0', result)
        def decrypt():
            try:
                shift = int(self.caesar_shift_var.get())
            except Exception:
                self.caesar_output.delete('1.0', tk.END)
                self.caesar_output.insert('1.0', 'Error: Shift must be an integer.')
                return
            msg = self.caesar_input.get('1.0', tk.END).strip()
            result = self.ciphers.caesar_decrypt(msg, shift)
            self.caesar_output.delete('1.0', tk.END)
            self.caesar_output.insert('1.0', result)
        def brute_force():
            msg = self.caesar_input.get('1.0', tk.END).strip()
            results = caesar_brute_force(msg)
            lines = [f"Shift {shift}: {text}" for shift, text in results]
            self.caesar_output.delete('1.0', tk.END)
            self.caesar_output.insert('1.0', "Brute Force Results:\n" + "\n".join(lines))
        def freq_analysis():
            from collections import Counter
            msg = self.caesar_input.get('1.0', tk.END).strip().upper()
            letters = [c for c in msg if c.isalpha()]
            freq = Counter(letters)
            total = sum(freq.values())
            lines = [f"{ch}: {freq[ch]} ({freq[ch]/total:.2%})" for ch in sorted(freq)] if total else ["No letters in input."]
            self.caesar_output.delete('1.0', tk.END)
            self.caesar_output.insert('1.0', "Frequency Analysis:\n" + "\n".join(lines))
        def clear():
            self.caesar_input.delete('1.0', tk.END)
            self.caesar_output.delete('1.0', tk.END)
        tk.Button(btn_frame, text="Encrypt", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=encrypt).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Decrypt", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=decrypt).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Brute Force", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=brute_force).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Frequency Analysis", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=freq_analysis).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=clear).pack(side='left', padx=5)
        tk.Label(frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.caesar_output = tk.Text(frame, height=8, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.caesar_output.pack(fill='x', padx=10, pady=2)
        tk.Button(frame, text="Copy Output", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=lambda: self.clipboard_append(self.caesar_output.get('1.0', tk.END).strip())).pack(anchor='e', pady=5, padx=10)

    def _adv_otp_ui(self):
        frame = self.adv_param_frame
        tk.Label(frame, text="One-Time Pad (OTP)", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        key_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(key_frame, text="Key (base64, same length as input):", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.otp_key_var = tk.StringVar(value="")
        key_entry = tk.Entry(key_frame, textvariable=self.otp_key_var, font=("Courier", 10), width=40, bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        key_entry.pack(side='left', padx=5)
        def set_random_key():
            import base64
            msg = self.otp_input.get('1.0', tk.END).strip().encode()
            key = secrets.token_bytes(len(msg)) if msg else secrets.token_bytes(8)
            self.otp_key_var.set(base64.b64encode(key).decode())
        tk.Button(key_frame, text="Random Key", font=("Arial", 9), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=set_random_key).pack(side='left', padx=5)
        tk.Label(frame, text="Input Text:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.otp_input = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.otp_input.pack(fill='x', padx=10, pady=2)
        btn_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        btn_frame.pack(fill='x', padx=10, pady=5)
        def encrypt():
            import base64
            msg = self.otp_input.get('1.0', tk.END).strip().encode()
            try:
                key = base64.b64decode(self.otp_key_var.get())
            except Exception:
                self.otp_output.delete('1.0', tk.END)
                self.otp_output.insert('1.0', 'Error: Invalid base64 key.')
                return
            if len(key) != len(msg):
                self.otp_output.delete('1.0', tk.END)
                self.otp_output.insert('1.0', 'Error: Key length must match input length.')
                return
            ct = bytes([m ^ k for m, k in zip(msg, key)])
            self.otp_output.delete('1.0', tk.END)
            self.otp_output.insert('1.0', base64.b64encode(ct).decode())
        def decrypt():
            import base64
            try:
                key = base64.b64decode(self.otp_key_var.get())
                ct = base64.b64decode(self.otp_input.get('1.0', tk.END).strip())
            except Exception:
                self.otp_output.delete('1.0', tk.END)
                self.otp_output.insert('1.0', 'Error: Invalid base64 input or key.')
                return
            if len(key) != len(ct):
                self.otp_output.delete('1.0', tk.END)
                self.otp_output.insert('1.0', 'Error: Key length must match input length.')
                return
            pt = bytes([c ^ k for c, k in zip(ct, key)])
            try:
                self.otp_output.delete('1.0', tk.END)
                self.otp_output.insert('1.0', pt.decode('utf-8'))
            except Exception:
                self.otp_output.insert('1.0', f"<non-UTF8 output>\n{pt.hex()}")
        def clear():
            self.otp_input.delete('1.0', tk.END)
            self.otp_output.delete('1.0', tk.END)
        tk.Button(btn_frame, text="Encrypt", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=encrypt).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Decrypt", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=decrypt).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=clear).pack(side='left', padx=5)
        tk.Label(frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.otp_output = tk.Text(frame, height=6, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.otp_output.pack(fill='x', padx=10, pady=2)
        tk.Button(frame, text="Copy Output", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=lambda: self.clipboard_append(self.otp_output.get('1.0', tk.END).strip())).pack(anchor='e', pady=5, padx=10)

    def _adv_base_ui(self):
        frame = self.adv_param_frame
        tk.Label(frame, text="Base64/32/16 Encoding/Decoding", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        import base64
        self.base_mode = tk.StringVar(value="base64")
        mode_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        mode_frame.pack(fill='x', padx=10, pady=5)
        for mode, label in [("base64", "Base64"), ("base32", "Base32"), ("base16", "Base16")]:
            tk.Radiobutton(mode_frame, text=label, variable=self.base_mode, value=mode, font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'), selectcolor=Theme.get_color('secondary')).pack(side='left', padx=5)
        tk.Label(frame, text="Input Text:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.base_input = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.base_input.pack(fill='x', padx=10, pady=2)
        btn_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        btn_frame.pack(fill='x', padx=10, pady=5)
        def encode():
            msg = self.base_input.get('1.0', tk.END).strip().encode()
            mode = self.base_mode.get()
            try:
                if mode == "base64":
                    result = base64.b64encode(msg).decode()
                elif mode == "base32":
                    result = base64.b32encode(msg).decode()
                elif mode == "base16":
                    result = base64.b16encode(msg).decode()
                else:
                    result = "Invalid mode."
            except Exception as e:
                result = f"Error: {e}"
            self.base_output.delete('1.0', tk.END)
            self.base_output.insert('1.0', result)
        def decode():
            msg = self.base_input.get('1.0', tk.END).strip()
            mode = self.base_mode.get()
            try:
                if mode == "base64":
                    result = base64.b64decode(msg).decode('utf-8')
                elif mode == "base32":
                    result = base64.b32decode(msg).decode('utf-8')
                elif mode == "base16":
                    result = base64.b16decode(msg).decode('utf-8')
                else:
                    result = "Invalid mode."
            except Exception as e:
                result = f"Error: {e}"
            self.base_output.delete('1.0', tk.END)
            self.base_output.insert('1.0', result)
        def clear():
            self.base_input.delete('1.0', tk.END)
            self.base_output.delete('1.0', tk.END)
        tk.Button(btn_frame, text="Encode", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=encode).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Decode", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=decode).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=clear).pack(side='left', padx=5)
        tk.Label(frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.base_output = tk.Text(frame, height=6, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.base_output.pack(fill='x', padx=10, pady=2)
        tk.Button(frame, text="Copy Output", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=lambda: self.clipboard_append(self.base_output.get('1.0', tk.END).strip())).pack(anchor='e', pady=5, padx=10)

    def _adv_sha256_ui(self):
        frame = self.adv_param_frame
        tk.Label(frame, text="SHA-256 Hash", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        tk.Label(frame, text="Input Text:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.sha256_input = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.sha256_input.pack(fill='x', padx=10, pady=2)
        btn_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        btn_frame.pack(fill='x', padx=10, pady=5)
        def hash_sha256():
            import hashlib
            msg = self.sha256_input.get('1.0', tk.END).strip().encode()
            result = hashlib.sha256(msg).hexdigest()
            self.sha256_output.delete('1.0', tk.END)
            self.sha256_output.insert('1.0', result)
        def clear():
            self.sha256_input.delete('1.0', tk.END)
            self.sha256_output.delete('1.0', tk.END)
        tk.Button(btn_frame, text="Hash", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=hash_sha256).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=clear).pack(side='left', padx=5)
        tk.Label(frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.sha256_output = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.sha256_output.pack(fill='x', padx=10, pady=2)
        tk.Button(frame, text="Copy Output", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=self._copy_sha256_output).pack(anchor='e', pady=5, padx=10)
    def _adv_md5_ui(self):
        frame = self.adv_param_frame
        tk.Label(frame, text="MD5 Hash", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        tk.Label(frame, text="Input Text:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.md5_input = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.md5_input.pack(fill='x', padx=10, pady=2)
        btn_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        btn_frame.pack(fill='x', padx=10, pady=5)
        def hash_md5():
            import hashlib
            msg = self.md5_input.get('1.0', tk.END).strip().encode()
            result = hashlib.md5(msg).hexdigest()
            self.md5_output.delete('1.0', tk.END)
            self.md5_output.insert('1.0', result)
        def clear():
            self.md5_input.delete('1.0', tk.END)
            self.md5_output.delete('1.0', tk.END)
        tk.Button(btn_frame, text="Hash", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=hash_md5).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=clear).pack(side='left', padx=5)
        tk.Label(frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.md5_output = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.md5_output.pack(fill='x', padx=10, pady=2)
        tk.Button(frame, text="Copy Output", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=self._copy_md5_output).pack(anchor='e', pady=5, padx=10)
    def _adv_hmac_ui(self):
        frame = self.adv_param_frame
        tk.Label(frame, text="HMAC (Keyed Hash)", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        key_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(key_frame, text="Key:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.hmac_key_var = tk.StringVar(value="")
        key_entry = tk.Entry(key_frame, textvariable=self.hmac_key_var, font=("Courier", 10), width=30, bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        key_entry.pack(side='left', padx=5)
        tk.Label(frame, text="Input Text:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.hmac_input = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.hmac_input.pack(fill='x', padx=10, pady=2)
        btn_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        btn_frame.pack(fill='x', padx=10, pady=5)
        def hash_hmac():
            import hmac, hashlib
            key = self.hmac_key_var.get().encode()
            msg = self.hmac_input.get('1.0', tk.END).strip().encode()
            result = hmac.new(key, msg, hashlib.sha256).hexdigest()
            self.hmac_output.delete('1.0', tk.END)
            self.hmac_output.insert('1.0', result)
        def clear():
            self.hmac_input.delete('1.0', tk.END)
            self.hmac_output.delete('1.0', tk.END)
        tk.Button(btn_frame, text="Hash", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=hash_hmac).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=clear).pack(side='left', padx=5)
        tk.Label(frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.hmac_output = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.hmac_output.pack(fill='x', padx=10, pady=2)
        tk.Button(frame, text="Copy Output", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=self._copy_hmac_output).pack(anchor='e', pady=5, padx=10)
    def _adv_magic_hasher_ui(self):
        frame = self.adv_param_frame
        # Title
        tk.Label(frame, text="Magic Hasher (Identify & Crack Hashes)", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        # Hash input section
        hash_frame = tk.LabelFrame(frame, text="Hash Input", font=("Arial", 12, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        hash_frame.pack(fill='x', padx=10, pady=5)
        # Hash input
        input_frame = tk.Frame(hash_frame, bg=Theme.get_color('primary'))
        input_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(input_frame, text="Hash:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.magic_hash_input = tk.Text(input_frame, height=3, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.magic_hash_input.pack(fill='x', pady=2)
        # File input and wordlist selection
        btn_frame = tk.Frame(hash_frame, bg=Theme.get_color('primary'))
        btn_frame.pack(fill='x', padx=10, pady=5)
        tk.Button(btn_frame, text="Load Hash File", font=("Arial", 10), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=self._magic_hasher_load_file).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear Input", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=self._magic_hasher_clear_input).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Select Wordlist", font=("Arial", 10), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=self._magic_hasher_select_wordlist).pack(side='left', padx=5)
        self.magic_wordlist_label = tk.Label(btn_frame, text="No wordlist selected", font=("Arial", 9, "italic"), bg=Theme.get_color('primary'), fg=Theme.get_color('text_secondary'))
        self.magic_wordlist_label.pack(side='left', padx=5)
        self.magic_wordlist_path = None
        # Action buttons
        action_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        action_frame.pack(fill='x', padx=10, pady=5)
        tk.Button(action_frame, text="🔍 Identify Hash", font=("Arial", 12, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=self._magic_hasher_identify).pack(side='left', padx=5)
        tk.Button(action_frame, text="🔨 Crack Hash", font=("Arial", 12, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=self._magic_hasher_crack).pack(side='left', padx=5)
        # Output section
        tk.Label(frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.magic_hasher_output = tk.Text(frame, height=10, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.magic_hasher_output.pack(fill='x', padx=10, pady=5)
        # Copy output button
        tk.Button(frame, text="Copy Output", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=self._magic_hasher_copy_results).pack(anchor='e', padx=10, pady=5)
        # Reset identified mode/type
        self.magic_identified_mode = None
        self.magic_identified_type = None

    def _identify_hash_type(self, hash_str):
        """Identify hash type based on length and patterns, and return (type, hashcat_mode)"""
        # Remove all whitespace for robust detection
        hash_str = ''.join(hash_str.split())
        length = len(hash_str)
        # Common hash patterns and hashcat modes
        # https://hashcat.net/wiki/doku.php?id=example_hashes
        if length == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
            return ("MD5", "0")
        elif length == 40 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
            return ("SHA-1", "100")
        elif length == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
            return ("SHA-256", "1400")
        elif length == 128 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
            return ("SHA-512", "1700")
        elif hash_str.startswith('$2a$') or hash_str.startswith('$2b$') or hash_str.startswith('$2y$'):
            return ("bcrypt", "3200")
        elif hash_str.startswith('$1$'):
            return ("MD5 Crypt", "500")
        elif hash_str.startswith('$5$'):
            return ("SHA-256 Crypt", "7400")
        elif hash_str.startswith('$6$'):
            return ("SHA-512 Crypt", "1800")
        elif hash_str.startswith('$pbkdf2$'):
            return ("PBKDF2", None)
        elif length == 13:
            return ("DES Crypt", "1500")
        elif length == 34 and hash_str.startswith('$P$'):
            return ("PHPass", "400")
        elif length == 86 and hash_str.startswith('$2a$'):
            return ("bcrypt", "3200")
        else:
            return ("Unknown/Unsupported", None)

    def _magic_hasher_identify(self):
        """Identify hash types using hashid"""
        hash_text = self.magic_hash_input.get('1.0', tk.END).strip()
        if not hash_text:
            messagebox.showwarning("Warning", "Please enter or load hashes.")
            return
        try:
            hashes = hash_text.split('\n')
            results = []
            # Only use the first non-empty hash for mode detection
            self.magic_identified_mode = None
            self.magic_identified_type = None
            for hash_line in hashes:
                hash_line = hash_line.strip()
                if not hash_line:
                    continue
                hash_type, hashcat_mode = self._identify_hash_type(hash_line)
                results.append(f"Hash: {hash_line}")
                results.append(f"Type: {hash_type}")
                if hashcat_mode:
                    results.append(f"Hashcat Mode: {hashcat_mode}")
                else:
                    results.append(f"Hashcat Mode: Unknown/Unsupported")
                results.append("-" * 50)
                # Store the first detected mode/type for use in cracking
                if self.magic_identified_mode is None and hashcat_mode:
                    self.magic_identified_mode = hashcat_mode
                    self.magic_identified_type = hash_type
            output = "Hash Identification Results:\n" + "="*50 + "\n\n"
            output += '\n'.join(results)
            self.magic_hasher_output.delete('1.0', tk.END)
            self.magic_hasher_output.insert('1.0', output)
        except Exception as e:
            messagebox.showerror("Error", f"Hash identification failed: {e}")

    def _magic_hasher_crack(self):
        hash_text = self.magic_hash_input.get('1.0', tk.END).strip()
        if not hash_text:
            messagebox.showwarning("Warning", "Please enter or load hashes.")
            return
        if not self.magic_wordlist_path:
            messagebox.showwarning("Warning", "Please select a wordlist before cracking.")
            return
        # Use identified mode if available
        mode = self.magic_identified_mode
        if not mode:
            self.magic_hasher_output.delete('1.0', tk.END)
            self.magic_hasher_output.insert('1.0', 'Hashcat mode not identified. Please run Identify Hash first and ensure the hash type is supported.\n')
            return
        import tempfile
        import subprocess
        try:
            with tempfile.NamedTemporaryFile('w+', delete=False) as tf:
                tf.write(hash_text)
                tf.flush()
                hash_file = tf.name
            cmd = ['hashcat', '-m', mode, hash_file, self.magic_wordlist_path, '--quiet', '--potfile-disable']
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            output = result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace')
            self.magic_hasher_output.delete('1.0', tk.END)
            self.magic_hasher_output.insert('1.0', output)
        except Exception as e:
            self.magic_hasher_output.delete('1.0', tk.END)
            self.magic_hasher_output.insert('1.0', f'Error running hashcat: {e}\n')

    def clear_input(self):
        """Clear input text area"""
        if hasattr(self, 'input_text_area'):
            self.input_text_area.delete(1.0, tk.END)

    def load_example(self):
        """Load an example string into the input area"""
        if hasattr(self, 'input_text_area'):
            self.input_text_area.delete(1.0, tk.END)
            self.input_text_area.insert(1.0, "HELLO WORLD")

    def clear_output(self):
        """Clear output text area"""
        if hasattr(self, 'output_text_area'):
            self.output_text_area.delete(1.0, tk.END)

    def copy_output(self):
        """Copy output text to clipboard"""
        if hasattr(self, 'output_text_area'):
            text = self.output_text_area.get(1.0, tk.END).strip()
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Output copied to clipboard!")

    def encrypt(self):
        """Encrypt the input text using the selected cipher"""
        if not hasattr(self, 'input_text_area') or not hasattr(self, 'output_text_area'):
            return
        input_text = self.input_text_area.get(1.0, tk.END).strip()
        cipher = self.current_cipher.get()
        result = ""
        try:
            if cipher == "caesar":
                shift = int(getattr(self, 'caesar_shift', tk.StringVar(value="3")).get())
                result = self.ciphers.caesar_encrypt(input_text, shift)
            elif cipher == "affine":
                a = int(getattr(self, 'affine_a', tk.StringVar(value="5")).get())
                b = int(getattr(self, 'affine_b', tk.StringVar(value="8")).get())
                result = self.ciphers.affine_encrypt(input_text, a, b)
            elif cipher == "atbash":
                result = self.ciphers.atbash_encrypt(input_text)
            elif cipher == "bacon":
                result = self.ciphers.bacon_encrypt(input_text)
            elif cipher == "binary":
                result = self.handle_binary_conversion(input_text, "encrypt")
            elif cipher == "playfair":
                key = getattr(self, 'playfair_key', tk.StringVar(value="MONARCHY")).get()
                result = self.ciphers.playfair_encrypt(input_text, key)
            elif cipher == "rail_fence":
                rails = int(getattr(self, 'rail_fence_rails', tk.StringVar(value="3")).get())
                result = self.ciphers.rail_fence_encrypt(input_text, rails)
            elif cipher == "rot13":
                result = self.ciphers.rot13_encrypt(input_text)
            elif cipher == "scytale":
                diameter = int(getattr(self, 'scytale_diameter', tk.StringVar(value="3")).get())
                result = self.ciphers.scytale_encrypt(input_text, diameter)
            elif cipher == "substitution":
                key = getattr(self, 'substitution_key', tk.StringVar(value="QWERTYUIOPASDFGHJKLZXCVBNM")).get()
                result = self.ciphers.substitution_encrypt(input_text, key)
            elif cipher == "vigenere":
                key = getattr(self, 'vigenere_key', tk.StringVar(value="KEY")).get()
                result = self.ciphers.vigenere_encrypt(input_text, key)
            # XOR handled in its own UI
            else:
                result = "Not implemented for this cipher."
        except Exception as e:
            result = f"Error: {str(e)}"
        self.output_text_area.delete(1.0, tk.END)
        self.output_text_area.insert(1.0, result)

    def decrypt(self):
        """Decrypt the input text using the selected cipher"""
        if not hasattr(self, 'input_text_area') or not hasattr(self, 'output_text_area'):
            return
        input_text = self.input_text_area.get(1.0, tk.END).strip()
        cipher = self.current_cipher.get()
        result = ""
        try:
            if cipher == "caesar":
                shift = int(getattr(self, 'caesar_shift', tk.StringVar(value="3")).get())
                result = self.ciphers.caesar_decrypt(input_text, shift)
            elif cipher == "affine":
                a = int(getattr(self, 'affine_a', tk.StringVar(value="5")).get())
                b = int(getattr(self, 'affine_b', tk.StringVar(value="8")).get())
                result = self.ciphers.affine_decrypt(input_text, a, b)
            elif cipher == "atbash":
                result = self.ciphers.atbash_decrypt(input_text)
            elif cipher == "bacon":
                result = self.ciphers.bacon_decrypt(input_text)
            elif cipher == "binary":
                result = self.handle_binary_conversion(input_text, "decrypt")
            elif cipher == "playfair":
                key = getattr(self, 'playfair_key', tk.StringVar(value="MONARCHY")).get()
                result = self.ciphers.playfair_decrypt(input_text, key)
            elif cipher == "rail_fence":
                rails = int(getattr(self, 'rail_fence_rails', tk.StringVar(value="3")).get())
                result = self.ciphers.rail_fence_decrypt(input_text, rails)
            elif cipher == "rot13":
                result = self.ciphers.rot13_decrypt(input_text)
            elif cipher == "scytale":
                diameter = int(getattr(self, 'scytale_diameter', tk.StringVar(value="3")).get())
                result = self.ciphers.scytale_decrypt(input_text, diameter)
            elif cipher == "substitution":
                key = getattr(self, 'substitution_key', tk.StringVar(value="QWERTYUIOPASDFGHJKLZXCVBNM")).get()
                result = self.ciphers.substitution_decrypt(input_text, key)
            elif cipher == "vigenere":
                key = getattr(self, 'vigenere_key', tk.StringVar(value="KEY")).get()
                result = self.ciphers.vigenere_decrypt(input_text, key)
            # XOR handled in its own UI
            else:
                result = "Not implemented for this cipher."
        except Exception as e:
            result = f"Error: {str(e)}"
        self.output_text_area.delete(1.0, tk.END)
        self.output_text_area.insert(1.0, result)

    def swap_text(self):
        """Swap input and output text areas"""
        if hasattr(self, 'input_text_area') and hasattr(self, 'output_text_area'):
            input_text = self.input_text_area.get(1.0, tk.END)
            output_text = self.output_text_area.get(1.0, tk.END)
            self.input_text_area.delete(1.0, tk.END)
            self.input_text_area.insert(1.0, output_text.strip())
            self.output_text_area.delete(1.0, tk.END)
            self.output_text_area.insert(1.0, input_text.strip())

    







    

    

    

 


   

    def _rail_fence_random_rails(self):
        """Generate random number of rails"""
        rails = random.randint(2, 10)
        self.rail_fence_rails.set(str(rails))

    def _rail_fence_encrypt(self):
        """Encrypt using Rail Fence cipher"""
        try:
            if not hasattr(self, 'rail_fence_input') or not hasattr(self, 'rail_fence_output'):
                messagebox.showerror("Error", "Rail Fence widgets not found.")
                return
            text = self.rail_fence_input.get('1.0', tk.END).strip()
            rails = int(self.rail_fence_rails.get())
            result = self.ciphers.rail_fence_encrypt(text, rails)
            self.rail_fence_output.delete('1.0', tk.END)
            self.rail_fence_output.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def _rail_fence_decrypt(self):
        """Decrypt using Rail Fence cipher"""
        try:
            if not hasattr(self, 'rail_fence_input') or not hasattr(self, 'rail_fence_output'):
                messagebox.showerror("Error", "Rail Fence widgets not found.")
                return
            text = self.rail_fence_input.get('1.0', tk.END).strip()
            rails = int(self.rail_fence_rails.get())
            result = self.ciphers.rail_fence_decrypt(text, rails)
            self.rail_fence_output.delete('1.0', tk.END)
            self.rail_fence_output.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def _rail_fence_brute_force(self):
        """Brute force Rail Fence cipher"""
        try:
            if not hasattr(self, 'rail_fence_input') or not hasattr(self, 'rail_fence_output'):
                messagebox.showerror("Error", "Rail Fence widgets not found.")
                return
            text = self.rail_fence_input.get('1.0', tk.END).strip()
            results = rail_fence_brute_force(text, max_rails=10)
            output = "Rail Fence Brute Force Results:\n" + "="*40 + "\n\n"
            for rails, decrypted in results:
                output += f"Rails {rails:2d}: {decrypted}\n"
            self.rail_fence_output.delete('1.0', tk.END)
            self.rail_fence_output.insert('1.0', output)
        except Exception as e:
            messagebox.showerror("Error", f"Brute force failed: {e}")

    def _rail_fence_clear(self):
        """Clear Rail Fence input and output"""
        if hasattr(self, 'rail_fence_input'):
            self.rail_fence_input.delete('1.0', tk.END)
        if hasattr(self, 'rail_fence_output'):
            self.rail_fence_output.delete('1.0', tk.END)

    def _magic_hasher_load_file(self):
        """Load hash file for analysis"""
        file_path = filedialog.askopenfilename(title="Select Hash File")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    hashes = f.readlines()
                self.magic_hash_input.delete(1.0, tk.END)
                self.magic_hash_input.insert(1.0, '\n'.join(hashes))
            except Exception as e:
                messagebox.showerror("Error", f"Could not load file: {str(e)}")

    def _magic_hasher_clear_input(self):
        """Clear hash input"""
        self.magic_hash_input.delete(1.0, tk.END)

    def _magic_hasher_copy_results(self):
        """Copy results to clipboard"""
        text = self.magic_hasher_output.get('1.0', tk.END).strip()
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "Results copied to clipboard!")

    def _rc4_random_key(self):
        # Use the length of the current key entry, or default to 16
        try:
            key_len = len(base64.b64decode(self.rc4_key.get()))
            if not (1 <= key_len <= 256):
                key_len = 16
        except Exception:
            key_len = 16
        key = secrets.token_bytes(key_len)
        self.rc4_key.delete(0, tk.END)
        self.rc4_key.insert(0, base64.b64encode(key).decode())

    def _rc4_encrypt(self):
        try:
            key = base64.b64decode(self.rc4_key.get())
            msg = self.rc4_input.get('1.0', tk.END).strip().encode()
            if not (1 <= len(key) <= 256):
                messagebox.showerror("Error", "Key must be 1-256 bytes.")
                return
            S = list(range(256))
            j = 0
            out = []
            # KSA
            for i in range(256):
                j = (j + S[i] + key[i % len(key)]) % 256
                S[i], S[j] = S[j], S[i]
            # PRGA
            i = j = 0
            for char in msg:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                K = S[(S[i] + S[j]) % 256]
                out.append(char ^ K)
            ct = bytes(out)
            self.rc4_output.delete('1.0', tk.END)
            self.rc4_output.insert('1.0', base64.b64encode(ct).decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def _rc4_decrypt(self):
        try:
            key = base64.b64decode(self.rc4_key.get())
            ct = base64.b64decode(self.rc4_input.get('1.0', tk.END).strip())
            if not (1 <= len(key) <= 256):
                messagebox.showerror("Error", "Key must be 1-256 bytes.")
                return
            S = list(range(256))
            j = 0
            out = []
            # KSA
            for i in range(256):
                j = (j + S[i] + key[i % len(key)]) % 256
                S[i], S[j] = S[j], S[i]
            # PRGA
            i = j = 0
            for char in ct:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                K = S[(S[i] + S[j]) % 256]
                out.append(char ^ K)
            pt = bytes(out)
            self.rc4_output.delete('1.0', tk.END)
            try:
                self.rc4_output.insert('1.0', pt.decode('utf-8'))
            except Exception:
                self.rc4_output.insert('1.0', f"<non-UTF8 output>\n{pt.hex()}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def _rc4_clear(self):
        self.rc4_input.delete('1.0', tk.END)
        self.rc4_output.delete('1.0', tk.END)

    def _rc4_copy_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.rc4_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")

    def _adv_rail_fence_ui(self):
        frame = self.adv_param_frame
        # Title
        tk.Label(frame, text="Rail Fence (Advanced)", font=("Arial", 16, "bold"), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        # Parameters section
        param_frame = tk.LabelFrame(frame, text="Parameters", font=("Arial", 12, "bold"),
                                   bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        param_frame.pack(fill='x', padx=10, pady=5)
        # Rails parameter
        rails_frame = tk.Frame(param_frame, bg=Theme.get_color('primary'))
        rails_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(rails_frame, text="Number of Rails:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(side='left')
        self.rail_fence_rails = tk.StringVar(value="3")
        rails_entry = tk.Entry(rails_frame, textvariable=self.rail_fence_rails, width=10,
                              bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        rails_entry.pack(side='left', padx=5)
        tk.Button(rails_frame, text="Random Rails", font=("Arial", 9),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._rail_fence_random_rails).pack(side='left', padx=5)
        # Input/Output section
        io_frame = tk.LabelFrame(frame, text="Input/Output", font=("Arial", 12, "bold"),
                                bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        io_frame.pack(fill='both', expand=True, padx=10, pady=5)
        # Input
        input_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        input_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(input_frame, text="Input Text:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.rail_fence_input = tk.Text(input_frame, height=4, font=("Courier", 10),
                                       bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.rail_fence_input.pack(fill='x', pady=2)
        # Action buttons
        action_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        action_frame.pack(fill='x', padx=10, pady=5)
        tk.Button(action_frame, text="🔒 Encrypt", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._rail_fence_encrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="🔓 Decrypt", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._rail_fence_decrypt).pack(side='left', padx=5)
        tk.Button(action_frame, text="🔍 Brute Force", font=("Arial", 12, "bold"),
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'),
                 command=self._rail_fence_brute_force).pack(side='left', padx=5)
        tk.Button(action_frame, text="Clear", font=("Arial", 10),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._rail_fence_clear).pack(side='left', padx=5)
        # Output
        output_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        tk.Label(output_frame, text="Output:", font=("Arial", 10), 
                bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w')
        self.rail_fence_output = tk.Text(output_frame, height=8, font=("Courier", 10),
                                        bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.rail_fence_output.pack(fill='both', expand=True, pady=2)
        # Copy Output button
        tk.Button(output_frame, text="Copy Output", font=("Arial", 10),
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'),
                 command=self._rail_fence_copy_output).pack(anchor='e', pady=5, padx=5)

    def _rail_fence_copy_output(self):
        if hasattr(self, 'rail_fence_output'):
            self.clipboard_clear()
            self.clipboard_append(self.rail_fence_output.get('1.0', tk.END).strip())
            messagebox.showinfo("Copied", "Output copied to clipboard!")

    def _adv_dots_ui(self):
        frame = self.adv_param_frame
        tk.Label(frame, text="Dots Tool", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        # Input area
        tk.Label(frame, text="Input Text:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.dots_input = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.dots_input.pack(fill='x', padx=10, pady=2)
        # File load button
        def load_file():
            file_path = filedialog.askopenfilename(title="Load text file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if file_path:
                try:
                    with open(file_path, 'r', encoding='utf-8') as file:
                        content = file.read()
                    self.dots_input.delete('1.0', tk.END)
                    self.dots_input.insert('1.0', content)
                    messagebox.showinfo("Success", "File loaded successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not load file: {str(e)}")
        tk.Button(frame, text="Load File", font=("Arial", 9), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=load_file).pack(anchor='w', padx=10, pady=(0, 5))
        # Action buttons
        btn_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        btn_frame.pack(fill='x', padx=10, pady=5)
        def to_binary():
            text = self.dots_input.get('1.0', tk.END).rstrip('\n')
            result = text_to_ascii_binary(text)
            self.dots_output.delete('1.0', tk.END)
            self.dots_output.insert('1.0', result)
        def to_text():
            binary = self.dots_output.get('1.0', tk.END).strip()
            result = ascii_binary_to_text(binary)
            self.dots_output.delete('1.0', tk.END)
            self.dots_output.insert('1.0', result)
        def clear():
            self.dots_input.delete('1.0', tk.END)
            self.dots_output.delete('1.0', tk.END)
        def copy_output():
            self.clipboard_clear()
            self.clipboard_append(self.dots_output.get('1.0', tk.END).strip())
            messagebox.showinfo("Copied", "Output copied to clipboard!")
        tk.Button(btn_frame, text="Text to Binary", font=("Arial", 10, "bold"), bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), command=to_binary).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Binary to Text", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=to_text).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Clear", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=clear).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Copy Output", font=("Arial", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=copy_output).pack(side='left', padx=5)
        # Output area
        tk.Label(frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.dots_output = tk.Text(frame, height=6, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.dots_output.pack(fill='x', padx=10, pady=2)

    def _adv_morse_ui(self):
        frame = self.adv_param_frame
        tk.Label(frame, text="Morse Code Tool", font=("Arial", 16, "bold"), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(pady=(10, 5))
        
        # Input area
        tk.Label(frame, text="Input (Text or Morse Code):", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.morse_input = tk.Text(frame, height=4, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.morse_input.pack(fill='x', padx=10, pady=2)
        
        # Audio file path storage
        self.morse_file_path = None
        self.morse_audio_label = tk.Label(frame, text="No audio file loaded", font=("Arial", 9), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        self.morse_audio_label.pack(anchor='w', padx=10, pady=(0, 5))
        
        # File load button
        def load_file():
            file_path = filedialog.askopenfilename(
                title="Load file (text or audio)", 
                filetypes=[
                    ("Text files", "*.txt"), 
                    ("WAV audio", "*.wav"), 
                    ("MP3 audio", "*.mp3"),
                    ("All files", "*.*")
                ]
            )
            if file_path:
                ext = os.path.splitext(file_path)[1].lower()
                if ext in ['.wav', '.mp3']:
                    self.morse_file_path = file_path
                    self.morse_audio_label.config(text=f"Audio file: {os.path.basename(file_path)}")
                    self.morse_input.delete('1.0', tk.END)
                    self.morse_input.insert('1.0', f"[Audio file loaded: {os.path.basename(file_path)}]")
                else:
                    try:
                        with open(file_path, 'r', encoding='utf-8') as file:
                            content = file.read()
                        self.morse_input.delete('1.0', tk.END)
                        self.morse_input.insert('1.0', content)
                        self.morse_file_path = None
                        self.morse_audio_label.config(text="No audio file loaded")
                        messagebox.showinfo("Success", "Text file loaded successfully!")
                    except Exception as e:
                        messagebox.showerror("Error", f"Could not load file: {str(e)}")
        
        tk.Button(frame, text="Load File", font=("Arial", 9), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), command=load_file).pack(anchor='w', padx=10, pady=(0, 5))
        
        # Action buttons
        btn_frame = tk.Frame(frame, bg=Theme.get_color('primary'))
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        def convert_text_to_morse():
            """Convert text to Morse code"""
            text = self.morse_input.get('1.0', tk.END).strip()
            if not text:
                messagebox.showwarning("Warning", "Please enter some text to convert to Morse code.")
                return
            result = text_to_morse(text)
            self.morse_output.delete('1.0', tk.END)
            self.morse_output.insert('1.0', result)
        
        def convert_morse_to_text():
            """Convert Morse code to text"""
            morse_code = self.morse_input.get('1.0', tk.END).strip()
            if not morse_code:
                messagebox.showwarning("Warning", "Please enter Morse code to convert to text.")
                return
            result = morse_to_text(morse_code)
            self.morse_output.delete('1.0', tk.END)
            self.morse_output.insert('1.0', result)
        
        def convert_audio_to_morse():
            """Convert audio file to Morse code and text"""
            if not self.morse_file_path:
                messagebox.showwarning("Warning", "No audio file loaded. Please load a WAV or MP3 file first.")
                return
            
            try:
                morse_result, err = audio_to_morse(self.morse_file_path)
                self.morse_output.delete('1.0', tk.END)
                
                if err:
                    self.morse_output.insert('1.0', f"Error: {err}")
                else:
                    if morse_result:
                        self.morse_output.insert('1.0', f"Morse Code: {morse_result}\n\n")
                        # Decode to text
                        text = morse_to_text(morse_result)
                        self.morse_output.insert(tk.END, f"Decoded Text: {text}")
                    else:
                        self.morse_output.insert('1.0', "No Morse code detected in the audio file.")
            except Exception as e:
                self.morse_output.delete('1.0', tk.END)
                self.morse_output.insert('1.0', f"Error processing audio: {str(e)}")
        
        def clear_all():
            """Clear input, output, and audio file"""
            self.morse_input.delete('1.0', tk.END)
            self.morse_output.delete('1.0', tk.END)
            self.morse_file_path = None
            self.morse_audio_label.config(text="No audio file loaded")
        
        def copy_output():
            """Copy output to clipboard"""
            output_text = self.morse_output.get('1.0', tk.END).strip()
            if output_text:
                self.clipboard_clear()
                self.clipboard_append(output_text)
                messagebox.showinfo("Copied", "Output copied to clipboard!")
            else:
                messagebox.showwarning("Warning", "No output to copy.")
        
        def play_morse_audio():
            """Generate and play Morse code audio"""
            morse_code = self.morse_input.get('1.0', tk.END).strip()
            if not morse_code:
                messagebox.showwarning("Warning", "Please enter Morse code to play.")
                return
            
            try:
                # Generate audio
                audio_data, error = morse_to_audio(morse_code, frequency=800, wpm=15)
                
                if error:
                    messagebox.showerror("Error", f"Failed to generate audio: {error}")
                    return
                
                # Save to temporary file
                import tempfile
                temp_file = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
                temp_file.close()
                
                # Save audio to file
                with wave.open(temp_file.name, 'w') as wf:
                    wf.setnchannels(1)  # Mono
                    wf.setsampwidth(2)  # 16-bit
                    wf.setframerate(44100)
                    wf.writeframes(audio_data.tobytes())
                
                # Try to play the audio
                try:
                    import subprocess
                    import platform
                    
                    system = platform.system()
                    if system == "Linux":
                        subprocess.Popen(["aplay", temp_file.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    elif system == "Darwin":  # macOS
                        subprocess.Popen(["afplay", temp_file.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    elif system == "Windows":
                        subprocess.Popen(["start", temp_file.name], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:
                        messagebox.showinfo("Info", f"Audio saved to: {temp_file.name}\nPlease play it manually.")
                        return
                    
                    messagebox.showinfo("Success", "Morse code audio is playing!")
                    
                except Exception as e:
                    messagebox.showinfo("Info", f"Audio saved to: {temp_file.name}\nPlease play it manually.\nError: {str(e)}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate audio: {str(e)}")
        
        def save_morse_audio():
            """Save Morse code audio to a user-specified file"""
            morse_code = self.morse_input.get('1.0', tk.END).strip()
            if not morse_code:
                messagebox.showwarning("Warning", "Please enter Morse code to save as audio.")
                return
            file_path = filedialog.asksaveasfilename(
                title="Save Morse Audio As",
                defaultextension=".wav",
                filetypes=[("WAV Audio", "*.wav"), ("All Files", "*.*")]
            )
            if not file_path:
                return  # User cancelled
            try:
                audio_data, error = morse_to_audio(morse_code, frequency=800, wpm=15)
                if error:
                    messagebox.showerror("Error", f"Failed to generate audio: {error}")
                    return
                import wave
                with wave.open(file_path, 'w') as wf:
                    wf.setnchannels(1)  # Mono
                    wf.setsampwidth(2)  # 16-bit
                    wf.setframerate(44100)
                    wf.writeframes(audio_data.tobytes())
                messagebox.showinfo("Success", f"Audio saved to: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save audio: {str(e)}")

        # Button layout
        tk.Button(btn_frame, text="Text → Morse", font=("Arial", 10, "bold"), 
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), 
                 command=convert_text_to_morse).pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="Morse → Text", font=("Arial", 10, "bold"), 
                 bg=Theme.get_color('accent'), fg=Theme.get_color('primary'), 
                 command=convert_morse_to_text).pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="Audio → Morse", font=("Arial", 10), 
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), 
                 command=convert_audio_to_morse).pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="Play Audio", font=("Arial", 10), 
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), 
                 command=play_morse_audio).pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="Save Audio", font=("Arial", 10), 
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), 
                 command=save_morse_audio).pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="Clear", font=("Arial", 10), 
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), 
                 command=clear_all).pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="Copy Output", font=("Arial", 10), 
                 bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'), 
                 command=copy_output).pack(side='left', padx=5)
        
        # Output area
        tk.Label(frame, text="Output:", font=("Arial", 10), bg=Theme.get_color('primary'), fg=Theme.get_color('accent')).pack(anchor='w', padx=10)
        self.morse_output = tk.Text(frame, height=8, font=("Courier", 10), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        self.morse_output.pack(fill='x', padx=10, pady=2)

    def apply_theme_to_all_widgets(self):
        self.apply_theme()

    def _on_external_theme_change(self, *args):
        # Called when the global theme_var changes
        if self.theme_var.get() != Theme.get_current_theme():
            Theme.set_theme(self.theme_var.get())
        self.apply_theme()
        if self.theme_combo is not None:
            self.theme_combo.set(self.theme_var.get())

    def _magic_hasher_select_wordlist(self):
        """Prompt user to select a wordlist file and update the label/path."""
        file_path = filedialog.askopenfilename(title="Select Wordlist File")
        if file_path:
            self.magic_wordlist_path = file_path
            self.magic_wordlist_label.config(text=f"Wordlist: {os.path.basename(file_path)}")
        else:
            self.magic_wordlist_path = None
            self.magic_wordlist_label.config(text="No wordlist selected")

    # --- Fix: Consistent clipboard copy for all output areas ---
    def _copy_md5_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.md5_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    def _copy_sha256_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.sha256_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    def _copy_base_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.base_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    def _copy_hmac_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.hmac_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    def _copy_otp_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.otp_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    def _copy_caesar_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.caesar_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    def _copy_subst_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.subst_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    def _copy_rail_fence_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.rail_fence_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    def _copy_dots_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.dots_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    def _copy_morse_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.morse_output.get('1.0', tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")
    # --- End fix ---

def text_to_ascii_binary(text):
    return ' '.join(f'{ord(ch):08b}' for ch in text)

def ascii_binary_to_text(binary):
    bits = ''.join(b for b in binary if b in '01')
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def text_to_morse(text):
    """Convert text to Morse code"""
    if not text:
        return ""
    
    result = []
    for char in text.upper():
        if char in MORSE_CODE_DICT:
            result.append(MORSE_CODE_DICT[char])
        elif char == ' ':
            result.append('/')  # Word separator
        else:
            result.append('?')  # Unknown character
    
    return ' '.join(result)

def morse_to_text(morse):
    """Convert Morse code to text"""
    if not morse:
        return ""
    
    try:
        # Split into words (separated by /)
        words = morse.strip().split(' / ')
        decoded_words = []
        
        for word in words:
            if not word.strip():
                continue
            # Split word into characters
            chars = word.strip().split()
            decoded_chars = []
            
            for char in chars:
                if char in MORSE_CODE_DICT_REVERSE:
                    decoded_chars.append(MORSE_CODE_DICT_REVERSE[char])
                else:
                    decoded_chars.append('?')  # Unknown Morse sequence
            
            decoded_words.append(''.join(decoded_chars))
        
        return ' '.join(decoded_words)
    except Exception as e:
        return f"Error decoding Morse: {str(e)}"

def audio_to_morse(file_path):
    """Convert audio file to Morse code"""
    try:
        # Check if numpy is available
        try:
            import numpy as np
        except ImportError:
            return None, "NumPy is required for audio processing. Please install it with: pip install numpy"
        
        # Check file extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in ['.wav', '.mp3']:
            return None, f"Unsupported audio format: {ext}. Only WAV and MP3 are supported."
        
        # Handle different audio formats
        if ext == '.wav':
            return _process_wav_audio(file_path)
        elif ext == '.mp3':
            return _process_mp3_audio(file_path)
        else:
            return None, f"Unsupported audio format: {ext}"
            
    except Exception as e:
        return None, f"Audio processing error: {str(e)}"

def _process_wav_audio(file_path):
    """Process WAV audio file"""
    try:
        import wave
        import numpy as np
        
        with wave.open(file_path, 'rb') as wf:
            # Get audio properties
            n_channels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            framerate = wf.getframerate()
            n_frames = wf.getnframes()
            
            # Read audio data
            audio_data = wf.readframes(n_frames)
            
            # Convert to numpy array
            dtype_map = {1: np.int8, 2: np.int16, 4: np.int32}
            if sampwidth not in dtype_map:
                return None, f"Unsupported sample width: {sampwidth}"
            
            samples = np.frombuffer(audio_data, dtype=dtype_map[sampwidth])
            
            # Convert to mono if stereo
            if n_channels == 2:
                samples = samples.reshape(-1, 2).mean(axis=1)
            elif n_channels > 2:
                samples = samples.reshape(-1, n_channels).mean(axis=1)
            
            # Normalize audio
            if len(samples) > 0:
                samples = samples.astype(np.float32)
                max_val = np.max(np.abs(samples))
                if max_val > 0:
                    samples = samples / max_val
            
            return _detect_morse_from_samples(samples, framerate)
            
    except Exception as e:
        return None, f"WAV processing error: {str(e)}"

def _process_mp3_audio(file_path):
    """Process MP3 audio file"""
    try:
        # Try to use pydub for MP3 processing
        try:
            from pydub import AudioSegment
            from pydub.utils import make_chunks
        except ImportError:
            return None, "PyDub is required for MP3 processing. Please install it with: pip install pydub"
        
        # Load MP3 file
        audio = AudioSegment.from_mp3(file_path)
        
        # Convert to mono if stereo
        if audio.channels > 1:
            audio = audio.set_channels(1)
        
        # Convert to numpy array
        samples = np.array(audio.get_array_of_samples())
        
        # Normalize
        if len(samples) > 0:
            samples = samples.astype(np.float32)
            max_val = np.max(np.abs(samples))
            if max_val > 0:
                samples = samples / max_val
        
        return _detect_morse_from_samples(samples, audio.frame_rate)
        
    except Exception as e:
        return None, f"MP3 processing error: {str(e)}"

def _detect_morse_from_samples(samples, sample_rate):
    """Detect Morse code from audio samples"""
    try:
        import numpy as np
        
        if len(samples) == 0:
            return None, "No audio data found"
        
        # Apply simple envelope detection
        envelope = np.abs(samples)
        
        # Apply smoothing to reduce noise
        window_size = max(1, int(sample_rate * 0.01))  # 10ms window
        if window_size > 1:
            envelope = np.convolve(envelope, np.ones(window_size)/window_size, mode='same')
        
        # Dynamic threshold calculation (more sensitive)
        threshold = np.percentile(envelope, 40)
        
        # Detect tone on/off
        is_tone = envelope > threshold
        
        # Group consecutive samples
        import itertools
        groups = [(k, sum(1 for _ in g)) for k, g in itertools.groupby(is_tone)]
        
        # Filter out very short signals (noise)
        min_signal_length = int(sample_rate * 0.015)  # 15ms minimum
        filtered_groups = [(k, l) for k, l in groups if l >= min_signal_length or not k]
        
        # Fallback: If no tone signals detected, try even lower threshold
        tone_lengths = [l for k, l in filtered_groups if k]
        if not tone_lengths:
            threshold = np.percentile(envelope, 20)
            is_tone = envelope > threshold
            groups = [(k, sum(1 for _ in g)) for k, g in itertools.groupby(is_tone)]
            filtered_groups = [(k, l) for k, l in groups if l >= min_signal_length or not k]
            tone_lengths = [l for k, l in filtered_groups if k]
            if not tone_lengths:
                return None, "No tone signals detected"
        
        # Calculate timing parameters
        dot_length = min(tone_lengths)
        dash_length = max(tone_lengths)
        
        # Convert to Morse
        morse = ""
        for k, l in filtered_groups:
            if k:  # Tone
                if l < (dot_length + dash_length) / 2:
                    morse += "."
                else:
                    morse += "-"
            else:  # Silence
                # Word separator (long silence)
                if l > 6 * dot_length:
                    morse += " / "
                # Character separator (medium silence)
                elif l > 2 * dot_length:
                    morse += " "
                # Element separator (short silence) - already handled by space
        
        return morse.strip(), None
        
    except Exception as e:
        return None, f"Morse detection error: {str(e)}"

def morse_to_audio(morse_code, output_file=None, frequency=800, sample_rate=44100, wpm=20):
    """Generate audio from Morse code"""
    try:
        import numpy as np
        import wave
        
        if not morse_code:
            return None, "No Morse code provided"
        
        # Morse timing (in seconds)
        dot_duration = 1.2 / wpm  # Standard dot duration
        dash_duration = 3 * dot_duration  # Dash is 3x dot
        element_gap = dot_duration  # Gap between elements
        char_gap = 3 * dot_duration  # Gap between characters
        word_gap = 7 * dot_duration  # Gap between words
        
        # Generate tone samples
        def generate_tone(duration):
            t = np.linspace(0, duration, int(sample_rate * duration), False)
            return np.sin(2 * np.pi * frequency * t)
        
        # Generate silence samples
        def generate_silence(duration):
            return np.zeros(int(sample_rate * duration))
        
        # Build audio
        audio_samples = []
        
        for char in morse_code:
            if char == '.':
                audio_samples.append(generate_tone(dot_duration))
                audio_samples.append(generate_silence(element_gap))
            elif char == '-':
                audio_samples.append(generate_tone(dash_duration))
                audio_samples.append(generate_silence(element_gap))
            elif char == ' ':
                audio_samples.append(generate_silence(char_gap - element_gap))
            elif char == '/':
                audio_samples.append(generate_silence(word_gap - element_gap))
        
        # Combine all samples
        if audio_samples:
            final_audio = np.concatenate(audio_samples)
            
            # Normalize audio
            max_val = np.max(np.abs(final_audio))
            if max_val > 0:
                final_audio = final_audio / max_val  # full volume
            
            # Convert to 16-bit integers
            audio_int16 = (final_audio * 32767).astype(np.int16)
            
            # Save to file if specified
            if output_file:
                with wave.open(output_file, 'w') as wf:
                    wf.setnchannels(1)  # Mono
                    wf.setsampwidth(2)  # 16-bit
                    wf.setframerate(sample_rate)
                    wf.writeframes(audio_int16.tobytes())
            
            return audio_int16, None
        else:
            return None, "No valid Morse code found"
            
    except Exception as e:
        return None, f"Audio generation error: {str(e)}"

def main():
    """Main function to run the crypto application"""
    root = tk.Tk()
    root.geometry("2000x1600")  # Much larger window
    root.minsize(1600, 1200)     # Minimum size
    root.resizable(True, True)  # Allow resizing
    app = CryptoMainWindow(root, lambda: None)
    root.mainloop()


if __name__ == "__main__":
    main() 