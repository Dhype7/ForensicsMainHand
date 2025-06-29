import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from ui.theme import Theme
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import binascii
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
import hashlib
import hmac
import string
from collections import Counter

try:
    from Crypto.Cipher import DES  # type: ignore
    DES_AVAILABLE = True
except ImportError:
    DES_AVAILABLE = False

class BaseCryptoWindow:
    """Base64/Base32/Base16 Encoding/Decoding"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("Base64/32/16 Encoding/Decoding")
        self.window.geometry("600x400")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class SHA256CryptoWindow:
    """SHA-256 Hashing Window"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("SHA-256 Hashing")
        self.window.geometry("600x400")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(self.window, text="🔑 SHA-256 Hashing", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn = tk.Button(self.window, text="Hash", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.hash)
        btn.pack(pady=10)
        out_label = tk.Label(self.window, text="SHA-256 Hash:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=3, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def hash(self):
        msg = self.msg_entry.get('1.0', tk.END).strip().encode()
        sha256_hash = hashlib.sha256(msg).hexdigest()
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', sha256_hash)

class RSACryptoWindow:
    """RSA Encryption/Decryption Window"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("RSA Encryption/Decryption")
        self.window.geometry("600x500")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.private_key = None
        self.public_key = None
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class AESCryptoWindow:
    """AES Encryption/Decryption Window"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("AES Encryption/Decryption")
        self.window.geometry("600x500")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class BlowfishCryptoWindow:
    """Blowfish Encryption/Decryption Window"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("Blowfish Encryption/Decryption")
        self.window.geometry("600x500")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class DESCryptoWindow:
    """DES Encryption/Decryption Window"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("DES Encryption/Decryption")
        self.window.geometry("600x500")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class OTPCryptoWindow:
    """One-Time Pad Encryption/Decryption Window"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("One-Time Pad Encryption/Decryption")
        self.window.geometry("600x500")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class RC4CryptoWindow:
    """RC4 Stream Cipher Window"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("RC4 Stream Cipher")
        self.window.geometry("600x500")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class RailFenceCryptoWindow:
    """Rail Fence Transposition Cipher"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("Rail Fence Cipher")
        self.window.geometry("600x500")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class SubstitutionCryptoWindow:
    """Substitution Cipher with Custom Alphabet"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("Substitution Cipher")
        self.window.geometry("700x600")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class XORCryptoWindow:
    """XOR Cipher with Key Analysis"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("XOR Cipher")
        self.window.geometry("700x600")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class PlayfairCryptoWindow:
    """Playfair Cipher Implementation"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("Playfair Cipher")
        self.window.geometry("700x600")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        # ... existing code ...
        pass

    # ... rest of the class ...

class HMACCryptoWindow:
    """HMAC (Keyed-Hash Message Authentication Code) Window"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("HMAC Authentication")
        self.window.geometry("600x400")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(self.window, text="🔑 HMAC Authentication", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        key_label = tk.Label(self.window, text="Key:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        key_label.pack(anchor='w', padx=20)
        self.key_entry = tk.Entry(self.window, font=Theme.get_font('monospace'), width=50)
        self.key_entry.pack(fill='x', padx=20, pady=5)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn = tk.Button(self.window, text="Compute HMAC", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.compute_hmac)
        btn.pack(pady=10)
        out_label = tk.Label(self.window, text="HMAC (SHA-256):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=3, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def compute_hmac(self):
        key = self.key_entry.get().encode()
        msg = self.msg_entry.get('1.0', tk.END).strip().encode()
        hmac_val = hmac.new(key, msg, hashlib.sha256).hexdigest()
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', hmac_val)

class MD5CryptoWindow:
    """MD5 Hashing Window"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("MD5 Hashing")
        self.window.geometry("600x400")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(self.window, text="🔑 MD5 Hashing", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn = tk.Button(self.window, text="Hash", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.hash)
        btn.pack(pady=10)
        out_label = tk.Label(self.window, text="MD5 Hash:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=3, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def hash(self):
        msg = self.msg_entry.get('1.0', tk.END).strip().encode()
        md5_hash = hashlib.md5(msg).hexdigest()
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', md5_hash)

class MagicHasherWindow:
    """Magic Hasher: Identify and crack hashes using hash-identifier and hashcat"""
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("Magic Hasher")
        self.window.geometry("700x500")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.grab_set()
        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(self.window, text="✨ Magic Hasher", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        # Input area
        input_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        input_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(input_frame, text="Hash or File:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(anchor='w')
        self.hash_entry = tk.Text(input_frame, height=3, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.hash_entry.pack(fill='x', pady=5)
        btn_frame = tk.Frame(input_frame, bg=Theme.get_color('primary'))
        btn_frame.pack(anchor='w', pady=2)
        tk.Button(btn_frame, text="Load File", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.load_file).pack(side='left', padx=2)
        tk.Button(btn_frame, text="Clear", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'), command=self.clear_input).pack(side='left', padx=2)
        # Identify and crack buttons
        action_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        action_frame.pack(pady=10)
        tk.Button(action_frame, text="Identify Hash Type", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.identify_hash).pack(side='left', padx=10)
        tk.Button(action_frame, text="Crack with Hashcat", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.crack_hash).pack(side='left', padx=10)
        # Output area
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=10, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='both', expand=True, padx=20, pady=5)

    def load_file(self):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(title="Select Hash File", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.hash_entry.delete('1.0', tk.END)
            self.hash_entry.insert('1.0', content)

    def clear_input(self):
        self.hash_entry.delete('1.0', tk.END)

    def identify_hash(self):
        import subprocess
        hash_value = self.hash_entry.get('1.0', tk.END).strip()
        if not hash_value:
            self.output_text.insert('1.0', 'Please enter a hash or load a file.\n')
            return
        try:
            # Run hash-identifier (must be installed and in PATH)
            result = subprocess.run(['hash-identifier'], input=hash_value.encode(), capture_output=True, timeout=10)
            output = result.stdout.decode(errors='replace')
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', output)
        except Exception as e:
            self.output_text.insert('1.0', f'Error running hash-identifier: {e}\n')

    def crack_hash(self):
        import subprocess
        import tempfile
        hash_value = self.hash_entry.get('1.0', tk.END).strip()
        if not hash_value:
            self.output_text.insert('1.0', 'Please enter a hash or load a file.\n')
            return
        # Ask user for hashcat mode
        from tkinter.simpledialog import askstring
        mode = askstring("Hashcat Mode", "Enter hashcat mode number (e.g., 0 for MD5, 100 for SHA1, 1400 for SHA256):\nRefer to https://hashcat.net/wiki/doku.php?id=example_hashes")
        if not mode or not mode.isdigit():
            self.output_text.insert('1.0', 'Invalid or missing hashcat mode.\n')
            return
        # Save hash to temp file
        with tempfile.NamedTemporaryFile('w+', delete=False) as tf:
            tf.write(hash_value)
            tf.flush()
            hash_file = tf.name
        # Ask user for wordlist
        from tkinter.filedialog import askopenfilename
        wordlist = askopenfilename(title="Select Wordlist for Hashcat", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not wordlist:
            self.output_text.insert('1.0', 'No wordlist selected.\n')
            return
        try:
            # Run hashcat (must be installed and in PATH)
            cmd = ['hashcat', '-m', mode, hash_file, wordlist, '--quiet', '--potfile-disable']
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            output = result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace')
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', output)
        except Exception as e:
            self.output_text.insert('1.0', f'Error running hashcat: {e}\n')

# Add Magic Hasher to the advanced types list in the launcher/grid