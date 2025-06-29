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
        title = tk.Label(self.window, text="🔢 Base64/32/16 Encoding/Decoding", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        input_label = tk.Label(self.window, text="Input:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        input_label.pack(anchor='w', padx=20)
        self.input_text = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.input_text.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encode Base64", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encode_base64).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Decode Base64", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decode_base64).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Encode Base32", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encode_base32).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Decode Base32", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decode_base32).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Encode Base16", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encode_base16).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Decode Base16", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decode_base16).pack(side='left', padx=5)
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=4, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def encode_base64(self):
        try:
            data = self.input_text.get('1.0', tk.END).strip().encode()
            result = base64.b64encode(data).decode()
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {e}")

    def decode_base64(self):
        try:
            data = self.input_text.get('1.0', tk.END).strip()
            result = base64.b64decode(data).decode(errors='replace')
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {e}")

    def encode_base32(self):
        try:
            data = self.input_text.get('1.0', tk.END).strip().encode()
            result = base64.b32encode(data).decode()
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {e}")

    def decode_base32(self):
        try:
            data = self.input_text.get('1.0', tk.END).strip()
            result = base64.b32decode(data).decode(errors='replace')
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {e}")

    def encode_base16(self):
        try:
            data = self.input_text.get('1.0', tk.END).strip().encode()
            result = base64.b16encode(data).decode()
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {e}")

    def decode_base16(self):
        try:
            data = self.input_text.get('1.0', tk.END).strip()
            result = base64.b16decode(data).decode(errors='replace')
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', result)
        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {e}")

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
        title = tk.Label(self.window, text="🔑 RSA Encryption/Decryption", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        key_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=20, pady=5)
        tk.Button(key_frame, text="Generate Key Pair", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.generate_keys).pack(side='left', padx=5)
        tk.Button(key_frame, text="Load Public Key", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'), command=self.load_public_key).pack(side='left', padx=5)
        tk.Button(key_frame, text="Load Private Key", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'), command=self.load_private_key).pack(side='left', padx=5)
        self.key_info = tk.Label(self.window, text="No key loaded.", font=Theme.get_font('default'), fg=Theme.get_color('text_secondary'), bg=Theme.get_color('primary'))
        self.key_info.pack(pady=2)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encrypt).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Decrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decrypt).pack(side='left', padx=10)
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=6, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def generate_keys(self):
        try:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            self.public_key = self.private_key.public_key()
            self.key_info.config(text="Key pair generated.")
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")

    def load_public_key(self):
        from tkinter.filedialog import askopenfilename
        path = askopenfilename(title="Select Public Key", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if path:
            try:
                with open(path, 'rb') as f:
                    self.public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
                from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
                if not isinstance(self.public_key, RSAPublicKey):
                    raise ValueError("Loaded public key is not an RSA key.")
                self.key_info.config(text=f"Loaded public key: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load public key: {e}")

    def load_private_key(self):
        from tkinter.filedialog import askopenfilename
        path = askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if path:
            try:
                with open(path, 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
                if not isinstance(self.private_key, RSAPrivateKey):
                    raise ValueError("Loaded private key is not an RSA key.")
                self.public_key = self.private_key.public_key()
                self.key_info.config(text=f"Loaded private key: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load private key: {e}")

    def encrypt(self):
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        if not self.public_key:
            messagebox.showwarning("Warning", "No public key loaded.")
            return
        if not isinstance(self.public_key, RSAPublicKey):
            messagebox.showerror("Error", "Loaded public key is not an RSA key.")
            return
        msg = self.msg_entry.get('1.0', tk.END).strip().encode()
        try:
            ciphertext = self.public_key.encrypt(
                msg,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', base64.b64encode(ciphertext).decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt(self):
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        if not self.private_key:
            messagebox.showwarning("Warning", "No private key loaded.")
            return
        if not isinstance(self.private_key, RSAPrivateKey):
            messagebox.showerror("Error", "Loaded private key is not an RSA key.")
            return
        try:
            ciphertext = base64.b64decode(self.msg_entry.get('1.0', tk.END).strip())
            plaintext = self.private_key.decrypt(
                ciphertext,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', plaintext.decode(errors='replace'))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

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
        title = tk.Label(self.window, text="🔑 AES Encryption/Decryption", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        key_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(key_frame, text="Key (16/24/32 bytes):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.key_entry = tk.Entry(key_frame, font=Theme.get_font('monospace'), width=32)
        self.key_entry.pack(side='left', padx=5)
        iv_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        iv_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(iv_frame, text="IV (16 bytes):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.iv_entry = tk.Entry(iv_frame, font=Theme.get_font('monospace'), width=16)
        self.iv_entry.pack(side='left', padx=5)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encrypt).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Decrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decrypt).pack(side='left', padx=10)
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=6, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def encrypt(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = self.key_entry.get().encode()
        iv = self.iv_entry.get().encode()
        msg = self.msg_entry.get('1.0', tk.END).strip().encode()
        if len(key) not in (16, 24, 32):
            messagebox.showerror("Error", "Key must be 16, 24, or 32 bytes.")
            return
        if len(iv) != 16:
            messagebox.showerror("Error", "IV must be 16 bytes.")
            return
        try:
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(msg) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_data) + encryptor.finalize()
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', base64.b64encode(ct).decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = self.key_entry.get().encode()
        iv = self.iv_entry.get().encode()
        try:
            ct = base64.b64decode(self.msg_entry.get('1.0', tk.END).strip())
        except Exception as e:
            messagebox.showerror("Error", f"Invalid base64 input: {e}")
            return
        if len(key) not in (16, 24, 32):
            messagebox.showerror("Error", "Key must be 16, 24, or 32 bytes.")
            return
        if len(iv) != 16:
            messagebox.showerror("Error", "IV must be 16 bytes.")
            return
        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', data.decode(errors='replace'))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

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
        title = tk.Label(self.window, text="🔑 Blowfish Encryption/Decryption", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        key_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(key_frame, text="Key (4-56 bytes):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.key_entry = tk.Entry(key_frame, font=Theme.get_font('monospace'), width=32)
        self.key_entry.pack(side='left', padx=5)
        iv_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        iv_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(iv_frame, text="IV (8 bytes):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.iv_entry = tk.Entry(iv_frame, font=Theme.get_font('monospace'), width=8)
        self.iv_entry.pack(side='left', padx=5)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encrypt).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Decrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decrypt).pack(side='left', padx=10)
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=6, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def encrypt(self):
        try:
            from Crypto.Cipher import Blowfish  # type: ignore
        except ImportError:
            messagebox.showerror("Error", "pycryptodome is required for Blowfish support.")
            return
        key = self.key_entry.get().encode()
        iv = self.iv_entry.get().encode()
        msg = self.msg_entry.get('1.0', tk.END).strip().encode()
        if not (4 <= len(key) <= 56):
            messagebox.showerror("Error", "Key must be 4-56 bytes.")
            return
        if len(iv) != 8:
            messagebox.showerror("Error", "IV must be 8 bytes.")
            return
        try:
            bs = Blowfish.block_size
            plen = bs - len(msg) % bs
            padding = bytes([plen]) * plen
            padded_msg = msg + padding
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            ct = cipher.encrypt(padded_msg)
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', base64.b64encode(ct).decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt(self):
        try:
            from Crypto.Cipher import Blowfish  # type: ignore
        except ImportError:
            messagebox.showerror("Error", "pycryptodome is required for Blowfish support.")
            return
        key = self.key_entry.get().encode()
        iv = self.iv_entry.get().encode()
        try:
            ct = base64.b64decode(self.msg_entry.get('1.0', tk.END).strip())
        except Exception as e:
            messagebox.showerror("Error", f"Invalid base64 input: {e}")
            return
        if not (4 <= len(key) <= 56):
            messagebox.showerror("Error", "Key must be 4-56 bytes.")
            return
        if len(iv) != 8:
            messagebox.showerror("Error", "IV must be 8 bytes.")
            return
        try:
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            padded_data = cipher.decrypt(ct)
            plen = padded_data[-1]
            data = padded_data[:-plen]
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', data.decode(errors='replace'))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

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
        title = tk.Label(self.window, text="🔑 DES Encryption/Decryption", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        key_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(key_frame, text="Key (8 bytes):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.key_entry = tk.Entry(key_frame, font=Theme.get_font('monospace'), width=8)
        self.key_entry.pack(side='left', padx=5)
        iv_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        iv_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(iv_frame, text="IV (8 bytes):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.iv_entry = tk.Entry(iv_frame, font=Theme.get_font('monospace'), width=8)
        self.iv_entry.pack(side='left', padx=5)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encrypt).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Decrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decrypt).pack(side='left', padx=10)
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=6, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def encrypt(self):
        if not DES_AVAILABLE:
            messagebox.showerror("Error", "pycryptodome is required for DES support.")
            return
        key = self.key_entry.get().encode()
        iv = self.iv_entry.get().encode()
        msg = self.msg_entry.get('1.0', tk.END).strip().encode()
        if len(key) != 8:
            messagebox.showerror("Error", "Key must be 8 bytes.")
            return
        if len(iv) != 8:
            messagebox.showerror("Error", "IV must be 8 bytes.")
            return
        try:
            bs = 8
            plen = bs - len(msg) % bs
            padding = bytes([plen]) * plen
            padded_msg = msg + padding
            from Crypto.Cipher import DES  # type: ignore
            cipher = DES.new(key, DES.MODE_CBC, iv)
            ct = cipher.encrypt(padded_msg)
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', base64.b64encode(ct).decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt(self):
        if not DES_AVAILABLE:
            messagebox.showerror("Error", "pycryptodome is required for DES support.")
            return
        key = self.key_entry.get().encode()
        iv = self.iv_entry.get().encode()
        try:
            ct = base64.b64decode(self.msg_entry.get('1.0', tk.END).strip())
        except Exception as e:
            messagebox.showerror("Error", f"Invalid base64 input: {e}")
            return
        if len(key) != 8:
            messagebox.showerror("Error", "Key must be 8 bytes.")
            return
        if len(iv) != 8:
            messagebox.showerror("Error", "IV must be 8 bytes.")
            return
        try:
            from Crypto.Cipher import DES  # type: ignore
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded_data = cipher.decrypt(ct)
            plen = padded_data[-1]
            data = padded_data[:-plen]
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', data.decode(errors='replace'))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

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
        title = tk.Label(self.window, text="🔑 One-Time Pad (OTP)", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        key_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(key_frame, text="Key (same length as message):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.key_entry = tk.Entry(key_frame, font=Theme.get_font('monospace'), width=32)
        self.key_entry.pack(side='left', padx=5)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encrypt).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Decrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decrypt).pack(side='left', padx=10)
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=6, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def encrypt(self):
        msg = self.msg_entry.get('1.0', tk.END).strip().encode()
        key = self.key_entry.get().encode()
        if len(msg) == 0 or len(key) == 0:
            messagebox.showerror("Error", "Message and key cannot be empty.")
            return
        if len(msg) != len(key):
            messagebox.showerror("Error", "Key must be the same length as the message.")
            return
        ct = bytes([m ^ k for m, k in zip(msg, key)])
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', base64.b64encode(ct).decode())

    def decrypt(self):
        try:
            ct = base64.b64decode(self.msg_entry.get('1.0', tk.END).strip())
        except Exception as e:
            messagebox.showerror("Error", f"Invalid base64 input: {e}")
            return
        key = self.key_entry.get().encode()
        if len(ct) == 0 or len(key) == 0:
            messagebox.showerror("Error", "Ciphertext and key cannot be empty.")
            return
        if len(ct) != len(key):
            messagebox.showerror("Error", "Key must be the same length as the ciphertext.")
            return
        msg = bytes([c ^ k for c, k in zip(ct, key)])
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', msg.decode(errors='replace'))

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
        title = tk.Label(self.window, text="🔑 RC4 Stream Cipher", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        key_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(key_frame, text="Key (1-256 bytes):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.key_entry = tk.Entry(key_frame, font=Theme.get_font('monospace'), width=32)
        self.key_entry.pack(side='left', padx=5)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encrypt).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Decrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decrypt).pack(side='left', padx=10)
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=6, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def encrypt(self):
        try:
            from Crypto.Cipher import ARC4  # type: ignore
        except ImportError:
            messagebox.showerror("Error", "pycryptodome is required for RC4 support.")
            return
        key = self.key_entry.get().encode()
        msg = self.msg_entry.get('1.0', tk.END).strip().encode()
        if not (1 <= len(key) <= 256):
            messagebox.showerror("Error", "Key must be 1-256 bytes.")
            return
        try:
            cipher = ARC4.new(key)
            ct = cipher.encrypt(msg)
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', base64.b64encode(ct).decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt(self):
        try:
            from Crypto.Cipher import ARC4  # type: ignore
        except ImportError:
            messagebox.showerror("Error", "pycryptodome is required for RC4 support.")
            return
        key = self.key_entry.get().encode()
        try:
            ct = base64.b64decode(self.msg_entry.get('1.0', tk.END).strip())
        except Exception as e:
            messagebox.showerror("Error", f"Invalid base64 input: {e}")
            return
        if not (1 <= len(key) <= 256):
            messagebox.showerror("Error", "Key must be 1-256 bytes.")
            return
        try:
            cipher = ARC4.new(key)
            msg = cipher.decrypt(ct)
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', msg.decode(errors='replace'))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

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
        title = tk.Label(self.window, text="🚂 Rail Fence Cipher", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        rails_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        rails_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(rails_frame, text="Rails:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.rails_entry = tk.Entry(rails_frame, font=Theme.get_font('monospace'), width=5)
        self.rails_entry.insert(0, "3")
        self.rails_entry.pack(side='left', padx=5)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encrypt).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Decrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decrypt).pack(side='left', padx=10)
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=6, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def encrypt(self):
        try:
            rails = int(self.rails_entry.get())
            msg = self.msg_entry.get('1.0', tk.END).strip()
            if rails < 2 or not msg:
                raise ValueError
            fence = [[] for _ in range(rails)]
            rail = 0
            var = 1
            for char in msg:
                fence[rail].append(char)
                rail += var
                if rail == 0 or rail == rails - 1:
                    var = -var
            result = ''.join(''.join(row) for row in fence)
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', result)
        except Exception:
            messagebox.showerror("Error", "Invalid rails or message.")

    def decrypt(self):
        try:
            rails = int(self.rails_entry.get())
            msg = self.msg_entry.get('1.0', tk.END).strip()
            if rails < 2 or not msg:
                raise ValueError
            pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
            pos = [0] * rails
            rail_len = [0] * rails
            idx = 0
            for char in msg:
                rail_len[pattern[idx % len(pattern)]] += 1
                idx += 1
            idx = 0
            rails_str = []
            for r in range(rails):
                rails_str.append(msg[idx:idx + rail_len[r]])
                idx += rail_len[r]
            result = []
            idxs = [0] * rails
            for i in range(len(msg)):
                r = pattern[i % len(pattern)]
                result.append(rails_str[r][idxs[r]])
                idxs[r] += 1
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', ''.join(result))
        except Exception:
            messagebox.showerror("Error", "Invalid rails or message.")

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
        title = tk.Label(self.window, text="🔤 Substitution Cipher", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        key_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(key_frame, text="Key (26 letters):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.key_entry = tk.Entry(key_frame, font=Theme.get_font('monospace'), width=30)
        self.key_entry.insert(0, "QWERTYUIOPASDFGHJKLZXCVBNM")
        self.key_entry.pack(side='left', padx=5)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encrypt).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Decrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decrypt).pack(side='left', padx=10)
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=6, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def encrypt(self):
        key = self.key_entry.get().upper()
        msg = self.msg_entry.get('1.0', tk.END).strip().upper()
        if len(key) != 26 or len(set(key)) != 26:
            messagebox.showerror("Error", "Key must be 26 unique letters.")
            return
        table = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", key)
        result = msg.translate(table)
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', result)

    def decrypt(self):
        key = self.key_entry.get().upper()
        msg = self.msg_entry.get('1.0', tk.END).strip().upper()
        if len(key) != 26 or len(set(key)) != 26:
            messagebox.showerror("Error", "Key must be 26 unique letters.")
            return
        table = str.maketrans(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        result = msg.translate(table)
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', result)

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
        title = tk.Label(self.window, text="❌ XOR Cipher", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        key_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(key_frame, text="Key:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.key_entry = tk.Entry(key_frame, font=Theme.get_font('monospace'), width=32)
        self.key_entry.pack(side='left', padx=5)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt/Decrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.xor).pack(side='left', padx=10)
        out_label = tk.Label(self.window, text="Output (hex):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=6, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def xor(self):
        msg = self.msg_entry.get('1.0', tk.END).strip().encode()
        key = self.key_entry.get().encode()
        if not msg or not key:
            messagebox.showerror("Error", "Message and key cannot be empty.")
            return
        result = bytes([m ^ key[i % len(key)] for i, m in enumerate(msg)])
        hex_result = result.hex()
        try:
            text_result = result.decode('utf-8')
        except Exception:
            text_result = "<non-UTF8 output>"
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', f"Text: {text_result}\nHex: {hex_result}")

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
        title = tk.Label(self.window, text="🔲 Playfair Cipher", font=Theme.get_font('title'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        title.pack(pady=10)
        key_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        key_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(key_frame, text="Key (letters):", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary')).pack(side='left')
        self.key_entry = tk.Entry(key_frame, font=Theme.get_font('monospace'), width=30)
        self.key_entry.insert(0, "KEYWORD")
        self.key_entry.pack(side='left', padx=5)
        msg_label = tk.Label(self.window, text="Message:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        msg_label.pack(anchor='w', padx=20)
        self.msg_entry = tk.Text(self.window, height=4, font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.msg_entry.pack(fill='x', padx=20, pady=5)
        btn_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.encrypt).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Decrypt", font=Theme.get_font('button'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('accent'), command=self.decrypt).pack(side='left', padx=10)
        out_label = tk.Label(self.window, text="Output:", font=Theme.get_font('default'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('primary'))
        out_label.pack(anchor='w', padx=20)
        self.output_text = tk.Text(self.window, height=6, font=Theme.get_font('monospace'), fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        self.output_text.pack(fill='x', padx=20, pady=5)

    def encrypt(self):
        # Placeholder: You can implement Playfair logic or call your core function here
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', "Playfair encryption not yet implemented.")

    def decrypt(self):
        # Placeholder: You can implement Playfair logic or call your core function here
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', "Playfair decryption not yet implemented.")

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