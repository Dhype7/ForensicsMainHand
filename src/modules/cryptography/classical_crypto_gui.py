"""
Classical Cryptography GUI Interface
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import sys

# Add parent directories to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from src.ui.theme import Theme
from src.ui.widgets import ModernButton
from src.config.settings import Settings
from src.modules.cryptography.crypto_main import ClassicalCiphers
from src.modules.cryptography.classical_ciphers import BinaryCipher, XORCipher

class ClassicalCryptoGUI:
    """GUI for classical cryptography ciphers"""
    
    def __init__(self, parent_frame: tk.Frame, back_callback=None):
        self.parent_frame = parent_frame
        self.back_callback = back_callback
        self.ciphers = ClassicalCiphers()
        self.current_cipher = tk.StringVar(value="caesar")
        self.input_text = ""
        self.output_text = ""
        
        self.create_widgets()
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = tk.Frame(self.parent_frame, bg=Theme.get_color('primary'))
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Back button
        def go_back():
            if self.back_callback:
                self.back_callback()
            else:
                self.parent_frame.destroy()
        ModernButton(main_frame, text="← Back", command=go_back, style='secondary').pack(anchor='w', pady=(0, 10))
        
        # Title
        title_label = tk.Label(main_frame, 
                              text="Classical Cryptography",
                              font=Theme.get_font('title'),
                              bg=Theme.get_color('primary'),
                              fg=Theme.get_color('accent'))
        title_label.pack(pady=(0, 20))
        
        # Cipher selection frame
        cipher_frame = tk.Frame(main_frame, bg=Theme.get_color('primary'))
        cipher_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(cipher_frame, text="Select Cipher:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary'),
                font=Theme.get_font('default')).pack(side='left', padx=(0, 10))
        
        cipher_combo = ttk.Combobox(cipher_frame, 
                                   textvariable=self.current_cipher,
                                   values=[
                                       "Caesar", "Affine", "Atbash", "Bacon", "Binary",
                                       "PlayFair", "Rail_Fence", "Rot13", 
                                       "Scytale", "Substitution", "Vigenere", "XOR"
                                   ],
                                   state='readonly',
                                   width=15)
        cipher_combo.pack(side='left', padx=(0, 20))
        cipher_combo.bind('<<ComboboxSelected>>', self.on_cipher_change)
        
        # Parameters frame
        self.params_frame = tk.Frame(main_frame, bg=Theme.get_color('primary'))
        self.params_frame.pack(fill='x', pady=(0, 20))
        
        # Input/Output frame
        io_frame = tk.Frame(main_frame, bg=Theme.get_color('primary'))
        io_frame.pack(fill='both', expand=True)
        
        # Input section
        input_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        input_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        tk.Label(input_frame, text="Input Text:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary'),
                font=Theme.get_font('heading')).pack(anchor='w')
        
        # Input buttons
        input_buttons_frame = tk.Frame(input_frame, bg=Theme.get_color('primary'))
        input_buttons_frame.pack(fill='x', pady=(5, 10))
        
        ModernButton(input_buttons_frame, text="Load File", 
                    command=self.load_file, style='secondary').pack(side='left', padx=(0, 10))
        ModernButton(input_buttons_frame, text="Clear", 
                    command=self.clear_input, style='secondary').pack(side='left')
        
        # Input text area
        self.input_text_area = scrolledtext.ScrolledText(input_frame, 
                                                        height=10, 
                                                        width=40,
                                                        font=('Courier', 10))
        self.input_text_area.pack(fill='both', expand=True)
        
        # Output section
        output_frame = tk.Frame(io_frame, bg=Theme.get_color('primary'))
        output_frame.pack(side='right', fill='both', expand=True, padx=(10, 0))
        
        tk.Label(output_frame, text="Output Text:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary'),
                font=Theme.get_font('heading')).pack(anchor='w')
        
        # Output buttons
        output_buttons_frame = tk.Frame(output_frame, bg=Theme.get_color('primary'))
        output_buttons_frame.pack(fill='x', pady=(5, 10))
        
        ModernButton(output_buttons_frame, text="Save File", 
                    command=self.save_file, style='secondary').pack(side='left', padx=(0, 10))
        ModernButton(output_buttons_frame, text="Clear", 
                    command=self.clear_output, style='secondary').pack(side='left', padx=(0, 10))
        
        # Output text area
        self.output_text_area = scrolledtext.ScrolledText(output_frame, 
                                                         height=10, 
                                                         width=40,
                                                         font=('Courier', 10))
        self.output_text_area.pack(fill='both', expand=True)
        
        # Action buttons
        action_frame = tk.Frame(main_frame, bg=Theme.get_color('primary'))
        action_frame.pack(fill='x', pady=(20, 0))
        
        ModernButton(action_frame, text="Encrypt", 
                    command=self.encrypt, style='primary').pack(side='left', padx=(0, 10))
        ModernButton(action_frame, text="Decrypt", 
                    command=self.decrypt, style='primary').pack(side='left')
        
        # Initialize parameters for first cipher
        self.on_cipher_change()
        
    def on_cipher_change(self, event=None):
        """Handle cipher selection change"""
        # Clear existing parameters
        for widget in self.params_frame.winfo_children():
            widget.destroy()
        # Hide XOR input frame if present
        if hasattr(self, 'xor_input_frame'):
            self.xor_input_frame.destroy()
            del self.xor_input_frame
        # Show main input area by default
        self.input_text_area.pack(fill='both', expand=True)
        cipher = self.current_cipher.get().lower()
        if cipher == "xor":
            # Hide main input area, show XOR dual input
            self.input_text_area.pack_forget()
            self.create_xor_dual_input()
            return
        elif cipher == "caesar":
            self.create_caesar_params()
        elif cipher == "affine":
            self.create_affine_params()
        elif cipher == "atbash":
            # No parameters needed
            pass
        elif cipher == "bacon":
            # No parameters needed
            pass
        elif cipher == "binary":
            self.create_binary_params()
        elif cipher == "playfair":
            self.create_playfair_params()
        elif cipher == "rail_fence":
            self.create_rail_fence_params()
        elif cipher == "rot13":
            # No parameters needed
            pass
        elif cipher == "scytale":
            self.create_scytale_params()
        elif cipher == "substitution":
            self.create_substitution_params()
        elif cipher == "vigenere":
            self.create_vigenere_params()
    
    def create_caesar_params(self):
        """Create Caesar cipher parameters"""
        tk.Label(self.params_frame, text="Shift:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary')).pack(side='left', padx=(0, 5))
        
        self.caesar_shift = tk.StringVar(value="3")
        shift_entry = tk.Entry(self.params_frame, textvariable=self.caesar_shift, width=10)
        shift_entry.pack(side='left')
    
    def create_affine_params(self):
        """Create Affine cipher parameters"""
        tk.Label(self.params_frame, text="a:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary')).pack(side='left', padx=(0, 5))
        
        self.affine_a = tk.StringVar(value="5")
        a_entry = tk.Entry(self.params_frame, textvariable=self.affine_a, width=5)
        a_entry.pack(side='left', padx=(0, 10))
        
        tk.Label(self.params_frame, text="b:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary')).pack(side='left', padx=(0, 5))
        
        self.affine_b = tk.StringVar(value="8")
        b_entry = tk.Entry(self.params_frame, textvariable=self.affine_b, width=5)
        b_entry.pack(side='left')
    
    def create_playfair_params(self):
        """Create Playfair cipher parameters"""
        tk.Label(self.params_frame, text="Key:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary')).pack(side='left', padx=(0, 5))
        
        self.playfair_key = tk.StringVar(value="MONARCHY")
        key_entry = tk.Entry(self.params_frame, textvariable=self.playfair_key, width=15)
        key_entry.pack(side='left')
    
    def create_rail_fence_params(self):
        """Create Rail Fence cipher parameters"""
        tk.Label(self.params_frame, text="Rails:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary')).pack(side='left', padx=(0, 5))
        
        self.rail_fence_rails = tk.StringVar(value="3")
        rails_entry = tk.Entry(self.params_frame, textvariable=self.rail_fence_rails, width=5)
        rails_entry.pack(side='left')
    
    def create_scytale_params(self):
        """Create Scytale cipher parameters"""
        tk.Label(self.params_frame, text="Diameter:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary')).pack(side='left', padx=(0, 5))
        
        self.scytale_diameter = tk.StringVar(value="5")
        diameter_entry = tk.Entry(self.params_frame, textvariable=self.scytale_diameter, width=5)
        diameter_entry.pack(side='left')
    
    def create_substitution_params(self):
        """Create Substitution cipher parameters"""
        tk.Label(self.params_frame, text="Key (26 chars):", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary')).pack(side='left', padx=(0, 5))
        
        self.substitution_key = tk.StringVar(value="QWERTYUIOPASDFGHJKLZXCVBNM")
        key_entry = tk.Entry(self.params_frame, textvariable=self.substitution_key, width=26)
        key_entry.pack(side='left')
    
    def create_vigenere_params(self):
        """Create Vigenère cipher parameters"""
        tk.Label(self.params_frame, text="Key:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary')).pack(side='left', padx=(0, 5))
        
        self.vigenere_key = tk.StringVar(value="KEY")
        key_entry = tk.Entry(self.params_frame, textvariable=self.vigenere_key, width=15)
        key_entry.pack(side='left')
    
    def create_xor_dual_input(self):
        """Create two horizontally-aligned input areas for XOR"""
        self.xor_input_frame = tk.Frame(self.parent_frame, bg=Theme.get_color('primary'))
        self.xor_input_frame.pack(fill='x', pady=(0, 10))
        # Input 1
        left = tk.Frame(self.xor_input_frame, bg=Theme.get_color('primary'))
        left.pack(side='left', fill='both', expand=True, padx=(0, 5))
        tk.Label(left, text="Input 1:", bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary')).pack(anchor='w')
        self.xor_input1_area = scrolledtext.ScrolledText(left, height=8, width=30, font=('Courier', 10))
        self.xor_input1_area.pack(fill='both', expand=True)
        ModernButton(left, text="Load File", command=lambda: self.load_xor_file(self.xor_input1_area), style='secondary').pack(anchor='w', pady=(5, 0))
        # Input 2
        right = tk.Frame(self.xor_input_frame, bg=Theme.get_color('primary'))
        right.pack(side='left', fill='both', expand=True, padx=(5, 0))
        tk.Label(right, text="Input 2:", bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary')).pack(anchor='w')
        self.xor_input2_area = scrolledtext.ScrolledText(right, height=8, width=30, font=('Courier', 10))
        self.xor_input2_area.pack(fill='both', expand=True)
        ModernButton(right, text="Load File", command=lambda: self.load_xor_file(self.xor_input2_area), style='secondary').pack(anchor='w', pady=(5, 0))

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

    def create_binary_params(self):
        """Create Binary cipher parameters"""
        # Conversion type selection
        tk.Label(self.params_frame, text="Conversion Type:", 
                bg=Theme.get_color('primary'), 
                fg=Theme.get_color('text_primary')).pack(side='left', padx=(0, 5))
        
        self.binary_conversion_type = tk.StringVar(value="text_to_binary")
        conversion_combo = ttk.Combobox(self.params_frame, 
                                       textvariable=self.binary_conversion_type,
                                       values=[
                                           "Text to Binary", "Binary to Text",
                                           "Text to ASCII", "ASCII to Text",
                                           "Text to Hex", "Hex to Text",
                                           "Binary to Hex", "Hex to Binary",
                                           "ASCII to Binary", "Binary to ASCII"
                                       ],
                                       state='readonly',
                                       width=15)
        conversion_combo.pack(side='left', padx=(0, 10))
        
        # Bind the conversion type change to update the button text
        conversion_combo.bind('<<ComboboxSelected>>', self.on_binary_conversion_change)
    
    def on_binary_conversion_change(self, event=None):
        """Handle binary conversion type change"""
        conversion_type = self.binary_conversion_type.get()
        # Update button text based on conversion type
        if "to" in conversion_type.lower():
            # This will be handled in the encrypt/decrypt methods
            pass
    
    def handle_binary_conversion(self, input_text: str, operation: str) -> str:
        """Handle binary cipher conversions"""
        conversion_type = self.binary_conversion_type.get().lower().replace(" ", "_")
        
        try:
            if conversion_type == "text_to_binary":
                return BinaryCipher.text_to_binary(input_text)
            elif conversion_type == "binary_to_text":
                return BinaryCipher.binary_to_text(input_text)
            elif conversion_type == "text_to_ascii":
                return BinaryCipher.text_to_ascii(input_text)
            elif conversion_type == "ascii_to_text":
                return BinaryCipher.ascii_to_text(input_text)
            elif conversion_type == "text_to_hex":
                return BinaryCipher.text_to_hex(input_text)
            elif conversion_type == "hex_to_text":
                return BinaryCipher.hex_to_text(input_text)
            elif conversion_type == "binary_to_hex":
                return BinaryCipher.binary_to_hex(input_text)
            elif conversion_type == "hex_to_binary":
                return BinaryCipher.hex_to_binary(input_text)
            elif conversion_type == "ascii_to_binary":
                return BinaryCipher.ascii_to_binary(input_text)
            elif conversion_type == "binary_to_ascii":
                return BinaryCipher.binary_to_ascii(input_text)
            else:
                return "Invalid conversion type"
        except Exception as e:
            return f"Conversion error: {str(e)}"
    
    def load_file(self):
        """Load text from file"""
        file_path = filedialog.askopenfilename(
            title="Select text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    self.input_text_area.delete(1.0, tk.END)
                    self.input_text_area.insert(1.0, content)
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
    
    def clear_input(self):
        """Clear input text area"""
        self.input_text_area.delete(1.0, tk.END)
    
    def clear_output(self):
        """Clear output text area"""
        self.output_text_area.delete(1.0, tk.END)
    
    def get_input_text(self):
        """Get text from input area"""
        return self.input_text_area.get(1.0, tk.END).strip()
    
    def set_output_text(self, text):
        """Set text in output area"""
        self.output_text_area.delete(1.0, tk.END)
        self.output_text_area.insert(1.0, text)
    
    def encrypt(self):
        """Encrypt the input text"""
        try:
            input_text = self.get_input_text()
            if not input_text:
                messagebox.showwarning("Warning", "Please enter some text to encrypt.")
                return
            
            cipher = self.current_cipher.get().lower()
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
            elif cipher == "xor":
                input1 = self.xor_input1_area.get(1.0, tk.END).strip()
                input2 = self.xor_input2_area.get(1.0, tk.END).strip()
                # XOR as bytes
                try:
                    b1 = input1.encode('utf-8')
                    b2 = input2.encode('utf-8')
                    min_len = min(len(b1), len(b2))
                    xor_bytes = bytes([x ^ y for x, y in zip(b1[:min_len], b2[:min_len])])
                    hex_result = ' '.join(f'{b:02x}' for b in xor_bytes)
                    result = hex_result
                except Exception as e:
                    result = f"XOR error: {str(e)}"
            
            self.set_output_text(result)
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid parameter: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt(self):
        """Decrypt the input text"""
        try:
            input_text = self.get_input_text()
            if not input_text:
                messagebox.showwarning("Warning", "Please enter some text to decrypt.")
                return
            
            cipher = self.current_cipher.get().lower()
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
            elif cipher == "xor":
                self.encrypt()
            else:
                result = "Decryption not implemented for this cipher"
            
            self.set_output_text(result)
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid parameter: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")