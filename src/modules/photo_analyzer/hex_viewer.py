import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import threading
import re

class HexViewerWindow:
    """A window for viewing and editing files as hex, with find/replace, search, and save as copy features."""
    spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    def __init__(self, root, file_path):
        self.root = root
        self.file_path = file_path
        self.root.title(f"Hex Viewer - {file_path}")
        self.hex_data = b''
        self.group_size = 2  # Group hex bytes by 2 for coloring
        self.loading_overlay = None
        self.loading_label = None
        self.loading_spinner = None
        self.spinner_index = 0
        self.loading_after_id = None
        self.create_widgets()
        self.show_loading("Loading file...")
        threading.Thread(target=self.load_file, daemon=True).start()
        self.root.geometry('1200x800')
        self.root.minsize(900, 600)

    def create_widgets(self):
        # Toolbar
        toolbar = tk.Frame(self.root)
        toolbar.pack(fill='x', padx=5, pady=5)
        
        tk.Button(toolbar, text="Find", command=self.find_hex).pack(side='left', padx=2)
        tk.Button(toolbar, text="Replace", command=self.replace_hex).pack(side='left', padx=2)
        tk.Button(toolbar, text="Search (ASCII)", command=self.search_ascii).pack(side='left', padx=2)
        tk.Button(toolbar, text="Save As Copy", command=self.save_as_copy).pack(side='right', padx=2)
        
        # --- CTF Feature Button Area ---
        try:
            from .widgets import ModernButton
            btn_class = ModernButton
        except ImportError:
            btn_class = tk.Button
        self.ctf_feature_button_frame = tk.Frame(self.root)
        self.ctf_feature_button_frame.pack(fill='x', padx=5, pady=(0, 5))
        ctf_buttons = [
            ("Highlight Flags", self.ctf_highlight_flags),
            ("Search Magic Numbers", self.ctf_search_magic_numbers),
            ("Copy Selected Hex", self.ctf_copy_selected_hex),
            ("Marker IDE", self.ctf_marker_ide),
        ]
        max_cols = 3
        for i, (label, command) in enumerate(ctf_buttons):
            btn = btn_class(self.ctf_feature_button_frame, text=label, command=command, width=16)
            row, col = divmod(i, max_cols)
            btn.grid(row=row, column=col, padx=3, pady=3, sticky='ew')
        for col in range(max_cols):
            self.ctf_feature_button_frame.grid_columnconfigure(col, weight=1)

        # Hex display
        self.text = tk.Text(self.root, wrap='none', font=('Consolas', 14), undo=True)
        self.text.pack(fill='both', expand=True)
        self.text.config(state='normal')
        
        # Scrollbars
        yscroll = tk.Scrollbar(self.text, orient='vertical', command=self.text.yview)
        yscroll.pack(side='right', fill='y')
        self.text.configure(yscrollcommand=yscroll.set)
        xscroll = tk.Scrollbar(self.text, orient='horizontal', command=self.text.xview)
        xscroll.pack(side='bottom', fill='x')
        self.text.configure(xscrollcommand=xscroll.set)

        # Tag configs for coloring
        self.text.tag_configure('offset', foreground='#3A6EA5', font=('Consolas', 14, 'bold'))
        self.text.tag_configure('ascii', foreground='#2E8B57', font=('Consolas', 14, 'bold'))
        self.text.tag_configure('group1', foreground='#B8860B')
        self.text.tag_configure('group2', foreground='#8B008B')
        self.text.tag_configure('highlight', background='yellow', foreground='black')
        self.text.tag_configure('hex_cursor', background='#FFD700', foreground='black')
        self.text.tag_configure('ascii_cursor', background='#FFD700', foreground='black')
        self.text.tag_configure('search', background='#00FF00', foreground='black')
        # Marker IDE color tags
        self.text.tag_configure('marker_length1', background='#4169E1', foreground='white')  # Blue - first 2 bytes (length)
        self.text.tag_configure('marker_length2', background='#4169E1', foreground='white')  # Blue - first 2 bytes (length)
        self.text.tag_configure('marker_fraction', background='#8A2BE2', foreground='white')  # Purple - 1 byte (data fraction)
        self.text.tag_configure('marker_height1', background='#32CD32', foreground='black')  # Green - 2 bytes (image height)
        self.text.tag_configure('marker_height2', background='#32CD32', foreground='black')  # Green - 2 bytes (image height)
        self.text.tag_configure('marker_width1', background='#FFA500', foreground='black')   # Orange - 2 bytes (image width)
        self.text.tag_configure('marker_width2', background='#FFA500', foreground='black')   # Orange - 2 bytes (image width)

        # Bind events for highlighting and editing
        self.text.bind('<Button-1>', self.on_click)
        self.text.bind('<KeyRelease>', self.on_key_release)
        self.text.bind('<Key>', self.on_key)
        self.text.bind('<Delete>', self.on_key)
        self.text.bind('<BackSpace>', self.on_key)
        # Enable Ctrl+C, Ctrl+V, Ctrl+X
        self.text.bind('<Control-c>', lambda e: self.text.event_generate('<<Copy>>'))
        self.text.bind('<Control-x>', lambda e: self.text.event_generate('<<Cut>>'))
        self.text.bind('<Control-v>', lambda e: self.text.event_generate('<<Paste>>'))
        # Clear highlight on click anywhere
        self.text.bind('<Button-1>', self.clear_all_highlights, add='+')

    # --- Loading Overlay ---
    def create_loading_overlay(self):
        if self.loading_overlay:
            return
        self.loading_overlay = tk.Frame(self.root, bg='black')
        self.loading_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.loading_overlay.lift()
        # Centered container
        loading_container = tk.Frame(self.loading_overlay, bg='#222', bd=3, relief='raised', padx=60, pady=50)
        loading_container.place(relx=0.5, rely=0.5, anchor='center')
        self.loading_spinner = tk.Label(loading_container, text=self.spinner_chars[0], font=('Segoe UI', 48), bg='#222', fg='#FFD700')
        self.loading_spinner.pack(pady=(0, 20))
        self.loading_label = tk.Label(loading_container, text="Loading...", font=('Segoe UI', 20, 'bold'), bg='#222', fg='white')
        self.loading_label.pack()

    def show_loading(self, message="Loading..."):
        if not self.loading_overlay:
            self.create_loading_overlay()
        if self.loading_label:
            self.loading_label.config(text=message)
        if self.loading_overlay:
            self.loading_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.loading_overlay.lift()
            self.root.update_idletasks()
            self.animate_spinner()

    def hide_loading(self):
        if self.loading_overlay:
            self.loading_overlay.place_forget()
            if self.loading_after_id:
                self.root.after_cancel(self.loading_after_id)
                self.loading_after_id = None

    def animate_spinner(self):
        if (self.loading_spinner and self.loading_overlay and self.loading_overlay.winfo_viewable()):
            self.spinner_index = (self.spinner_index + 1) % len(self.spinner_chars)
            self.loading_spinner.config(text=self.spinner_chars[self.spinner_index])
            self.loading_after_id = self.root.after(100, self.animate_spinner)

    # --- Hex Logic ---
    def load_file(self):
        try:
            with open(self.file_path, 'rb') as f:
                self.hex_data = f.read()
            self.root.after(0, self.display_hex)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load file: {e}"))
            self.root.after(0, self.root.destroy)
        finally:
            self.root.after(0, self.hide_loading)

    def display_hex(self):
        self.text.config(state='normal')
        self.text.delete('1.0', tk.END)
        lines = []
        for i in range(0, len(self.hex_data), 16):
            chunk = self.hex_data[i:i+16]
            offset = f'{i:08X}'
            hex_parts = []
            ascii_part = ''
            for j, b in enumerate(chunk):
                group_tag = 'group1' if (j // self.group_size) % 2 == 0 else 'group2'
                hex_parts.append((f'{b:02X}', group_tag))
                ascii_part += chr(b) if 32 <= b < 127 else '.'
            hex_str = ''
            for idx, (hx, tag) in enumerate(hex_parts):
                if idx > 0:
                    hex_str += ' '
                hex_str += hx
            hex_str = f'{hex_str:<47}'
            line = f'{offset}  {hex_str}  {ascii_part}'
            lines.append(line)
        self.text.insert('1.0', '\n'.join(lines))
        # Colorize columns and groups
        for line_idx in range(len(lines)):
            base = f'{line_idx+1}.0'
            self.text.tag_add('offset', base, f'{line_idx+1}.8')
            hex_start = 10
            for j in range(16):
                group_tag = 'group1' if (j // self.group_size) % 2 == 0 else 'group2'
                col = hex_start + j*3
                self.text.tag_add(group_tag, f'{line_idx+1}.{col}', f'{line_idx+1}.{col+2}')
            ascii_start = 60
            self.text.tag_add('ascii', f'{line_idx+1}.{ascii_start}', f'{line_idx+1}.{ascii_start+16}')
        self.text.config(state='normal')

    def update_hex_from_text(self):
        # Parse the hex area and update self.hex_data
        lines = self.text.get('1.0', tk.END).splitlines()
        new_bytes = bytearray()
        for line in lines:
            if len(line) < 60:
                continue
            hex_area = line[10:58]
            hex_bytes = hex_area.split()
            for hx in hex_bytes:
                try:
                    new_bytes.append(int(hx, 16))
                except Exception:
                    pass  # Ignore invalid
        self.hex_data = bytes(new_bytes)
        self.display_hex()

    def on_key(self, event):
        # Allow only valid hex editing in the hex area
        cursor = self.text.index(tk.INSERT)
        line, col = map(int, cursor.split('.'))
        # Navigation keys: do nothing, let Tkinter handle
        if event.keysym in ('Left', 'Right', 'Up', 'Down', 'Tab', 'Shift_L', 'Shift_R', 'Control_L', 'Control_R', 'Home', 'End', 'Next', 'Prior'):
            return  # Do not update data or re-render
        if 10 <= col < 58:  # Hex area
            # Allow hex digits, space, backspace, delete
            if event.keysym in ('BackSpace', 'Delete'):
                self.root.after_idle(self.update_hex_from_text)
                return
            if event.char.upper() in '0123456789ABCDEF':
                self.root.after_idle(self.update_hex_from_text)
                return
            if event.char == ' ':
                return
            return 'break'  # Block other keys
        elif 60 <= col < 76:  # ASCII area
            # Allow ASCII editing
            if event.keysym in ('BackSpace', 'Delete'):
                self.root.after_idle(self.update_ascii_from_text)
                return
            if 32 <= ord(event.char) < 127:
                self.root.after_idle(self.update_ascii_from_text)
                return
            return 'break'
        else:
            return 'break'

    def update_ascii_from_text(self):
        # Parse the ASCII area and update self.hex_data
        lines = self.text.get('1.0', tk.END).splitlines()
        new_bytes = bytearray()
        for line in lines:
            if len(line) < 76:
                continue
            ascii_area = line[60:76]
            for ch in ascii_area:
                new_bytes.append(ord(ch) if 32 <= ord(ch) < 127 else 0x2E)
        self.hex_data = bytes(new_bytes)
        self.display_hex()

    def find_hex(self):
        # Use a Toplevel dialog for better paste support
        dialog = tk.Toplevel(self.root)
        dialog.title("Find Hex")
        dialog.geometry("350x100")
        dialog.transient(self.root)
        dialog.grab_set()
        tk.Label(dialog, text="Enter hex bytes to find (e.g. 89 50 4E 47):").pack(pady=5)
        entry = tk.Entry(dialog, font=('Consolas', 12))
        entry.pack(padx=10, pady=5, fill='x')
        entry.focus_set()
        entry.bind('<Control-v>', lambda e: entry.event_generate('<<Paste>>'))
        entry.bind('<Control-c>', lambda e: entry.event_generate('<<Copy>>'))
        entry.bind('<Control-x>', lambda e: entry.event_generate('<<Cut>>'))
        result = []
        def on_ok():
            result.append(entry.get())
            dialog.destroy()
        tk.Button(dialog, text="OK", command=on_ok).pack(pady=5)
        self.root.wait_window(dialog)
        hex_str = result[0] if result else None
        if not hex_str:
            return
        try:
            pattern = bytes.fromhex(hex_str)
        except Exception:
            messagebox.showerror("Error", "Invalid hex input.")
            return
        self.clear_search_highlight()
        idx = self.hex_data.find(pattern)
        if idx == -1:
            messagebox.showinfo("Find Hex", "Pattern not found.")
        else:
            self.highlight_offset(idx, len(pattern), tag='search')

    def replace_hex(self):
        hex_find = simpledialog.askstring("Find Hex", "Enter hex bytes to find:")
        hex_replace = simpledialog.askstring("Replace With", "Enter replacement hex bytes:")
        if not hex_find or hex_replace is None:
            return
        try:
            find_bytes = bytes.fromhex(hex_find)
            replace_bytes = bytes.fromhex(hex_replace)
        except Exception:
            messagebox.showerror("Error", "Invalid hex input.")
            return
        idx = self.hex_data.find(find_bytes)
        if idx == -1:
            messagebox.showinfo("Replace Hex", "Pattern not found.")
            return
        self.hex_data = self.hex_data[:idx] + replace_bytes + self.hex_data[idx+len(find_bytes):]
        self.display_hex()
        messagebox.showinfo("Replace Hex", f"Replaced at offset {idx:08X}.")

    def search_ascii(self):
        # Use a Toplevel dialog for better paste support
        dialog = tk.Toplevel(self.root)
        dialog.title("Search ASCII")
        dialog.geometry("350x100")
        dialog.transient(self.root)
        dialog.grab_set()
        tk.Label(dialog, text="Enter ASCII string to search:").pack(pady=5)
        entry = tk.Entry(dialog, font=('Consolas', 12))
        entry.pack(padx=10, pady=5, fill='x')
        entry.focus_set()
        entry.bind('<Control-v>', lambda e: entry.event_generate('<<Paste>>'))
        entry.bind('<Control-c>', lambda e: entry.event_generate('<<Copy>>'))
        entry.bind('<Control-x>', lambda e: entry.event_generate('<<Cut>>'))
        result = []
        def on_ok():
            result.append(entry.get())
            dialog.destroy()
        tk.Button(dialog, text="OK", command=on_ok).pack(pady=5)
        self.root.wait_window(dialog)
        ascii_str = result[0] if result else None
        if not ascii_str:
            return
        self.clear_search_highlight()
        idx = self.hex_data.find(ascii_str.encode())
        if idx == -1:
            messagebox.showinfo("Search ASCII", "String not found.")
        else:
            self.highlight_offset(idx, len(ascii_str), tag='search')

    def clear_search_highlight(self):
        self.text.tag_remove('search', '1.0', tk.END)

    def clear_all_highlights(self, event=None):
        if event:
            index = self.text.index(f'@{event.x},{event.y}')
            line, col = map(int, index.split('.'))
            # Only clear if not in hex or ASCII columns
            if 10 <= col < 58 or 60 <= col < 76:
                return
        self.text.tag_remove('search', '1.0', tk.END)
        self.text.tag_remove('hex_cursor', '1.0', tk.END)
        self.text.tag_remove('ascii_cursor', '1.0', tk.END)
        self.text.tag_remove('highlight', '1.0', tk.END)
        # Clear marker IDE tags
        self.text.tag_remove('marker_length1', '1.0', tk.END)
        self.text.tag_remove('marker_length2', '1.0', tk.END)
        self.text.tag_remove('marker_fraction', '1.0', tk.END)
        self.text.tag_remove('marker_height1', '1.0', tk.END)
        self.text.tag_remove('marker_height2', '1.0', tk.END)
        self.text.tag_remove('marker_width1', '1.0', tk.END)
        self.text.tag_remove('marker_width2', '1.0', tk.END)

    def highlight_offset(self, offset, length, tag='hex_cursor'):
        line = offset // 16 + 1
        col = 10 + (offset % 16) * 3
        end_col = col + length * 3 - 1
        ascii_start = 60 + (offset % 16)
        ascii_end = ascii_start + length
        # Only temporarily set state to normal for tag changes
        prev_state = self.text.cget('state')
        if prev_state not in ('normal', 'disabled'):
            prev_state = 'normal'
        self.text.config(state='normal')
        if tag == 'search':
            self.text.tag_add('search', f'{line}.{col}', f'{line}.{end_col}')
            self.text.tag_add('search', f'{line}.{ascii_start}', f'{line}.{ascii_end}')
            self.text.see(f'{line}.0')
        else:
            self.text.tag_remove('highlight', '1.0', tk.END)
            self.text.tag_remove('hex_cursor', '1.0', tk.END)
            self.text.tag_remove('ascii_cursor', '1.0', tk.END)
            self.text.tag_add('hex_cursor', f'{line}.{col}', f'{line}.{end_col}')
            self.text.tag_add('ascii_cursor', f'{line}.{ascii_start}', f'{line}.{ascii_end}')
            self.text.see(f'{line}.0')
        self.text.config(state=prev_state)

    def on_click(self, event):
        index = self.text.index(f'@{event.x},{event.y}')
        line, col = map(int, index.split('.'))
        if 10 <= col < 58:  # Hex area
            byte_idx = (col - 10) // 3
            if 0 <= byte_idx < 16:
                offset = (line - 1) * 16 + byte_idx
                self.highlight_offset(offset, 1)
        elif 60 <= col < 76:  # ASCII area
            byte_idx = col - 60
            if 0 <= byte_idx < 16:
                offset = (line - 1) * 16 + byte_idx
                self.highlight_offset(offset, 1)

    def on_key_release(self, event):
        prev_state = self.text.cget('state')
        if prev_state not in ('normal', 'disabled'):
            prev_state = 'normal'
        self.text.config(state='normal')
        self.text.tag_remove('hex_cursor', '1.0', tk.END)
        self.text.tag_remove('ascii_cursor', '1.0', tk.END)
        self.text.config(state=prev_state)

    def save_as_copy(self):
        out_path = filedialog.asksaveasfilename(title="Save Hex Copy As", defaultextension=".bin")
        if not out_path:
            return
        try:
            with open(out_path, 'wb') as f:
                f.write(self.hex_data)
            messagebox.showinfo("Save As Copy", f"File saved as {out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

    def ctf_highlight_flags(self):
        """Highlight potential flag patterns in the hex view"""
        import re
        
        # Common flag patterns
        flag_patterns = [
            rb'flag\{[^}]*\}',  # flag{...}
            rb'FLAG\{[^}]*\}',  # FLAG{...}
            rb'ctf\{[^}]*\}',   # ctf{...}
            rb'CTF\{[^}]*\}',   # CTF{...}
            rb'key\{[^}]*\}',   # key{...}
            rb'KEY\{[^}]*\}',   # KEY{...}
            rb'secret\{[^}]*\}', # secret{...}
            rb'SECRET\{[^}]*\}', # SECRET{...}
        ]
        
        # Clear previous highlights
        self.text.tag_remove('highlight', '1.0', tk.END)
        
        found_flags = []
        
        for pattern in flag_patterns:
            matches = list(re.finditer(pattern, self.hex_data))
            for match in matches:
                start_offset = match.start()
                end_offset = match.end()
                found_flags.append((start_offset, end_offset, match.group().decode('utf-8', errors='ignore')))
        
        if not found_flags:
            messagebox.showinfo("Flag Highlight", "No flag patterns found in the file.")
            return
        
        # Highlight all found flags
        for start_offset, end_offset, flag_text in found_flags:
            self.highlight_offset(start_offset, end_offset - start_offset, tag='highlight')
        
        # Show results
        result_text = f"Found {len(found_flags)} potential flag(s):\n\n"
        for i, (start_offset, end_offset, flag_text) in enumerate(found_flags, 1):
            result_text += f"{i}. {flag_text}\n   Offset: 0x{start_offset:08X}\n\n"
        
        # Create result window
        result_window = tk.Toplevel(self.root)
        result_window.title("Flag Analysis Results")
        result_window.geometry("600x400")
        result_window.transient(self.root)
        
        # Add text widget to show results
        text_widget = tk.Text(result_window, wrap='word', font=('Consolas', 10))
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert('1.0', result_text)
        text_widget.config(state='disabled')
        
        # Add copy button
        def copy_all_flags():
            import pyperclip
            all_flags = '\n'.join([flag_text for _, _, flag_text in found_flags])
            try:
                pyperclip.copy(all_flags)
                messagebox.showinfo("Copy", "All flags copied to clipboard!")
            except ImportError:
                messagebox.showerror("Error", "pyperclip not available. Please install it for clipboard support.")
        
        copy_btn = tk.Button(result_window, text="Copy All Flags", command=copy_all_flags)
        copy_btn.pack(pady=5)

    def ctf_search_magic_numbers(self):
        """Search for common magic numbers and file signatures"""
        
        # Common magic numbers and file signatures
        magic_numbers = {
            b'\x89PNG\r\n\x1a\n': "PNG Image",
            b'\xff\xd8\xff': "JPEG Image",
            b'GIF87a': "GIF Image (87a)",
            b'GIF89a': "GIF Image (89a)",
            b'BM': "BMP Image",
            b'%PDF': "PDF Document",
            b'PK\x03\x04': "ZIP Archive",
            b'PK\x05\x06': "ZIP Archive (empty)",
            b'PK\x07\x08': "ZIP Archive (spanned)",
            b'\x1f\x8b\x08': "GZIP Archive",
            b'Rar!': "RAR Archive",
            b'\x7fELF': "ELF Executable",
            b'MZ': "PE Executable (Windows)",
            b'\xca\xfe\xba\xbe': "Java Class File",
            b'\xfe\xed\xfa\xce': "Mach-O Executable (32-bit)",
            b'\xfe\xed\xfa\xcf': "Mach-O Executable (64-bit)",
            b'\xce\xfa\xed\xfe': "Mach-O Executable (32-bit, swapped)",
            b'\xcf\xfa\xed\xfe': "Mach-O Executable (64-bit, swapped)",
            b'\x00\x00\x01\x00': "ICO Icon",
            b'RIFF': "RIFF Container (WAV, AVI, etc.)",
            b'ID3': "MP3 Audio",
            b'\xff\xfb': "MP3 Audio (no ID3)",
            b'\x00\x00\x00\x18ftyp': "MP4 Video",
            b'\x00\x00\x00\x20ftyp': "MP4 Video",
            b'\x00\x00\x00\x1cftyp': "MP4 Video",
            b'\x00\x00\x00\x14ftyp': "MP4 Video",
            b'\x00\x00\x00\x0cftyp': "MP4 Video",
            b'\x00\x00\x00\x08ftyp': "MP4 Video",
            b'\x00\x00\x00\x04ftyp': "MP4 Video",
            b'\x00\x00\x00\x00ftyp': "MP4 Video",
            b'\x1a\x45\xdf\xa3': "Matroska Video",
            b'\x52\x61\x72\x21\x1a\x07': "RAR Archive (v1.5+)",
            b'\x52\x61\x72\x21\x1a\x07\x00': "RAR Archive (v5.0+)",
        }
        
        found_magic = []
        
        for magic_bytes, description in magic_numbers.items():
            offset = self.hex_data.find(magic_bytes)
            if offset != -1:
                found_magic.append((offset, len(magic_bytes), description, magic_bytes))
        
        if not found_magic:
            messagebox.showinfo("Magic Numbers", "No common magic numbers found in the file.")
            return
        
        # Clear previous highlights and highlight magic numbers
        self.text.tag_remove('search', '1.0', tk.END)
        
        for offset, length, description, magic_bytes in found_magic:
            self.highlight_offset(offset, length, tag='search')
        
        # Show results
        result_text = f"Found {len(found_magic)} magic number(s):\n\n"
        for i, (offset, length, description, magic_bytes) in enumerate(found_magic, 1):
            hex_str = ' '.join(f'{b:02X}' for b in magic_bytes)
            result_text += f"{i}. {description}\n   Offset: 0x{offset:08X}\n   Hex: {hex_str}\n   Length: {length} bytes\n\n"
        
        # Create result window
        result_window = tk.Toplevel(self.root)
        result_window.title("Magic Number Analysis")
        result_window.geometry("700x500")
        result_window.transient(self.root)
        
        # Add text widget to show results
        text_widget = tk.Text(result_window, wrap='word', font=('Consolas', 10))
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert('1.0', result_text)
        text_widget.config(state='disabled')
        
        # Add scrollbar
        scrollbar = tk.Scrollbar(text_widget)
        scrollbar.pack(side='right', fill='y')
        text_widget.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=text_widget.yview)

    def ctf_copy_selected_hex(self):
        """Copy selected hex or ASCII data to clipboard"""
        try:
            import pyperclip
        except ImportError:
            messagebox.showerror("Error", "pyperclip not available. Please install it for clipboard support.")
            return
        
        # Get current selection
        try:
            selection = self.text.tag_ranges('sel')
            if not selection:
                messagebox.showinfo("Copy Hex", "No text selected. Please select hex or ASCII data first.")
                return
            
            start, end = selection
            selected_text = self.text.get(start, end)
            
            # Determine if selection is in hex or ASCII area
            start_line, start_col = map(int, str(start).split('.'))
            end_line, end_col = map(int, str(end).split('.'))
            
            # Check if selection is in hex area (columns 10-58)
            if 10 <= start_col < 58 and 10 <= end_col < 58:
                # Extract hex bytes from selection
                hex_bytes = []
                lines = selected_text.split('\n')
                for line in lines:
                    # Remove offset and ASCII parts, keep only hex
                    if len(line) >= 58:
                        hex_part = line[10:58]
                        hex_bytes.extend(hex_part.split())
                
                hex_str = ' '.join(hex_bytes)
                pyperclip.copy(hex_str)
                messagebox.showinfo("Copy Hex", f"Copied {len(hex_bytes)} hex bytes to clipboard:\n{hex_str}")
                
            # Check if selection is in ASCII area (columns 60-76)
            elif 60 <= start_col < 76 and 60 <= end_col < 76:
                # Extract ASCII characters from selection
                ascii_chars = []
                lines = selected_text.split('\n')
                for line in lines:
                    if len(line) >= 76:
                        ascii_part = line[60:76]
                        ascii_chars.extend(list(ascii_part))
                
                ascii_str = ''.join(ascii_chars)
                pyperclip.copy(ascii_str)
                messagebox.showinfo("Copy ASCII", f"Copied {len(ascii_chars)} ASCII characters to clipboard:\n{ascii_str}")
                
            else:
                # Mixed selection or other area
                pyperclip.copy(selected_text)
                messagebox.showinfo("Copy Text", f"Copied selected text to clipboard:\n{selected_text}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy selection: {e}")

    def ctf_marker_ide(self):
        """Search for JPEG marker bytes (FF C0 and FF C2) and colorize the following 7 bytes with specific colors for image metadata analysis."""
        
        # JPEG marker bytes to search for
        marker_patterns = [
            b'\xff\xc0',  # Start of frame (baseline DCT)
            b'\xff\xc2',  # Start of frame (progressive DCT)
        ]
        
        # Clear previous highlights
        self.text.tag_remove('highlight', '1.0', tk.END)
        self.text.tag_remove('marker_length1', '1.0', tk.END)
        self.text.tag_remove('marker_length2', '1.0', tk.END)
        self.text.tag_remove('marker_fraction', '1.0', tk.END)
        self.text.tag_remove('marker_height1', '1.0', tk.END)
        self.text.tag_remove('marker_height2', '1.0', tk.END)
        self.text.tag_remove('marker_width1', '1.0', tk.END)
        self.text.tag_remove('marker_width2', '1.0', tk.END)
        
        found_markers = []
        
        for marker_bytes in marker_patterns:
            offset = 0
            while True:
                offset = self.hex_data.find(marker_bytes, offset)
                if offset == -1:
                    break
                
                # Check if we have enough bytes after the marker (7 bytes needed)
                if offset + 2 + 7 <= len(self.hex_data):
                    # Extract the 7 bytes following the marker
                    metadata_bytes = self.hex_data[offset + 2:offset + 2 + 7]
                    
                    # Parse the metadata
                    length = int.from_bytes(metadata_bytes[0:2], byteorder='big')
                    data_fraction = metadata_bytes[2]
                    image_height = int.from_bytes(metadata_bytes[3:5], byteorder='big')
                    image_width = int.from_bytes(metadata_bytes[5:7], byteorder='big')
                    
                    found_markers.append({
                        'offset': offset,
                        'marker': marker_bytes,
                        'length': length,
                        'data_fraction': data_fraction,
                        'image_height': image_height,
                        'image_width': image_width,
                        'metadata_bytes': metadata_bytes
                    })
                    
                    # Colorize the marker (yellow highlight)
                    self.highlight_offset(offset, 2, tag='highlight')
                    
                    # Colorize the 7 metadata bytes with specific colors
                    # First 2 bytes (length) - Blue
                    self.highlight_metadata_byte(offset + 2, 'marker_length1')
                    self.highlight_metadata_byte(offset + 3, 'marker_length2')
                    
                    # Next 1 byte (data fraction) - Purple
                    self.highlight_metadata_byte(offset + 4, 'marker_fraction')
                    
                    # Next 2 bytes (image height) - Green
                    self.highlight_metadata_byte(offset + 5, 'marker_height1')
                    self.highlight_metadata_byte(offset + 6, 'marker_height2')
                    
                    # Last 2 bytes (image width) - Orange
                    self.highlight_metadata_byte(offset + 7, 'marker_width1')
                    self.highlight_metadata_byte(offset + 8, 'marker_width2')
                
                offset += 2  # Move to next possible position
        
        if not found_markers:
            messagebox.showinfo("Marker IDE", "No JPEG marker bytes (FF C0 or FF C2) found in the file.")
            return
        
        # Show results
        result_text = f"Found {len(found_markers)} JPEG marker(s):\n\n"
        for i, marker_info in enumerate(found_markers, 1):
            marker_hex = ' '.join(f'{b:02X}' for b in marker_info['marker'])
            metadata_hex = ' '.join(f'{b:02X}' for b in marker_info['metadata_bytes'])
            result_text += f"{i}. Marker: {marker_hex}\n"
            result_text += f"   Offset: 0x{marker_info['offset']:08X}\n"
            result_text += f"   Metadata: {metadata_hex}\n"
            result_text += f"   Length: {marker_info['length']} bytes\n"
            result_text += f"   Data Fraction: {marker_info['data_fraction']}\n"
            result_text += f"   Image Height: {marker_info['image_height']} pixels\n"
            result_text += f"   Image Width: {marker_info['image_width']} pixels\n\n"
        
        # Create result window
        result_window = tk.Toplevel(self.root)
        result_window.title("Marker IDE Analysis")
        result_window.geometry("700x500")
        result_window.transient(self.root)
        
        # Add text widget to show results
        text_widget = tk.Text(result_window, wrap='word', font=('Consolas', 10))
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert('1.0', result_text)
        text_widget.config(state='disabled')
        
        # Add scrollbar
        scrollbar = tk.Scrollbar(text_widget)
        scrollbar.pack(side='right', fill='y')
        text_widget.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=text_widget.yview)
        
        # Add copy button
        def copy_all_markers():
            import pyperclip
            marker_summary = []
            for marker_info in found_markers:
                marker_hex = ' '.join(f'{b:02X}' for b in marker_info['marker'])
                metadata_hex = ' '.join(f'{b:02X}' for b in marker_info['metadata_bytes'])
                summary = f"Marker: {marker_hex} | Metadata: {metadata_hex} | Size: {marker_info['image_width']}x{marker_info['image_height']}"
                marker_summary.append(summary)
            
            all_markers = '\n'.join(marker_summary)
            try:
                pyperclip.copy(all_markers)
                messagebox.showinfo("Copy", "All marker information copied to clipboard!")
            except ImportError:
                messagebox.showerror("Error", "pyperclip not available. Please install it for clipboard support.")
        
        copy_btn = tk.Button(result_window, text="Copy All Markers", command=copy_all_markers)
        copy_btn.pack(pady=5)

    def highlight_metadata_byte(self, offset, tag):
        """Highlight a specific byte in the hex view with a given tag"""
        line = offset // 16 + 1
        col = 10 + (offset % 16) * 3
        ascii_start = 60 + (offset % 16)
        
        # Only temporarily set state to normal for tag changes
        prev_state = self.text.cget('state')
        if prev_state not in ('normal', 'disabled'):
            prev_state = 'normal'
        self.text.config(state='normal')
        
        # Apply tag to both hex and ASCII areas
        self.text.tag_add(tag, f'{line}.{col}', f'{line}.{col+2}')
        self.text.tag_add(tag, f'{line}.{ascii_start}', f'{line}.{ascii_start+1}')
        
        self.text.config(state=prev_state) 