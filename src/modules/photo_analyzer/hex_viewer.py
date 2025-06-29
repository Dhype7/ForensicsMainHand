import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import threading

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