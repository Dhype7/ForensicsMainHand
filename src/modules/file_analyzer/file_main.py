"""
File Analyzer Module Main Window
Professional, robust, and extensible implementation.
"""
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional, Callable, Any, List, Dict
from PIL import Image, ImageTk

# Add parent directories to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from ui.theme import Theme
from ui.widgets import ModernButton, FileSelector, StatusBar, ToolButton
from config.settings import Settings
from .file_utils import FileAnalyzerUtils

class FileAnalyzerMainWindow(tk.Frame):
    """
    Main application frame for File Analyzer (CTF style).
    Provides a professional, robust, and extensible UI for file analysis tools.
    """
    def __init__(self, parent, back_callback: Callable[[], None], theme_change_callback: Optional[Callable[[], None]] = None, theme_var: Optional[tk.StringVar] = None, *args, **kwargs) -> None:
        super().__init__(parent, *args, **kwargs)
        self.back_callback = back_callback
        self.theme_change_callback = theme_change_callback
        self.selected_file_path: Optional[str] = None
        self.selected_wordlist_path: Optional[str] = None
        self.result_text: Optional[tk.Text] = None
        self.status_bar: Optional[StatusBar] = None
        self.file_selector: Optional[FileSelector] = None
        self.main_frame: Optional[tk.Frame] = None
        self.result_search_var = tk.StringVar()
        self.result_content = ""
        self.loading_overlay: Optional[tk.Frame] = None
        self.loading_label: Optional[tk.Label] = None
        self.loading_spinner: Optional[tk.Label] = None
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.spinner_index = 0
        self.loading_after_id = None
        self.tool_buttons: List[ToolButton] = []
        self.theme_var = theme_var or tk.StringVar(value=Theme.get_current_theme())
        self.theme_var.trace_add('write', self._on_external_theme_change)
        self._extract_cmd = None
        self._extract_details = ''
        self._build_ui()

    def _build_ui(self) -> None:
        """Builds the main UI layout."""
        self.main_frame = tk.Frame(self, bg=Theme.get_color('primary'))
        self.main_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('medium'), pady=Theme.get_spacing('medium'))
        self._create_header()
        self._create_file_selection()
        self._create_main_content()
        self._create_status_bar()
        self._apply_theme_to_all_widgets()

    def _create_header(self) -> None:
        """Creates the header section with logo, title, and theme selector."""
        header_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        header_frame.pack(fill='x', pady=(0, Theme.get_spacing('large')))
        # Back button
        back_btn = ModernButton(header_frame, text="← Back", command=self.back_callback, style='secondary')
        back_btn.pack(side='left', padx=(0, 10))
        # NYX logo
        try:
            logo_img = Image.open("pics/Picsart_25-07-01_17-15-32-191.png")
            logo_img = logo_img.resize((32, 32), Image.Resampling.LANCZOS)
            logo = ImageTk.PhotoImage(logo_img)
            logo_label = tk.Label(header_frame, image=logo, bg=Theme.get_color('primary'))
            setattr(logo_label, "image", logo)
            logo_label.pack(side='left', padx=(0, 8))
        except Exception:
            logo_label = tk.Label(header_frame, text="NYX", font=("Arial", 16, "bold"), fg="#FFD600", bg=Theme.get_color('primary'))
            logo_label.pack(side='left', padx=(0, 8))
        # Title
        title_label = tk.Label(header_frame, text="File Analyzer", font=Theme.get_font('title'), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        title_label.pack(side='left')
        # Theme selector
        theme_label = tk.Label(header_frame, text="Theme:", bg=Theme.get_color('primary'), fg=Theme.get_color('text_secondary'), font=Theme.get_font('default'))
        theme_label.pack(side='right', padx=(0, 5))
        theme_dropdown = ttk.Combobox(header_frame, textvariable=self.theme_var, values=Theme.get_available_themes(), width=8, state='readonly')
        theme_dropdown.pack(side='right', padx=(0, 10))
        theme_dropdown.bind('<<ComboboxSelected>>', self.on_theme_change)
        subtitle_label = tk.Label(header_frame, text="CTF-Grade File Carving, Extraction, and Analysis", font=Theme.get_font('default'), bg=Theme.get_color('primary'), fg=Theme.get_color('text_secondary'))
        subtitle_label.pack(anchor='w')

    def _create_file_selection(self) -> None:
        """Creates the file selection area."""
        file_frame = tk.Frame(self.main_frame, bg=Theme.get_color('secondary'))
        file_frame.pack(fill='x', pady=Theme.get_spacing('medium'))
        self.file_selector = FileSelector(
            file_frame,
            title="Select File for Analysis",
            file_types=[("All Files", "*.*")]
        )
        self.file_selector.pack(fill='x', padx=Theme.get_spacing('medium'), pady=Theme.get_spacing('medium'))
        ModernButton(file_frame, text="Load File", command=self.load_file, style='primary').pack(pady=Theme.get_spacing('small'))

    def _create_main_content(self) -> None:
        """Creates the main content area with tools and results."""
        content_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        content_frame.pack(fill='both', expand=True, pady=Theme.get_spacing('medium'))
        self._create_tools_area(content_frame)
        self._create_results_area(content_frame)
        content_frame.columnconfigure(0, weight=1)
        content_frame.columnconfigure(1, weight=2)

    def _create_tools_area(self, parent: tk.Frame) -> None:
        """Creates the tools area with all analysis buttons."""
        tools_frame = tk.Frame(parent, bg=Theme.get_color('primary'))
        tools_frame.grid(row=0, column=0, sticky='nsew', padx=(0, Theme.get_spacing('medium')))
        tools_title = tk.Label(tools_frame, text="Analysis Tools", font=Theme.get_font('heading'), bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary'))
        tools_title.pack(anchor='w', pady=(0, Theme.get_spacing('medium')))
        tools_grid = tk.Frame(tools_frame, bg=Theme.get_color('primary'))
        tools_grid.pack(fill='x')
        # Define tool buttons in a config list for easy extensibility
        tool_configs = [
            {"text": "Type Detection", "desc": "Detect file type (magic)", "cmd": self.analyze_type, "icon": "📄", "tooltip": "Detect file type using magic bytes and mimetypes"},
            {"text": "Extract Archive", "desc": "Extract files from archives", "cmd": self.analyze_extract, "icon": "🗜️", "tooltip": "Extract all files from supported archive formats"},
            {"text": "Compress File", "desc": "Compress file to archive", "cmd": self.analyze_compress, "icon": "📦", "tooltip": "Compress file or folder to archive"},
            {"text": "String Extraction", "desc": "Extract readable strings", "cmd": self.analyze_strings, "icon": "🔍", "tooltip": "Extract printable strings from file"},
            {"text": "File Carving", "desc": "Carve files from binary", "cmd": self.analyze_carve, "icon": "🪓", "tooltip": "Carve embedded files from binary data"},
            {"text": "Entropy Analysis", "desc": "Detect packed/obfuscated data", "cmd": self.analyze_entropy, "icon": "📊", "tooltip": "Analyze file entropy for packing/obfuscation"},
            {"text": "Stego Analysis", "desc": "Detect steganography", "cmd": self.analyze_stego, "icon": "🕵️", "tooltip": "Detect steganography in files"},
            {"text": "File Breaker", "desc": "Crack archive/file passwords", "cmd": self.analyze_file_breaker, "icon": "💥", "tooltip": "Crack file passwords using John the Ripper and auto-decode tools"},
            {"text": "Recursive Extraction", "desc": "Extract files recursively", "cmd": self.analyze_recursive, "icon": "🔁", "tooltip": "Recursively extract nested archives"},
        ]
        for i, cfg in enumerate(tool_configs):
            btn = ToolButton(tools_grid, text=cfg["text"], description=cfg["desc"], command=cfg["cmd"], icon=cfg["icon"])
            btn.grid(row=i//2, column=i%2, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
            self._add_tooltip(btn, cfg["tooltip"])
            self.tool_buttons.append(btn)
        tools_grid.columnconfigure(0, weight=1)
        tools_grid.columnconfigure(1, weight=1)
        # Add Select Wordlist button
        wordlist_btn = ModernButton(tools_frame, text="Select Wordlist", command=self.select_wordlist, style='secondary')
        wordlist_btn.pack(pady=(Theme.get_spacing('small'), 0))
        self._add_tooltip(wordlist_btn, "Select a wordlist for password cracking (John the Ripper)")

    def _add_tooltip(self, widget: Any, text: str) -> None:
        """Adds a tooltip to a widget."""
        try:
            if hasattr(widget, 'bind'):
                def on_enter(event):
                    if self.status_bar:
                        self.status_bar.set_status(text, status_type='info')
                def on_leave(event):
                    if self.status_bar:
                        self.status_bar.set_status("", status_type='info')
                widget.bind('<Enter>', on_enter)
                widget.bind('<Leave>', on_leave)
        except Exception:
            pass

    def _create_results_area(self, parent: tk.Frame) -> None:
        """Creates the results area with search, copy, clear, and save functionality."""
        self.result_frame = tk.Frame(parent, bg=Theme.get_color('secondary'), bd=3, relief='raised', highlightthickness=1, highlightbackground=Theme.get_color('accent'))
        self.result_frame.grid(row=0, column=1, sticky='nsew')
        # Extraction button (hidden by default)
        self.extract_btn = tk.Button(self.result_frame, text="Extract", font=('Segoe UI', 11, 'bold'), bg=Theme.get_color('accent'), fg='white', relief='flat', bd=0, padx=10, pady=3, cursor='hand2', command=self._do_extract_archive)
        self.extract_btn.pack(fill='x', padx=10, pady=(10, 0))
        self.extract_btn.pack_forget()
        header_frame = tk.Frame(self.result_frame, bg=Theme.get_color('accent'), height=40)
        header_frame.pack(fill='x', pady=(0, 2))
        header_frame.pack_propagate(False)
        title_label = tk.Label(header_frame, text="🔍 Analysis Results", font=('Segoe UI', 14, 'bold'), bg=Theme.get_color('accent'), fg='white')
        title_label.pack(side='left', padx=10, pady=5)
        controls_frame = tk.Frame(header_frame, bg=Theme.get_color('accent'))
        controls_frame.pack(side='right', padx=10, pady=5)
        # Save Results button
        save_btn = tk.Button(controls_frame, text="💾 Save Results", command=self.save_results, font=('Segoe UI', 10, 'bold'), bg=Theme.get_color('success'), fg='white', relief='flat', bd=0, padx=10, pady=3, cursor='hand2')
        save_btn.pack(side='right', padx=(0, 5))
        self._add_tooltip(save_btn, "Save the current analysis results to a text file")
        search_frame = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        search_frame.pack(fill='x', padx=10, pady=5)
        search_label = tk.Label(search_frame, text="Search:", font=('Segoe UI', 11, 'bold'), bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'))
        search_label.pack(side='left', padx=(0, 5))
        search_entry = tk.Entry(search_frame, textvariable=self.result_search_var, font=('Segoe UI', 11), bg=Theme.get_color('entry_bg'), fg=Theme.get_color('entry_fg'), relief='solid', bd=1, width=25)
        search_entry.pack(side='left', padx=(0, 5))
        search_btn = tk.Button(search_frame, text="🔍 Search", command=self.search_in_results, font=('Segoe UI', 10, 'bold'), bg=Theme.get_color('accent'), fg='white', relief='flat', bd=0, padx=15, pady=3, cursor='hand2')
        search_btn.pack(side='left', padx=(0, 5))
        copy_btn = tk.Button(search_frame, text="📋 Copy", command=self.copy_results, font=('Segoe UI', 10, 'bold'), bg=Theme.get_color('success'), fg='white', relief='flat', bd=0, padx=15, pady=3, cursor='hand2')
        copy_btn.pack(side='left', padx=(0, 5))
        clear_btn = tk.Button(search_frame, text="🗑️ Clear", command=self.clear_results, font=('Segoe UI', 10, 'bold'), bg=Theme.get_color('error'), fg='white', relief='flat', bd=0, padx=15, pady=3, cursor='hand2')
        clear_btn.pack(side='left')
        text_container = tk.Frame(self.result_frame, bg=Theme.get_color('text_bg'), bd=2, relief='sunken')
        text_container.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.result_text = tk.Text(text_container, wrap='word', font=('Consolas', 12), bg=Theme.get_color('text_bg'), fg=Theme.get_color('text_primary'), relief='flat', bd=0)
        self.result_text.pack(fill='both', expand=True)
        self.result_text.config(state='disabled')
        # Loading overlay (hidden by default)
        self.loading_overlay = tk.Frame(self.result_frame, bg='#000000')
        self.loading_label = tk.Label(self.loading_overlay, text="Analyzing...", font=('Segoe UI', 16, 'bold'), fg='white', bg='#000000')
        self.loading_spinner = tk.Label(self.loading_overlay, text=self.spinner_chars[0], font=('Segoe UI', 32), fg='white', bg='#000000')
        # Compression type dropdown (hidden by default)
        self.compress_type_var = tk.StringVar()
        self.compress_type_dropdown = ttk.Combobox(self.result_frame, textvariable=self.compress_type_var, state='readonly')
        self.compress_type_dropdown['values'] = [
            'zip', '7z', 'tar', 'gz', 'bz2', 'xz', 'lzma', 'rar', 'zst', 'ar', 'lz4'
        ]
        self.compress_type_dropdown.pack(fill='x', padx=10, pady=(10, 0))
        self.compress_type_dropdown.pack_forget()
        self.compress_type_dropdown.bind('<<ComboboxSelected>>', self._on_compress_type_selected)
        # String Extraction toolbar (hidden by default)
        self.strings_toolbar = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        self.strings_toolbar.pack(fill='x', padx=10, pady=(10, 0))
        self.strings_toolbar.pack_forget()
        self.strings_minlen_var = tk.IntVar(value=4)
        self.strings_mode_var = tk.StringVar(value='both')
        self.strings_unique_var = tk.BooleanVar(value=False)
        tk.Label(self.strings_toolbar, text='Min Length:', bg=Theme.get_color('secondary')).pack(side='left')
        tk.Entry(self.strings_toolbar, textvariable=self.strings_minlen_var, width=3).pack(side='left', padx=(0, 8))
        tk.Label(self.strings_toolbar, text='Mode:', bg=Theme.get_color('secondary')).pack(side='left')
        mode_menu = ttk.Combobox(self.strings_toolbar, textvariable=self.strings_mode_var, state='readonly', width=8)
        mode_menu['values'] = ['ascii', 'unicode', 'both']
        mode_menu.pack(side='left', padx=(0, 8))
        unique_btn = tk.Checkbutton(self.strings_toolbar, text='Unique Only', variable=self.strings_unique_var, bg=Theme.get_color('secondary'))
        unique_btn.pack(side='left', padx=(0, 8))
        tk.Button(self.strings_toolbar, text='Extract', command=self._run_strings_extraction).pack(side='left', padx=(0, 8))
        tk.Button(self.strings_toolbar, text='Copy All', command=self._copy_strings_result).pack(side='left', padx=(0, 8))
        tk.Button(self.strings_toolbar, text='Save', command=self._save_strings_result).pack(side='left', padx=(0, 8))
        tk.Label(self.strings_toolbar, text='Filter:', bg=Theme.get_color('secondary')).pack(side='left')
        self.strings_filter_var = tk.StringVar()
        tk.Entry(self.strings_toolbar, textvariable=self.strings_filter_var, width=15).pack(side='left', padx=(0, 8))
        tk.Button(self.strings_toolbar, text='Apply Filter', command=self._filter_strings_result).pack(side='left')
        self.strings_last_result = []
        self.strings_last_display = []
        # File Carving toolbar (hidden by default)
        self.carve_toolbar = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        self.carve_toolbar.pack(fill='x', padx=10, pady=(10, 0))
        self.carve_toolbar.pack_forget()
        self.carve_filter_var = tk.StringVar()
        tk.Button(self.carve_toolbar, text='Save All', command=self._carve_save_all).pack(side='left', padx=(0, 8))
        tk.Button(self.carve_toolbar, text='Save Selected', command=self._carve_save_selected).pack(side='left', padx=(0, 8))
        tk.Label(self.carve_toolbar, text='Filter Type:', bg=Theme.get_color('secondary')).pack(side='left')
        tk.Entry(self.carve_toolbar, textvariable=self.carve_filter_var, width=10).pack(side='left', padx=(0, 8))
        tk.Button(self.carve_toolbar, text='Apply Filter', command=self._carve_apply_filter).pack(side='left', padx=(0, 8))
        tk.Button(self.carve_toolbar, text='Hex Preview', command=self._carve_hex_preview).pack(side='left', padx=(0, 8))
        self.carve_last_files = []
        self.carve_last_display = []
        self.carve_selected_index = None
        # Entropy Analysis toolbar (hidden by default)
        self.entropy_toolbar = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        self.entropy_toolbar.pack(fill='x', padx=10, pady=(10, 0))
        self.entropy_toolbar.pack_forget()
        self.entropy_window_var = tk.IntVar(value=1024)
        tk.Label(self.entropy_toolbar, text='Window Size:', bg=Theme.get_color('secondary')).pack(side='left')
        tk.Entry(self.entropy_toolbar, textvariable=self.entropy_window_var, width=6).pack(side='left', padx=(0, 8))
        tk.Button(self.entropy_toolbar, text='Analyze', command=self._run_entropy_analysis).pack(side='left', padx=(0, 8))
        tk.Button(self.entropy_toolbar, text='Export Graph', command=self._export_entropy_graph).pack(side='left', padx=(0, 8))
        self.entropy_last_graph = ''
        self.entropy_last_stats = {}
        # Stego Analysis toolbar (hidden by default)
        self.stego_toolbar = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        self.stego_toolbar.pack(fill='x', padx=10, pady=(10, 0))
        self.stego_toolbar.pack_forget()
        tk.Button(self.stego_toolbar, text='Save All Findings', command=self._stego_save_all).pack(side='left', padx=(0, 8))
        tk.Button(self.stego_toolbar, text='Open Output Folder', command=self._stego_open_output).pack(side='left', padx=(0, 8))
        tk.Button(self.stego_toolbar, text='Re-run Analysis', command=self.analyze_stego).pack(side='left', padx=(0, 8))
        self.stego_last_results = []
        self.stego_output_dir = ''
        # File Breaker toolbar (hidden by default)
        self.breaker_toolbar = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        self.breaker_toolbar.pack(fill='x', padx=10, pady=(10, 0))
        self.breaker_toolbar.pack_forget()
        tk.Button(self.breaker_toolbar, text='Re-run', command=self.analyze_file_breaker).pack(side='left', padx=(0, 8))
        tk.Button(self.breaker_toolbar, text='Select Wordlist', command=self.select_wordlist).pack(side='left', padx=(0, 8))
        tk.Button(self.breaker_toolbar, text='Save Results', command=self.save_results).pack(side='left', padx=(0, 8))
        tk.Button(self.breaker_toolbar, text='Extract with Password', command=self._extract_with_manual_password).pack(side='left', padx=(0, 8))
        self.breaker_last_result = ''
        self.breaker_found_password = None

    def _create_status_bar(self) -> None:
        """Creates the status bar at the bottom."""
        self.status_bar = StatusBar(self)
        self.status_bar.pack(fill='x', side='bottom')

    def _apply_theme_to_all_widgets(self) -> None:
        """Recursively applies the current theme to all widgets."""
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

    def on_theme_change(self, event=None) -> None:
        """Handles theme change from the dropdown."""
        # Only call the callback if this is a local theme change (not from external)
        if self.theme_change_callback and not hasattr(self, '_external_theme_change'):
            self.theme_change_callback()
        else:
            Theme.set_theme(self.theme_var.get())
            self._apply_theme_to_all_widgets()
        self.update_idletasks()

    def _on_external_theme_change(self, *args) -> None:
        """Handles external theme changes (e.g., global variable)."""
        # Set flag to prevent recursion
        self._external_theme_change = True
        if self.theme_var.get() != Theme.get_current_theme():
            Theme.set_theme(self.theme_var.get())
        self._apply_theme_to_all_widgets()
        # If there is a theme dropdown, update its value
        for child in self.winfo_children():
            if isinstance(child, ttk.Combobox):
                child.set(self.theme_var.get())
        # Clear the flag
        delattr(self, '_external_theme_change')

    def load_file(self) -> None:
        """Loads the selected file for analysis."""
        if self.file_selector is None:
            messagebox.showerror("Error", "File selector not initialized.")
            return
        file_path = self.file_selector.get_selected_file()  # type: ignore
        if not file_path or not os.path.isfile(file_path):
            messagebox.showerror("Error", "Please select a valid file to analyze.")
            return
        self.selected_file_path = file_path
        if self.status_bar:
            self.status_bar.set_status(f"Loaded file: {file_path}", status_type='success')
        messagebox.showinfo("File Loaded", f"File loaded successfully:\n{file_path}")

    def search_in_results(self) -> None:
        """Searches for a query in the results text box."""
        if not isinstance(self.result_text, tk.Text):
            return
        query = self.result_search_var.get().strip()
        self.result_text.tag_remove('search', '1.0', tk.END)
        if not query:
            return
        idx = '1.0'
        while True:
            idx = self.result_text.search(query, idx, nocase=True, stopindex=tk.END)
            if not idx:
                break
            lastidx = f"{idx}+{len(query)}c"
            self.result_text.tag_add('search', idx, lastidx)
            idx = lastidx
        self.result_text.tag_config('search', background='yellow', foreground='black')

    def copy_results(self) -> None:
        """Copies the results to the clipboard."""
        if not isinstance(self.result_text, tk.Text):
            return
        self.clipboard_clear()
        self.clipboard_append(self.result_text.get('1.0', tk.END))
        if self.status_bar:
            self.status_bar.set_status("Results copied to clipboard!", status_type='success')

    def clear_results(self) -> None:
        """Clears the results text box."""
        if not isinstance(self.result_text, tk.Text):
            return
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.config(state='disabled')
        if self.status_bar:
            self.status_bar.set_status("Results cleared.", status_type='info')

    def display_results(self, result: str) -> None:
        if hasattr(self, 'extract_btn'):
            self.extract_btn.pack_forget()
        if hasattr(self, 'extract_with_password_frame'):
            self.extract_with_password_frame.pack_forget()
        if hasattr(self, 'compress_type_dropdown'):
            self.compress_type_dropdown.pack_forget()
        if hasattr(self, 'strings_toolbar'):
            self.strings_toolbar.pack_forget()
        if hasattr(self, 'carve_toolbar'):
            self.carve_toolbar.pack_forget()
        if hasattr(self, 'entropy_toolbar'):
            self.entropy_toolbar.pack_forget()
        if hasattr(self, 'stego_toolbar'):
            self.stego_toolbar.pack_forget()
        if hasattr(self, 'breaker_toolbar'):
            self.breaker_toolbar.pack_forget()
        if not isinstance(self.result_text, tk.Text):
            return
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, result)
        self.result_text.config(state='disabled')
        
        # Show extract button if password was found
        if hasattr(self, 'breaker_found_password') and self.breaker_found_password:
            self._show_extract_with_password_button()
        
        if self.status_bar:
            self.status_bar.set_status("Analysis complete.", status_type='success')

    def display_error(self, error: str) -> None:
        """Displays an error message in the results text box."""
        if hasattr(self, 'extract_btn'):
            self.extract_btn.pack_forget()
        if hasattr(self, 'extract_with_password_frame'):
            self.extract_with_password_frame.pack_forget()
        if hasattr(self, 'compress_type_dropdown'):
            self.compress_type_dropdown.pack_forget()
        if hasattr(self, 'strings_toolbar'):
            self.strings_toolbar.pack_forget()
        if hasattr(self, 'carve_toolbar'):
            self.carve_toolbar.pack_forget()
        if hasattr(self, 'entropy_toolbar'):
            self.entropy_toolbar.pack_forget()
        if hasattr(self, 'stego_toolbar'):
            self.stego_toolbar.pack_forget()
        if hasattr(self, 'breaker_toolbar'):
            self.breaker_toolbar.pack_forget()
        if not isinstance(self.result_text, tk.Text):
            return
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, f"[Error] {error}\n")
        self.result_text.config(state='disabled')
        if self.status_bar:
            self.status_bar.set_status("Error occurred.", status_type='error')

    # --- Tool button handlers and utilities (move above _create_tools_area) ---
    def analyze_type(self) -> None:
        if not self.selected_file_path:
            return
        def analysis():
            file_path = str(self.selected_file_path)
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            file_type = FileAnalyzerUtils.detect_file_type(file_path)
            # Get ls -l output
            try:
                import subprocess
                ls_output = subprocess.check_output(['ls', '-l', file_path], text=True).strip()
            except Exception as e:
                ls_output = f"[Error running ls -l: {e}]"
            # Extract permission string and explain in a user-friendly way
            perm_explanation = ""
            if ls_output and not ls_output.startswith('[Error'):
                parts = ls_output.split()
                if parts:
                    perm_str = parts[0]
                    # Parse permission string
                    type_char = perm_str[0]
                    owner = perm_str[1:4]
                    group = perm_str[4:7]
                    others = perm_str[7:10]
                    type_map = {'-': "It's a regular file (not a folder).", 'd': "It's a directory (folder).", 'l': "It's a symbolic link.", 'c': "It's a character device.", 'b': "It's a block device.", 's': "It's a socket.", 'p': "It's a named pipe (FIFO)."}
                    type_expl = type_map.get(type_char, "Unknown file type.")
                    def perm_to_text(perm):
                        perms = []
                        if perm[0] == 'r': perms.append('read')
                        if perm[1] == 'w': perms.append('write')
                        if perm[2] == 'x': perms.append('execute')
                        if not perms:
                            return 'no permissions'
                        return ' and '.join(perms)
                    perm_explanation = (
                        f"{perm_str} means:\n"
                        f"{type_char} → {type_expl}\n"
                        f"{owner} → The owner can {perm_to_text(owner)}.\n"
                        f"{group} → The group can {perm_to_text(group)}.\n"
                        f"{others} → Others can {perm_to_text(others)}.\n"
                    )
            details = (
                f"File Name: {file_name}\n"
                f"File Path: {file_path}\n"
                f"File Size: {file_size} bytes\n"
                f"File Type: "
            )
            return details, file_type, ls_output, perm_explanation
        def display_result(result_tuple):
            details, file_type, ls_output, perm_explanation = result_tuple
            if not isinstance(self.result_text, tk.Text):
                return
            self.result_text.config(state='normal')
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert(tk.END, details)
            start = self.result_text.index(tk.END)
            self.result_text.insert(tk.END, file_type + "\n\n")
            end = self.result_text.index(tk.END)
            self.result_text.tag_add('filetype', f"{float(start)-1} linestart", f"{float(end)-1} linestart")
            self.result_text.tag_config('filetype', foreground=Theme.get_color('accent'))
            self.result_text.insert(tk.END, f"ls -l output:\n{ls_output}\n\n")
            if perm_explanation:
                self.result_text.insert(tk.END, perm_explanation + "\n")
            self.result_text.config(state='disabled')
            if self.status_bar:
                self.status_bar.set_status(f"File type detected: {file_type}", status_type='success')
        self.show_loading()
        def run():
            try:
                result = analysis()
                self.after(0, lambda: [self.hide_loading(), display_result(result)])
            except Exception as e:
                self.after(0, lambda e=e: [self.hide_loading(), self.display_error(str(e))])
        import threading
        threading.Thread(target=run, daemon=True).start()

    def analyze_extract(self) -> None:
        if not self.selected_file_path:
            return
        file_path = str(self.selected_file_path)
        def detect_file_type(filename):
            try:
                import subprocess
                result = subprocess.check_output(['file', filename], text=True)
                return result.lower()
            except Exception as e:
                return f"[!] Error detecting file type: {e}"
        def is_password_protected(filename, filetype):
            import subprocess
            if any(word in filetype for word in ['encrypted', 'password', 'protected']):
                return True
            try:
                if 'zip archive' in filetype or filename.lower().endswith('.zip'):
                    out = subprocess.check_output(['unzip', '-t', filename], stderr=subprocess.STDOUT, text=True)
                    if 'password' in out.lower() or 'encrypted' in out.lower():
                        return True
                elif 'rar archive' in filetype or filename.lower().endswith('.rar'):
                    out = subprocess.check_output(['unrar', 't', filename], stderr=subprocess.STDOUT, text=True)
                    if 'password' in out.lower() or 'encrypted' in out.lower():
                        return True
                elif '7-zip' in filetype or '7z archive' in filetype or filename.lower().endswith('.7z'):
                    out = subprocess.check_output(['7z', 't', filename], stderr=subprocess.STDOUT, text=True)
                    if 'password' in out.lower() or 'encrypted' in out.lower():
                        return True
            except Exception:
                pass
            return False
        def get_extract_command(filename, filetype):
            filetype = filetype.lower()
            fname = filename.lower()
            if '7-zip' in filetype or '7z archive' in filetype or fname.endswith('.7z'):
                return f'7z x "{filename}"'
            elif 'zip archive' in filetype or fname.endswith('.zip'):
                return f'unzip -o "{filename}"'
            elif 'rar archive' in filetype or fname.endswith('.rar'):
                return f'unrar x -o+ "{filename}"'
            elif ('tar archive' in filetype or fname.endswith('.tar')) and not (fname.endswith('.tar.gz') or fname.endswith('.tgz') or fname.endswith('.tar.bz2') or fname.endswith('.tar.xz') or fname.endswith('.tar.lzma') or fname.endswith('.tar.zst') or fname.endswith('.tar.lz4')):
                return f'tar -xvf "{filename}"'
            elif 'gzip compressed' in filetype or fname.endswith('.gz'):
                if fname.endswith('.tar.gz') or fname.endswith('.tgz'):
                    return f'tar -xzvf "{filename}"'
                else:
                    return f'gunzip -k "{filename}"'
            elif 'bzip2 compressed' in filetype or fname.endswith('.bz2'):
                if fname.endswith('.tar.bz2'):
                    return f'tar -xjvf "{filename}"'
                else:
                    return f'bunzip2 -k "{filename}"'
            elif 'xz compressed' in filetype or fname.endswith('.xz'):
                if fname.endswith('.tar.xz'):
                    return f'tar -xJvf "{filename}"'
                else:
                    return f'unxz -k "{filename}"'
            elif 'lzma compressed' in filetype or fname.endswith('.lzma'):
                if fname.endswith('.tar.lzma'):
                    return f'tar --lzma -xvf "{filename}"'
                else:
                    return f'unlzma -k "{filename}"'
            elif 'zstandard compressed' in filetype or fname.endswith('.zst'):
                if fname.endswith('.tar.zst'):
                    return f'tar --use-compress-program=unzstd -xvf "{filename}"'
                else:
                    return f'unzstd -k "{filename}"'
            elif 'current ar archive' in filetype or fname.endswith('.ar'):
                return f'ar x "{filename}"'
            elif 'lz4 compressed' in filetype or fname.endswith('.lz4'):
                if fname.endswith('.tar.lz4'):
                    return f'tar --use-compress-program=lz4 -xvf "{filename}"'
                else:
                    return f'lz4 -d "{filename}"'
            else:
                return None
        def analysis():
            filetype = detect_file_type(file_path)
            passworded = is_password_protected(file_path, filetype)
            cmd = get_extract_command(file_path, filetype)
            details = f"Detected archive type: {filetype.strip()}\n"
            if cmd:
                details += f"Extraction command: {cmd}\n"
            else:
                details += "[!] Unknown or unsupported file type.\n"
            if passworded:
                details += "\n[!] This archive appears to be password-protected. Please use the 'file breaker' tool to attempt extraction.\n"
            else:
                details += "\nWould you like to extract the file? (Press the Extraction button above)\n"
            self._extract_cmd = cmd if not passworded else None
            self._extract_details = details
            return details, cmd, passworded
        def display_result(result_tuple):
            details, cmd, passworded = result_tuple
            if not isinstance(self.result_text, tk.Text):
                return
            self.result_text.config(state='normal')
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert(tk.END, details)
            self.result_text.config(state='disabled')
            if self.status_bar:
                self.status_bar.set_status("Archive type detected.", status_type='info')
            if cmd and not passworded:
                self.extract_btn.pack(fill='x', padx=10, pady=(10, 0))
            else:
                self.extract_btn.pack_forget()
        self.show_loading()
        def run():
            try:
                result = analysis()
                self.after(0, lambda: [self.hide_loading(), display_result(result)])
            except Exception as e:
                self.after(0, lambda e=e: [self.hide_loading(), self.display_error(str(e))])
        threading.Thread(target=run, daemon=True).start()

    def analyze_compress(self) -> None:
        if not self.selected_file_path:
            return
        if hasattr(self, 'extract_btn'):
            self.extract_btn.pack_forget()
        if hasattr(self, 'compress_type_dropdown'):
            self.compress_type_dropdown.set('')
            self.compress_type_dropdown.pack(fill='x', padx=10, pady=(10, 0))
        if not isinstance(self.result_text, tk.Text):
            return
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, "Select a compression type from the dropdown above.\nSupported types: zip, 7z, tar, gz, bz2, xz, lzma, rar, zst, ar, lz4\n")
        self.result_text.insert(tk.END, "\nAfter selecting, you will be prompted for a password (leave empty for no password).\n")
        self.result_text.config(state='disabled')
        if self.status_bar:
            self.status_bar.set_status("Select compression type.", status_type='info')

    def analyze_strings(self) -> None:
        if not self.selected_file_path:
            return
        if hasattr(self, 'extract_btn'):
            self.extract_btn.pack_forget()
        if hasattr(self, 'compress_type_dropdown'):
            self.compress_type_dropdown.pack_forget()
        if hasattr(self, 'strings_toolbar'):
            self.strings_toolbar.pack(fill='x', padx=10, pady=(10, 0))
        if not isinstance(self.result_text, tk.Text):
            return
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, "Press 'Extract' above to extract strings. You can adjust options before extraction.\n")
        self.result_text.config(state='disabled')
        if self.status_bar:
            self.status_bar.set_status("Ready to extract strings.", status_type='info')

    def analyze_carve(self) -> None:
        if not self.selected_file_path:
            return
        if hasattr(self, 'extract_btn'):
            self.extract_btn.pack_forget()
        if hasattr(self, 'compress_type_dropdown'):
            self.compress_type_dropdown.pack_forget()
        if hasattr(self, 'strings_toolbar'):
            self.strings_toolbar.pack_forget()
        if hasattr(self, 'carve_toolbar'):
            self.carve_toolbar.pack(fill='x', padx=10, pady=(10, 0))
        if not isinstance(self.result_text, tk.Text):
            return
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, "Press 'Save All' to save all carved files, or select a file and use the toolbar.\n")
        self.result_text.config(state='disabled')
        if self.status_bar:
            self.status_bar.set_status("Ready to carve files.", status_type='info')
        self._run_carve_extraction()

    def analyze_metadata(self) -> None:
        if not self.selected_file_path:
            return
        self.show_loading()
        def run():
            try:
                from .file_utils import FileAnalyzerUtils
                result = FileAnalyzerUtils.extract_metadata(str(self.selected_file_path))
                self.after(0, lambda: self.display_results(str(result)))
            except Exception as e:
                self.after(0, lambda: self.display_error(str(e)))
            finally:
                self.after(0, self.hide_loading)
        import threading
        threading.Thread(target=run, daemon=True).start()

    def analyze_entropy(self) -> None:
        if not self.selected_file_path:
            return
        if hasattr(self, 'extract_btn'):
            self.extract_btn.pack_forget()
        if hasattr(self, 'compress_type_dropdown'):
            self.compress_type_dropdown.pack_forget()
        if hasattr(self, 'strings_toolbar'):
            self.strings_toolbar.pack_forget()
        if hasattr(self, 'carve_toolbar'):
            self.carve_toolbar.pack_forget()
        if hasattr(self, 'entropy_toolbar'):
            self.entropy_toolbar.pack(fill='x', padx=10, pady=(10, 0))
        if not isinstance(self.result_text, tk.Text):
            return
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, "Press 'Analyze' above to run entropy analysis. You can adjust the window size (in bytes).\n")
        self.result_text.config(state='disabled')
        if self.status_bar:
            self.status_bar.set_status("Ready for entropy analysis.", status_type='info')

    def analyze_file_breaker(self) -> None:
        if not self.selected_file_path:
            return
        # If no wordlist selected, show button and note
        if not self.selected_wordlist_path:
            rockyou_path = '/usr/share/wordlists/rockyou.txt'
            if os.path.exists(rockyou_path):
                # Show UI with Select Wordlist button and note
                if hasattr(self, 'extract_btn'):
                    self.extract_btn.pack_forget()
                if hasattr(self, 'extract_with_password_frame'):
                    self.extract_with_password_frame.pack_forget()
                if hasattr(self, 'compress_type_dropdown'):
                    self.compress_type_dropdown.pack_forget()
                if hasattr(self, 'strings_toolbar'):
                    self.strings_toolbar.pack_forget()
                if hasattr(self, 'carve_toolbar'):
                    self.carve_toolbar.pack_forget()
                if hasattr(self, 'entropy_toolbar'):
                    self.entropy_toolbar.pack_forget()
                if hasattr(self, 'stego_toolbar'):
                    self.stego_toolbar.pack_forget()
                if hasattr(self, 'breaker_toolbar'):
                    self.breaker_toolbar.pack(fill='x', padx=10, pady=(10, 0))
                if hasattr(self, 'result_text') and isinstance(self.result_text, tk.Text):
                    self.result_text.config(state='normal')
                    self.result_text.delete('1.0', tk.END)
                    self.result_text.insert(tk.END, "No wordlist selected.\n\n")
                    self.result_text.insert(tk.END, "Please select a wordlist using the button below.\n")
                    self.result_text.insert(tk.END, f"If you do not select a wordlist, the tool will automatically use the default: {rockyou_path}\n\n")
                    self.result_text.config(state='disabled')
                if self.status_bar:
                    self.status_bar.set_status("No wordlist selected. Select one or rockyou.txt will be used by default.", status_type='info')
                # Add Run Default button
                if not hasattr(self, 'run_default_btn'):
                    self.run_default_btn = tk.Button(self.result_frame, text="Run Default", font=('Segoe UI', 11, 'bold'), bg=Theme.get_color('accent'), fg='white', relief='flat', bd=0, padx=10, pady=3, cursor='hand2', command=self._run_default_wordlist)
                self.run_default_btn.pack(fill='x', padx=10, pady=(5, 10))
                return
            else:
                self.display_error("No wordlist selected and default rockyou.txt not found. Please use the 'Select Wordlist' button to choose a wordlist before running the file breaker.")
                return
        # If user still hasn't selected, auto-select rockyou.txt if available
        if not self.selected_wordlist_path:
            rockyou_path = '/usr/share/wordlists/rockyou.txt'
            if os.path.exists(rockyou_path):
                self.selected_wordlist_path = rockyou_path
                if self.status_bar:
                    self.status_bar.set_status(f"Auto-selected default wordlist: {rockyou_path}", status_type='info')
            else:
                self.display_error("No wordlist selected and default rockyou.txt not found. Please use the 'Select Wordlist' button to choose a wordlist before running the file breaker.")
                return
        if hasattr(self, 'extract_btn'):
            self.extract_btn.pack_forget()
        if hasattr(self, 'extract_with_password_frame'):
            self.extract_with_password_frame.pack_forget()
        if hasattr(self, 'compress_type_dropdown'):
            self.compress_type_dropdown.pack_forget()
        if hasattr(self, 'strings_toolbar'):
            self.strings_toolbar.pack_forget()
        if hasattr(self, 'carve_toolbar'):
            self.carve_toolbar.pack_forget()
        if hasattr(self, 'entropy_toolbar'):
            self.entropy_toolbar.pack_forget()
        if hasattr(self, 'stego_toolbar'):
            self.stego_toolbar.pack_forget()
        if hasattr(self, 'breaker_toolbar'):
            self.breaker_toolbar.pack(fill='x', padx=10, pady=(10, 0))
        if not isinstance(self.result_text, tk.Text):
            return
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, "Running file breaker (password cracker)...\n")
        self.result_text.config(state='disabled')
        if self.status_bar:
            self.status_bar.set_status("Running file breaker...", status_type='info')
        self._run_file_breaker()

    def _run_file_breaker(self):
        import os
        file_path = str(self.selected_file_path)
        wordlist = self.selected_wordlist_path
        if not wordlist:
            self.display_error("No wordlist selected. Please use the 'Select Wordlist' button to choose a wordlist before running the file breaker.")
            return
        self.show_loading()
        def breaker():
            try:
                from .file_utils import FileAnalyzerUtils
                result = FileAnalyzerUtils.crack_archive_password(file_path, wordlist)
                
                # Parse the result to extract password if found
                found_password = None
                if result and not result.startswith('[Error]') and not result.startswith('[Info]'):
                    # Password was found - it's returned directly
                    found_password = result
                    result_msg = f"Password found: {found_password}"
                else:
                    # Error or info message
                    result_msg = result
                
                msg = f"[+] File Breaker Result\n\n{result_msg}\n\n"
                msg += "Explanation:\n"
                msg += "- This tool uses John the Ripper and the correct *2john tool to crack archive passwords.\n"
                if found_password:
                    msg += f"- Password found: '{found_password}'. You can now extract the archive using this password.\n"
                    msg += "- Click the 'Extract with Password' button above to extract the archive.\n"
                else:
                    msg += "- If a password is found, use it to extract the archive.\n"
                msg += "- For other file types, try auto-decode or manual analysis.\n"
                
                self.breaker_last_result = msg
                self.breaker_found_password = found_password
                self.after(0, lambda: self.display_results(msg))
            except Exception as e:
                self.after(0, lambda: self.display_error(f"File breaker error: {e}"))
            finally:
                self.after(0, self.hide_loading)
        import threading
        threading.Thread(target=breaker, daemon=True).start()

    def _run_default_wordlist(self):
        rockyou_path = '/usr/share/wordlists/rockyou.txt'
        if os.path.exists(rockyou_path):
            self.selected_wordlist_path = rockyou_path
            if hasattr(self, 'run_default_btn'):
                self.run_default_btn.pack_forget()
            if self.status_bar:
                self.status_bar.set_status(f"Auto-selected default wordlist: {rockyou_path}", status_type='info')
            self.analyze_file_breaker()
        else:
            self.display_error("Default wordlist rockyou.txt not found at /usr/share/wordlists/rockyou.txt.")

    def analyze_recursive(self) -> None:
        if not self.selected_file_path:
            return
        self.show_loading()
        def run():
            try:
                from .file_utils import FileAnalyzerUtils
                import os
                file_path = str(self.selected_file_path)
                output_dir = 'file_analyzer_output'
                results = FileAnalyzerUtils.recursive_extract(file_path, output_dir)
                # Build a professional summary
                msg = f"[+] Recursive Extraction Results\n\n"
                msg += f"Input file: {file_path}\nOutput directory: {os.path.abspath(output_dir)}\n\n"
                msg += "Index | Depth | Type   | Status\n"
                msg += "-"*70 + "\n"
                for i, r in enumerate(results):
                    msg += f"[{i}]   {r.get('depth', '?'):>3}   {r.get('type', '?'):>6}   {r.get('status', '')[:50]}\n"
                msg += "\n"
                # Plain-language explanation
                msg += "Explanation:\n"
                msg += "- This tool recursively extracts nested archives up to 5 levels deep.\n"
                msg += "- Password-protected or unsupported archives are skipped and reported.\n"
                msg += "- You can open the output folder to review extracted files.\n"
                if any('Password-protected' in r.get('status','') for r in results):
                    msg += "- Some archives were password-protected. Use the File Breaker tool to attempt cracking.\n"
                if any('failed' in r.get('status','') for r in results):
                    msg += "- Some archives failed to extract. They may be corrupted or unsupported.\n"
                self.after(0, lambda: [self.display_results(msg), self._show_open_output_button(output_dir)])
            except Exception as e:
                self.after(0, lambda: self.display_error(str(e)))
            finally:
                self.after(0, self.hide_loading)
        import threading
        threading.Thread(target=run, daemon=True).start()

    def _show_extract_with_password_button(self):
        """Shows the extract with password button when a password is found."""
        # Create a frame to hold the password info and extract button
        if not hasattr(self, 'extract_with_password_frame'):
            self.extract_with_password_frame = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
            
            # Password display label
            self.password_label = tk.Label(
                self.extract_with_password_frame,
                text="",
                font=('Segoe UI', 10),
                bg=Theme.get_color('secondary'),
                fg=Theme.get_color('text')
            )
            self.password_label.pack(fill='x', padx=10, pady=(5, 0))
            
            # Extract button
            self.extract_with_password_btn = tk.Button(
                self.extract_with_password_frame, 
                text="Extract with Found Password", 
                font=('Segoe UI', 11, 'bold'), 
                bg=Theme.get_color('accent'), 
                fg='white', 
                relief='flat', 
                bd=0, 
                padx=10, 
                pady=3, 
                cursor='hand2',
                command=self._extract_with_found_password
            )
            self.extract_with_password_btn.pack(fill='x', padx=10, pady=(5, 10))
        
        # Update password label
        if self.breaker_found_password:
            # Show password as asterisks for security
            masked_password = '*' * len(self.breaker_found_password)
            self.password_label.config(text=f"Found Password: {masked_password} (Click 'Extract with Found Password' to use)")
        
        self.extract_with_password_frame.pack(fill='x', padx=10, pady=(10, 0))

    def _extract_with_found_password(self):
        """Extracts the archive using the found password."""
        if not self.breaker_found_password or not self.selected_file_path:
            return
        
        # Ask user for extraction directory
        out_dir = filedialog.askdirectory(title="Select Extraction Directory")
        if not out_dir:
            return
        
        self.show_loading()
        def do_extract():
            try:
                from .file_utils import FileAnalyzerUtils
                extracted_files = FileAnalyzerUtils.extract_archive(
                    str(self.selected_file_path), 
                    out_dir, 
                    self.breaker_found_password
                )
                msg = f"[+] Extraction completed successfully!\n\n"
                msg += f"Password used: {self.breaker_found_password}\n"
                msg += f"Output directory: {os.path.abspath(out_dir)}\n"
                msg += f"Files extracted: {len(extracted_files)}\n\n"
                if extracted_files:
                    msg += "Extracted files:\n"
                    for file_path in extracted_files:
                        msg += f"- {os.path.basename(file_path)}\n"
                self.after(0, lambda: [self.display_results(msg), self._show_open_output_button(out_dir)])
            except Exception as e:
                self.after(0, lambda: self.display_error(f"Extraction failed: {e}"))
            finally:
                self.after(0, self.hide_loading)
        import threading
        threading.Thread(target=do_extract, daemon=True).start()

    def _extract_with_manual_password(self):
        """Extracts the archive using a manually entered password."""
        if not self.selected_file_path:
            return
        
        # Ask user for password
        import tkinter.simpledialog as simpledialog
        password = simpledialog.askstring("Extract Archive", "Enter password:", show='*')
        if password is None:  # User cancelled
            return
        
        # Ask user for extraction directory
        out_dir = filedialog.askdirectory(title="Select Extraction Directory")
        if not out_dir:
            return
        
        self.show_loading()
        def do_extract():
            try:
                from .file_utils import FileAnalyzerUtils
                extracted_files = FileAnalyzerUtils.extract_archive(
                    str(self.selected_file_path), 
                    out_dir, 
                    password
                )
                msg = f"[+] Extraction completed successfully!\n\n"
                msg += f"Password used: {password}\n"
                msg += f"Output directory: {os.path.abspath(out_dir)}\n"
                msg += f"Files extracted: {len(extracted_files)}\n\n"
                if extracted_files:
                    msg += "Extracted files:\n"
                    for file_path in extracted_files:
                        msg += f"- {os.path.basename(file_path)}\n"
                self.after(0, lambda: [self.display_results(msg), self._show_open_output_button(out_dir)])
            except Exception as e:
                self.after(0, lambda: self.display_error(f"Extraction failed: {e}"))
            finally:
                self.after(0, self.hide_loading)
        import threading
        threading.Thread(target=do_extract, daemon=True).start()

    def _show_open_output_button(self, output_dir):
        import os, sys, subprocess
        if not hasattr(self, 'open_output_btn'):
            self.open_output_btn = tk.Button(self.result_frame, text="Open Output Folder", font=('Segoe UI', 11, 'bold'), bg=Theme.get_color('accent'), fg='white', relief='flat', bd=0, padx=10, pady=3, cursor='hand2')
        def open_folder():
            if sys.platform.startswith('darwin'):
                subprocess.call(['open', output_dir])
            elif os.name == 'nt':
                os.startfile(output_dir)
            else:
                subprocess.call(['xdg-open', output_dir])
        self.open_output_btn.config(command=open_folder)
        self.open_output_btn.pack(fill='x', padx=10, pady=(10, 0))

    def ctf_auto_analyze(self) -> None:
        if not self.selected_file_path:
            return
        self.show_loading()
        def run():
            try:
                from .file_utils import FileAnalyzerUtils
                result = FileAnalyzerUtils.analyze_file(str(self.selected_file_path), 'file_analyzer_output')
                self.after(0, lambda: self.display_results(str(result)))
            except Exception as e:
                self.after(0, lambda: self.display_error(str(e)))
            finally:
                self.after(0, self.hide_loading)
        import threading
        threading.Thread(target=run, daemon=True).start()

    def select_wordlist(self) -> None:
        path = filedialog.askopenfilename(title="Select Wordlist", filetypes=[("Wordlist Files", "*.txt *.lst *wordlist*"), ("All Files", "*.*")])
        if path:
            self.selected_wordlist_path = path
            if self.status_bar:
                self.status_bar.set_status(f"Selected wordlist: {os.path.basename(path)}", status_type='info')

    def save_results(self) -> None:
        if not isinstance(self.result_text, tk.Text):
            return
        result = self.result_text.get('1.0', tk.END)
        if not result.strip():
            messagebox.showinfo("Save Results", "No results to save.")
            return
        path = filedialog.asksaveasfilename(title="Save Results", defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(result)
                if self.status_bar:
                    self.status_bar.set_status(f"Results saved to {os.path.basename(path)}", status_type='success')
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save results: {e}")

    def show_loading(self) -> None:
        if self.loading_overlay and self.loading_label and self.loading_spinner:
            self.loading_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._update_spinner()
        self.set_tool_buttons_state('disabled')

    def hide_loading(self) -> None:
        if self.loading_overlay and self.loading_label and self.loading_spinner:
            self.loading_overlay.place_forget()
            self.loading_label.place_forget()
            self.loading_spinner.place_forget()
            if self.loading_after_id:
                self.after_cancel(self.loading_after_id)
                self.loading_after_id = None
        self.set_tool_buttons_state('normal')

    def _update_spinner(self) -> None:
        """Updates the loading spinner animation."""
        if self.loading_spinner:
            self.spinner_index = (self.spinner_index + 1) % len(self.spinner_chars)
            self.loading_spinner.config(text=self.spinner_chars[self.spinner_index])
            self.loading_after_id = self.after(100, self._update_spinner)

    def set_tool_buttons_state(self, state: str) -> None:
        """Sets the state of all tool buttons (enable/disable)."""
        for btn in self.tool_buttons:
            if hasattr(btn, 'set_state'):
                btn.set_state(state)

    def _do_extract_archive(self):
        import os
        cmd = getattr(self, '_extract_cmd', None)
        details = getattr(self, '_extract_details', '')
        if not cmd:
            return
        # Ask user for extraction directory
        out_dir = filedialog.askdirectory(title="Select Extraction Directory")
        if not out_dir:
            return
        # Optionally, ask for a new name if it's a single-file archive (not implemented for all types)
        # For now, just extract to the chosen directory
        # Update command to extract to out_dir if possible
        # For most tools, add -d or -C or similar
        updated_cmd = cmd
        if cmd.startswith('unzip'):
            updated_cmd = cmd + f' -d "{out_dir}"'
        elif cmd.startswith('7z'):
            updated_cmd = cmd + f' -o"{out_dir}"'
        elif cmd.startswith('unrar'):
            updated_cmd = cmd + f' "{out_dir}"'
        elif cmd.startswith('tar'):
            updated_cmd = cmd.replace('tar ', f'tar -C "{out_dir}" ', 1)
        elif cmd.startswith('gunzip') or cmd.startswith('bunzip2') or cmd.startswith('unxz') or cmd.startswith('unzstd') or cmd.startswith('unlzma') or cmd.startswith('lz4'):
            # These decompress in place; move result after extraction if needed
            pass
        elif cmd.startswith('ar'):
            updated_cmd = cmd + f' -C "{out_dir}"'
        # else: fallback to original
        self.show_loading()
        def do_extract():
            try:
                import subprocess
                proc = subprocess.run(updated_cmd, shell=True, capture_output=True, text=True)
                output = proc.stdout + proc.stderr
                msg = "[+] Extraction completed.\n" if proc.returncode == 0 else "[!] Extraction failed.\n"
                self.after(0, lambda: self.display_results(details + msg + output))
            except Exception as e:
                self.after(0, lambda: self.display_error(f"Extraction error: {e}"))
            finally:
                self.after(0, self.hide_loading)
        threading.Thread(target=do_extract, daemon=True).start()

    def _on_compress_type_selected(self, event=None):
        import tkinter.simpledialog as simpledialog
        ctype = self.compress_type_var.get()
        if not ctype:
            return
        # Ask for password
        password = simpledialog.askstring("Compression Password", "Enter password (leave empty for no password):", show='*')
        if password is None:
            return
        # Ask for output file
        import os
        out_path = filedialog.asksaveasfilename(
            title="Save Compressed File As",
            defaultextension=f'.{ctype}',
            filetypes=[(f"{ctype.upper()} Archives", f"*.{ctype}"), ("All Files", "*.*")]
        )
        if not out_path:
            return
        self.show_loading()
        def do_compress():
            try:
                from .file_utils import FileAnalyzerUtils
                result = FileAnalyzerUtils.compress_file(str(self.selected_file_path), out_path, ctype, password if password else None)
                msg = f"[+] Compression completed.\nOutput: {result}\n"
                self.after(0, lambda: self.display_results(msg))
            except Exception as e:
                self.after(0, lambda: self.display_error(f"Compression error: {e}"))
            finally:
                self.after(0, self.hide_loading)
        threading.Thread(target=do_compress, daemon=True).start()

    def _run_strings_extraction(self):
        import re
        file_path = str(self.selected_file_path)
        minlen = self.strings_minlen_var.get()
        mode = self.strings_mode_var.get()
        unique = self.strings_unique_var.get()
        self.show_loading()
        def extract():
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                results = []
                if mode in ('ascii', 'both'):
                    ascii_re = rb'([\x20-\x7E]{%d,})' % minlen
                    results += [m.decode('ascii', errors='ignore') for m in re.findall(ascii_re, data)]
                if mode in ('unicode', 'both'):
                    uni_re = (rb'(?:[\x20-\x7E][\x00]){%d,}' % minlen)
                    results += [m.decode('utf-16le', errors='ignore') for m in re.findall(uni_re, data)]
                if unique:
                    results = list(dict.fromkeys(results))
                self.strings_last_result = results
                self.strings_last_display = results
                msg = f"[+] Found {len(results)} strings.\n\n" + '\n'.join(results)
                self.after(0, lambda: self.display_results(msg))
            except Exception as e:
                self.after(0, lambda: self.display_error(f"String extraction error: {e}"))
            finally:
                self.after(0, self.hide_loading)
        threading.Thread(target=extract, daemon=True).start()

    def _copy_strings_result(self):
        if self.strings_last_display:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(self.strings_last_display))
            if self.status_bar:
                self.status_bar.set_status("Strings copied to clipboard!", status_type='success')

    def _save_strings_result(self):
        if self.strings_last_display:
            path = filedialog.asksaveasfilename(title="Save Strings Result", defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
            if path:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(self.strings_last_display))
                if self.status_bar:
                    self.status_bar.set_status(f"Strings saved to {os.path.basename(path)}", status_type='success')

    def _filter_strings_result(self):
        query = self.strings_filter_var.get().strip()
        if not query:
            self.strings_last_display = self.strings_last_result
        else:
            self.strings_last_display = [s for s in self.strings_last_result if query in s]
        msg = f"[+] Found {len(self.strings_last_display)} strings.\n\n" + '\n'.join(self.strings_last_display)
        self.display_results(msg)

    def _run_carve_extraction(self):
        import re
        import tempfile
        file_path = str(self.selected_file_path)
        self.show_loading()
        def carve():
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                # Define file signatures (magic numbers)
                signatures = [
                    (b'\x89PNG\r\n\x1a\n', b'IEND', 'png'),
                    (b'\xff\xd8\xff', b'\xff\xd9', 'jpg'),
                    (b'GIF89a', b';', 'gif'),
                    (b'GIF87a', b';', 'gif'),
                    (b'%PDF-', b'%%EOF', 'pdf'),
                    (b'PK\x03\x04', None, 'zip'),
                    (b'Rar!\x1a\x07\x00', None, 'rar'),
                    (b'7z\xBC\xAF\x27\x1C', None, '7z'),
                    (b'\x1f\x8b', None, 'gz'),
                    (b'BZh', None, 'bz2'),
                    (b'\xfd7zXZ\x00', None, 'xz'),
                    (b'\x7fELF', None, 'elf'),
                ]
                found = []
                for sig, end, ftype in signatures:
                    start = 0
                    while True:
                        idx = data.find(sig, start)
                        if idx == -1:
                            break
                        # Try to find end marker for types that have it
                        if end:
                            end_idx = data.find(end, idx + len(sig))
                            if end_idx != -1:
                                end_idx += len(end)
                                carved = data[idx:end_idx]
                            else:
                                carved = data[idx:idx+4096]  # fallback: 4KB
                        else:
                            # For archive types, try to find next signature or end of file
                            next_idx = min([data.find(s2, idx+1) for s2, _, _ in signatures if s2 != sig and data.find(s2, idx+1) != -1] or [len(data)])
                            carved = data[idx:next_idx]
                        found.append({'type': ftype, 'offset': idx, 'size': len(carved), 'data': carved})
                        start = idx + len(sig)
                self.carve_last_files = found
                self.carve_last_display = found
                msg = f"[+] Found {len(found)} files.\n\n"
                for i, f in enumerate(found):
                    msg += f"[{i}] Type: {f['type']} | Offset: {f['offset']} | Size: {f['size']} bytes\n"
                self.after(0, lambda: self.display_results(msg))
            except Exception as e:
                self.after(0, lambda: self.display_error(f"File carving error: {e}"))
            finally:
                self.after(0, self.hide_loading)
        threading.Thread(target=carve, daemon=True).start()

    def _carve_save_all(self):
        import os
        if not self.carve_last_display:
            return
        out_dir = filedialog.askdirectory(title="Select Directory to Save Carved Files")
        if not out_dir:
            return
        for i, f in enumerate(self.carve_last_display):
            out_path = os.path.join(out_dir, f"carved_{i}.{f['type']}")
            with open(out_path, 'wb') as out_f:
                out_f.write(f['data'])
        if self.status_bar:
            self.status_bar.set_status(f"Saved {len(self.carve_last_display)} files.", status_type='success')

    def _carve_save_selected(self):
        import os
        if not self.carve_last_display:
            return
        idx = self._carve_get_selected_index()
        if idx is None or idx >= len(self.carve_last_display):
            return
        f = self.carve_last_display[idx]
        out_path = filedialog.asksaveasfilename(title="Save Selected Carved File", defaultextension=f'.{f['type']}', filetypes=[(f['type'].upper(), f"*.{f['type']}")])
        if out_path:
            with open(out_path, 'wb') as out_f:
                out_f.write(f['data'])
            if self.status_bar:
                self.status_bar.set_status(f"Saved file: {out_path}", status_type='success')

    def _carve_apply_filter(self):
        ftype = self.carve_filter_var.get().strip().lower()
        if not ftype:
            self.carve_last_display = self.carve_last_files
        else:
            self.carve_last_display = [f for f in self.carve_last_files if f['type'] == ftype]
        msg = f"[+] Found {len(self.carve_last_display)} files.\n\n"
        for i, f in enumerate(self.carve_last_display):
            msg += f"[{i}] Type: {f['type']} | Offset: {f['offset']} | Size: {f['size']} bytes\n"
        self.display_results(msg)

    def _carve_get_selected_index(self):
        # For now, just ask user for index
        import tkinter.simpledialog as simpledialog
        if not self.carve_last_display:
            return None
        idx = simpledialog.askinteger("Select File", f"Enter file index (0-{len(self.carve_last_display)-1}):")
        return idx

    def _carve_hex_preview(self):
        idx = self._carve_get_selected_index()
        if idx is None or idx >= len(self.carve_last_display):
            return
        f = self.carve_last_display[idx]
        data = f['data']
        hex_str = ' '.join(f'{b:02x}' for b in data[:256])
        msgbox = tk.Toplevel()
        msgbox.title("Hex Preview")
        text = tk.Text(msgbox, wrap='none', width=80, height=16)
        text.pack(fill='both', expand=True)
        text.insert('1.0', hex_str)
        text.config(state='disabled')

    def _run_entropy_analysis(self):
        import math
        import os
        file_path = str(self.selected_file_path)
        window_size = self.entropy_window_var.get()
        self.show_loading()
        def entropy(data):
            if not data:
                return 0.0
            occur = [0] * 256
            for b in data:
                occur[b] += 1
            total = len(data)
            ent = 0.0
            for c in occur:
                if c:
                    p = c / total
                    ent -= p * math.log2(p)
            return ent
        def analyze():
            try:
                filesize = os.path.getsize(file_path)
                if filesize > 100*1024*1024:  # 100MB
                    self.after(0, lambda: self.display_error("File too large for entropy analysis (limit: 100MB)."))
                    return
                with open(file_path, 'rb') as f:
                    data = f.read()
                entropies = []
                for i in range(0, len(data), window_size):
                    chunk = data[i:i+window_size]
                    entropies.append(entropy(chunk))
                overall = entropy(data)
                min_ent = min(entropies) if entropies else 0.0
                max_ent = max(entropies) if entropies else 0.0
                avg_ent = sum(entropies)/len(entropies) if entropies else 0.0
                # Bar graph (unicode blocks)
                bars = '▁▂▃▄▅▆▇█'
                bargraph = ''.join(bars[min(int((e/8)*7),7)] for e in entropies)
                self.entropy_last_graph = bargraph
                self.entropy_last_stats = {
                    'window_size': window_size,
                    'overall': overall,
                    'min': min_ent,
                    'max': max_ent,
                    'avg': avg_ent,
                    'windows': len(entropies)
                }
                msg = (
                    f"[+] Entropy Analysis (window size: {window_size} bytes)\n"
                    f"File size: {filesize} bytes\n"
                    f"Overall entropy: {overall:.3f} bits/byte\n"
                    f"Min entropy: {min_ent:.3f}\n"
                    f"Max entropy: {max_ent:.3f}\n"
                    f"Average entropy: {avg_ent:.3f}\n"
                    f"Windows: {len(entropies)}\n\n"
                    f"Entropy per window (bar graph):\n{bargraph}\n\n"
                )
                # Plain-language explanation
                msg += "Explanation:\n"
                if overall > 7.5:
                    msg += "- High entropy: This file is likely encrypted or compressed.\n"
                elif overall > 6.0:
                    msg += "- Medium entropy: This file may be an image, executable, or contain mixed data.\n"
                else:
                    msg += "- Low entropy: This file is likely plain text or uncompressed data.\n"
                msg += "- Spikes in the bar graph indicate regions of high or low randomness.\n"
                msg += "- If you see a sudden jump, it may indicate embedded or hidden data.\n"
                msg += "- Use a smaller window size for more detailed analysis.\n"
                msg += "- High entropy regions are good candidates for further analysis (e.g., carving, stego, crypto).\n"
                self.after(0, lambda: self.display_results(msg))
            except Exception as e:
                self.after(0, lambda: self.display_error(f"Entropy analysis error: {e}"))
            finally:
                self.after(0, self.hide_loading)
        threading.Thread(target=analyze, daemon=True).start()

    def _export_entropy_graph(self):
        if not self.entropy_last_graph:
            messagebox.showinfo("Export Graph", "No entropy graph to export. Run analysis first.")
            return
        path = filedialog.asksaveasfilename(title="Export Entropy Graph", defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write("Entropy Bar Graph:\n")
                    f.write(self.entropy_last_graph + "\n")
                    for k, v in self.entropy_last_stats.items():
                        f.write(f"{k}: {v}\n")
                if self.status_bar:
                    self.status_bar.set_status(f"Entropy graph exported to {os.path.basename(path)}", status_type='success')
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {e}")

    def analyze_stego(self) -> None:
        if not self.selected_file_path:
            return
        if hasattr(self, 'extract_btn'):
            self.extract_btn.pack_forget()
        if hasattr(self, 'compress_type_dropdown'):
            self.compress_type_dropdown.pack_forget()
        if hasattr(self, 'strings_toolbar'):
            self.strings_toolbar.pack_forget()
        if hasattr(self, 'carve_toolbar'):
            self.carve_toolbar.pack_forget()
        if hasattr(self, 'entropy_toolbar'):
            self.entropy_toolbar.pack_forget()
        if hasattr(self, 'stego_toolbar'):
            self.stego_toolbar.pack(fill='x', padx=10, pady=(10, 0))
        if not isinstance(self.result_text, tk.Text):
            return
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, "Running steganography analysis...\n")
        self.result_text.config(state='disabled')
        if self.status_bar:
            self.status_bar.set_status("Running stego analysis...", status_type='info')
        self._run_stego_analysis()

    def _run_stego_analysis(self):
        import os
        file_path = str(self.selected_file_path)
        output_dir = os.path.join('file_analyzer_output', os.path.basename(file_path) + '_stego')
        self.stego_output_dir = output_dir
        self.show_loading()
        def analyze():
            try:
                from .file_utils import FileAnalyzerUtils
                results = FileAnalyzerUtils.analyze_steganography(file_path, output_dir)
                self.stego_last_results = results
                msg = f"[+] Steganography Analysis Results\n\n"
                msg += "Tool\t\tResult\t\tExtracted File\n"
                msg += "-"*70 + "\n"
                for i, r in enumerate(results):
                    tool = r.get('tool', '')
                    res = r.get('result', '').replace('\n', ' ')[:80]
                    extracted = r.get('extracted', '')
                    if extracted:
                        msg += f"[{i}] {tool}\t✔\t{os.path.basename(str(extracted))}\n"
                    else:
                        msg += f"[{i}] {tool}\t{res}\t-\n"
                msg += "\n"
                msg += "Explanation:\n"
                msg += "- This tool runs multiple steganography and metadata tools.\n"
                msg += "- If an extracted file is found, you can save it or open the output folder.\n"
                msg += "- Try running with a wordlist for password-protected stego (e.g., stegcracker).\n"
                msg += "- For more advanced analysis, use dedicated tools on the output files.\n"
                self.after(0, lambda: self.display_results(msg))
            except Exception as e:
                self.after(0, lambda: self.display_error(f"Stego analysis error: {e}"))
            finally:
                self.after(0, self.hide_loading)
        threading.Thread(target=analyze, daemon=True).start()

    def _stego_save_all(self):
        import shutil, os
        if not self.stego_last_results:
            return
        out_dir = filedialog.askdirectory(title="Select Directory to Save Findings")
        if not out_dir:
            return
        for r in self.stego_last_results:
            extracted = r.get('extracted')
            if extracted and os.path.exists(extracted):
                shutil.copy(extracted, out_dir)
        if self.status_bar:
            self.status_bar.set_status(f"Saved all extracted files to {out_dir}", status_type='success')

    def _stego_open_output(self):
        import os, subprocess, sys
        if not self.stego_output_dir or not os.path.exists(self.stego_output_dir):
            messagebox.showinfo("Open Output Folder", "No output folder found.")
            return
        if sys.platform.startswith('darwin'):
            subprocess.call(['open', self.stego_output_dir])
        elif os.name == 'nt':
            os.startfile(self.stego_output_dir)
        else:
            subprocess.call(['xdg-open', self.stego_output_dir])

if __name__ == "__main__":
    root = tk.Tk()
    app = FileAnalyzerMainWindow(root, lambda: None)
    root.mainloop() 
