"""
Photo Analyzer Main Window Module
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from PIL import Image, ImageTk
import os
import threading
from typing import Optional, Callable, Any, Dict, Union

from .theme import Theme
from .widgets import ModernButton, ModernEntry, ModernText, FileSelector, StatusBar, ToolButton
from .exif_analyzer import EXIFAnalyzer
from .location_analyzer import LocationAnalyzer
from .steganography import SteganographyAnalyzer
from .metadata_analyzer import MetadataAnalyzer
from .string_analyzer import StringAnalyzer
from .binwalk_analyzer import BinwalkAnalyzer
from .zsteg_analyzer import ZstegAnalyzer
from .ocr_analyzer import OCRAnalyzer
from .qr_barcode_analyzer import QRCodeBarcodeAnalyzer
from .crypto_analyzer import CryptoAnalyzer
from .file_carving_analyzer import FileCarvingAnalyzer
from .file_utils import FileUtils
from .settings import Settings
from .hex_viewer import HexViewerWindow

class MainWindow:
    """Main application window"""
    
    def __init__(self, root: Union[tk.Tk, tk.Toplevel]) -> None:
        self.root = root
        self.selected_file_path: Optional[str] = None
        self.image_label: Optional[tk.Label] = None
        self.result_text: Optional[tk.Text] = None
        self.status_bar: Optional[StatusBar] = None
        self.file_selector: Optional[FileSelector] = None
        self.main_frame: Optional[tk.Frame] = None
        self.theme_var = tk.StringVar(value=Theme.get_current_theme())
        self.result_frame: Optional[tk.Frame] = None
        self.result_search_var = tk.StringVar()
        self.result_content = ""
        self.loading_overlay: Optional[tk.Frame] = None
        self.loading_label: Optional[tk.Label] = None
        self.loading_spinner: Optional[tk.Label] = None
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.spinner_index = 0
        self.loading_after_id = None
        
        # Initialize analyzers
        self.exif_analyzer = EXIFAnalyzer()
        self.location_analyzer = LocationAnalyzer()
        self.steganography_analyzer = SteganographyAnalyzer()
        self.metadata_analyzer = MetadataAnalyzer()
        self.string_analyzer = StringAnalyzer()
        self.binwalk_analyzer = BinwalkAnalyzer()
        self.zsteg_analyzer = ZstegAnalyzer()
        self.ocr_analyzer = OCRAnalyzer()
        self.qr_barcode_analyzer = QRCodeBarcodeAnalyzer()
        self.crypto_analyzer = CryptoAnalyzer()
        self.file_carving_analyzer = FileCarvingAnalyzer()
        
        self.setup_window()
        self.create_widgets()
        self.setup_layout()
        self.apply_theme_to_all_widgets()
        
    def setup_window(self):
        """Setup main window properties"""
        self.root.title(f"{Settings.APP_NAME} v{Settings.APP_VERSION}")
        self.root.geometry(f"{Settings.WINDOW_WIDTH}x{Settings.WINDOW_HEIGHT}")
        self.root.minsize(Settings.MIN_WINDOW_WIDTH, Settings.MIN_WINDOW_HEIGHT)
        
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
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        self.main_frame = tk.Frame(self.root, bg=Theme.get_color('primary'))
        self.main_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('medium'), 
                           pady=Theme.get_spacing('medium'))
        
        # Header
        self.create_header()
        
        # File selection area
        self.create_file_selection()
        
        # Main content area (tools + results side by side)
        self.create_main_content()
        
        # Status bar
        self.create_status_bar()
        
    def create_header(self):
        """Create application header with theme selector"""
        header_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        header_frame.pack(fill='x', pady=(0, Theme.get_spacing('large')))
        # Title
        title_label = tk.Label(header_frame, 
                              text=Settings.APP_NAME,
                              font=Theme.get_font('title'),
                              bg=Theme.get_color('primary'),
                              fg=Theme.get_color('accent'))
        title_label.pack(side='left')
        # Theme selector
        theme_label = tk.Label(header_frame, text="Theme:", bg=Theme.get_color('primary'), fg=Theme.get_color('text_secondary'), font=Theme.get_font('default'))
        theme_label.pack(side='right', padx=(0, 5))
        theme_dropdown = ttk.Combobox(header_frame, textvariable=self.theme_var, values=Theme.get_available_themes(), width=8, state='readonly')
        theme_dropdown.pack(side='right', padx=(0, 10))
        theme_dropdown.bind('<<ComboboxSelected>>', self.on_theme_change)
        # Subtitle
        subtitle_label = tk.Label(header_frame,
                                 text=Settings.APP_DESCRIPTION,
                                 font=Theme.get_font('default'),
                                 bg=Theme.get_color('primary'),
                                 fg=Theme.get_color('text_secondary'))
        subtitle_label.pack(anchor='w')
        
    def create_file_selection(self):
        """Create file selection area"""
        file_frame = tk.Frame(self.main_frame, bg=Theme.get_color('secondary'))
        file_frame.pack(fill='x', pady=Theme.get_spacing('medium'))
        
        # File selector
        self.file_selector = FileSelector(
            file_frame,
            title="Select File for Analysis",
            file_types=[
                ("Image Files", "*.jpg *.jpeg *.png *.bmp *.gif *.tiff *.ico *.webp"),
                ("All Files", "*.*")
            ]
        )
        self.file_selector.pack(fill='x', padx=Theme.get_spacing('medium'), 
                              pady=Theme.get_spacing('medium'))
        
        # Load button
        self.load_button = ModernButton(
            file_frame,
            text="Load File",
            command=self.load_file,
            style='primary'
        )
        self.load_button.pack(pady=Theme.get_spacing('small'))
        
        # Image preview
        self.image_frame = tk.Frame(file_frame, bg=Theme.get_color('secondary'))
        self.image_frame.pack(fill='x', pady=Theme.get_spacing('small'))
        
        self.image_label = tk.Label(self.image_frame, 
                                   text="No image loaded",
                                   bg=Theme.get_color('secondary'),
                                   fg=Theme.get_color('text_muted'))
        self.image_label.pack()
        
    def create_main_content(self):
        """Create main content area with tools on left and results on right"""
        content_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        content_frame.pack(fill='both', expand=True, pady=Theme.get_spacing('medium'))
        
        # Tools area (left side)
        self.create_tools_area(content_frame)
        
        # Results area (right side)
        self.create_results_area(content_frame)
        
        # Configure grid weights
        content_frame.columnconfigure(0, weight=1)  # Tools
        content_frame.columnconfigure(1, weight=2)  # Results (wider)
        
    def create_tools_area(self, parent):
        """Create tools area with analysis buttons"""
        tools_frame = tk.Frame(parent, bg=Theme.get_color('primary'))
        tools_frame.grid(row=0, column=0, sticky='nsew', padx=(0, Theme.get_spacing('medium')))
        
        # Tools title
        tools_title = tk.Label(tools_frame,
                              text="Analysis Tools",
                              font=Theme.get_font('heading'),
                              bg=Theme.get_color('primary'),
                              fg=Theme.get_color('text_primary'))
        tools_title.pack(anchor='w', pady=(0, Theme.get_spacing('medium')))
        
        # Tools grid
        tools_grid = tk.Frame(tools_frame, bg=Theme.get_color('primary'))
        tools_grid.pack(fill='x')
        
        # Row 1
        self.exif_button = ToolButton(
            tools_grid,
            text="EXIF Analysis",
            description="Extract device and image metadata",
            command=self.analyze_exif,
            icon="📸"
        )
        self.exif_button.grid(row=0, column=0, padx=Theme.get_spacing('small'), 
                             pady=Theme.get_spacing('small'), sticky='ew')
        
        self.location_button = ToolButton(
            tools_grid,
            text="Location Analysis",
            description="Extract GPS coordinates and address",
            command=self.analyze_location,
            icon="📍"
        )
        self.location_button.grid(row=0, column=1, padx=Theme.get_spacing('small'), 
                                 pady=Theme.get_spacing('small'), sticky='ew')
        
        self.steganography_button = ToolButton(
            tools_grid,
            text="Steganography",
            description="Hide/extract data in images",
            command=self.open_steganography,
            icon="🔐"
        )
        self.steganography_button.grid(row=0, column=2, padx=Theme.get_spacing('small'), 
                                      pady=Theme.get_spacing('small'), sticky='ew')
        
        # Row 2
        self.metadata_button = ToolButton(
            tools_grid,
            text="Metadata Analysis",
            description="Detailed metadata with ExifTool",
            command=self.analyze_metadata,
            icon="📋"
        )
        self.metadata_button.grid(row=1, column=0, padx=Theme.get_spacing('small'), 
                                 pady=Theme.get_spacing('small'), sticky='ew')
        
        self.strings_button = ToolButton(
            tools_grid,
            text="String Extraction",
            description="Extract readable strings from files",
            command=self.analyze_strings,
            icon="🔍"
        )
        self.strings_button.grid(row=1, column=1, padx=Theme.get_spacing('small'), 
                                pady=Theme.get_spacing('small'), sticky='ew')
        
        self.binwalk_button = ToolButton(
            tools_grid,
            text="Binwalk Analysis",
            description="Advanced file analysis and extraction",
            command=self.analyze_binwalk,
            icon="🔧"
        )
        self.binwalk_button.grid(row=1, column=2, padx=Theme.get_spacing('small'), 
                                pady=Theme.get_spacing('small'), sticky='ew')
        
        # Row 3 - New CTF Tools
        self.zsteg_button = ToolButton(
            tools_grid,
            text="Zsteg Analysis",
            description="PNG/BMP LSB steganography analysis",
            command=self.analyze_zsteg,
            icon="🎨"
        )
        self.zsteg_button.grid(row=2, column=0, padx=Theme.get_spacing('small'), 
                              pady=Theme.get_spacing('small'), sticky='ew')
        
        self.ocr_button = ToolButton(
            tools_grid,
            text="OCR Analysis",
            description="Extract text from images",
            command=self.analyze_ocr,
            icon="📝"
        )
        self.ocr_button.grid(row=2, column=1, padx=Theme.get_spacing('small'), 
                            pady=Theme.get_spacing('small'), sticky='ew')
        
        self.ctf_auto_button = ToolButton(
            tools_grid,
            text="CTF Auto-Analyze",
            description="Run all CTF-relevant analyses",
            command=self.ctf_auto_analyze,
            icon="🚀"
        )
        self.ctf_auto_button.grid(row=2, column=2, padx=Theme.get_spacing('small'), 
                                 pady=Theme.get_spacing('small'), sticky='ew')
        
        # Row 4 - Advanced Tools
        self.qr_barcode_button = ToolButton(
            tools_grid,
            text="QR/Barcode Scan",
            description="Detect and decode QR codes/barcodes",
            command=self.analyze_qr_barcode,
            icon="📱"
        )
        self.qr_barcode_button.grid(row=3, column=0, padx=Theme.get_spacing('small'), 
                                   pady=Theme.get_spacing('small'), sticky='ew')
        
        self.hex_viewer_button = ToolButton(
            tools_grid,
            text="Hex Viewer",
            description="View and edit file as hex (find/replace, search, save as copy)",
            command=self.open_hex_viewer,
            icon="🧮"
        )
        self.hex_viewer_button.grid(row=3, column=1, padx=Theme.get_spacing('small'), 
                                   pady=Theme.get_spacing('small'), sticky='ew')
        
        self.file_carving_button = ToolButton(
            tools_grid,
            text="File Carving",
            description="Extract files from binary data",
            command=self.analyze_file_carving,
            icon="🗜️"
        )
        self.file_carving_button.grid(row=3, column=2, padx=Theme.get_spacing('small'), 
                                     pady=Theme.get_spacing('small'), sticky='ew')
        
        # Configure grid weights
        tools_grid.columnconfigure(0, weight=1)
        tools_grid.columnconfigure(1, weight=1)
        tools_grid.columnconfigure(2, weight=1)
        
    def create_results_area(self, parent):
        """Create modern results display area with enhanced styling"""
        self.result_frame = tk.Frame(parent, bg=Theme.get_color('secondary'), 
                                    bd=3, relief='raised', highlightthickness=1,
                                    highlightbackground=Theme.get_color('accent'))
        self.result_frame.grid(row=0, column=1, sticky='nsew')
        
        # Results header with title and controls
        header_frame = tk.Frame(self.result_frame, bg=Theme.get_color('accent'), height=40)
        header_frame.pack(fill='x', pady=(0, 2))
        header_frame.pack_propagate(False)
        
        # Title
        title_label = tk.Label(header_frame, text="🔍 Analysis Results", 
                              font=('Segoe UI', 14, 'bold'),
                              bg=Theme.get_color('accent'), fg='white')
        title_label.pack(side='left', padx=10, pady=5)
        
        # Control buttons
        controls_frame = tk.Frame(header_frame, bg=Theme.get_color('accent'))
        controls_frame.pack(side='right', padx=10, pady=5)
        
        # Search frame
        search_frame = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        search_frame.pack(fill='x', padx=10, pady=5)
        
        search_label = tk.Label(search_frame, text="Search:", 
                               font=('Segoe UI', 11, 'bold'),
                               bg=Theme.get_color('secondary'), 
                               fg=Theme.get_color('text_primary'))
        search_label.pack(side='left', padx=(0, 5))
        
        search_entry = tk.Entry(search_frame, textvariable=self.result_search_var, 
                               font=('Segoe UI', 11),
                               bg=Theme.get_color('entry_bg'), 
                               fg=Theme.get_color('entry_fg'),
                               relief='solid', bd=1, width=25)
        search_entry.pack(side='left', padx=(0, 5))
        
        search_btn = tk.Button(search_frame, text="🔍 Search", 
                              command=self.search_in_results,
                              font=('Segoe UI', 10, 'bold'),
                              bg=Theme.get_color('accent'), fg='white',
                              relief='flat', bd=0, padx=15, pady=3,
                              cursor='hand2')
        search_btn.pack(side='left', padx=(0, 5))
        
        copy_btn = tk.Button(search_frame, text="📋 Copy", 
                            command=self.copy_results,
                            font=('Segoe UI', 10, 'bold'),
                            bg=Theme.get_color('success'), fg='white',
                            relief='flat', bd=0, padx=15, pady=3,
                            cursor='hand2')
        copy_btn.pack(side='left', padx=(0, 5))
        
        clear_btn = tk.Button(search_frame, text="🗑️ Clear", 
                             command=self.clear_results,
                             font=('Segoe UI', 10, 'bold'),
                             bg=Theme.get_color('error'), fg='white',
                             relief='flat', bd=0, padx=15, pady=3,
                             cursor='hand2')
        clear_btn.pack(side='left')
        
        # Results text area with enhanced styling
        text_container = tk.Frame(self.result_frame, bg=Theme.get_color('text_bg'), 
                                 bd=2, relief='sunken')
        text_container.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Custom text widget with larger font and better colors
        self.result_text = tk.Text(text_container, 
                                  wrap='word',
                                  font=('Consolas', 12),  # Larger, monospace font
                                  bg=Theme.get_color('text_bg'),
                                  fg=Theme.get_color('text_fg'),
                                  relief='flat',
                                  bd=0,
                                  padx=10,
                                  pady=10,
                                  insertbackground=Theme.get_color('accent'),
                                  selectbackground=Theme.get_color('accent'),
                                  selectforeground='white',
                                  cursor='xterm')
        self.result_text.pack(side='left', fill='both', expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(text_container, orient='vertical', 
                                 command=self.result_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        # Configure text tags for syntax highlighting
        self.result_text.tag_configure('header', 
                                      font=('Segoe UI', 14, 'bold'),
                                      foreground=Theme.get_color('accent'))
        self.result_text.tag_configure('success', 
                                      foreground=Theme.get_color('success'),
                                      font=('Consolas', 12, 'bold'))
        self.result_text.tag_configure('error', 
                                      foreground=Theme.get_color('error'),
                                      font=('Consolas', 12, 'bold'))
        self.result_text.tag_configure('warning', 
                                      foreground=Theme.get_color('warning'),
                                      font=('Consolas', 12, 'bold'))
        self.result_text.tag_configure('info', 
                                      foreground=Theme.get_color('info'),
                                      font=('Consolas', 12, 'bold'))
        self.result_text.tag_configure('highlight', 
                                      background=Theme.get_color('highlight'),
                                      font=('Consolas', 12, 'bold'))
        
    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = StatusBar(self.root)
        self.status_bar.pack(side='bottom', fill='x')
        
    def setup_layout(self):
        """Setup final layout"""
        # Configure main frame weights
        if self.main_frame:
            self.main_frame.columnconfigure(0, weight=1)
            self.main_frame.rowconfigure(2, weight=1)  # Results area
        
    def apply_theme_to_all_widgets(self):
        """Recursively apply the current theme to all widgets in the main window"""
        import tkinter.ttk as ttk
        def update_widget_colors(widget):
            # Skip ttk widgets
            if isinstance(widget, ttk.Widget):
                return
            # Update background and foreground for known widget types
            if isinstance(widget, (tk.Frame, tk.LabelFrame)):
                widget.configure(bg=Theme.get_color('primary'))
            elif isinstance(widget, tk.Label):
                widget.configure(bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary'))
            elif isinstance(widget, tk.Button):
                widget.configure(bg=Theme.get_color('button_bg'), fg=Theme.get_color('button_fg'), activebackground=Theme.get_color('button_hover'))
            elif isinstance(widget, tk.Entry):
                widget.configure(bg=Theme.get_color('entry_bg'), fg=Theme.get_color('entry_fg'), insertbackground=Theme.get_color('accent'))
            elif isinstance(widget, tk.Text):
                widget.configure(bg=Theme.get_color('text_bg'), fg=Theme.get_color('text_fg'), insertbackground=Theme.get_color('accent'), selectbackground=Theme.get_color('accent'), selectforeground=Theme.get_color('text_primary'))
            # Recursively update children
            for child in widget.winfo_children():
                update_widget_colors(child)
        update_widget_colors(self.root)
        # Special handling for result_frame and accent areas
        if self.result_frame:
            self.result_frame.configure(bg=Theme.get_color('secondary'), highlightbackground=Theme.get_color('accent'))
        if self.result_text:
            self.result_text.configure(bg=Theme.get_color('text_bg'), fg=Theme.get_color('text_fg'), insertbackground=Theme.get_color('accent'), selectbackground=Theme.get_color('accent'), selectforeground='white')
            self.result_text.tag_configure('header', foreground=Theme.get_color('accent'))
            self.result_text.tag_configure('success', foreground=Theme.get_color('success'))
            self.result_text.tag_configure('error', foreground=Theme.get_color('error'))
            self.result_text.tag_configure('warning', foreground=Theme.get_color('warning'))
            self.result_text.tag_configure('info', foreground=Theme.get_color('info'))
            self.result_text.tag_configure('highlight', background=Theme.get_color('highlight'))
        # Update accent header in result area
        if hasattr(self, 'result_frame') and self.result_frame:
            for child in self.result_frame.winfo_children():
                if isinstance(child, tk.Frame) and child.winfo_height() == 40:
                    child.configure(bg=Theme.get_color('accent'))
                    for subchild in child.winfo_children():
                        if isinstance(subchild, tk.Label):
                            subchild.configure(bg=Theme.get_color('accent'), fg='white')
                        elif isinstance(subchild, tk.Frame):
                            subchild.configure(bg=Theme.get_color('accent'))
        # Update search bar and buttons in result area
        if hasattr(self, 'result_frame') and self.result_frame:
            for child in self.result_frame.winfo_children():
                if isinstance(child, tk.Frame):
                    for subchild in child.winfo_children():
                        if isinstance(subchild, tk.Entry):
                            subchild.configure(bg=Theme.get_color('entry_bg'), fg=Theme.get_color('entry_fg'), insertbackground=Theme.get_color('accent'))
                        elif isinstance(subchild, tk.Button):
                            text = subchild.cget('text')
                            if 'Search' in text:
                                subchild.configure(bg=Theme.get_color('accent'), fg='white', activebackground=Theme.get_color('accent_hover'))
                            elif 'Copy' in text:
                                subchild.configure(bg=Theme.get_color('success'), fg='white', activebackground=Theme.get_color('success'))
                            elif 'Clear' in text:
                                subchild.configure(bg=Theme.get_color('error'), fg='white', activebackground=Theme.get_color('error'))
        # Update status bar
        if self.status_bar:
            self.status_bar.configure(bg=Theme.get_color('secondary'))
        # Update loading overlay if it exists
        if self.loading_overlay:
            self.loading_overlay.configure(bg='black')
            for child in self.loading_overlay.winfo_children():
                if isinstance(child, tk.Frame):
                    child.configure(bg=Theme.get_color('secondary'))
                    for subchild in child.winfo_children():
                        if isinstance(subchild, tk.Label):
                            if subchild == self.loading_spinner:
                                subchild.configure(bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
                            else:
                                subchild.configure(bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'))

    def on_theme_change(self, event=None):
        Theme.set_theme(self.theme_var.get())
        self.apply_theme_to_all_widgets()
        self.refresh_result_area_theme()
        self.root.update_idletasks()

    def refresh_result_area_theme(self):
        if self.result_frame:
            self.result_frame.configure(bg=Theme.get_color('secondary'))
        if self.result_text:
            self.result_text.configure(
                bg=Theme.get_color('text_bg'),
                fg=Theme.get_color('text_fg'),
                insertbackground=Theme.get_color('accent'),
                selectbackground=Theme.get_color('accent'),
                selectforeground='white'
            )
            # Update text tags
            self.result_text.tag_configure('header', foreground=Theme.get_color('accent'))
            self.result_text.tag_configure('success', foreground=Theme.get_color('success'))
            self.result_text.tag_configure('error', foreground=Theme.get_color('error'))
            self.result_text.tag_configure('warning', foreground=Theme.get_color('warning'))
            self.result_text.tag_configure('info', foreground=Theme.get_color('info'))
            self.result_text.tag_configure('highlight', background=Theme.get_color('highlight'))

    def search_in_results(self):
        term = self.result_search_var.get()
        if not self.result_text:
            return
        self.result_text.tag_remove('search', '1.0', 'end')
        if not term:
            return
        idx = '1.0'
        while True:
            idx = self.result_text.search(term, idx, nocase=True, stopindex='end')
            if not idx:
                break
            lastidx = f"{idx}+{len(term)}c"
            self.result_text.tag_add('search', idx, lastidx)
            self.result_text.tag_config('search', background=Theme.get_color('accent'), foreground=Theme.get_color('text_primary'))
            idx = lastidx

    def copy_results(self):
        if not self.result_text:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.result_text.get('1.0', 'end').strip())

    def clear_results(self):
        if self.result_text:
            self.result_text.delete('1.0', 'end')
        self.result_content = ""

    def load_file(self):
        """Load selected file"""
        if not self.file_selector:
            messagebox.showerror("Error", "File selector not initialized.")
            return
            
        file_path = self.file_selector.get_selected_file()
        
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file first.")
            return
        
        if not FileUtils.file_exists(file_path):
            messagebox.showerror("Error", f"File not found: {file_path}")
            return
        
        self.selected_file_path = file_path
        if self.status_bar:
            self.status_bar.set_status(f"Loaded: {os.path.basename(file_path)}", 'success')
        
        # Update image preview if it's an image
        if FileUtils.is_image_file(file_path):
            self.update_image_preview(file_path)
        elif self.image_label:
            self.image_label.configure(text=f"File: {os.path.basename(file_path)}")
        
        # Clear previous results
        if self.result_text:
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', f"File loaded: {file_path}\n\nReady for analysis.")
        
    def update_image_preview(self, image_path: str):
        """Update image preview"""
        if not self.image_label:
            return
            
        try:
            with Image.open(image_path) as img:
                # Resize image for preview
                img.thumbnail((150, 150), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                
                self.image_label.configure(image=photo, text="")
                self.image_label.image = photo  # Keep a reference  # type: ignore
                
        except Exception as e:
            self.image_label.configure(text=f"Error loading image: {e}")
            
    def create_loading_overlay(self):
        """Create loading overlay with spinner and status"""
        if self.loading_overlay:
            return
            
        # Create overlay frame
        self.loading_overlay = tk.Frame(self.root, bg='black')
        
        # Create loading container
        loading_container = tk.Frame(self.loading_overlay, 
                                   bg=Theme.get_color('secondary'),
                                   bd=3, relief='raised',
                                   padx=40, pady=30)
        loading_container.pack(expand=True)
        
        # Spinner
        self.loading_spinner = tk.Label(loading_container,
                                       text=self.spinner_chars[0],
                                       font=('Segoe UI', 24),
                                       bg=Theme.get_color('secondary'),
                                       fg=Theme.get_color('accent'))
        self.loading_spinner.pack(pady=(0, 10))
        
        # Loading text
        self.loading_label = tk.Label(loading_container,
                                     text="Analyzing...",
                                     font=('Segoe UI', 12, 'bold'),
                                     bg=Theme.get_color('secondary'),
                                     fg=Theme.get_color('text_primary'))
        self.loading_label.pack()
        
    def show_loading(self, message: str = "Analyzing..."):
        """Show loading overlay with custom message"""
        if not self.loading_overlay:
            self.create_loading_overlay()
            
        if self.loading_label:
            self.loading_label.config(text=message)
        if self.loading_overlay:
            self.loading_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.loading_overlay.lift()
            self.root.update_idletasks()
            
            # Start spinner animation
            self.animate_spinner()
        
    def hide_loading(self):
        """Hide loading overlay"""
        if self.loading_overlay:
            self.loading_overlay.place_forget()
            if self.loading_after_id:
                self.root.after_cancel(self.loading_after_id)
                self.loading_after_id = None
                
    def animate_spinner(self):
        """Animate the spinner"""
        if (self.loading_spinner and self.loading_overlay and 
            self.loading_overlay.winfo_viewable()):
            self.spinner_index = (self.spinner_index + 1) % len(self.spinner_chars)
            self.loading_spinner.config(text=self.spinner_chars[self.spinner_index])
            self.loading_after_id = self.root.after(100, self.animate_spinner)
            
    def run_analysis(self, analysis_func: Callable[..., str], *args: Any):
        """Run analysis in separate thread with loading indicator"""
        def run():
            try:
                result = analysis_func(*args)
                self.root.after(0, self.display_results, result)
            except Exception as e:
                self.root.after(0, self.display_error, str(e))
            finally:
                self.root.after(0, self.hide_loading)
        
        # Show loading before starting analysis
        self.show_loading("Running analysis...")
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        
    def display_results(self, result: str):
        if self.result_text:
            self.result_text.delete('1.0', tk.END)
            
            # Apply formatting based on content
            lines = result.split('\n')
            for line in lines:
                if line.startswith('='):
                    # Section header
                    self.result_text.insert(tk.END, line + '\n', 'header')
                elif 'Error:' in line or 'Failed:' in line:
                    # Error lines
                    self.result_text.insert(tk.END, line + '\n', 'error')
                elif 'Success:' in line or 'Found:' in line:
                    # Success lines
                    self.result_text.insert(tk.END, line + '\n', 'success')
                elif 'Warning:' in line:
                    # Warning lines
                    self.result_text.insert(tk.END, line + '\n', 'warning')
                elif line.startswith('  ') or line.startswith('\t'):
                    # Indented lines (data)
                    self.result_text.insert(tk.END, line + '\n', 'info')
                else:
                    # Regular lines
                    self.result_text.insert(tk.END, line + '\n')
            
            self.result_content = result
            self.result_text.tag_remove('search', '1.0', 'end')

    def display_error(self, error: str):
        if self.result_text:
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', f"❌ Error: {error}", 'error')
            self.result_content = error
            self.result_text.tag_remove('search', '1.0', 'end')
        
    def analyze_exif(self):
        """Analyze EXIF data"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        self.run_analysis(self._analyze_exif_thread)
        
    def _analyze_exif_thread(self):
        """EXIF analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
            
        if not FileUtils.is_image_file(self.selected_file_path):
            return "Error: Selected file is not an image."
        
        self.exif_analyzer.extract_exif(self.selected_file_path)
        formatted_data = self.exif_analyzer.format_exif_data()
        
        if not formatted_data:
            return "No EXIF data found in the image."
        
        return self.exif_analyzer.export_to_text()
        
    def analyze_location(self):
        """Analyze location data"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        self.run_analysis(self._analyze_location_thread)
        
    def _analyze_location_thread(self):
        """Location analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
            
        if not FileUtils.is_image_file(self.selected_file_path):
            return "Error: Selected file is not an image."
        
        result = self.location_analyzer.analyze_location(self.selected_file_path)
        return self.location_analyzer.export_to_text(result)
        
    def open_steganography(self):
        """Open steganography window"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        # Create steganography window
        stego_window = SteganographyWindow(self.root, self.selected_file_path, 
                                         self.steganography_analyzer)
        
    def analyze_metadata(self):
        """Analyze metadata with ExifTool"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        self.run_analysis(self._analyze_metadata_thread)
        
    def _analyze_metadata_thread(self):
        """Metadata analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
            
        result = self.metadata_analyzer.analyze_file(self.selected_file_path)
        return self.metadata_analyzer.export_to_text(result)
        
    def analyze_strings(self):
        """Analyze strings"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        self.run_analysis(self._analyze_strings_thread)
        
    def _analyze_strings_thread(self):
        """String analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
            
        result = self.string_analyzer.extract_strings(self.selected_file_path)
        return self.string_analyzer.export_to_text(result)
        
    def analyze_binwalk(self):
        """Analyze with Binwalk"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        self.run_analysis(self._analyze_binwalk_thread)
        
    def _analyze_binwalk_thread(self):
        """Binwalk analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
        
        # Check if binwalk is available first
        if not self.binwalk_analyzer.check_binwalk_available():
            return """❌ Binwalk Analysis Failed!

Error: Binwalk is not installed on your system.

To install Binwalk on Kali Linux:
sudo apt update
sudo apt install binwalk

Or install from source:
git clone https://github.com/ReFirmLabs/binwalk.git
cd binwalk
sudo python3 setup.py install

After installation, restart the application and try again."""
        
        try:
            # Add debugging
            result = self.binwalk_analyzer.analyze_file(self.selected_file_path)
            
            if not result.get('success', False):
                return f"❌ Binwalk Analysis Failed!\n\nError: {result.get('error', 'Unknown error')}"
            
            return self.binwalk_analyzer.export_to_text(result)
            
        except Exception as e:
            return f"❌ Binwalk Analysis Error!\n\nException: {str(e)}\n\nPlease check if the file exists and is accessible."

    def analyze_zsteg(self):
        """Analyze with Zsteg"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        self.run_analysis(self._analyze_zsteg_thread)
        
    def _analyze_zsteg_thread(self):
        """Zsteg analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
        
        # Check if zsteg is available first
        if not self.zsteg_analyzer.check_zsteg_available():
            return "Error: Zsteg is not installed on your system. Please install zsteg to use Zsteg analysis."
        
        try:
            result = self.zsteg_analyzer.basic_scan(self.selected_file_path)
            
            if not result.get('success', False):
                return f"❌ Zsteg Analysis Failed!\n\nError: {result.get('error', 'Unknown error')}"
            
            return self.zsteg_analyzer.export_to_text(result)
            
        except Exception as e:
            return f"❌ Zsteg Analysis Error!\n\nException: {str(e)}\n\nPlease check if the file exists and is accessible."

    def analyze_ocr(self):
        """Analyze with OCR"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        self.run_analysis(self._analyze_ocr_thread)
        
    def _analyze_ocr_thread(self):
        """OCR analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
        
        try:
            # Check if file is an image
            if not self.selected_file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.ico', '.webp')):
                return "❌ OCR Analysis Error!\n\nOCR analysis only works with image files.\nSupported formats: JPG, PNG, BMP, GIF, TIFF, ICO, WebP"
            
            # Try basic OCR first
            result = self.ocr_analyzer.extract_text(self.selected_file_path)
            
            if not result.get('success'):
                # Try with preprocessing
                result = self.ocr_analyzer.extract_text_with_preprocessing(self.selected_file_path)
            
            if result.get('success'):
                text = result.get('text', '')
                confidence = result.get('confidence', 0.0)
                method = result.get('preprocessing_method', 'basic')
                
                output = []
                output.append("🔍 OCR Analysis Results")
                output.append("=" * 50)
                output.append("")
                output.append(f"📊 Confidence: {confidence:.2f}%")
                output.append(f"🔧 Method: {method}")
                output.append(f"📝 Characters Found: {len(text)}")
                output.append("")
                output.append("📄 Extracted Text:")
                output.append("-" * 20)
                output.append(text if text.strip() else "No text found")
                output.append("")
                
                # Analyze text for patterns
                if text.strip():
                    output.append("🔍 Text Analysis:")
                    output.append("-" * 20)
                    
                    # Check for URLs
                    import re
                    urls = re.findall(r'https?://[^\s]+', text)
                    if urls:
                        output.append(f"🌐 URLs found: {len(urls)}")
                        for url in urls:
                            output.append(f"  • {url}")
                        output.append("")
                    
                    # Check for emails
                    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
                    if emails:
                        output.append(f"📧 Emails found: {len(emails)}")
                        for email in emails:
                            output.append(f"  • {email}")
                        output.append("")
                    
                    # Check for potential flags
                    flag_patterns = [
                        r'flag\{[^}]+\}',
                        r'FLAG\{[^}]+\}',
                        r'ctf\{[^}]+\}',
                        r'CTF\{[^}]+\}',
                        r'key\{[^}]+\}',
                        r'KEY\{[^}]+\}'
                    ]
                    
                    flags_found = []
                    for pattern in flag_patterns:
                        flags = re.findall(pattern, text, re.IGNORECASE)
                        flags_found.extend(flags)
                    
                    if flags_found:
                        output.append(f"🚩 Potential flags found: {len(flags_found)}")
                        for flag in flags_found:
                            output.append(f"  • {flag}")
                        output.append("")
                
                return "\n".join(output)
            else:
                return f"❌ OCR Analysis Failed!\n\nError: {result.get('error', 'Unknown error')}\n\nPlease ensure:\n• The image contains readable text\n• Tesseract is installed on your system\n• The image is not corrupted"
                
        except Exception as e:
            return f"❌ OCR Analysis Error!\n\nException: {str(e)}\n\nPlease check if the file exists and is accessible."

    def ctf_auto_analyze(self):
        """Run all CTF-relevant analyses"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        self.run_analysis(self._ctf_auto_analyze_thread)
        
    def _ctf_auto_analyze_thread(self):
        """CTF auto-analyze in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
        
        try:
            # Run all CTF-relevant analyses
            results = []
            
            # EXIF Analysis
            try:
                exif_result = self.exif_analyzer.extract_exif(self.selected_file_path)
                if exif_result.get('success'):
                    results.append("📸 EXIF Analysis:\n" + exif_result.get('formatted_data', 'No data'))
                else:
                    results.append("📸 EXIF Analysis: No EXIF data found")
            except Exception as e:
                results.append(f"📸 EXIF Analysis: Failed - {str(e)}")
            
            # String Analysis
            try:
                string_result = self.string_analyzer.extract_strings(self.selected_file_path)
                if string_result.get('success'):
                    results.append("🔍 String Analysis:\n" + f"Found {string_result.get('total_count', 0)} strings")
                    # Show some interesting strings
                    interesting_strings = string_result.get('interesting_strings', [])
                    if interesting_strings:
                        results.append("  Interesting strings:")
                        for s in interesting_strings[:5]:
                            results.append(f"    • {s}")
                else:
                    results.append("🔍 String Analysis: No strings found")
            except Exception as e:
                results.append(f"🔍 String Analysis: Failed - {str(e)}")
            
            # Binwalk Analysis
            try:
                binwalk_result = self.binwalk_analyzer.basic_scan(self.selected_file_path)
                if binwalk_result.get('success'):
                    results.append("🔧 Binwalk Analysis:\n" + f"Found {binwalk_result.get('signatures_found', 0)} signatures")
                else:
                    results.append("🔧 Binwalk Analysis: No signatures found")
            except Exception as e:
                results.append(f"🔧 Binwalk Analysis: Failed - {str(e)}")
            
            # Zsteg Analysis (if PNG/BMP)
            try:
                if self.selected_file_path.lower().endswith(('.png', '.bmp')):
                    zsteg_result = self.zsteg_analyzer.basic_scan(self.selected_file_path)
                    if zsteg_result.get('success'):
                        results.append("🎨 Zsteg Analysis:\n" + f"Found {len(zsteg_result.get('findings', []))} findings")
                    else:
                        results.append("🎨 Zsteg Analysis: No steganography found")
                else:
                    results.append("🎨 Zsteg Analysis: Skipped (not PNG/BMP)")
            except Exception as e:
                results.append(f"🎨 Zsteg Analysis: Failed - {str(e)}")
            
            # OCR Analysis (if image)
            try:
                if self.selected_file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.ico', '.webp')):
                    ocr_result = self.ocr_analyzer.extract_text_with_preprocessing(self.selected_file_path)
                    if ocr_result.get('success'):
                        text = ocr_result.get('text', '')
                        results.append("🔍 OCR Analysis:\n" + f"Extracted {len(text)} characters")
                        if text.strip():
                            results.append(f"  Text: {text[:100]}{'...' if len(text) > 100 else ''}")
                    else:
                        results.append("🔍 OCR Analysis: No text found")
                else:
                    results.append("🔍 OCR Analysis: Skipped (not an image)")
            except Exception as e:
                results.append(f"🔍 OCR Analysis: Failed - {str(e)}")
            
            # QR/Barcode Analysis (if image)
            try:
                if self.selected_file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.ico', '.webp')):
                    qr_result = self.qr_barcode_analyzer.detect_codes_with_preprocessing(self.selected_file_path)
                    if qr_result.get('success'):
                        results.append("📱 QR/Barcode Analysis:\n" + f"Found {qr_result.get('total_codes', 0)} codes")
                        for code in qr_result.get('codes', []):
                            results.append(f"  • {code.get('type', 'Unknown')}: {code.get('data', 'No data')}")
                    else:
                        results.append("📱 QR/Barcode Analysis: No codes found")
                else:
                    results.append("📱 QR/Barcode Analysis: Skipped (not an image)")
            except Exception as e:
                results.append(f"📱 QR/Barcode Analysis: Failed - {str(e)}")
            
            # Crypto Analysis (try to decode file content)
            try:
                with open(self.selected_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().strip()
                
                if content:
                    crypto_result = self.crypto_analyzer.auto_decode(content)
                    if crypto_result.get('success'):
                        best_match = crypto_result.get('best_match')
                        if best_match:
                            results.append("🔓 Crypto Analysis:\n" + f"Best decode ({best_match['encoding']}): {best_match['decoded']}")
                        else:
                            results.append("🔓 Crypto Analysis: Multiple decodes found")
                    else:
                        results.append("🔓 Crypto Analysis: No successful decodes")
                else:
                    results.append("🔓 Crypto Analysis: Skipped (empty file)")
            except Exception as e:
                results.append(f"🔓 Crypto Analysis: Failed - {str(e)}")
            
            # File Carving Analysis
            try:
                carving_result = self.file_carving_analyzer.auto_carve(self.selected_file_path)
                if carving_result.get('success'):
                    total_files = carving_result.get('total_files_extracted', 0)
                    results.append("🗜️ File Carving Analysis:\n" + f"Extracted {total_files} files")
                    
                    # Show signature scan results
                    if carving_result.get('signature_results'):
                        sig_results = carving_result['signature_results']
                        if sig_results.get('success'):
                            sig_count = sig_results.get('total_signatures', 0)
                            if sig_count > 0:
                                results.append(f"  Found {sig_count} file signatures")
                else:
                    results.append("🗜️ File Carving Analysis: No files extracted")
            except Exception as e:
                results.append(f"🗜️ File Carving Analysis: Failed - {str(e)}")
            
            # Combine results
            combined_results = "\n\n" + "="*50 + "\n\n".join(results)
            combined_results = "🚀 CTF Auto-Analysis Results\n" + combined_results
            
            return combined_results
            
        except Exception as e:
            return f"❌ CTF Auto-Analysis Error!\n\nException: {str(e)}"

    def analyze_qr_barcode(self):
        """Analyze QR/Barcode"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        self.run_analysis(self._analyze_qr_barcode_thread)
        
    def _analyze_qr_barcode_thread(self):
        """QR/Barcode analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
        
        try:
            # Check if file is an image
            if not self.selected_file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.ico', '.webp')):
                return "❌ QR/Barcode Analysis Error!\n\nQR/Barcode analysis only works with image files.\nSupported formats: JPG, PNG, BMP, GIF, TIFF, ICO, WebP"
            
            # Try basic detection first
            result = self.qr_barcode_analyzer.detect_codes(self.selected_file_path)
            
            if not result.get('success'):
                # Try with preprocessing
                result = self.qr_barcode_analyzer.detect_codes_with_preprocessing(self.selected_file_path)
            
            if result.get('success'):
                codes = result.get('codes', [])
                total_codes = result.get('total_codes', 0)
                method = result.get('preprocessing_method', 'basic')
                
                output = []
                output.append("📱 QR/Barcode Analysis Results")
                output.append("=" * 50)
                output.append("")
                output.append(f"🔍 Total Codes Found: {total_codes}")
                output.append(f"🔧 Detection Method: {method}")
                output.append("")
                
                if codes:
                    output.append("📋 Detected Codes:")
                    output.append("-" * 20)
                    
                    for i, code in enumerate(codes, 1):
                        code_type = code.get('type', 'Unknown')
                        code_data = code.get('data', 'No data')
                        
                        output.append(f"Code {i}:")
                        output.append(f"  📊 Type: {code_type}")
                        output.append(f"  📄 Data: {code_data}")
                        
                        # Analyze content
                        content_analysis = self.qr_barcode_analyzer.analyze_code_content(code_data)
                        if content_analysis['type'] != 'unknown':
                            output.append(f"  🔍 Content Type: {content_analysis['type']}")
                            
                            if content_analysis['is_url']:
                                output.append(f"  🌐 URL: {content_analysis['url']}")
                            elif content_analysis['is_email']:
                                output.append(f"  📧 Email: {content_analysis['email']}")
                            elif content_analysis['is_phone']:
                                output.append(f"  📞 Phone: {content_analysis['phone']}")
                        
                        # Check for potential flags
                        import re
                        flag_patterns = [
                            r'flag\{[^}]+\}',
                            r'FLAG\{[^}]+\}',
                            r'ctf\{[^}]+\}',
                            r'CTF\{[^}]+\}',
                            r'key\{[^}]+\}',
                            r'KEY\{[^}]+\}'
                        ]
                        
                        flags_found = []
                        for pattern in flag_patterns:
                            flags = re.findall(pattern, code_data, re.IGNORECASE)
                            flags_found.extend(flags)
                        
                        if flags_found:
                            output.append(f"  🚩 Potential flags found: {len(flags_found)}")
                            for flag in flags_found:
                                output.append(f"    • {flag}")
                        
                        output.append("")
                else:
                    output.append("❌ No QR codes or barcodes found in the image.")
                    output.append("")
                    output.append("💡 Tips:")
                    output.append("• Ensure the code is clearly visible and not blurry")
                    output.append("• Try with different image preprocessing methods")
                    output.append("• Check if the code is properly oriented")
                    output.append("• Some codes may be embedded in steganography")
                
                return "\n".join(output)
            else:
                return f"❌ QR/Barcode Analysis Failed!\n\nError: {result.get('error', 'Unknown error')}\n\nPlease ensure:\n• The image contains visible QR codes or barcodes\n• The codes are not too blurry or damaged\n• pyzbar and OpenCV are properly installed"
                
        except Exception as e:
            return f"❌ QR/Barcode Analysis Error!\n\nException: {str(e)}\n\nPlease check if the file exists and is accessible."

    def analyze_crypto(self):
        """Analyze crypto"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        # Open crypto popup window
        CryptoPopupWindow(self.root, self.selected_file_path, self.crypto_analyzer)
        
    def analyze_file_carving(self):
        """Analyze file carving"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        self.run_analysis(self._analyze_file_carving_thread)
        
    def _analyze_file_carving_thread(self):
        """File carving analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
        
        try:
            # Check if file exists
            if not os.path.exists(self.selected_file_path):
                return "❌ File Carving Analysis Error!\n\nFile not found."
            
            # Get file size
            file_size = os.path.getsize(self.selected_file_path)
            
            output = []
            output.append("🗜️ File Carving Analysis Results")
            output.append("=" * 50)
            output.append("")
            output.append(f"📁 File: {os.path.basename(self.selected_file_path)}")
            output.append(f"📊 Size: {file_size:,} bytes")
            output.append("")
            
            # Check tool availability
            foremost_available = self.file_carving_analyzer.check_foremost_available()
            binwalk_available = self.file_carving_analyzer.check_binwalk_available()
            
            if not foremost_available and not binwalk_available:
                output.append("❌ No file carving tools available!")
                output.append("")
                output.append("💡 Please install one of the following tools:")
                output.append("• Foremost: sudo apt-get install foremost")
                output.append("• Binwalk: sudo apt-get install binwalk")
                output.append("")
                output.append("🔍 File Signature Scan:")
                output.append("-" * 25)
                
                # Try signature scan only
                sig_result = self.file_carving_analyzer.scan_file_signatures(self.selected_file_path)
                if sig_result.get('success'):
                    output.append(f"✅ Found {sig_result.get('total_signatures', 0)} file signatures:")
                    for sig in sig_result.get('signatures_found', []):
                        output.append(f"  📄 {sig['type']} (x{sig['count']})")
                else:
                    output.append("❌ No file signatures found")
                
                return "\n".join(output)
            
            # Run auto-carving
            carving_result = self.file_carving_analyzer.auto_carve(self.selected_file_path)
            
            if carving_result.get('success'):
                # Signature scan results
                if carving_result.get('signature_results'):
                    sig_results = carving_result['signature_results']
                    if sig_results.get('success'):
                        output.append("🔍 File Signatures Found:")
                        output.append("-" * 30)
                        output.append(f"Total Signatures: {sig_results.get('total_signatures', 0)}")
                        output.append("")
                        
                        for sig in sig_results.get('signatures_found', []):
                            output.append(f"📄 {sig['type']}:")
                            output.append(f"   Count: {sig['count']}")
                            output.append(f"   Positions: {sig['positions'][:3]}{'...' if len(sig['positions']) > 3 else ''}")
                            output.append("")
                
                # Foremost results
                if carving_result.get('foremost_results'):
                    fore_results = carving_result['foremost_results']
                    if fore_results.get('success'):
                        output.append("🗜️ Foremost Extraction:")
                        output.append("-" * 25)
                        output.append(f"Files Found: {fore_results.get('files_found', 0)}")
                        output.append(f"Output Directory: {fore_results.get('output_dir', 'N/A')}")
                        output.append("")
                        
                        for file_info in fore_results.get('extracted_files', []):
                            output.append(f"  📄 {file_info['name']}")
                            output.append(f"     Size: {file_info['size']:,} bytes")
                            output.append(f"     Type: {file_info['type']}")
                            output.append("")
                
                # Binwalk results
                if carving_result.get('binwalk_results'):
                    bin_results = carving_result['binwalk_results']
                    if bin_results.get('success'):
                        output.append("🔧 Binwalk Analysis:")
                        output.append("-" * 20)
                        output.append(f"Entries Found: {bin_results.get('entries_found', 0)}")
                        output.append("")
                        
                        for entry in bin_results.get('entries', []):
                            output.append(f"  📄 {entry['description']}")
                            output.append(f"     Offset: {entry['offset']}")
                            output.append(f"     Size: {entry['size']:,} bytes")
                            output.append("")
                
                return "\n".join(output)
            else:
                output.append("❌ File carving failed!")
                output.append(f"Error: {carving_result.get('error', 'Unknown error')}")
                return "\n".join(output)
                
        except Exception as e:
            return f"❌ File Carving Analysis Error!\n\nException: {str(e)}\n\nPlease check if the file exists and is accessible."

    def open_hex_viewer(self):
        """Open the Hex Viewer tool window"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first")
            return
        hex_window = tk.Toplevel(self.root)
        HexViewerWindow(hex_window, self.selected_file_path)

class SteganographyWindow:
    """Steganography analysis window"""
    
    def __init__(self, parent, file_path: str, analyzer: SteganographyAnalyzer):
        self.window = tk.Toplevel(parent)
        self.file_path = file_path
        self.analyzer = analyzer
        self.result_text = None
        
        self.setup_window()
        self.create_widgets()
        
    def setup_window(self):
        """Setup window properties"""
        self.window.title("Steganography Analysis")
        self.window.geometry("700x600")
        self.window.configure(bg=Theme.get_color('primary'))
        self.window.resizable(True, True)
        
        # Center window
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')
        
    def create_widgets(self):
        """Create steganography widgets"""
        # Main container
        main_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        main_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('medium'), 
                       pady=Theme.get_spacing('medium'))
        
        # Header
        header_frame = tk.Frame(main_frame, bg=Theme.get_color('primary'))
        header_frame.pack(fill='x', pady=(0, Theme.get_spacing('large')))
        
        title_label = tk.Label(header_frame, 
                              text="Steganography Analysis",
                              font=Theme.get_font('title'),
                              bg=Theme.get_color('primary'),
                              fg=Theme.get_color('accent'))
        title_label.pack()
        
        subtitle_label = tk.Label(header_frame,
                                 text=f"File: {os.path.basename(self.file_path)}",
                                 font=Theme.get_font('default'),
                                 bg=Theme.get_color('primary'),
                                 fg=Theme.get_color('text_secondary'))
        subtitle_label.pack()
        
        # Check steghide availability
        if not self.analyzer.check_steghide_available():
            error_frame = tk.Frame(main_frame, bg=Theme.get_color('error'))
            error_frame.pack(fill='x', pady=Theme.get_spacing('medium'))
            
            error_label = tk.Label(error_frame,
                                  text="⚠️ Steghide is not installed. Please install steghide to use steganography features.",
                                  font=Theme.get_font('default'),
                                  bg=Theme.get_color('error'),
                                  fg='white',
                                  wraplength=650)
            error_label.pack(padx=Theme.get_spacing('medium'), pady=Theme.get_spacing('medium'))
            return
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill='both', expand=True)
        
        # Hide Data Tab
        hide_frame = tk.Frame(notebook, bg=Theme.get_color('secondary'))
        notebook.add(hide_frame, text="Hide Data")
        self.create_hide_tab(hide_frame)
        
        # Extract Data Tab
        extract_frame = tk.Frame(notebook, bg=Theme.get_color('secondary'))
        notebook.add(extract_frame, text="Extract Data")
        self.create_extract_tab(extract_frame)
        
        # Results Tab
        results_frame = tk.Frame(notebook, bg=Theme.get_color('secondary'))
        notebook.add(results_frame, text="Results")
        self.create_results_tab(results_frame)
        
    def create_hide_tab(self, parent):
        """Create the hide data tab"""
        # Mode selection
        mode_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        mode_frame.pack(fill='x', padx=Theme.get_spacing('medium'), 
                       pady=Theme.get_spacing('medium'))
        
        mode_label = tk.Label(mode_frame,
                             text="Hide Mode:",
                             font=Theme.get_font('heading'),
                             bg=Theme.get_color('secondary'),
                             fg=Theme.get_color('text_primary'))
        mode_label.pack(anchor='w')
        
        self.hide_mode = tk.StringVar(value="text")
        
        text_radio = tk.Radiobutton(mode_frame,
                                   text="Hide Text",
                                   variable=self.hide_mode,
                                   value="text",
                                   bg=Theme.get_color('secondary'),
                                   fg=Theme.get_color('text_primary'),
                                   selectcolor=Theme.get_color('primary'),
                                   command=self.on_mode_change)
        text_radio.pack(anchor='w', pady=(5, 0))
        
        file_radio = tk.Radiobutton(mode_frame,
                                   text="Hide File",
                                   variable=self.hide_mode,
                                   value="file",
                                   bg=Theme.get_color('secondary'),
                                   fg=Theme.get_color('text_primary'),
                                   selectcolor=Theme.get_color('primary'),
                                   command=self.on_mode_change)
        file_radio.pack(anchor='w')
        
        # Text input area
        self.text_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        self.text_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('medium'), 
                            pady=Theme.get_spacing('medium'))
        
        text_label = tk.Label(self.text_frame,
                             text="Text to Hide:",
                             font=Theme.get_font('heading'),
                             bg=Theme.get_color('secondary'),
                             fg=Theme.get_color('text_primary'))
        text_label.pack(anchor='w')
        
        self.text_input = ModernText(self.text_frame, wrap='word', height=8)
        self.text_input.pack(fill='both', expand=True, pady=(5, 0))
        
        # File input area (initially hidden)
        self.file_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        
        file_label = tk.Label(self.file_frame,
                             text="File to Hide:",
                             font=Theme.get_font('heading'),
                             bg=Theme.get_color('secondary'),
                             fg=Theme.get_color('text_primary'))
        file_label.pack(anchor='w')
        
        file_select_frame = tk.Frame(self.file_frame, bg=Theme.get_color('secondary'))
        file_select_frame.pack(fill='x', pady=(5, 0))
        
        self.file_path_var = tk.StringVar()
        self.file_entry = ModernEntry(file_select_frame, textvariable=self.file_path_var, 
                                     placeholder="Select file to hide...")
        self.file_entry.pack(side='left', fill='x', expand=True)
        
        browse_button = ModernButton(file_select_frame,
                                   text="Browse",
                                   command=self.browse_file,
                                   style='secondary')
        browse_button.pack(side='right', padx=(10, 0))
        
        # Password input
        password_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        password_frame.pack(fill='x', padx=Theme.get_spacing('medium'), 
                           pady=Theme.get_spacing('medium'))
        
        password_label = tk.Label(password_frame,
                                 text="Password:",
                                 font=Theme.get_font('heading'),
                                 bg=Theme.get_color('secondary'),
                                 fg=Theme.get_color('text_primary'))
        password_label.pack(anchor='w')
        
        self.password_entry = ModernEntry(password_frame, show="*", 
                                         placeholder="Enter password for encryption...")
        self.password_entry.pack(fill='x', pady=(5, 0))
        
        # Output file
        output_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        output_frame.pack(fill='x', padx=Theme.get_spacing('medium'), 
                         pady=Theme.get_spacing('medium'))
        
        output_label = tk.Label(output_frame,
                               text="Output File:",
                               font=Theme.get_font('heading'),
                               bg=Theme.get_color('secondary'),
                               fg=Theme.get_color('text_primary'))
        output_label.pack(anchor='w')
        
        output_select_frame = tk.Frame(output_frame, bg=Theme.get_color('secondary'))
        output_select_frame.pack(fill='x', pady=(5, 0))
        
        base_name = os.path.splitext(os.path.basename(self.file_path))[0]
        self.output_path_var = tk.StringVar(value=f"{base_name}_hidden.jpg")
        self.output_entry = ModernEntry(output_select_frame, textvariable=self.output_path_var)
        self.output_entry.pack(side='left', fill='x', expand=True)
        
        save_button = ModernButton(output_select_frame,
                                  text="Save As",
                                  command=self.browse_output,
                                  style='secondary')
        save_button.pack(side='right', padx=(10, 0))
        
        # Hide button
        button_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        button_frame.pack(fill='x', padx=Theme.get_spacing('medium'), 
                         pady=Theme.get_spacing('medium'))
        
        self.hide_button = ModernButton(button_frame,
                                       text="Hide Data",
                                       command=self.hide_data,
                                       style='primary')
        self.hide_button.pack()
        
    def create_extract_tab(self, parent):
        """Create the extract data tab"""
        # Password input
        password_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        password_frame.pack(fill='x', padx=Theme.get_spacing('medium'), 
                           pady=Theme.get_spacing('medium'))
        
        password_label = tk.Label(password_frame,
                                 text="Password:",
                                 font=Theme.get_font('heading'),
                                 bg=Theme.get_color('secondary'),
                                 fg=Theme.get_color('text_primary'))
        password_label.pack(anchor='w')
        
        self.extract_password_entry = ModernEntry(password_frame, show="*", 
                                                 placeholder="Enter password for decryption...")
        self.extract_password_entry.pack(fill='x', pady=(5, 0))
        
        # Extract options
        options_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        options_frame.pack(fill='x', padx=Theme.get_spacing('medium'), 
                          pady=Theme.get_spacing('medium'))
        
        options_label = tk.Label(options_frame,
                                text="Extract Options:",
                                font=Theme.get_font('heading'),
                                bg=Theme.get_color('secondary'),
                                fg=Theme.get_color('text_primary'))
        options_label.pack(anchor='w')
        
        self.extract_as_file_var = tk.BooleanVar(value=False)
        extract_file_check = tk.Checkbutton(options_frame,
                                           text="Extract as file (if hidden data is a file)",
                                           variable=self.extract_as_file_var,
                                           bg=Theme.get_color('secondary'),
                                           fg=Theme.get_color('text_primary'),
                                           selectcolor=Theme.get_color('primary'))
        extract_file_check.pack(anchor='w', pady=(5, 0))
        
        # Extract button
        button_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        button_frame.pack(fill='x', padx=Theme.get_spacing('medium'), 
                         pady=Theme.get_spacing('medium'))
        
        self.extract_button = ModernButton(button_frame,
                                          text="Extract Data",
                                          command=self.extract_data,
                                          style='primary')
        self.extract_button.pack()
        
    def create_results_tab(self, parent):
        """Create the results tab"""
        # Results text area
        results_label = tk.Label(parent,
                                text="Operation Results:",
                                font=Theme.get_font('heading'),
                                bg=Theme.get_color('secondary'),
                                fg=Theme.get_color('text_primary'))
        results_label.pack(anchor='w', padx=Theme.get_spacing('medium'), 
                          pady=Theme.get_spacing('medium'))
        
        text_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        text_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('medium'), 
                       pady=Theme.get_spacing('medium'))
        
        self.result_text = ModernText(text_frame, wrap='word')
        self.result_text.pack(side='left', fill='both', expand=True)
        
        scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=self.result_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        # Clear button
        button_frame = tk.Frame(parent, bg=Theme.get_color('secondary'))
        button_frame.pack(fill='x', padx=Theme.get_spacing('medium'), 
                         pady=Theme.get_spacing('medium'))
        
        clear_button = ModernButton(button_frame,
                                   text="Clear Results",
                                   command=self.clear_results,
                                   style='secondary')
        clear_button.pack()
        
    def on_mode_change(self):
        """Handle mode change between text and file"""
        if self.hide_mode.get() == "text":
            self.file_frame.pack_forget()
            self.text_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('medium'), 
                                pady=Theme.get_spacing('medium'))
        else:
            self.text_frame.pack_forget()
            self.file_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('medium'), 
                                pady=Theme.get_spacing('medium'))
    
    def browse_file(self):
        """Browse for file to hide"""
        file_path = filedialog.askopenfilename(
            title="Select File to Hide",
            filetypes=[
                ("All Files", "*.*"),
                ("Text Files", "*.txt"),
                ("Image Files", "*.jpg *.jpeg *.png *.bmp *.gif"),
                ("Document Files", "*.pdf *.doc *.docx")
            ]
        )
        if file_path:
            self.file_path_var.set(file_path)
    
    def browse_output(self):
        """Browse for output file location"""
        file_path = filedialog.asksaveasfilename(
            title="Save Hidden File As",
            defaultextension=".jpg",
            filetypes=[
                ("JPEG Files", "*.jpg"),
                ("PNG Files", "*.png"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            self.output_path_var.set(file_path)
    
    def hide_data(self):
        """Hide data in the image"""
        if not self.password_entry.get():
            messagebox.showerror("Error", "Please enter a password.")
            return
        
        if self.hide_mode.get() == "text":
            if not self.text_input.get('1.0', tk.END).strip():
                messagebox.showerror("Error", "Please enter text to hide.")
                return
            
            text = self.text_input.get('1.0', tk.END).strip()
            result = self.analyzer.inject_text(
                self.file_path,
                text,
                self.output_path_var.get(),
                self.password_entry.get()
            )
        else:
            if not self.file_path_var.get():
                messagebox.showerror("Error", "Please select a file to hide.")
                return
            
            result = self.analyzer.inject_file(
                self.file_path,
                self.file_path_var.get(),
                self.output_path_var.get(),
                self.password_entry.get()
            )
        
        self.display_result(result, "Hide")
    
    def extract_data(self):
        """Extract hidden data from the image"""
        if not self.extract_password_entry.get():
            messagebox.showerror("Error", "Please enter a password.")
            return
        
        result = self.analyzer.extract_data(
            self.file_path,
            self.extract_password_entry.get(),
            self.extract_as_file_var.get()
        )
        
        self.display_result(result, "Extract")
    
    def display_result(self, result: Dict[str, Any], operation: str):
        """Display operation result"""
        if not self.result_text:
            return
        
        self.result_text.delete('1.0', tk.END)
        
        if result['success']:
            self.result_text.insert('1.0', f"✅ {operation} Operation Successful!\n\n")
            
            if operation == "Hide":
                self.result_text.insert(tk.END, f"Hidden data saved to: {result['output_file']}\n")
            else:  # Extract
                if result.get('data'):
                    self.result_text.insert(tk.END, f"Extracted text:\n{result['data']}\n")
                if result.get('extracted_file'):
                    self.result_text.insert(tk.END, f"Extracted file: {result['extracted_file']}\n")
        else:
            self.result_text.insert('1.0', f"❌ {operation} Operation Failed!\n\n")
            self.result_text.insert(tk.END, f"Error: {result['error']}\n")
    
    def clear_results(self):
        """Clear results text"""
        if self.result_text:
            self.result_text.delete('1.0', tk.END) 

class CryptoPopupWindow:
    """Popup window for crypto analysis with type selection and manual input"""
    
    def __init__(self, parent, file_path: str, crypto_analyzer: CryptoAnalyzer):
        self.parent = parent
        self.file_path = file_path
        self.crypto_analyzer = crypto_analyzer
        
        # Create popup window
        self.window = tk.Toplevel(parent)
        self.window.title("Crypto Analysis")
        self.window.geometry("600x500")
        self.window.resizable(True, True)
        self.window.transient(parent)
        self.window.grab_set()
        
        # Center the window
        self.center_window()
        
        # Setup window
        self.setup_window()
        self.create_widgets()
        
    def center_window(self):
        """Center the popup window on screen"""
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f"{width}x{height}+{x}+{y}")
        
    def setup_window(self):
        """Setup window properties"""
        # Apply theme
        self.window.configure(bg=Theme.get_color('primary'))
        
    def create_widgets(self):
        """Create all widgets"""
        # Header
        header_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        header_frame.pack(fill='x', padx=20, pady=(20, 10))
        
        title_label = tk.Label(
            header_frame,
            text="🔓 Crypto Analysis",
            font=Theme.get_font('title'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary')
        )
        title_label.pack()
        
        # Options frame
        options_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        options_frame.pack(fill='x', padx=20, pady=10)
        
        # Encryption type selection
        type_frame = tk.LabelFrame(
            options_frame,
            text="Select Encryption Type",
            font=Theme.get_font('heading'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            relief='solid',
            bd=1
        )
        type_frame.pack(fill='x', pady=(0, 15))
        
        self.encryption_type = tk.StringVar(value="auto")
        
        encryption_types = [
            ("Auto Detect", "auto"),
            ("Base64", "base64"),
            ("Base32", "base32"),
            ("Hexadecimal", "hex"),
            ("ROT13", "rot13"),
            ("Caesar Cipher", "caesar"),
            ("Binary", "binary"),
            ("Morse Code", "morse")
        ]
        
        for i, (text, value) in enumerate(encryption_types):
            rb = tk.Radiobutton(
                type_frame,
                text=text,
                variable=self.encryption_type,
                value=value,
                font=Theme.get_font('default'),
                fg=Theme.get_color('text_primary'),
                bg=Theme.get_color('primary'),
                selectcolor=Theme.get_color('secondary'),
                activebackground=Theme.get_color('primary'),
                activeforeground=Theme.get_color('text_primary'),
                command=self.on_encryption_type_change
            )
            rb.grid(row=i//2, column=i%2, sticky='w', padx=20, pady=5)
        
        # Input method selection
        input_frame = tk.LabelFrame(
            options_frame,
            text="Input Method",
            font=Theme.get_font('heading'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            relief='solid',
            bd=1
        )
        input_frame.pack(fill='x', pady=(0, 15))
        
        self.input_method = tk.StringVar(value="file")
        
        file_rb = tk.Radiobutton(
            input_frame,
            text="Analyze loaded file",
            variable=self.input_method,
            value="file",
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            selectcolor=Theme.get_color('secondary'),
            activebackground=Theme.get_color('primary'),
            activeforeground=Theme.get_color('text_primary'),
            command=self.on_input_method_change
        )
        file_rb.pack(anchor='w', padx=20, pady=5)
        
        manual_rb = tk.Radiobutton(
            input_frame,
            text="Enter text manually",
            variable=self.input_method,
            value="manual",
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            selectcolor=Theme.get_color('secondary'),
            activebackground=Theme.get_color('primary'),
            activeforeground=Theme.get_color('text_primary'),
            command=self.on_input_method_change
        )
        manual_rb.pack(anchor='w', padx=20, pady=5)
        
        # Manual input text area
        self.manual_input_frame = tk.Frame(input_frame, bg=Theme.get_color('primary'))
        self.manual_input_frame.pack(fill='x', padx=20, pady=(0, 10))
        
        manual_label = tk.Label(
            self.manual_input_frame,
            text="Enter text to decode:",
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary')
        )
        manual_label.pack(anchor='w', pady=(0, 5))
        
        self.manual_text = tk.Text(
            self.manual_input_frame,
            height=4,
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('secondary'),
            insertbackground=Theme.get_color('text_primary'),
            relief='solid',
            bd=1,
            wrap='word'
        )
        self.manual_text.pack(fill='x', pady=(0, 5))
        
        # Scrollbar for manual text
        manual_scrollbar = tk.Scrollbar(
            self.manual_input_frame,
            orient='vertical',
            command=self.manual_text.yview
        )
        manual_scrollbar.pack(side='right', fill='y')
        self.manual_text.configure(yscrollcommand=manual_scrollbar.set)
        
        # Initially hide manual input
        self.manual_input_frame.pack_forget()
        
        # Caesar shift frame (only for Caesar cipher)
        self.caesar_frame = tk.Frame(input_frame, bg=Theme.get_color('primary'))
        self.caesar_frame.pack(fill='x', padx=20, pady=(0, 10))
        
        caesar_label = tk.Label(
            self.caesar_frame,
            text="Caesar Shift (leave empty for auto-detect):",
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary')
        )
        caesar_label.pack(anchor='w', pady=(0, 5))
        
        self.caesar_shift_var = tk.StringVar()
        caesar_entry = tk.Entry(
            self.caesar_frame,
            textvariable=self.caesar_shift_var,
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('secondary'),
            insertbackground=Theme.get_color('text_primary'),
            relief='solid',
            bd=1
        )
        caesar_entry.pack(fill='x', pady=(0, 5))
        
        # Initially hide caesar frame
        self.caesar_frame.pack_forget()
        
        # Buttons
        button_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        button_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        analyze_button = tk.Button(
            button_frame,
            text="🔓 Analyze",
            font=Theme.get_font('button'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('accent'),
            activebackground=Theme.get_color('accent_hover'),
            activeforeground=Theme.get_color('text_primary'),
            relief='flat',
            bd=0,
            padx=20,
            pady=10,
            cursor='hand2',
            command=self.analyze
        )
        analyze_button.pack(side='left', padx=(0, 10))
        
        cancel_button = tk.Button(
            button_frame,
            text="❌ Cancel",
            font=Theme.get_font('button'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('secondary'),
            activebackground=Theme.get_color('button_hover'),
            activeforeground=Theme.get_color('text_primary'),
            relief='flat',
            bd=0,
            padx=20,
            pady=10,
            cursor='hand2',
            command=self.window.destroy
        )
        cancel_button.pack(side='left')
        
        # Results area
        results_frame = tk.LabelFrame(
            self.window,
            text="Results",
            font=Theme.get_font('heading'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            relief='solid',
            bd=1
        )
        results_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        self.results_text = tk.Text(
            results_frame,
            font=Theme.get_font('monospace'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('secondary'),
            insertbackground=Theme.get_color('text_primary'),
            relief='flat',
            bd=0,
            wrap='word',
            state='disabled'
        )
        self.results_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Scrollbar for results
        results_scrollbar = tk.Scrollbar(
            results_frame,
            orient='vertical',
            command=self.results_text.yview
        )
        results_scrollbar.pack(side='right', fill='y')
        self.results_text.configure(yscrollcommand=results_scrollbar.set)
        
    def on_input_method_change(self):
        """Handle input method change"""
        if self.input_method.get() == "manual":
            self.manual_input_frame.pack(fill='x', padx=20, pady=(0, 10))
        else:
            self.manual_input_frame.pack_forget()
            
    def on_encryption_type_change(self):
        """Handle encryption type change"""
        if self.encryption_type.get() == "caesar":
            self.caesar_frame.pack(fill='x', padx=20, pady=(0, 10))
        else:
            self.caesar_frame.pack_forget()
            
    def analyze(self):
        """Perform crypto analysis"""
        try:
            # Get input text
            if self.input_method.get() == "file":
                if not self.file_path:
                    messagebox.showerror("Error", "No file selected!")
                    return
                    
                with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().strip()
                    
                if not content:
                    messagebox.showerror("Error", "File appears to be empty!")
                    return
            else:
                content = self.manual_text.get("1.0", tk.END).strip()
                if not content:
                    messagebox.showerror("Error", "Please enter text to decode!")
                    return
            
            # Get encryption type
            encryption_type = self.encryption_type.get()
            
            # Perform analysis
            if encryption_type == "auto":
                result = self.crypto_analyzer.auto_decode(content)
            else:
                # Get specific method
                method_map = {
                    "base64": self.crypto_analyzer.decode_base64,
                    "base32": self.crypto_analyzer.decode_base32,
                    "hex": self.crypto_analyzer.decode_hex,
                    "rot13": self.crypto_analyzer.decode_rot13,
                    "binary": self.crypto_analyzer.decode_binary,
                    "morse": self.crypto_analyzer.decode_morse,
                    "caesar": lambda x: self.crypto_analyzer.decode_caesar(x, self._get_caesar_shift())
                }
                
                method = method_map.get(encryption_type)
                if method:
                    result = method(content)
                else:
                    result = {"success": False, "error": "Unknown encryption type"}
            
            # Display results
            self.display_results(result, content, encryption_type)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
            
    def _get_caesar_shift(self) -> Optional[int]:
        """Get Caesar shift value from entry"""
        shift_text = self.caesar_shift_var.get().strip()
        if shift_text:
            try:
                return int(shift_text)
            except ValueError:
                return None
        return None
        
    def display_results(self, result: Dict[str, Any], original_content: str, encryption_type: str):
        """Display analysis results"""
        self.results_text.config(state='normal')
        self.results_text.delete("1.0", tk.END)
        
        output = []
        output.append("🔓 Crypto Analysis Results")
        output.append("=" * 50)
        output.append("")
        output.append(f"📄 Original Content: {original_content[:100]}{'...' if len(original_content) > 100 else ''}")
        output.append(f"🔧 Method: {encryption_type.upper()}")
        output.append("")
        
        if result.get('success'):
            if encryption_type == "auto":
                # Auto-decode results
                if result.get('best_match'):
                    best = result['best_match']
                    output.append("🎯 Best Match:")
                    output.append("-" * 15)
                    output.append(f"Encoding: {best['encoding'].upper()}")
                    if 'shift' in best:
                        output.append(f"Shift: {best['shift']}")
                    output.append(f"Decoded: {best['decoded']}")
                    output.append("")
                
                # Show all results
                output.append("📋 All Decode Attempts:")
                output.append("-" * 25)
                
                for i, attempt in enumerate(result.get('results', []), 1):
                    output.append(f"{i}. {attempt['encoding'].upper()}")
                    if 'shift' in attempt:
                        output.append(f"   Shift: {attempt['shift']}")
                    output.append(f"   Result: {attempt['decoded']}")
                    output.append("")
                    
                # Search for flags
                all_decoded_text = ""
                for attempt in result.get('results', []):
                    all_decoded_text += attempt['decoded'] + " "
                
                flags_found = self.crypto_analyzer.search_for_flags(all_decoded_text)
                if flags_found:
                    output.append("🚩 Potential Flags Found:")
                    output.append("-" * 25)
                    for flag in flags_found:
                        output.append(f"  • {flag}")
                    output.append("")
            else:
                # Single method result
                output.append("✅ Decode Result:")
                output.append("-" * 15)
                output.append(f"Encoding: {result.get('encoding', encryption_type).upper()}")
                if 'shift' in result:
                    output.append(f"Shift: {result['shift']}")
                output.append(f"Decoded: {result['decoded']}")
                output.append("")
                
                # Search for flags
                flags_found = self.crypto_analyzer.search_for_flags(result['decoded'])
                if flags_found:
                    output.append("🚩 Potential Flags Found:")
                    output.append("-" * 25)
                    for flag in flags_found:
                        output.append(f"  • {flag}")
                    output.append("")
        else:
            output.append("❌ Decode Failed:")
            output.append("-" * 15)
            output.append(f"Error: {result.get('error', 'Unknown error')}")
            output.append("")
            output.append("💡 Tips:")
            output.append("• Check if the content is properly formatted")
            output.append("• Try a different encryption type")
            output.append("• Some content may need preprocessing")
        
        self.results_text.insert("1.0", "\n".join(output))
        self.results_text.config(state='disabled')