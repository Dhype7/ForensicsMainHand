"""
Photo Analyzer Main Window Module
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from PIL import Image, ImageTk
import os
import threading
from typing import Optional, Callable, Any, Dict, Union
import base64
import json
import webbrowser
import binascii

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

class MainWindow(tk.Frame):
    """Main application frame for Photo Analyzer"""
    def __init__(self, parent, back_callback: Callable[[], None], theme_change_callback=None, theme_var=None, *args, **kwargs) -> None:
        super().__init__(parent, *args, **kwargs)
        self.back_callback = back_callback
        self.theme_change_callback = theme_change_callback
        self.selected_file_path: Optional[str] = None
        self.image_label: Optional[tk.Label] = None
        self.result_text: Optional[tk.Text] = None
        self.status_bar: Optional[StatusBar] = None
        self.file_selector: Optional[FileSelector] = None
        self.main_frame: Optional[tk.Frame] = None
        if theme_var is None:
            self.theme_var = tk.StringVar(value=Theme.get_current_theme())
        else:
            self.theme_var = theme_var
        self.theme_var.trace_add('write', self._on_external_theme_change)
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
        self.create_widgets()
        self.setup_layout()
        self.apply_theme_to_all_widgets()

    def _on_external_theme_change(self, *args):
        # Called when the global theme_var changes
        if self.theme_var.get() != Theme.get_current_theme():
            Theme.set_theme(self.theme_var.get())
        self.apply_theme_to_all_widgets()
        # If there is a theme dropdown, update its value
        for child in self.winfo_children():
            if isinstance(child, ttk.Combobox):
                child.set(self.theme_var.get())

    def create_widgets(self):
        # Main container
        self.main_frame = tk.Frame(self, bg=Theme.get_color('primary'))
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
        title_label = tk.Label(header_frame, text=Settings.APP_NAME, font=Theme.get_font('title'), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
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
        update_widget_colors(self)
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
        if self.theme_change_callback:
            self.theme_change_callback()
        else:
            Theme.set_theme(self.theme_var.get())
            self.apply_theme_to_all_widgets()
            self.refresh_result_area_theme()
        self.update_idletasks()

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
        self.clipboard_clear()
        self.clipboard_append(self.result_text.get('1.0', 'end').strip())

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
        self.loading_overlay = tk.Frame(self, bg='black')
        
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
            self.update_idletasks()
            
            # Start spinner animation
            self.animate_spinner()
        
    def hide_loading(self):
        """Hide loading overlay"""
        if self.loading_overlay:
            self.loading_overlay.place_forget()
            if self.loading_after_id:
                self.after_cancel(self.loading_after_id)
                self.loading_after_id = None
                
    def animate_spinner(self):
        """Animate the spinner"""
        if (self.loading_spinner and self.loading_overlay and 
            self.loading_overlay.winfo_viewable()):
            self.spinner_index = (self.spinner_index + 1) % len(self.spinner_chars)
            self.loading_spinner.config(text=self.spinner_chars[self.spinner_index])
            self.loading_after_id = self.after(100, self.animate_spinner)
            
    def run_analysis(self, analysis_func: Callable[..., str], *args: Any):
        """Run analysis in separate thread with loading indicator"""
        def run():
            try:
                result = analysis_func(*args)
                self.after(0, self.display_results, result)
            except Exception as e:
                self.after(0, self.display_error, str(e))
            finally:
                self.after(0, self.hide_loading)
        
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
            self.display_error("No file loaded.")
            return
        # Set CTF feature buttons for EXIF tool
        self.update_ctf_feature_buttons([
            ("Show Suspicious Lines", self.exif_show_suspicious_lines),
            ("Deep Scan", self.exif_deep_scan),
            ("Copy All", self.exif_copy_all),
        ])
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

    def exif_show_suspicious_lines(self):
        """Show suspicious or unfamiliar EXIF lines that might contain hidden data."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        exif_data = self.exif_analyzer.extract_exif(self.selected_file_path)
        if not exif_data:
            self.display_error("No EXIF data found in the image.")
            return
        
        # Define suspicious patterns and uncommon fields
        suspicious_patterns = [
            'Unknown_', 'UserComment', 'XPComment', 'XPSubject', 'XPTitle', 'XPKeywords',
            'XPAuthor', 'XPArtist', 'XPCopyright', 'XPSoftware', 'XPDescription',
            'ImageUniqueID', 'ImageID', 'DocumentName', 'ImageDescription', 'Artist',
            'Copyright', 'Software', 'HostComputer', 'ColorProfile', 'ICC_Profile',
            'InteroperabilityIndex', 'InteroperabilityVersion', 'RelatedImageFileFormat',
            'RelatedImageWidth', 'RelatedImageLength', 'ImageSourceData', 'ImageHistory',
            'TIFFEPStandardID', 'TIFFEPStandardID', 'TIFFEPStandardID', 'TIFFEPStandardID'
        ]
        
        suspicious_lines = []
        for key, value in exif_data.items():
            # Check if key matches suspicious patterns
            is_suspicious = any(pattern in key for pattern in suspicious_patterns)
            
            # Check if value contains suspicious content
            value_str = str(value).lower()
            suspicious_content = any(term in value_str for term in [
                'flag', 'ctf', 'secret', 'hidden', 'password', 'key', 'encrypt',
                'stego', 'data', 'message', 'note', 'comment', 'hint', 'clue'
            ])
            
            # Check for base64-like content
            import re
            base64_pattern = r'^[A-Za-z0-9+/]{20,}={0,2}$'
            is_base64 = bool(re.match(base64_pattern, str(value)))
            
            # Check for hex-like content
            hex_pattern = r'^[0-9a-fA-F]{10,}$'
            is_hex = bool(re.match(hex_pattern, str(value)))
            
            if is_suspicious or suspicious_content or is_base64 or is_hex:
                suspicious_lines.append({
                    'key': key,
                    'value': str(value),
                    'reason': []
                })
                
                if is_suspicious:
                    suspicious_lines[-1]['reason'].append('Uncommon field')
                if suspicious_content:
                    suspicious_lines[-1]['reason'].append('Suspicious content')
                if is_base64:
                    suspicious_lines[-1]['reason'].append('Base64-like')
                if is_hex:
                    suspicious_lines[-1]['reason'].append('Hex-like')
        
        if suspicious_lines:
            # Format the output
            output = "🔍 Suspicious EXIF Lines Found:\n\n"
            for i, line in enumerate(suspicious_lines, 1):
                output += f"{i}. {line['key']}:\n"
                output += f"   Value: {line['value']}\n"
                output += f"   Reasons: {', '.join(line['reason'])}\n\n"
            
            # Copy to clipboard
            self.clipboard_clear()
            clipboard_text = '\n'.join([f"{line['key']}: {line['value']}" for line in suspicious_lines])
            self.clipboard_append(clipboard_text)
            
            output += f"✅ Copied {len(suspicious_lines)} suspicious lines to clipboard."
            self.display_results(output)
        else:
            self.display_results("No suspicious EXIF lines found.")

    def exif_deep_scan(self):
        """Perform a deep scan showing every possible EXIF field."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        exif_data = self.exif_analyzer.extract_exif(self.selected_file_path)
        if not exif_data:
            self.display_error("No EXIF data found in the image.")
            return
        
        # Get all EXIF data including raw tag IDs
        try:
            from PIL import Image, ExifTags
            with Image.open(self.selected_file_path) as image:
                raw_exif = image.getexif()
                if raw_exif:
                    # Include both named and unnamed tags
                    deep_data = {}
                    
                    # Add named tags
                    for tag_id, value in raw_exif.items():
                        tag_name = ExifTags.TAGS.get(tag_id, f"Unknown_{tag_id}")
                        deep_data[tag_name] = str(value)
                    
                    # Add any additional metadata
                    if hasattr(image, 'info'):
                        for key, value in image.info.items():
                            if key not in deep_data:
                                deep_data[f"Info_{key}"] = str(value)
                    
                    # Format the deep scan results
                    output = "🔬 Deep EXIF Scan Results:\n\n"
                    output += f"Total Fields Found: {len(deep_data)}\n\n"
                    
                    # Group by categories
                    categories = {
                        'Device & Software': [],
                        'Date & Time': [],
                        'Image Properties': [],
                        'Camera Settings': [],
                        'GPS Data': [],
                        'Unknown/Uncommon': [],
                        'Other': []
                    }
                    
                    for key, value in deep_data.items():
                        key_lower = key.lower()
                        if any(term in key_lower for term in ['make', 'model', 'software', 'artist', 'copyright']):
                            categories['Device & Software'].append((key, value))
                        elif any(term in key_lower for term in ['date', 'time']):
                            categories['Date & Time'].append((key, value))
                        elif any(term in key_lower for term in ['width', 'height', 'resolution', 'color', 'orientation']):
                            categories['Image Properties'].append((key, value))
                        elif any(term in key_lower for term in ['exposure', 'iso', 'focal', 'flash', 'aperture']):
                            categories['Camera Settings'].append((key, value))
                        elif 'gps' in key_lower:
                            categories['GPS Data'].append((key, value))
                        elif key.startswith('Unknown_') or any(term in key_lower for term in ['xp', 'interop', 'tiff']):
                            categories['Unknown/Uncommon'].append((key, value))
                        else:
                            categories['Other'].append((key, value))
                    
                    # Output each category
                    for category, items in categories.items():
                        if items:
                            output += f"--- {category} ({len(items)} fields) ---\n"
                            for key, value in items:
                                output += f"  {key}: {value}\n"
                            output += "\n"
                    
                    # Copy to clipboard
                    self.clipboard_clear()
                    clipboard_text = '\n'.join([f"{key}: {value}" for key, value in deep_data.items()])
                    self.clipboard_append(clipboard_text)
                    
                    output += f"✅ Copied {len(deep_data)} EXIF fields to clipboard."
                    self.display_results(output)
                else:
                    self.display_results("No raw EXIF data found in the image.")
        except Exception as e:
            self.display_error(f"Error during deep scan: {str(e)}")

    def exif_copy_all(self):
        """Copy all EXIF metadata to clipboard."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        exif_data = self.exif_analyzer.extract_exif(self.selected_file_path)
        if not exif_data:
            self.display_error("No EXIF data found in the image.")
            return
        
        # Format all EXIF data
        formatted_lines = []
        for key, value in exif_data.items():
            formatted_lines.append(f"{key}: {value}")
        
        # Copy to clipboard
        self.clipboard_clear()
        clipboard_text = '\n'.join(formatted_lines)
        self.clipboard_append(clipboard_text)
        
        output = f"✅ Copied {len(exif_data)} EXIF fields to clipboard.\n\n"
        output += "📋 EXIF Data:\n"
        output += "-" * 20 + "\n"
        output += clipboard_text
        self.display_results(output)

    def analyze_location(self):
        """Analyze location data"""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        # Set CTF feature buttons for Location tool
        self.update_ctf_feature_buttons([
            ("Show on Map", self.location_show_on_map),
            ("Reverse Geocode", self.location_reverse_geocode),
            ("Copy GPS Coordinates", self.location_copy_gps),
        ])
        self.run_analysis(self._analyze_location_thread)

    def location_show_on_map(self):
        """Open GPS coordinates in browser map if available."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        result = self.location_analyzer.analyze_location(self.selected_file_path)
        coords = result.get('coordinates')
        if coords and coords.get('latitude') and coords.get('longitude'):
            url = f"https://www.google.com/maps/search/?api=1&query={coords['latitude']},{coords['longitude']}"
            import webbrowser
            webbrowser.open(url)
            self.display_results(f"✅ Opened coordinates in Google Maps:\n\n📍 Coordinates: {coords['latitude']}, {coords['longitude']}\n🌐 URL: {url}")
        else:
            self.display_error("No GPS coordinates found in the file.")

    def location_reverse_geocode(self):
        """Reverse geocode coordinates to get address information."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        # First, let's check what GPS data we can extract
        gps_data = self.location_analyzer.extract_gps_data(self.selected_file_path)
        if not gps_data:
            self.display_error("No GPS data found in the file.")
            return
        
        # Show extracted GPS data for debugging
        debug_output = "🔍 GPS Data Found:\n"
        debug_output += "-" * 20 + "\n"
        for key, value in gps_data.items():
            debug_output += f"{key}: {value}\n"
        debug_output += "\n"
        
        result = self.location_analyzer.analyze_location(self.selected_file_path)
        coords = result.get('coordinates')
        
        if not coords or not coords.get('latitude') or not coords.get('longitude'):
            debug_output += "❌ Could not extract valid coordinates from GPS data.\n"
            debug_output += "This might be due to:\n"
            debug_output += "• GPS data format not supported\n"
            debug_output += "• Missing latitude/longitude information\n"
            debug_output += "• Coordinate conversion error\n"
            self.display_error(debug_output)
            return
        
        try:
            # Get coordinates as tuple
            lat = coords['latitude']
            lon = coords['longitude']
            coordinates = (lat, lon)
            
            # Display coordinates being used for debugging
            output = debug_output + f"🌍 Reverse Geocoding for coordinates: {lat}, {lon}\n\n"
            output += "⏳ Requesting address information...\n\n"
            self.display_results(output)
            
            # Perform reverse geocoding
            location_info = self.location_analyzer.reverse_geocode(coordinates)
            
            if location_info:
                output = "🌍 Reverse Geocoding Results:\n\n"
                output += f"📍 Coordinates: {lat}, {lon}\n\n"
                output += "🏠 Address Information:\n"
                output += "-" * 30 + "\n"
                output += f"Full Address: {location_info.get('address', 'N/A')}\n\n"
                
                # Parse address components
                raw_data = location_info.get('raw', {})
                address_components = raw_data.get('address', {})
                
                if address_components:
                    output += "📍 Address Components:\n"
                    output += "-" * 25 + "\n"
                    
                    # Common address fields
                    address_fields = {
                        'house_number': 'House Number',
                        'road': 'Street',
                        'suburb': 'Suburb',
                        'city': 'City',
                        'state': 'State/Province',
                        'postcode': 'Postal Code',
                        'country': 'Country',
                        'neighbourhood': 'Neighbourhood',
                        'quarter': 'Quarter',
                        'district': 'District',
                        'county': 'County',
                        'region': 'Region'
                    }
                    
                    for field, label in address_fields.items():
                        if field in address_components:
                            output += f"{label}: {address_components[field]}\n"
                    
                    output += "\n"
                
                # Copy to clipboard
                self.clipboard_clear()
                clipboard_text = f"Coordinates: {lat}, {lon}\nAddress: {location_info.get('address', 'N/A')}"
                self.clipboard_append(clipboard_text)
                
                output += "✅ Address information copied to clipboard."
                self.display_results(output)
            else:
                error_msg = "Reverse geocoding failed. This could be due to:\n"
                error_msg += "• Invalid coordinates\n"
                error_msg += "• Internet connection issues\n"
                error_msg += "• Geocoding service being temporarily unavailable\n"
                error_msg += "• Rate limiting from the geocoding service\n\n"
                error_msg += f"Coordinates attempted: {lat}, {lon}"
                self.display_error(error_msg)
                
        except Exception as e:
            error_msg = f"Error during reverse geocoding: {str(e)}\n\n"
            error_msg += "This might be due to:\n"
            error_msg += "• Missing geopy library (pip install geopy)\n"
            error_msg += "• Network connectivity issues\n"
            error_msg += "• Invalid coordinates format"
            self.display_error(error_msg)

    def location_copy_gps(self):
        """Copy GPS coordinates from EXIF/location data to clipboard."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        result = self.location_analyzer.analyze_location(self.selected_file_path)
        coords = result.get('coordinates')
        if coords and coords.get('latitude') and coords.get('longitude'):
            coord_str = f"{coords['latitude']}, {coords['longitude']}"
            self.clipboard_clear()
            self.clipboard_append(coord_str)
            
            output = f"✅ Copied GPS coordinates to clipboard:\n\n"
            output += f"📍 Coordinates: {coord_str}\n\n"
            
            # Add additional GPS info if available
            if result.get('altitude'):
                output += f"🏔️ Altitude: {result['altitude']} meters\n"
            
            if result.get('google_maps_link'):
                output += f"🌐 Google Maps: {result['google_maps_link']}\n"
            
            self.display_results(output)
        else:
            self.display_error("No GPS coordinates found in the file.")

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
        # Set CTF feature buttons for Steganography tool
        self.update_ctf_feature_buttons([
            ("Try Common Passwords", self.try_common_steghide_passwords),
            ("Run LSB Analysis", self.run_lsb_analysis),
            ("Extract Hidden Data", self.extract_hidden_data),
        ])
        # Create steganography window
        stego_window = SteganographyWindow(self, self.selected_file_path, 
                                         self.steganography_analyzer)

    def try_common_steghide_passwords(self):
        """Try common steghide passwords and show results."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        common_passwords = ["password", "1234", "ctf", "flag", "letmein", "root", "admin", "secret", "toor", "guest", "test", "qwerty", "abc123", "iloveyou", "1q2w3e4r"]
        found = []
        for pwd in common_passwords:
            result = self.steganography_analyzer.extract_data(self.selected_file_path, pwd, extract_as_file=False)
            if result.get('success') and result.get('data'):
                found.append((pwd, result['data'][:100]))
        if found:
            msg = '\n\n'.join([f"Password: {pwd}\nData: {data}" for pwd, data in found])
            messagebox.showinfo("Steghide Passwords Found", f"Found {len(found)} possible passwords:\n\n{msg}")
        else:
            messagebox.showinfo("No Data", "No hidden data found with common passwords.")

    def run_lsb_analysis(self):
        """Run LSB steganalysis using Zsteg if available."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        if not self.zsteg_analyzer.check_zsteg_available():
            messagebox.showinfo("Not Available", "Zsteg is not installed. Please install zsteg for LSB analysis.")
            return
        result = self.zsteg_analyzer.basic_scan(self.selected_file_path)
        if not result.get('success'):
            messagebox.showerror("LSB Analysis Failed", result.get('error', 'Unknown error'))
            return
        findings = result.get('findings', [])
        if findings:
            messagebox.showinfo("LSB Analysis Results", f"Found {len(findings)} possible LSB findings:\n\n" + '\n'.join(str(f) for f in findings[:10]) + ("\n..." if len(findings) > 10 else ""))
        else:
            messagebox.showinfo("No LSB Data", "No LSB steganography found.")

    def extract_hidden_data(self):
        """Extract hidden data using steghide (prompt for passphrase)."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        passphrase = simpledialog.askstring("Passphrase", "Enter passphrase for extraction (leave blank if none):", show='*')
        if passphrase is None:
            return
        result = self.steganography_analyzer.extract_data(self.selected_file_path, passphrase, extract_as_file=False)
        if result.get('success') and result.get('data'):
            self.clipboard_clear()
            self.clipboard_append(result['data'])
            messagebox.showinfo("Extracted", f"Extracted hidden text and copied to clipboard.\n\n{result['data'][:500]}" + ("\n..." if len(result['data']) > 500 else ""))
        elif result.get('success') and result.get('extracted_file'):
            messagebox.showinfo("Extracted", f"Extracted hidden file: {result['extracted_file']}")
        else:
            messagebox.showinfo("No Data", result.get('error', 'No hidden data found or extraction failed.'))

    def analyze_metadata(self):
        """Analyze metadata with ExifTool"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        # Set CTF feature buttons for Metadata tool
        self.update_ctf_feature_buttons([
            ("Show Suspicious Fields", self.metadata_show_suspicious_fields),
            ("Deep Scan", self.metadata_deep_scan),
            ("Copy All", self.metadata_copy_all),
        ])
        self.run_analysis(self._analyze_metadata_thread)

    def metadata_show_suspicious_fields(self):
        """Show suspicious or unfamiliar metadata fields that might contain hidden data."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        result = self.metadata_analyzer.analyze_file(self.selected_file_path)
        if not result.get('success'):
            self.display_error("No metadata found in the file.")
            return
        
        metadata = result.get('metadata', {})
        if not metadata:
            self.display_error("No metadata found in the file.")
            return
        
        # Define suspicious patterns and uncommon fields
        suspicious_patterns = [
            'Unknown_', 'UserComment', 'XPComment', 'XPSubject', 'XPTitle', 'XPKeywords',
            'XPAuthor', 'XPArtist', 'XPCopyright', 'XPSoftware', 'XPDescription',
            'ImageUniqueID', 'ImageID', 'DocumentName', 'ImageDescription', 'Artist',
            'Copyright', 'Software', 'HostComputer', 'ColorProfile', 'ICC_Profile',
            'InteroperabilityIndex', 'InteroperabilityVersion', 'RelatedImageFileFormat',
            'RelatedImageWidth', 'RelatedImageLength', 'ImageSourceData', 'ImageHistory',
            'TIFFEPStandardID', 'TIFFEPStandardID', 'TIFFEPStandardID', 'TIFFEPStandardID',
            'Creator', 'Producer', 'Subject', 'Keywords', 'Description', 'Title',
            'Author', 'CreatorTool', 'ModifyDate', 'CreateDate', 'MetadataDate'
        ]
        
        suspicious_fields = []
        for key, value in metadata.items():
            # Check if key matches suspicious patterns
            is_suspicious = any(pattern in key for pattern in suspicious_patterns)
            
            # Check if value contains suspicious content
            value_str = str(value).lower()
            suspicious_content = any(term in value_str for term in [
                'flag', 'ctf', 'secret', 'hidden', 'password', 'key', 'encrypt',
                'stego', 'data', 'message', 'note', 'comment', 'hint', 'clue'
            ])
            
            # Check for base64-like content
            import re
            base64_pattern = r'^[A-Za-z0-9+/]{20,}={0,2}$'
            is_base64 = bool(re.match(base64_pattern, str(value)))
            
            # Check for hex-like content
            hex_pattern = r'^[0-9a-fA-F]{10,}$'
            is_hex = bool(re.match(hex_pattern, str(value)))
            
            if is_suspicious or suspicious_content or is_base64 or is_hex:
                suspicious_fields.append({
                    'key': key,
                    'value': str(value),
                    'reason': []
                })
                
                if is_suspicious:
                    suspicious_fields[-1]['reason'].append('Uncommon field')
                if suspicious_content:
                    suspicious_fields[-1]['reason'].append('Suspicious content')
                if is_base64:
                    suspicious_fields[-1]['reason'].append('Base64-like')
                if is_hex:
                    suspicious_fields[-1]['reason'].append('Hex-like')
        
        if suspicious_fields:
            # Format the output
            output = "🔍 Suspicious Metadata Fields Found:\n\n"
            for i, field in enumerate(suspicious_fields, 1):
                output += f"{i}. {field['key']}:\n"
                output += f"   Value: {field['value']}\n"
                output += f"   Reasons: {', '.join(field['reason'])}\n\n"
            
            # Copy to clipboard
            self.clipboard_clear()
            clipboard_text = '\n'.join([f"{field['key']}: {field['value']}" for field in suspicious_fields])
            self.clipboard_append(clipboard_text)
            
            output += f"✅ Copied {len(suspicious_fields)} suspicious fields to clipboard."
            self.display_results(output)
        else:
            self.display_results("No suspicious metadata fields found.")

    def metadata_deep_scan(self):
        """Perform a deep scan showing every possible metadata field."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        result = self.metadata_analyzer.analyze_file(self.selected_file_path)
        if not result.get('success'):
            self.display_error("No metadata found in the file.")
            return
        
        metadata = result.get('metadata', {})
        if not metadata:
            self.display_error("No metadata found in the file.")
            return
        
        # Format the deep scan results
        output = "🔬 Deep Metadata Scan Results:\n\n"
        output += f"Total Fields Found: {len(metadata)}\n\n"
        
        # Group by categories
        categories = {
            'Device & Software': [],
            'Date & Time': [],
            'Image Properties': [],
            'Camera Settings': [],
            'Document Info': [],
            'Unknown/Uncommon': [],
            'Other': []
        }
        
        for key, value in metadata.items():
            key_lower = key.lower()
            if any(term in key_lower for term in ['make', 'model', 'software', 'artist', 'copyright', 'creator']):
                categories['Device & Software'].append((key, value))
            elif any(term in key_lower for term in ['date', 'time', 'create', 'modify']):
                categories['Date & Time'].append((key, value))
            elif any(term in key_lower for term in ['width', 'height', 'resolution', 'color', 'orientation', 'size']):
                categories['Image Properties'].append((key, value))
            elif any(term in key_lower for term in ['exposure', 'iso', 'focal', 'flash', 'aperture', 'camera']):
                categories['Camera Settings'].append((key, value))
            elif any(term in key_lower for term in ['title', 'subject', 'description', 'keywords', 'author', 'document']):
                categories['Document Info'].append((key, value))
            elif key.startswith('Unknown_') or any(term in key_lower for term in ['xp', 'interop', 'tiff']):
                categories['Unknown/Uncommon'].append((key, value))
            else:
                categories['Other'].append((key, value))
        
        # Output each category
        for category, items in categories.items():
            if items:
                output += f"--- {category} ({len(items)} fields) ---\n"
                for key, value in items:
                    output += f"  {key}: {value}\n"
                output += "\n"
        
        # Copy to clipboard
        self.clipboard_clear()
        clipboard_text = '\n'.join([f"{key}: {value}" for key, value in metadata.items()])
        self.clipboard_append(clipboard_text)
        
        output += f"✅ Copied {len(metadata)} metadata fields to clipboard.\n\n"
        output += "📋 Metadata:\n"
        output += "-" * 20 + "\n"
        output += clipboard_text
        self.display_results(output)

    def metadata_copy_all(self):
        """Copy all metadata to clipboard."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        result = self.metadata_analyzer.analyze_file(self.selected_file_path)
        if not result.get('success'):
            self.display_error("No metadata found in the file.")
            return
        
        metadata = result.get('metadata', {})
        if not metadata:
            self.display_error("No metadata found in the file.")
            return
        
        # Format all metadata
        formatted_lines = []
        for key, value in metadata.items():
            formatted_lines.append(f"{key}: {value}")
        
        # Copy to clipboard
        self.clipboard_clear()
        clipboard_text = '\n'.join(formatted_lines)
        self.clipboard_append(clipboard_text)
        
        output = f"✅ Copied {len(metadata)} metadata fields to clipboard.\n\n"
        output += "📋 Metadata:\n"
        output += "-" * 20 + "\n"
        output += clipboard_text
        self.display_results(output)

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
        # Set CTF feature buttons for Strings tool
        self.update_ctf_feature_buttons([
            ("Show All Lines", self.strings_show_all_lines),
            ("Use Grep", self.strings_use_grep),
            ("Show URLs", self.show_urls_from_strings),
        ])
        self.run_analysis(self._analyze_strings_thread)

    def strings_show_all_lines(self):
        """Show all extracted strings in the main output box."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        result = self.string_analyzer.extract_strings(self.selected_file_path)
        if not result.get('success'):
            self.display_error("Failed to extract strings from file.")
            return
        
        all_strings = result.get('strings', [])
        if not all_strings:
            self.display_error("No strings found in the file.")
            return
        
        # Format the output
        output = "🔤 All Extracted Strings:\n\n"
        output += f"Total Strings Found: {len(all_strings)}\n\n"
        output += "📋 Strings:\n"
        output += "-" * 20 + "\n"
        
        # Show all strings with line numbers
        for i, string in enumerate(all_strings, 1):
            output += f"{i:4d}. {string}\n"
        
        # Copy to clipboard
        self.clipboard_clear()
        clipboard_text = '\n'.join(all_strings)
        self.clipboard_append(clipboard_text)
        
        output += f"\n✅ Copied {len(all_strings)} strings to clipboard."
        self.display_results(output)

    def strings_use_grep(self):
        """Search through extracted strings using grep-like functionality."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        # Get search pattern from user
        search_pattern = simpledialog.askstring("Grep Search", 
                                               "Enter search pattern (supports regex):\n\nExamples:\n• flag{.*}\n• password\n• admin\n• [0-9]{3,}\n• http",
                                               initialvalue="flag{")
        
        if not search_pattern:  # User cancelled or entered empty string
            return
        
        # Extract strings
        result = self.string_analyzer.extract_strings(self.selected_file_path)
        if not result.get('success'):
            self.display_error("Failed to extract strings from file.")
            return
        
        all_strings = result.get('strings', [])
        if not all_strings:
            self.display_error("No strings found in the file.")
            return
        
        # Search through strings
        import re
        try:
            pattern = re.compile(search_pattern, re.IGNORECASE)
            matching_strings = []
            
            for i, string in enumerate(all_strings, 1):
                if pattern.search(string):
                    matching_strings.append((i, string))
            
            # Format the output
            output = f"🔍 Grep Search Results:\n\n"
            output += f"Search Pattern: {search_pattern}\n"
            output += f"Total Strings Searched: {len(all_strings)}\n"
            output += f"Matches Found: {len(matching_strings)}\n\n"
            
            if matching_strings:
                output += "📋 Matching Strings:\n"
                output += "-" * 25 + "\n"
                
                for line_num, string in matching_strings:
                    output += f"{line_num:4d}. {string}\n"
                
                # Copy to clipboard
                self.clipboard_clear()
                clipboard_text = '\n'.join([f"{line_num}. {string}" for line_num, string in matching_strings])
                self.clipboard_append(clipboard_text)
                
                output += f"\n✅ Copied {len(matching_strings)} matching strings to clipboard."
            else:
                output += "❌ No matches found for the given pattern."
            
            self.display_results(output)
            
        except re.error as e:
            self.display_error(f"Invalid regex pattern: {str(e)}\n\nPlease check your search pattern and try again.")

    def show_urls_from_strings(self):
        """Show all URLs found in extracted strings in main output box."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        categories = self.string_analyzer.categorize_strings()
        urls = categories.get('URLs', [])
        
        if not urls:
            self.display_error("No URLs found in extracted strings.")
            return
        
        # Format the output
        output = "🌐 URLs Found in Strings:\n\n"
        output += f"Total URLs Found: {len(urls)}\n\n"
        output += "📋 URLs:\n"
        output += "-" * 15 + "\n"
        
        for i, url in enumerate(urls, 1):
            output += f"{i:3d}. {url}\n"
        
        # Copy to clipboard
        self.clipboard_clear()
        clipboard_text = '\n'.join(urls)
        self.clipboard_append(clipboard_text)
        
        output += f"\n✅ Copied {len(urls)} URLs to clipboard."
        self.display_results(output)

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
        # Set CTF feature buttons for Binwalk tool
        self.update_ctf_feature_buttons([
            ("Extract", self.binwalk_extract),
            ("Show File Types", self.binwalk_show_file_types),
            ("Advanced Scan", self.binwalk_advanced_scan),
        ])
        self.run_analysis(self._analyze_binwalk_thread)

    def binwalk_extract(self):
        """Extract files with Binwalk and ask user for output location and name."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        # Ask user for output directory
        output_dir = filedialog.askdirectory(
            title="Select Output Directory for Extracted Files",
            initialdir=os.path.dirname(self.selected_file_path)
        )
        
        if not output_dir:  # User cancelled
            return
        
        # Ask user for base name for extracted files
        base_name = simpledialog.askstring(
            "Extract Files", 
            "Enter base name for extracted files (optional):\nLeave empty to use default naming",
            initialvalue=os.path.splitext(os.path.basename(self.selected_file_path))[0]
        )
        
        if base_name is None:  # User cancelled
            return
        
        # Show loading message
        self.display_results("🔄 Extracting files with Binwalk...\n\nPlease wait, this may take a moment.")
        
        # Run extraction in thread
        def extract_thread():
            try:
                # Create custom output directory with base name if provided
                if base_name:
                    custom_output_dir = os.path.join(output_dir, f"{base_name}_extracted")
                else:
                    custom_output_dir = output_dir
                
                if not self.selected_file_path:
                    self.after(0, self.display_error, "No file loaded.")
                    return
                
                result = self.binwalk_analyzer.extract_files(
                    self.selected_file_path, 
                    output_dir=custom_output_dir
                )
                
                if result.get('success'):
                    extracted_files = result.get('extracted_files', [])
                    if extracted_files:
                        output = "✅ Binwalk Extraction Complete!\n\n"
                        output += f"📁 Output Directory: {result.get('extraction_dir', custom_output_dir)}\n"
                        output += f"📊 Files Extracted: {len(extracted_files)}\n\n"
                        output += "📋 Extracted Files:\n"
                        output += "-" * 25 + "\n"
                        
                        for i, file_info in enumerate(extracted_files, 1):
                            output += f"{i:2d}. {file_info.get('name', 'Unknown')}\n"
                            output += f"    Size: {file_info.get('size', 0):,} bytes\n"
                            if file_info.get('path'):
                                output += f"    Path: {file_info.get('path')}\n"
                            output += "\n"
                        
                        # Copy file list to clipboard
                        self.clipboard_clear()
                        clipboard_text = '\n'.join([f.get('name', 'Unknown') for f in extracted_files])
                        self.clipboard_append(clipboard_text)
                        
                        output += f"✅ Copied {len(extracted_files)} filenames to clipboard."
                    else:
                        output = "⚠️ Extraction completed but no files were found.\n\n"
                        output += "This could mean:\n"
                        output += "• No embedded files in the original file\n"
                        output += "• Files are corrupted or incomplete\n"
                        output += "• Different extraction method needed"
                else:
                    output = f"❌ Binwalk Extraction Failed!\n\nError: {result.get('error', 'Unknown error')}"
                
                self.after(0, self.display_results, output)
                
            except Exception as e:
                error_msg = f"❌ Extraction Error!\n\nException: {str(e)}"
                self.after(0, self.display_error, error_msg)
        
        thread = threading.Thread(target=extract_thread, daemon=True)
        thread.start()

    def binwalk_show_file_types(self):
        """Show summary of found file types from Binwalk results."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        # Show loading message
        self.display_results("🔍 Scanning for file signatures...\n\nPlease wait.")
        
        def scan_thread():
            try:
                if not self.selected_file_path:
                    self.after(0, self.display_error, "No file loaded.")
                    return
                
                # Use signature_scan method instead of basic_scan
                scan_result = self.binwalk_analyzer.signature_scan(self.selected_file_path)
                
                if not scan_result.get('success'):
                    self.after(0, self.display_error, f"❌ Scan Failed!\n\nError: {scan_result.get('error', 'Unknown error')}")
                    return
                
                signatures = scan_result.get('signatures', [])
                
                if not signatures:
                    self.after(0, self.display_results, "❌ No file signatures found in the file.")
                    return
                
                # Group by file type
                file_types = {}
                for sig in signatures:
                    file_type = sig.get('type', 'Unknown')
                    if file_type not in file_types:
                        file_types[file_type] = []
                    file_types[file_type].append(sig)
                
                # Format output
                output = "📊 File Types Found:\n\n"
                output += f"Total Signatures: {len(signatures)}\n"
                output += f"Unique File Types: {len(file_types)}\n\n"
                output += "📋 File Types:\n"
                output += "-" * 20 + "\n"
                
                for file_type, sigs in sorted(file_types.items()):
                    output += f"📄 {file_type}:\n"
                    output += f"   Count: {len(sigs)}\n"
                    output += f"   Positions: {', '.join([str(sig.get('offset', 'N/A')) for sig in sigs[:3]])}"
                    if len(sigs) > 3:
                        output += f" (+{len(sigs) - 3} more)"
                    output += "\n\n"
                
                # Copy to clipboard
                self.clipboard_clear()
                clipboard_text = '\n'.join([f"{ft}: {len(sigs)} signatures" for ft, sigs in file_types.items()])
                self.clipboard_append(clipboard_text)
                
                output += f"✅ Copied file type summary to clipboard."
                
                self.after(0, self.display_results, output)
                
            except Exception as e:
                error_msg = f"❌ File Type Analysis Error!\n\nException: {str(e)}"
                self.after(0, self.display_error, error_msg)
        
        thread = threading.Thread(target=scan_thread, daemon=True)
        thread.start()

    def binwalk_advanced_scan(self):
        """Perform an advanced scan with detailed analysis."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        # Show loading message
        self.display_results("🔬 Running Advanced Binwalk Scan...\n\nThis may take several minutes for large files.")
        
        def advanced_scan_thread():
            try:
                if not self.selected_file_path:
                    self.after(0, self.display_error, "No file loaded.")
                    return
                
                # Use combination of basic_scan and signature_scan instead of deep_scan
                # to avoid Qt/OpenCV issues
                output = "🔬 Advanced Binwalk Scan Results:\n\n"
                
                # File information
                if self.selected_file_path and os.path.exists(self.selected_file_path):
                    file_size = os.path.getsize(self.selected_file_path)
                    output += "📁 File Information:\n"
                    output += "-" * 20 + "\n"
                    output += f"Size: {file_size:,} bytes\n"
                    output += f"Path: {self.selected_file_path}\n\n"
                
                # Basic scan
                output += "🔍 Basic Scan Results:\n"
                output += "-" * 20 + "\n"
                basic_result = self.binwalk_analyzer.basic_scan(self.selected_file_path)
                
                if basic_result.get('success'):
                    output += basic_result.get('output', 'No output available')
                    output += f"\n\nSignatures Found: {basic_result.get('signatures_found', 0)}\n"
                else:
                    output += f"❌ Basic scan failed: {basic_result.get('error', 'Unknown error')}\n"
                output += "\n"
                
                # Signature scan
                output += "📊 Detailed Signature Analysis:\n"
                output += "-" * 30 + "\n"
                sig_result = self.binwalk_analyzer.signature_scan(self.selected_file_path)
                
                if sig_result.get('success'):
                    signatures = sig_result.get('signatures', [])
                    if signatures:
                        output += f"Total Signatures: {len(signatures)}\n\n"
                        
                        # Group by type
                        type_counts = {}
                        for sig in signatures:
                            sig_type = sig.get('type', 'Unknown')
                            type_counts[sig_type] = type_counts.get(sig_type, 0) + 1
                        
                        output += "📋 Signature Types:\n"
                        for sig_type, count in sorted(type_counts.items()):
                            output += f"  • {sig_type}: {count} instances\n"
                        output += "\n"
                        
                        # Show first 10 signatures in detail
                        output += "🔍 First 10 Signatures:\n"
                        for i, sig in enumerate(signatures[:10], 1):
                            output += f"  {i:2d}. Offset {sig.get('offset', 'N/A')}: {sig.get('type', 'Unknown')}\n"
                            output += f"      Description: {sig.get('description', 'N/A')}\n"
                        output += "\n"
                        
                        if len(signatures) > 10:
                            output += f"... and {len(signatures) - 10} more signatures\n\n"
                    else:
                        output += "❌ No signatures found\n\n"
                else:
                    output += f"❌ Signature scan failed: {sig_result.get('error', 'Unknown error')}\n\n"
                
                # Manual entropy analysis (simple approach)
                output += "📊 Simple Entropy Analysis:\n"
                output += "-" * 25 + "\n"
                try:
                    with open(self.selected_file_path, 'rb') as f:
                        data = f.read(1024)  # Read first 1KB for analysis
                    
                    # Calculate simple entropy
                    byte_counts = [0] * 256
                    for byte in data:
                        byte_counts[byte] += 1
                    
                    # Shannon entropy calculation
                    import math
                    entropy = 0
                    for count in byte_counts:
                        if count > 0:
                            p = count / len(data)
                            entropy -= p * math.log2(p)
                    
                    output += f"Sample Size: {len(data)} bytes\n"
                    output += f"Entropy: {entropy:.2f} bits/byte\n"
                    
                    # Interpret entropy
                    if entropy > 7.5:
                        output += "Entropy Level: High (likely compressed/encrypted data)\n"
                    elif entropy > 6.0:
                        output += "Entropy Level: Medium (mixed content)\n"
                    else:
                        output += "Entropy Level: Low (structured data)\n"
                    
                    # Check for patterns
                    unique_bytes = sum(1 for count in byte_counts if count > 0)
                    output += f"Unique Bytes: {unique_bytes}/256\n"
                    
                except Exception as e:
                    output += f"❌ Entropy analysis failed: {str(e)}\n"
                
                output += "\n"
                
                # Magic number analysis
                output += "🔢 Magic Number Analysis:\n"
                output += "-" * 25 + "\n"
                try:
                    with open(self.selected_file_path, 'rb') as f:
                        header = f.read(16)
                    
                    # Common magic numbers
                    magic_numbers = {
                        b'\xff\xd8\xff': 'JPEG',
                        b'\x89PNG\r\n\x1a\n': 'PNG',
                        b'GIF87a': 'GIF',
                        b'GIF89a': 'GIF',
                        b'BM': 'BMP',
                        b'%PDF': 'PDF',
                        b'PK\x03\x04': 'ZIP/JAR/DOCX/XLSX/PPTX',
                        b'Rar!': 'RAR',
                        b'7z\xbc\xaf\'\x1c': '7ZIP',
                        b'\x1f\x8b': 'GZIP',
                        b'ID3': 'MP3',
                        b'OggS': 'OGG',
                        b'fLaC': 'FLAC',
                        b'\x7fELF': 'ELF',
                        b'MZ': 'EXE/DLL',
                    }
                    
                    found_magic = []
                    for magic, name in magic_numbers.items():
                        if header.startswith(magic):
                            found_magic.append(name)
                    
                    if found_magic:
                        output += f"Magic Numbers Found: {', '.join(found_magic)}\n"
                    else:
                        output += "No known magic numbers found in header\n"
                    
                    # Show hex dump of header
                    output += f"Header (hex): {header.hex()[:64]}...\n"
                    
                except Exception as e:
                    output += f"❌ Magic number analysis failed: {str(e)}\n"
                
                output += "\n"
                
                # Copy to clipboard
                self.clipboard_clear()
                if self.selected_file_path:
                    filename = os.path.basename(self.selected_file_path)
                else:
                    filename = "unknown_file"
                clipboard_text = f"Advanced Binwalk Scan Results for {filename}\n"
                clipboard_text += f"File Size: {file_size:,} bytes\n"
                clipboard_text += f"Basic Scan: {'Success' if basic_result.get('success') else 'Failed'}\n"
                clipboard_text += f"Signature Scan: {'Success' if sig_result.get('success') else 'Failed'}\n"
                clipboard_text += f"Signatures Found: {len(sig_result.get('signatures', []))}"
                self.clipboard_append(clipboard_text)
                
                output += f"✅ Copied scan summary to clipboard."
                
                self.after(0, self.display_results, output)
                
            except Exception as e:
                error_msg = f"❌ Advanced Scan Error!\n\nException: {str(e)}"
                self.after(0, self.display_error, error_msg)
        
        thread = threading.Thread(target=advanced_scan_thread, daemon=True)
        thread.start()

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
        # Set CTF feature buttons for Zsteg tool
        self.update_ctf_feature_buttons([
            ("All Channels Scan", self.zsteg_all_channels_scan),
            ("Extract Data", self.zsteg_extract_data),
            ("LSB Analysis", self.zsteg_lsb_analysis),
        ])
        self.run_analysis(self._analyze_zsteg_thread)

    def _analyze_zsteg_thread(self):
        """Zsteg analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
        
        try:
            # Check if zsteg is available first
            if not self.zsteg_analyzer.check_zsteg_available():
                return """❌ Zsteg Analysis Failed!

Error: Zsteg is not installed on your system.

To install Zsteg on Kali Linux:
sudo apt update
sudo apt install zsteg

Or install via Ruby gems:
sudo gem install zsteg

After installation, restart the application and try again."""
            
            # Run basic zsteg scan
            result = self.zsteg_analyzer.basic_scan(self.selected_file_path)
            
            if not result.get('success', False):
                return f"❌ Zsteg Analysis Failed!\n\nError: {result.get('error', 'Unknown error')}"
            
            return self.zsteg_analyzer.export_to_text(result)
            
        except Exception as e:
            return f"❌ Zsteg Analysis Error!\n\nException: {str(e)}\n\nPlease check if the file exists and is accessible."

    def zsteg_all_channels_scan(self):
        """Perform comprehensive scan using all known Zsteg methods."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        # Show loading message
        self.display_results("🔍 Running All Channels Zsteg Scan...\n\nThis may take a moment.")
        
        def all_channels_thread():
            try:
                if not self.selected_file_path:
                    self.after(0, self.display_error, "No file loaded.")
                    return
                
                # Use deep_scan method which uses -a flag for all channels
                result = self.zsteg_analyzer.deep_scan(self.selected_file_path)
                
                if not result.get('success'):
                    self.after(0, self.display_error, f"❌ All Channels Scan Failed!\n\nError: {result.get('error', 'Unknown error')}")
                    return
                
                # Format comprehensive results
                output = "🔍 All Channels Zsteg Scan Results:\n\n"
                
                # File information
                if self.selected_file_path and os.path.exists(self.selected_file_path):
                    file_size = os.path.getsize(self.selected_file_path)
                    output += "📁 File Information:\n"
                    output += "-" * 20 + "\n"
                    output += f"Size: {file_size:,} bytes\n"
                    output += f"Path: {self.selected_file_path}\n\n"
                
                # Main scan output
                if result.get('output'):
                    output += "🔍 Scan Results:\n"
                    output += "-" * 15 + "\n"
                    output += result['output']
                    output += "\n"
                
                # Findings summary
                findings = result.get('findings', [])
                if findings:
                    output += "🎯 Findings Summary:\n"
                    output += "-" * 20 + "\n"
                    output += f"Total Findings: {len(findings)}\n\n"
                    
                    # Group by type
                    type_counts = {}
                    for finding in findings:
                        finding_type = self._extract_finding_type(str(finding))
                        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
                    
                    output += "📋 Finding Types:\n"
                    for finding_type, count in sorted(type_counts.items()):
                        output += f"  • {finding_type}: {count} instances\n"
                    output += "\n"
                    
                    # Show first 10 findings in detail
                    output += "🔍 First 10 Findings:\n"
                    for i, finding in enumerate(findings[:10], 1):
                        output += f"  {i:2d}. {str(finding)}\n"
                    output += "\n"
                    
                    if len(findings) > 10:
                        output += f"... and {len(findings) - 10} more findings\n\n"
                else:
                    output += "❌ No findings detected\n\n"
                
                # Channel analysis
                channels = result.get('channels', {})
                if channels:
                    output += "📊 Channel Analysis:\n"
                    output += "-" * 20 + "\n"
                    for channel, data in channels.items():
                        output += f"Channel {channel}: {len(data)} findings\n"
                    output += "\n"
                
                # Copy to clipboard
                self.clipboard_clear()
                if self.selected_file_path:
                    filename = os.path.basename(self.selected_file_path)
                else:
                    filename = "unknown_file"
                clipboard_text = f"All Channels Zsteg Scan Results for {filename}\n"
                clipboard_text += f"File Size: {file_size:,} bytes\n"
                clipboard_text += f"Total Findings: {len(findings)}\n"
                clipboard_text += f"Channels Analyzed: {len(channels)}"
                self.clipboard_append(clipboard_text)
                
                output += f"✅ Copied scan summary to clipboard."
                
                self.after(0, self.display_results, output)
                
            except Exception as e:
                error_msg = f"❌ All Channels Scan Error!\n\nException: {str(e)}"
                self.after(0, self.display_error, error_msg)
        
        thread = threading.Thread(target=all_channels_thread, daemon=True)
        thread.start()

    def zsteg_extract_data(self):
        """Extract data from specific channels using Zsteg."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        # Ask user for extraction parameters
        extraction_dialog = tk.Toplevel(self)
        extraction_dialog.title("Zsteg Data Extraction")
        extraction_dialog.geometry("800x700")
        extraction_dialog.grab_set()
        
        # Center the dialog
        extraction_dialog.update_idletasks()
        x = (extraction_dialog.winfo_screenwidth() // 2) - (800 // 2)
        y = (extraction_dialog.winfo_screenheight() // 2) - (700 // 2)
        extraction_dialog.geometry(f"800x700+{x}+{y}")
        
        # Create dialog content
        main_frame = tk.Frame(extraction_dialog, bg=Theme.get_color('primary'))
        main_frame.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Title
        title_label = tk.Label(main_frame, text="🔓 Zsteg Data Extraction", 
                              font=Theme.get_font('title'), 
                              bg=Theme.get_color('primary'), 
                              fg=Theme.get_color('accent'))
        title_label.pack(pady=(0, 25))
        
        # Create a frame for the two columns
        content_frame = tk.Frame(main_frame, bg=Theme.get_color('primary'))
        content_frame.pack(fill='both', expand=True)
        content_frame.columnconfigure(0, weight=1)
        content_frame.columnconfigure(1, weight=1)
        
        # Left column - Channel selection
        channel_frame = tk.LabelFrame(content_frame, text="Channel Selection", 
                                     font=Theme.get_font('heading'),
                                     bg=Theme.get_color('primary'),
                                     fg=Theme.get_color('text_primary'))
        channel_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 15), pady=(0, 20))
        
        channel_var = tk.StringVar(value="b,r,g,lsb")
        common_channels = [
            ("b,r,g,lsb", "Blue, Red, Green - LSB"),
            ("b,r,g,msb", "Blue, Red, Green - MSB"),
            ("b,r,lsb", "Blue, Red - LSB"),
            ("b,r,msb", "Blue, Red - MSB"),
            ("b,g,lsb", "Blue, Green - LSB"),
            ("b,g,msb", "Blue, Green - MSB"),
            ("r,g,lsb", "Red, Green - LSB"),
            ("r,g,msb", "Red, Green - MSB"),
            ("b,lsb", "Blue - LSB"),
            ("b,msb", "Blue - MSB"),
            ("r,lsb", "Red - LSB"),
            ("r,msb", "Red - MSB"),
            ("g,lsb", "Green - LSB"),
            ("g,msb", "Green - MSB"),
            ("a,lsb", "Alpha - LSB"),
            ("a,msb", "Alpha - MSB"),
        ]
        
        # Create a canvas with scrollbar for channels
        channel_canvas = tk.Canvas(channel_frame, bg=Theme.get_color('primary'), height=300)
        channel_scrollbar = tk.Scrollbar(channel_frame, orient='vertical', command=channel_canvas.yview)
        channel_inner_frame = tk.Frame(channel_canvas, bg=Theme.get_color('primary'))
        
        channel_inner_frame.bind(
            '<Configure>',
            lambda e: channel_canvas.configure(scrollregion=channel_canvas.bbox('all'))
        )
        channel_canvas.create_window((0, 0), window=channel_inner_frame, anchor='nw')
        channel_canvas.configure(yscrollcommand=channel_scrollbar.set)
        
        channel_canvas.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        channel_scrollbar.pack(side='right', fill='y', pady=10)
        
        for i, (value, description) in enumerate(common_channels):
            rb = tk.Radiobutton(channel_inner_frame, text=description, variable=channel_var, value=value,
                               bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary'),
                               selectcolor=Theme.get_color('secondary'), font=Theme.get_font('default'))
            rb.pack(anchor='w', padx=10, pady=3)
        
        # Right column - Bits selection
        bits_frame = tk.LabelFrame(content_frame, text="Bits to Extract", 
                                  font=Theme.get_font('heading'),
                                  bg=Theme.get_color('primary'),
                                  fg=Theme.get_color('text_primary'))
        bits_frame.grid(row=0, column=1, sticky='nsew', padx=(15, 0), pady=(0, 20))
        
        bits_var = tk.StringVar(value="1")
        bits_options = [("1", "1 bit (LSB/MSB)"), ("2", "2 bits"), ("4", "4 bits"), ("8", "8 bits")]
        
        for value, description in bits_options:
            rb = tk.Radiobutton(bits_frame, text=description, variable=bits_var, value=value,
                               bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary'),
                               selectcolor=Theme.get_color('secondary'), font=Theme.get_font('default'))
            rb.pack(anchor='w', padx=20, pady=8)
        
        # Information frame at the bottom
        info_frame = tk.LabelFrame(main_frame, text="Information", 
                                  font=Theme.get_font('heading'),
                                  bg=Theme.get_color('primary'),
                                  fg=Theme.get_color('text_primary'))
        info_frame.pack(fill='x', pady=(0, 20))
        
        info_text = """• LSB (Least Significant Bit): Extracts the least significant bit from each color channel
• MSB (Most Significant Bit): Extracts the most significant bit from each color channel
• Multiple channels can be combined for more comprehensive extraction
• Higher bit counts extract more data but may produce larger files
• Common channels: b=blue, r=red, g=green, a=alpha"""
        
        info_label = tk.Label(info_frame, text=info_text, 
                             bg=Theme.get_color('primary'), fg=Theme.get_color('text_secondary'),
                             font=Theme.get_font('default'), justify='left', wraplength=700)
        info_label.pack(padx=15, pady=15)
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg=Theme.get_color('primary'))
        button_frame.pack(fill='x', pady=(20, 0))
        
        def extract():
            channel = channel_var.get()
            bits = int(bits_var.get())
            extraction_dialog.destroy()
            
            # Show loading message
            self.display_results(f"🔓 Extracting data with Zsteg...\n\nChannel: {channel}\nBits: {bits}")
            
            def extract_thread():
                try:
                    if not self.selected_file_path:
                        self.after(0, self.display_error, "No file loaded.")
                        return
                    
                    result = self.zsteg_analyzer.extract_data(
                        self.selected_file_path, 
                        channel=channel, 
                        bits=bits
                    )
                    
                    if result.get('success'):
                        data = result.get('data', '')
                        extracted_file = result.get('extracted_file')
                        
                        output = f"✅ Zsteg Data Extraction Successful!\n\n"
                        output += f"📊 Extraction Parameters:\n"
                        output += f"Channel: {channel}\n"
                        output += f"Bits: {bits}\n"
                        output += f"Data Length: {len(data)} characters\n\n"
                        
                        if extracted_file:
                            output += f"💾 Extracted File: {extracted_file}\n\n"
                        
                        # Show data preview
                        output += "📄 Extracted Data Preview:\n"
                        output += "-" * 25 + "\n"
                        preview = data[:500] if len(data) > 500 else data
                        output += preview
                        
                        if len(data) > 500:
                            output += f"\n\n... (truncated, {len(data) - 500} more characters)"
                        
                        # Copy to clipboard
                        self.clipboard_clear()
                        self.clipboard_append(data)
                        
                        output += f"\n\n✅ Copied {len(data)} characters to clipboard."
                        
                        self.after(0, self.display_results, output)
                    else:
                        error_msg = f"❌ Extraction Failed!\n\nError: {result.get('error', 'Unknown error')}"
                        self.after(0, self.display_error, error_msg)
                        
                except Exception as e:
                    error_msg = f"❌ Extraction Error!\n\nException: {str(e)}"
                    self.after(0, self.display_error, error_msg)
            
            thread = threading.Thread(target=extract_thread, daemon=True)
            thread.start()
        
        def cancel():
            extraction_dialog.destroy()
        
        extract_btn = tk.Button(button_frame, text="🔓 Extract", command=extract,
                               bg=Theme.get_color('accent'), fg='white',
                               font=Theme.get_font('button'), padx=30, pady=12)
        extract_btn.pack(side='left', padx=(0, 15))
        
        cancel_btn = tk.Button(button_frame, text="❌ Cancel", command=cancel,
                              bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'),
                              font=Theme.get_font('button'), padx=30, pady=12)
        cancel_btn.pack(side='left')

    def zsteg_lsb_analysis(self):
        """Perform focused LSB (Least Significant Bit) analysis."""
        if not self.selected_file_path:
            self.display_error("No file loaded.")
            return
        
        # Show loading message
        self.display_results("🔍 Running LSB Analysis...\n\nAnalyzing least significant bits.")
        
        def lsb_analysis_thread():
            try:
                if not self.selected_file_path:
                    self.after(0, self.display_error, "No file loaded.")
                    return
                
                output = "🔍 LSB Analysis Results:\n\n"
                
                # File information
                if self.selected_file_path and os.path.exists(self.selected_file_path):
                    file_size = os.path.getsize(self.selected_file_path)
                    output += "📁 File Information:\n"
                    output += "-" * 20 + "\n"
                    output += f"Size: {file_size:,} bytes\n"
                    output += f"Path: {self.selected_file_path}\n\n"
                
                # Test common LSB channels
                lsb_channels = [
                    ("b,r,g,lsb", "Blue, Red, Green - LSB"),
                    ("b,r,lsb", "Blue, Red - LSB"),
                    ("b,g,lsb", "Blue, Green - LSB"),
                    ("r,g,lsb", "Red, Green - LSB"),
                    ("b,lsb", "Blue - LSB"),
                    ("r,lsb", "Red - LSB"),
                    ("g,lsb", "Green - LSB"),
                    ("a,lsb", "Alpha - LSB"),
                ]
                
                output += "🔍 LSB Channel Analysis:\n"
                output += "-" * 25 + "\n"
                
                all_findings = []
                
                for channel, description in lsb_channels:
                    try:
                        result = self.zsteg_analyzer.analyze_specific_channel(
                            self.selected_file_path, channel
                        )
                        
                        if result.get('success'):
                            findings = result.get('findings', [])
                            if findings:
                                output += f"✅ {description}:\n"
                                output += f"   Findings: {len(findings)}\n"
                                for finding in findings[:3]:  # Show first 3 findings
                                    output += f"   • {str(finding)}\n"
                                if len(findings) > 3:
                                    output += f"   ... and {len(findings) - 3} more\n"
                                output += "\n"
                                all_findings.extend(findings)
                            else:
                                output += f"❌ {description}: No findings\n\n"
                        else:
                            output += f"❌ {description}: Failed - {result.get('error', 'Unknown error')}\n\n"
                            
                    except Exception as e:
                        output += f"❌ {description}: Error - {str(e)}\n\n"
                
                # Summary
                output += "📊 LSB Analysis Summary:\n"
                output += "-" * 25 + "\n"
                output += f"Total Channels Tested: {len(lsb_channels)}\n"
                output += f"Total Findings: {len(all_findings)}\n"
                
                if all_findings:
                    # Group by type
                    type_counts = {}
                    for finding in all_findings:
                        finding_type = self._extract_finding_type(str(finding))
                        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
                    
                    output += f"Finding Types:\n"
                    for finding_type, count in type_counts.items():
                        output += f"  • {finding_type}: {count}\n"
                    
                    # Copy to clipboard
                    self.clipboard_clear()
                    clipboard_text = f"LSB Analysis Results for {os.path.basename(self.selected_file_path)}\n"
                    clipboard_text += f"Total Findings: {len(all_findings)}\n"
                    clipboard_text += f"Channels Tested: {len(lsb_channels)}"
                    self.clipboard_append(clipboard_text)
                    
                    output += f"\n✅ Copied analysis summary to clipboard."
                else:
                    output += "No LSB steganography detected.\n"
                
                self.after(0, self.display_results, output)
                
            except Exception as e:
                error_msg = f"❌ LSB Analysis Error!\n\nException: {str(e)}"
                self.after(0, self.display_error, error_msg)
        
        thread = threading.Thread(target=lsb_analysis_thread, daemon=True)
        thread.start()

    def _extract_finding_type(self, finding_str: str) -> str:
        """Extract the type of finding from zsteg output."""
        finding_lower = finding_str.lower()
        if 'text' in finding_lower:
            return 'Text'
        elif 'zlib' in finding_lower:
            return 'Compressed'
        elif 'extradata' in finding_lower:
            return 'Extra Data'
        elif 'bmp' in finding_lower:
            return 'BMP'
        elif 'png' in finding_lower:
            return 'PNG'
        elif 'gif' in finding_lower:
            return 'GIF'
        elif 'jpeg' in finding_lower or 'jpg' in finding_lower:
            return 'JPEG'
        elif 'pdf' in finding_lower:
            return 'PDF'
        elif 'zip' in finding_lower:
            return 'ZIP'
        elif 'rar' in finding_lower:
            return 'RAR'
        else:
            return 'Unknown'

    def analyze_ocr(self):
        """Analyze OCR"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        # Set CTF feature buttons for OCR tool
        self.update_ctf_feature_buttons([
            ("Highlight Flags", self.ocr_highlight_flags),
            ("Copy All Text", self.ocr_copy_all_text),
        ])
        self.run_analysis(self._analyze_ocr_thread)

    def ocr_copy_all_text(self):
        """Copy all detected OCR text to clipboard."""
        if not self.selected_file_path:
            messagebox.showinfo("No Text", "No file loaded.")
            return
        result = self.ocr_analyzer.extract_text(self.selected_file_path)
        if not result.get('success'):
            result = self.ocr_analyzer.extract_text_with_preprocessing(self.selected_file_path)
        text = result.get('text', '') if isinstance(result, dict) else str(result)
        if text.strip():
            self.clipboard_clear()
            self.clipboard_append(text.strip())
            messagebox.showinfo("Copied", f"Copied OCR text to clipboard.\n\n" + text.strip()[:500] + ("\n..." if len(text.strip()) > 500 else ""))
        else:
            messagebox.showinfo("No Text", "No OCR text found.")

    def ocr_show_urls(self):
        """Show all URLs found in OCR text and copy to clipboard."""
        if not self.selected_file_path:
            messagebox.showinfo("No URLs", "No file loaded.")
            return
        import re
        result = self.ocr_analyzer.extract_text(self.selected_file_path)
        if not result.get('success'):
            result = self.ocr_analyzer.extract_text_with_preprocessing(self.selected_file_path)
        text = result.get('text', '') if isinstance(result, dict) else str(result)
        urls = re.findall(r'https?://[^\s]+', text)
        if urls:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(urls))
            messagebox.showinfo("URLs Found", f"Copied {len(urls)} URL(s) to clipboard.\n\n" + '\n'.join(urls[:10]) + ("\n..." if len(urls) > 10 else ""))
        else:
            messagebox.showinfo("No URLs", "No URLs found in OCR text.")

    def ocr_highlight_flags(self):
        """Highlight flag-like patterns in OCR text and show in a popup."""
        if not self.selected_file_path:
            messagebox.showinfo("No Flags", "No file loaded.")
            return
        import re
        result = self.ocr_analyzer.extract_text(self.selected_file_path)
        if not result.get('success'):
            result = self.ocr_analyzer.extract_text_with_preprocessing(self.selected_file_path)
        text = result.get('text', '') if isinstance(result, dict) else str(result)
        flags = []
        flag_patterns = [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'key\{[^}]+\}', r'KEY\{[^}]+\}'
        ]
        for pattern in flag_patterns:
            found = re.findall(pattern, text)
            flags.extend(found)
        if flags:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(flags))
            messagebox.showinfo("Flags Found", f"Copied {len(flags)} flag(s) to clipboard.\n\n" + '\n'.join(flags[:10]) + ("\n..." if len(flags) > 10 else ""))
        else:
            messagebox.showinfo("No Flags", "No flag-like patterns found in OCR text.")

    def ocr_auto_translate(self):
        """Auto-translate OCR text if non-English (placeholder)."""
        messagebox.showinfo("Not Implemented", "This would auto-translate OCR text if non-English.")

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
        # Set CTF feature buttons for CTF Auto tool
        self.update_ctf_feature_buttons([
            ("Export Report", self.ctf_export_report),
            ("Copy All Flags", self.ctf_copy_all_flags),
            ("Show Summary", self.ctf_show_summary),
        ])
        self.run_analysis(self._ctf_auto_analyze_thread)

    def ctf_export_report(self):
        """Export CTF auto-analysis report to a text file."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        report = self._ctf_auto_analyze_thread()
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if save_path:
            with open(save_path, 'w') as f:
                f.write(report)
            messagebox.showinfo("Exported", f"CTF report exported to {save_path}")

    def ctf_copy_all_flags(self):
        """Copy all found flags from all analyses to clipboard."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        # Aggregate flags from all relevant analyzers
        all_flags = []
        # Strings
        categories = self.string_analyzer.categorize_strings()
        all_flags.extend(categories.get('Flags', []))
        # QR/Barcode
        result = self.qr_barcode_analyzer.detect_codes(self.selected_file_path)
        if not result.get('success'):
            result = self.qr_barcode_analyzer.detect_codes_with_preprocessing(self.selected_file_path)
        codes = result.get('codes', []) if result.get('success') else []
        import re
        flag_patterns = [r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'key\{[^}]+\}', r'KEY\{[^}]+\}']
        for c in codes:
            data = c.get('data', '')
            for pattern in flag_patterns:
                all_flags.extend(re.findall(pattern, data))
        # OCR
        ocr_result = self.ocr_analyzer.extract_text(self.selected_file_path)
        if not ocr_result.get('success'):
            ocr_result = self.ocr_analyzer.extract_text_with_preprocessing(self.selected_file_path)
        text = ocr_result.get('text', '') if isinstance(ocr_result, dict) else str(ocr_result)
        for pattern in flag_patterns:
            all_flags.extend(re.findall(pattern, text))
        # Metadata
        meta_result = self.metadata_analyzer.analyze_file(self.selected_file_path)
        if meta_result.get('success'):
            all_flags.extend(meta_result.get('flags', []))
        # File Carving
        carving_result = self.file_carving_analyzer.auto_carve(self.selected_file_path)
        if carving_result.get('success'):
            files = []
            if carving_result.get('foremost_results') and carving_result['foremost_results'].get('success'):
                files += [f.get('filename') for f in carving_result['foremost_results'].get('files_found', [])]
            if carving_result.get('binwalk_results') and carving_result['binwalk_results'].get('success'):
                files += [f.get('filename') for f in carving_result['binwalk_results'].get('files_found', [])]
            for fname in files:
                for pattern in flag_patterns:
                    all_flags.extend(re.findall(pattern, fname))
        # Zsteg
        zsteg_result = self.zsteg_analyzer.basic_scan(self.selected_file_path)
        if zsteg_result.get('success'):
            findings = zsteg_result.get('findings', [])
            for finding in findings:
                for pattern in flag_patterns:
                    all_flags.extend(re.findall(pattern, str(finding)))
        # Steganography (try blank password)
        stego_result = self.steganography_analyzer.extract_data(self.selected_file_path, '', extract_as_file=False)
        if stego_result.get('success') and stego_result.get('data'):
            for pattern in flag_patterns:
                all_flags.extend(re.findall(pattern, stego_result['data']))
        # Deduplicate
        all_flags = list(set(all_flags))
        if all_flags:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(all_flags))
            messagebox.showinfo("Copied", f"Copied {len(all_flags)} flag(s) to clipboard.\n\n" + '\n'.join(all_flags[:10]) + ("\n..." if len(all_flags) > 10 else ""))
        else:
            messagebox.showinfo("No Flags", "No flag-like patterns found in any analysis.")

    def ctf_show_summary(self):
        """Show summary of CTF auto-analysis."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        summary = self._ctf_auto_analyze_thread()
        messagebox.showinfo("CTF Summary", summary[:2000] + ("\n..." if len(summary) > 2000 else ""))

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
                    results.append("�� String Analysis:\n" + f"Found {string_result.get('total_count', 0)} strings")
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
        # Set CTF feature buttons for QR/Barcode tool
        self.update_ctf_feature_buttons([
            ("Copy All Codes", self.qr_copy_all_codes),
            ("Show URLs", self.qr_show_urls),
            ("Highlight Flags", self.qr_highlight_flags),
        ])
        self.run_analysis(self._analyze_qr_barcode_thread)

    def qr_copy_all_codes(self):
        """Copy all detected QR/Barcode codes to clipboard."""
        if not self.selected_file_path:
            messagebox.showinfo("No Codes", "No file loaded.")
            return
        # Try both detection methods for robustness
        result = self.qr_barcode_analyzer.detect_codes(self.selected_file_path)
        if not result.get('success'):
            result = self.qr_barcode_analyzer.detect_codes_with_preprocessing(self.selected_file_path)
        codes = result.get('codes', []) if result.get('success') else []
        code_data = [c.get('data', '') for c in codes if c.get('data')]
        if code_data:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(code_data))
            messagebox.showinfo("Copied", f"Copied {len(code_data)} code(s) to clipboard.\n\n" + '\n'.join(code_data[:10]) + ("\n..." if len(code_data) > 10 else ""))
        else:
            messagebox.showinfo("No Codes", "No QR/Barcode codes found.")

    def qr_show_urls(self):
        """Show all URLs found in QR/Barcode codes and copy to clipboard."""
        if not self.selected_file_path:
            messagebox.showinfo("No URLs", "No file loaded.")
            return
        import re
        result = self.qr_barcode_analyzer.detect_codes(self.selected_file_path)
        if not result.get('success'):
            result = self.qr_barcode_analyzer.detect_codes_with_preprocessing(self.selected_file_path)
        codes = result.get('codes', []) if result.get('success') else []
        urls = []
        for c in codes:
            data = c.get('data', '')
            if re.match(r'https?://', data):
                urls.append(data)
        if urls:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(urls))
            messagebox.showinfo("URLs Found", f"Copied {len(urls)} URL(s) to clipboard.\n\n" + '\n'.join(urls[:10]) + ("\n..." if len(urls) > 10 else ""))
        else:
            messagebox.showinfo("No URLs", "No URLs found in QR/Barcode codes.")

    def qr_highlight_flags(self):
        """Highlight flag-like patterns in QR/Barcode codes and show in a popup."""
        if not self.selected_file_path:
            messagebox.showinfo("No Flags", "No file loaded.")
            return
        import re
        result = self.qr_barcode_analyzer.detect_codes(self.selected_file_path)
        if not result.get('success'):
            result = self.qr_barcode_analyzer.detect_codes_with_preprocessing(self.selected_file_path)
        codes = result.get('codes', []) if result.get('success') else []
        flags = []
        flag_patterns = [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'key\{[^}]+\}', r'KEY\{[^}]+\}'
        ]
        for c in codes:
            data = c.get('data', '')
            for pattern in flag_patterns:
                found = re.findall(pattern, data)
                flags.extend(found)
        if flags:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(flags))
            messagebox.showinfo("Flags Found", f"Copied {len(flags)} flag(s) to clipboard.\n\n" + '\n'.join(flags[:10]) + ("\n..." if len(flags) > 10 else ""))
        else:
            messagebox.showinfo("No Flags", "No flag-like patterns found in QR/Barcode codes.")

    def analyze_crypto(self):
        """Analyze crypto"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        
        # Open crypto popup window
        CryptoPopupWindow(self, self.selected_file_path, self.crypto_analyzer)
        
    def analyze_file_carving(self):
        """Analyze file carving"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        # Set CTF feature buttons for File Carving tool
        self.update_ctf_feature_buttons([
            ("Show Carved Files", self.carving_show_files),
            ("Open in Hex Viewer", self.carving_open_in_hex),
            ("Copy File List", self.carving_copy_file_list),
        ])
        self.run_analysis(self._analyze_file_carving_thread)

    def carving_show_files(self):
        """Show carved files in a popup."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        result = self.file_carving_analyzer.auto_carve(self.selected_file_path)
        if not result.get('success'):
            messagebox.showerror("Extraction Failed", result.get('error', 'Unknown error'))
            return
        files = []
        if result.get('foremost_results') and result['foremost_results'].get('success'):
            files += [f.get('filename') for f in result['foremost_results'].get('files_found', [])]
        if result.get('binwalk_results') and result['binwalk_results'].get('success'):
            files += [f.get('filename') for f in result['binwalk_results'].get('files_found', [])]
        if files:
            messagebox.showinfo("Carved Files", f"Extracted {len(files)} file(s):\n\n" + '\n'.join(files[:20]) + ("\n..." if len(files) > 20 else ""))
        else:
            messagebox.showinfo("No Files", "No files were extracted.")

    def carving_open_in_hex(self):
        """Open first carved file in hex viewer."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        result = self.file_carving_analyzer.auto_carve(self.selected_file_path)
        if not result.get('success'):
            messagebox.showerror("Extraction Failed", result.get('error', 'Unknown error'))
            return
        files = []
        if result.get('foremost_results') and result['foremost_results'].get('success'):
            files += [f.get('path') for f in result['foremost_results'].get('files_found', [])]
        if result.get('binwalk_results') and result['binwalk_results'].get('success'):
            files += [f.get('path') for f in result['binwalk_results'].get('files_found', [])]
        if files:
            hex_window = tk.Toplevel(self)
            HexViewerWindow(hex_window, files[0])
        else:
            messagebox.showinfo("No Files", "No files were extracted.")

    def carving_copy_file_list(self):
        """Copy list of carved files to clipboard."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        result = self.file_carving_analyzer.auto_carve(self.selected_file_path)
        if not result.get('success'):
            messagebox.showerror("Extraction Failed", result.get('error', 'Unknown error'))
            return
        files = []
        if result.get('foremost_results') and result['foremost_results'].get('success'):
            files += [f.get('filename') for f in result['foremost_results'].get('files_found', [])]
        if result.get('binwalk_results') and result['binwalk_results'].get('success'):
            files += [f.get('filename') for f in result['binwalk_results'].get('files_found', [])]
        if files:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(files))
            messagebox.showinfo("Copied", f"Copied {len(files)} filename(s) to clipboard.\n\n" + '\n'.join(files[:10]) + ("\n..." if len(files) > 10 else ""))
        else:
            messagebox.showinfo("No Files", "No files were extracted.")

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
        """Open hex viewer window"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please load a file first.")
            return
        # Set CTF feature buttons for Hex Viewer tool
        self.update_ctf_feature_buttons([
            ("Highlight Flags", self.hex_highlight_flags),
            ("Search Magic Numbers", self.hex_search_magic_numbers),
            ("Copy Selected Hex", self.hex_copy_selected),
        ])
        hex_window = tk.Toplevel(self)
        HexViewerWindow(hex_window, self.selected_file_path)

    def hex_search_magic_numbers(self):
        """Search for magic numbers in hex data."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        try:
            with open(self.selected_file_path, 'rb') as f:
                data = f.read()
            # Common magic numbers
            magic = {
                b'\x89PNG\r\n\x1a\n': 'PNG',
                b'GIF87a': 'GIF',
                b'GIF89a': 'GIF',
                b'BM': 'BMP',
                b'\xff\xd8\xff': 'JPEG',
                b'%PDF': 'PDF',
                b'PK\x03\x04': 'ZIP/JAR/DOCX/XLSX/PPTX',
                b'Rar!': 'RAR',
                b'7z\xbc\xaf\'\x1c': '7ZIP',
                b'\x1f\x8b': 'GZIP',
                b'ID3': 'MP3',
                b'OggS': 'OGG',
                b'fLaC': 'FLAC',
                b'\x7fELF': 'ELF',
                b'MZ': 'EXE/DLL',
            }
            found = []
            for sig, name in magic.items():
                if sig in data:
                    found.append(name)
            if found:
                messagebox.showinfo("Magic Numbers Found", f"Found: {', '.join(found)}")
            else:
                messagebox.showinfo("No Magic Numbers", "No known magic numbers found.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")

    def hex_copy_selected(self):
        """Copy selected hex or ASCII from the hex view (not implemented, needs integration with HexViewerWindow)."""
        messagebox.showinfo("Not Implemented", "Copying selected hex/ASCII requires integration with the hex viewer widget.")

    def hex_copy_all_hex(self):
        """Copy all hex data from the loaded file to clipboard."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        try:
            with open(self.selected_file_path, 'rb') as f:
                hex_data = f.read().hex()
            self.clipboard_clear()
            self.clipboard_append(hex_data)
            messagebox.showinfo("Copied", "Copied all hex data to clipboard.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")

    def hex_copy_all_ascii(self):
        """Copy all ASCII data from the loaded file to clipboard."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        try:
            with open(self.selected_file_path, 'rb') as f:
                ascii_data = f.read().decode(errors='replace')
            self.clipboard_clear()
            self.clipboard_append(ascii_data)
            messagebox.showinfo("Copied", "Copied all ASCII data to clipboard.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")

    def hex_highlight_flags(self):
        """Highlight flag-like patterns in ASCII data and show in a popup."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        import re
        try:
            with open(self.selected_file_path, 'rb') as f:
                ascii_data = f.read().decode(errors='replace')
            flags = []
            flag_patterns = [
                r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'key\{[^}]+\}', r'KEY\{[^}]+\}'
            ]
            for pattern in flag_patterns:
                found = re.findall(pattern, ascii_data)
                flags.extend(found)
            if flags:
                self.clipboard_clear()
                self.clipboard_append('\n'.join(flags))
                messagebox.showinfo("Flags Found", f"Copied {len(flags)} flag(s) to clipboard.\n\n" + '\n'.join(flags[:10]) + ("\n..." if len(flags) > 10 else ""))
            else:
                messagebox.showinfo("No Flags", "No flag-like patterns found in ASCII data.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")

    def create_file_selection(self):
        """Create file selection area"""
        self.file_selector = FileSelector(self.main_frame, title="Select File", file_types=[
            ("All Files", "*.*"),
            ("Image Files", "*.jpg *.jpeg *.png *.bmp *.gif *.tiff *.ico *.webp")
        ])
        self.file_selector.pack(fill='x', pady=(0, Theme.get_spacing('medium')))
        # Add Load Image button
        load_btn = ModernButton(self.main_frame, text="Load Image", command=self.load_file, style='primary')
        load_btn.pack(fill='x', pady=(0, Theme.get_spacing('small')))
        # Image/file preview label
        self.image_label = tk.Label(self.main_frame, text="No file selected", font=Theme.get_font('default'), bg=Theme.get_color('primary'), fg=Theme.get_color('text_secondary'))
        self.image_label.pack(fill='x', pady=(0, Theme.get_spacing('medium')))

    def create_main_content(self):
        """Create main content area (tools + results side by side)"""
        content_frame = tk.Frame(self.main_frame, bg=Theme.get_color('secondary'))
        content_frame.pack(fill='both', expand=True, pady=(0, Theme.get_spacing('medium')))
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(0, weight=1)

        # Left: Tool buttons (with vertical scrollbar)
        tools_canvas = tk.Canvas(content_frame, bg=Theme.get_color('primary'), highlightthickness=0)
        tools_scrollbar = tk.Scrollbar(content_frame, orient='vertical', command=tools_canvas.yview)
        tools_canvas.grid(row=0, column=0, sticky='ns', padx=(0, Theme.get_spacing('large')))
        tools_scrollbar.grid(row=0, column=0, sticky='nse', padx=(0, Theme.get_spacing('large')))

        tools_inner_frame = tk.Frame(tools_canvas, bg=Theme.get_color('primary'))
        tools_inner_frame.bind(
            '<Configure>',
            lambda e: tools_canvas.configure(scrollregion=tools_canvas.bbox('all'))
        )
        tools_canvas.create_window((0, 0), window=tools_inner_frame, anchor='nw')
        tools_canvas.configure(yscrollcommand=tools_scrollbar.set, height=400)

        # Add tool buttons to the inner frame
        ToolButton(tools_inner_frame, text="EXIF", description="Analyze EXIF data", command=self.analyze_exif, icon="��").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="Location", description="Analyze GPS/location", command=self.analyze_location, icon="📍").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="Steganography", description="Detect/Hide data in images", command=self.open_steganography, icon="🕵️").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="Metadata", description="Analyze file metadata", command=self.analyze_metadata, icon="📝").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="Strings", description="Extract strings from file", command=self.analyze_strings, icon="🔤").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="Binwalk", description="Scan for embedded files", command=self.analyze_binwalk, icon="🛠️").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="Zsteg", description="Detect stego in PNG/BMP", command=self.analyze_zsteg, icon="🎨").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="OCR", description="Extract text from image", command=self.analyze_ocr, icon="🔎").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="QR/Barcode", description="Scan for QR/barcodes", command=self.analyze_qr_barcode, icon="📱").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="File Carving", description="Extract embedded files", command=self.analyze_file_carving, icon="🗜️").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="CTF Auto", description="Run all CTF analyses", command=self.ctf_auto_analyze, icon="🚀").pack(fill='x', pady=2)
        ToolButton(tools_inner_frame, text="Hex Viewer", description="View file in hex", command=self.open_hex_viewer, icon="🔢").pack(fill='x', pady=2)

        # Right: Results area
        self.result_frame = tk.Frame(content_frame, bg=Theme.get_color('secondary'), highlightbackground=Theme.get_color('accent'), highlightthickness=1)
        self.result_frame.grid(row=0, column=1, sticky='nsew')
        self.result_frame.columnconfigure(0, weight=1)
        self.result_frame.rowconfigure(1, weight=1)

        # Search bar and buttons
        search_frame = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        search_frame.grid(row=0, column=0, sticky='ew', padx=Theme.get_spacing('medium'), pady=(Theme.get_spacing('medium'), 0))
        search_frame.columnconfigure(1, weight=1)
        tk.Label(search_frame, text="Search Results:", bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'), font=Theme.get_font('default')).pack(side='left')
        search_entry = tk.Entry(search_frame, textvariable=self.result_search_var, bg=Theme.get_color('entry_bg'), fg=Theme.get_color('entry_fg'), insertbackground=Theme.get_color('accent'))
        search_entry.pack(side='left', fill='x', expand=True, padx=(8, 0))
        tk.Button(search_frame, text="Search", command=self.search_in_results).pack(side='left', padx=4)
        tk.Button(search_frame, text="Copy", command=self.copy_results).pack(side='left', padx=4)
        tk.Button(search_frame, text="Clear", command=self.clear_results).pack(side='left', padx=4)

        # --- Dynamic CTF Feature Button Area ---
        self.ctf_feature_button_frame = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        self.ctf_feature_button_frame.grid(row=1, column=0, sticky='ew', padx=Theme.get_spacing('medium'), pady=(0, 4))

        # --- Output Font Size Buttons ---
        font_size_frame = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        font_size_frame.grid(row=2, column=0, sticky='e', padx=(0, Theme.get_spacing('medium')), pady=(0, 2))
        self.output_font_size = 10
        ModernButton(font_size_frame, text="A+", command=self.increase_output_font, style='secondary', width=4).pack(side='right', padx=2)
        ModernButton(font_size_frame, text="A-", command=self.decrease_output_font, style='secondary', width=4).pack(side='right', padx=2)

        # Results text area
        self.result_text = ModernText(self.result_frame, wrap='word')
        self.result_text.grid(row=3, column=0, sticky='nsew', padx=Theme.get_spacing('medium'), pady=(0, Theme.get_spacing('medium')))
        # Set initial font size
        self.set_output_font_size(self.output_font_size)

    def set_output_font_size(self, size):
        if hasattr(self, 'result_text') and self.result_text:
            self.result_text.configure(font=("Segoe UI", size))

    def increase_output_font(self):
        if self.output_font_size < 32:
            self.output_font_size += 1
            self.set_output_font_size(self.output_font_size)

    def decrease_output_font(self):
        if self.output_font_size > 6:
            self.output_font_size -= 1
            self.set_output_font_size(self.output_font_size)

    def update_ctf_feature_buttons(self, features):
        """Update the dynamic CTF feature button area with a list of (label, command) tuples."""
        for widget in self.ctf_feature_button_frame.winfo_children():
            widget.destroy()
        max_cols = 3
        for i, (label, command) in enumerate(features):
            btn = ModernButton(self.ctf_feature_button_frame, text=label, command=command, style='secondary', width=16)
            row, col = divmod(i, max_cols)
            btn.grid(row=row, column=col, padx=3, pady=3, sticky='ew')
        for col in range(max_cols):
            self.ctf_feature_button_frame.grid_columnconfigure(col, weight=1)

    def create_status_bar(self):
        """Create status bar at the bottom"""
        self.status_bar = StatusBar(self.main_frame)
        self.status_bar.pack(fill='x', side='bottom')

    def _analyze_qr_barcode_thread(self):
        """QR/Barcode analysis in thread"""
        if not self.selected_file_path:
            return "Error: No file selected."
        try:
            # Check if file is an image
            if not self.selected_file_path.lower().endswith((
                '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.ico', '.webp')):
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
                        if content_analysis and content_analysis['type'] != 'unknown':
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

    def file_carving_auto_extract(self):
        """Automatically extract all carved files and show a summary."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        result = self.file_carving_analyzer.auto_carve(self.selected_file_path)
        if not result.get('success'):
            messagebox.showerror("Extraction Failed", result.get('error', 'Unknown error'))
            return
        files = []
        # Collect files from foremost and binwalk
        if result.get('foremost_results') and result['foremost_results'].get('success'):
            files += [f.get('filename') for f in result['foremost_results'].get('files_found', [])]
        if result.get('binwalk_results') and result['binwalk_results'].get('success'):
            files += [f.get('filename') for f in result['binwalk_results'].get('files_found', [])]
        if files:
            messagebox.showinfo("Extraction Complete", f"Extracted {len(files)} file(s):\n\n" + '\n'.join(files[:10]) + ("\n..." if len(files) > 10 else ""))
        else:
            messagebox.showinfo("No Files", "No files were extracted.")

    def file_carving_copy_filenames(self):
        """Copy all carved filenames to clipboard."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        result = self.file_carving_analyzer.auto_carve(self.selected_file_path)
        if not result.get('success'):
            messagebox.showerror("Extraction Failed", result.get('error', 'Unknown error'))
            return
        files = []
        if result.get('foremost_results') and result['foremost_results'].get('success'):
            files += [f.get('filename') for f in result['foremost_results'].get('files_found', [])]
        if result.get('binwalk_results') and result['binwalk_results'].get('success'):
            files += [f.get('filename') for f in result['binwalk_results'].get('files_found', [])]
        if files:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(files))
            messagebox.showinfo("Copied", f"Copied {len(files)} filename(s) to clipboard.\n\n" + '\n'.join(files[:10]) + ("\n..." if len(files) > 10 else ""))
        else:
            messagebox.showinfo("No Files", "No files were extracted.")

    def file_carving_highlight_flags(self):
        """Highlight flag-like patterns in carved files' names and show in a popup."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        import re
        result = self.file_carving_analyzer.auto_carve(self.selected_file_path)
        if not result.get('success'):
            messagebox.showerror("Extraction Failed", result.get('error', 'Unknown error'))
            return
        files = []
        if result.get('foremost_results') and result['foremost_results'].get('success'):
            files += [f.get('filename') for f in result['foremost_results'].get('files_found', [])]
        if result.get('binwalk_results') and result['binwalk_results'].get('success'):
            files += [f.get('filename') for f in result['binwalk_results'].get('files_found', [])]
        flags = []
        flag_patterns = [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'key\{[^}]+\}', r'KEY\{[^}]+\}'
        ]
        for fname in files:
            for pattern in flag_patterns:
                found = re.findall(pattern, fname)
                flags.extend(found)
        if flags:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(flags))
            messagebox.showinfo("Flags Found", f"Copied {len(flags)} flag(s) to clipboard.\n\n" + '\n'.join(flags[:10]) + ("\n..." if len(flags) > 10 else ""))
        else:
            messagebox.showinfo("No Flags", "No flag-like patterns found in carved filenames.")

    def stego_extract_hidden_text(self):
        """Extract hidden text from image using steganography analyzer."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        passphrase = simpledialog.askstring("Passphrase", "Enter passphrase for extraction (leave blank if none):", show='*')
        if passphrase is None:
            return  # User cancelled
        result = self.steganography_analyzer.extract_data(self.selected_file_path, passphrase, extract_as_file=False)
        if result.get('success') and result.get('data'):
            self.clipboard_clear()
            self.clipboard_append(result['data'])
            messagebox.showinfo("Extracted", f"Extracted hidden text and copied to clipboard.\n\n{result['data'][:500]}" + ("\n..." if len(result['data']) > 500 else ""))
        else:
            messagebox.showinfo("No Data", result.get('error', 'No hidden text found or extraction failed.'))

    def stego_extract_hidden_file(self):
        """Extract hidden file from image using steganography analyzer."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        passphrase = simpledialog.askstring("Passphrase", "Enter passphrase for extraction (leave blank if none):", show='*')
        if passphrase is None:
            return  # User cancelled
        result = self.steganography_analyzer.extract_data(self.selected_file_path, passphrase, extract_as_file=True)
        if result.get('success') and result.get('extracted_file'):
            messagebox.showinfo("Extracted", f"Extracted hidden file: {result['extracted_file']}")
        else:
            messagebox.showinfo("No File", result.get('error', 'No hidden file found or extraction failed.'))

    def stego_highlight_flags(self):
        """Highlight flag-like patterns in extracted hidden text and show in a popup."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        passphrase = simpledialog.askstring("Passphrase", "Enter passphrase for extraction (leave blank if none):", show='*')
        if passphrase is None:
            return  # User cancelled
        result = self.steganography_analyzer.extract_data(self.selected_file_path, passphrase, extract_as_file=False)
        if not result.get('success') or not result.get('data'):
            messagebox.showinfo("No Data", result.get('error', 'No hidden text found or extraction failed.'))
            return
        import re
        text = result['data']
        flags = []
        flag_patterns = [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'key\{[^}]+\}', r'KEY\{[^}]+\}'
        ]
        for pattern in flag_patterns:
            found = re.findall(pattern, text)
            flags.extend(found)
        if flags:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(flags))
            messagebox.showinfo("Flags Found", f"Copied {len(flags)} flag(s) to clipboard.\n\n" + '\n'.join(flags[:10]) + ("\n..." if len(flags) > 10 else ""))
        else:
            messagebox.showinfo("No Flags", "No flag-like patterns found in hidden text.")

    def zsteg_extract_all(self):
        """Extract all possible data using Zsteg and show a summary."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        result = self.zsteg_analyzer.basic_scan(self.selected_file_path)
        if not result.get('success'):
            messagebox.showerror("Extraction Failed", result.get('error', 'Unknown error'))
            return
        findings = result.get('findings', [])
        if findings:
            messagebox.showinfo("Extraction Complete", f"Extracted {len(findings)} finding(s):\n\n" + '\n'.join(str(f) for f in findings[:10]) + ("\n..." if len(findings) > 10 else ""))
        else:
            messagebox.showinfo("No Data", "No findings were extracted.")

    def zsteg_copy_all_results(self):
        """Copy all Zsteg findings/results to clipboard."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        result = self.zsteg_analyzer.basic_scan(self.selected_file_path)
        if not result.get('success'):
            messagebox.showerror("Extraction Failed", result.get('error', 'Unknown error'))
            return
        findings = result.get('findings', [])
        if findings:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(str(f) for f in findings))
            messagebox.showinfo("Copied", f"Copied {len(findings)} finding(s) to clipboard.\n\n" + '\n'.join(str(f) for f in findings[:10]) + ("\n..." if len(findings) > 10 else ""))
        else:
            messagebox.showinfo("No Data", "No findings were extracted.")

    def zsteg_highlight_flags(self):
        """Highlight flag-like patterns in Zsteg findings and show in a popup."""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file loaded.")
            return
        import re
        result = self.zsteg_analyzer.basic_scan(self.selected_file_path)
        if not result.get('success'):
            messagebox.showerror("Extraction Failed", result.get('error', 'Unknown error'))
            return
        findings = result.get('findings', [])
        flags = []
        flag_patterns = [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'key\{[^}]+\}', r'KEY\{[^}]+\}'
        ]
        for finding in findings:
            for pattern in flag_patterns:
                found = re.findall(pattern, str(finding))
                flags.extend(found)
        if flags:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(flags))
            messagebox.showinfo("Flags Found", f"Copied {len(flags)} flag(s) to clipboard.\n\n" + '\n'.join(flags[:10]) + ("\n..." if len(flags) > 10 else ""))
        else:
            messagebox.showinfo("No Flags", "No flag-like patterns found in Zsteg findings.")

    def apply_theme(self):
        self.apply_theme_to_all_widgets()

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

        # --- CTF Feature Button Area ---
        self.ctf_feature_button_frame = tk.Frame(main_frame, bg=Theme.get_color('primary'))
        self.ctf_feature_button_frame.pack(fill='x', pady=(0, Theme.get_spacing('medium')))
        ctf_buttons = [
            ("Try Common Passwords", self.ctf_try_common_passwords),
            ("Run LSB Analysis", self.ctf_run_lsb_analysis),
            ("Extract Hidden Data", self.ctf_extract_hidden_data),
        ]
        max_cols = 3
        for i, (label, command) in enumerate(ctf_buttons):
            btn = ModernButton(self.ctf_feature_button_frame, text=label, command=command, style='secondary', width=16)
            row, col = divmod(i, max_cols)
            btn.grid(row=row, column=col, padx=3, pady=3, sticky='ew')
        for col in range(max_cols):
            self.ctf_feature_button_frame.grid_columnconfigure(col, weight=1)
        
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
        
    def ctf_try_common_passwords(self):
        messagebox.showinfo("Not Implemented", "This would try common steghide passwords and show results.")

    def ctf_run_lsb_analysis(self):
        messagebox.showinfo("Not Implemented", "This would run LSB steganalysis (e.g., zsteg, stegsolve) and show results.")

    def ctf_extract_hidden_data(self):
        messagebox.showinfo("Not Implemented", "This would extract hidden data using steghide or other methods.")
    
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