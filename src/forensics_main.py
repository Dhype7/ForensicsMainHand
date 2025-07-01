"""
Forensics Toolkit Main Window
"""
import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
from typing import Optional, Union
import threading
import webbrowser

# Add the modules directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

from ui.theme import Theme
from ui.widgets import ModernButton
from config.settings import Settings
from modules.file_analyzer.file_main import FileAnalyzerMainWindow
from modules.photo_analyzer.main_window import MainWindow as PhotoAnalyzerMainWindow
from modules.cryptography.crypto_main import CryptoMainWindow

class ForensicsToolkitWindow:
    """Main forensics toolkit window with three main modules"""
    
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.theme_var = tk.StringVar(value=Theme.get_current_theme())
        self.file_analyzer_frame = FileAnalyzerMainWindow(self.root, self.show_main_menu)
        self.photo_analyzer_frame = PhotoAnalyzerMainWindow(self.root, self.show_main_menu)
        self.crypto_frame = CryptoMainWindow(self.root, self.show_main_menu)
        self.setup_window()
        self.create_widgets()
        self.setup_layout()
        self.apply_theme()
        
    def setup_window(self):
        """Setup main window properties"""
        self.root.title(f"{Settings.APP_NAME} - Forensics Toolkit v{Settings.APP_VERSION}")
        self.root.geometry("1400x1000")
        self.root.minsize(1000, 800)
        
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
        self.main_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('large'), 
                           pady=Theme.get_spacing('large'))
        
        # Header
        self.create_header()
        
        # Main content area
        self.create_main_content()
        
        # Footer
        self.create_footer()
        
        # File Analyzer frame (hidden by default)
        self.file_analyzer_frame.pack_forget()  # type: ignore
        self.photo_analyzer_frame.pack_forget()  # type: ignore
        self.crypto_frame.pack_forget()  # type: ignore
        
    def create_header(self):
        """Create application header"""
        header_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        header_frame.pack(fill='x', pady=(0, Theme.get_spacing('large')))
        
        # Title
        title_label = tk.Label(header_frame, 
                              text="Forensics Toolkit",
                              font=Theme.get_font('title'),
                              bg=Theme.get_color('primary'),
                              fg=Theme.get_color('accent'))
        title_label.pack(side='left')
        
        # Theme selector
        theme_label = tk.Label(header_frame, 
                              text="Theme:", 
                              bg=Theme.get_color('primary'), 
                              fg=Theme.get_color('text_secondary'), 
                              font=Theme.get_font('default'))
        theme_label.pack(side='right', padx=(0, 5))
        
        theme_dropdown = ttk.Combobox(header_frame, 
                                     textvariable=self.theme_var, 
                                     values=Theme.get_available_themes(), 
                                     width=8, 
                                     state='readonly')
        theme_dropdown.pack(side='right', padx=(0, 10))
        theme_dropdown.bind('<<ComboboxSelected>>', self.on_theme_change)
        
        # Subtitle
        subtitle_label = tk.Label(header_frame,
                                 text="Comprehensive Digital Forensics Analysis Suite",
                                 font=Theme.get_font('default'),
                                 bg=Theme.get_color('primary'),
                                 fg=Theme.get_color('text_secondary'))
        subtitle_label.pack(anchor='w')
        
    def create_main_content(self):
        """Create main content area with three module buttons"""
        content_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        content_frame.pack(fill='both', expand=True, pady=Theme.get_spacing('large'))
        
        # Welcome message
        welcome_label = tk.Label(content_frame,
                                text="Select a module to begin analysis:",
                                font=Theme.get_font('heading'),
                                bg=Theme.get_color('primary'),
                                fg=Theme.get_color('text_primary'))
        welcome_label.pack(pady=(0, Theme.get_spacing('large')))
        
        # Buttons container
        buttons_frame = tk.Frame(content_frame, bg=Theme.get_color('primary'))
        buttons_frame.pack(expand=True)
        
        # Configure grid weights for centering
        buttons_frame.columnconfigure(0, weight=1)
        buttons_frame.columnconfigure(1, weight=1)
        buttons_frame.columnconfigure(2, weight=1)
        
        # Cryptography Module Button
        crypto_frame = tk.Frame(buttons_frame, bg=Theme.get_color('secondary'), 
                               relief='raised', bd=2)
        crypto_frame.grid(row=0, column=0, padx=Theme.get_spacing('medium'), 
                         pady=Theme.get_spacing('medium'), sticky='nsew')
        
        crypto_icon = tk.Label(crypto_frame, text="🔐", font=('Arial', 48),
                              bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        crypto_icon.pack(pady=(Theme.get_spacing('medium'), Theme.get_spacing('small')))
        
        crypto_title = tk.Label(crypto_frame, text="Cryptography", 
                               font=Theme.get_font('heading'),
                               bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'))
        crypto_title.pack()
        
        crypto_desc = tk.Label(crypto_frame, text="Encryption/Decryption\nHash Analysis\nKey Management",
                              font=Theme.get_font('small'),
                              bg=Theme.get_color('secondary'), fg=Theme.get_color('text_secondary'),
                              justify='center')
        crypto_desc.pack(pady=(0, Theme.get_spacing('medium')))
        
        self.crypto_button = ModernButton(crypto_frame, text="Open Cryptography",
                                         command=self.open_cryptography, style='primary')
        self.crypto_button.pack(pady=(0, Theme.get_spacing('medium')))
        
        # Photo Analyzer Module Button
        photo_frame = tk.Frame(buttons_frame, bg=Theme.get_color('secondary'), 
                              relief='raised', bd=2)
        photo_frame.grid(row=0, column=1, padx=Theme.get_spacing('medium'), 
                        pady=Theme.get_spacing('medium'), sticky='nsew')
        
        photo_icon = tk.Label(photo_frame, text="📷", font=('Arial', 48),
                             bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        photo_icon.pack(pady=(Theme.get_spacing('medium'), Theme.get_spacing('small')))
        
        photo_title = tk.Label(photo_frame, text="Photo Analyzer", 
                              font=Theme.get_font('heading'),
                              bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'))
        photo_title.pack()
        
        photo_desc = tk.Label(photo_frame, text="EXIF Analysis\nSteganography\nMetadata Extraction",
                             font=Theme.get_font('small'),
                             bg=Theme.get_color('secondary'), fg=Theme.get_color('text_secondary'),
                             justify='center')
        photo_desc.pack(pady=(0, Theme.get_spacing('medium')))
        
        self.photo_button = ModernButton(photo_frame, text="Open Photo Analyzer",
                                        command=self.open_photo_analyzer, style='primary')
        self.photo_button.pack(pady=(0, Theme.get_spacing('medium')))
        
        # File Analyzer Module Button
        file_frame = tk.Frame(buttons_frame, bg=Theme.get_color('secondary'), 
                             relief='raised', bd=2)
        file_frame.grid(row=0, column=2, padx=Theme.get_spacing('medium'), 
                       pady=Theme.get_spacing('medium'), sticky='nsew')
        
        file_icon = tk.Label(file_frame, text="📁", font=('Arial', 48),
                            bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        file_icon.pack(pady=(Theme.get_spacing('medium'), Theme.get_spacing('small')))
        
        file_title = tk.Label(file_frame, text="File Analyzer", 
                             font=Theme.get_font('heading'),
                             bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'))
        file_title.pack()
        
        file_desc = tk.Label(file_frame, text="File Carving\nString Analysis\nBinary Analysis",
                            font=Theme.get_font('small'),
                            bg=Theme.get_color('secondary'), fg=Theme.get_color('text_secondary'),
                            justify='center')
        file_desc.pack(pady=(0, Theme.get_spacing('medium')))
        
        self.file_button = ModernButton(file_frame, text="Open File Analyzer",
                                       command=self.open_file_analyzer, style='primary')
        self.file_button.pack(pady=(0, Theme.get_spacing('medium')))
        
        # Web Analyzer Button (new)
        web_frame = tk.Frame(buttons_frame, bg=Theme.get_color('secondary'), relief='raised', bd=2)
        web_frame.grid(row=1, column=1, padx=Theme.get_spacing('medium'), pady=Theme.get_spacing('medium'), sticky='nsew')
        web_icon = tk.Label(web_frame, text="🌐", font=('Arial', 48), bg=Theme.get_color('secondary'), fg=Theme.get_color('accent'))
        web_icon.pack(pady=(Theme.get_spacing('medium'), Theme.get_spacing('small')))
        web_title = tk.Label(web_frame, text="Web Analyzer", font=Theme.get_font('heading'), bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'))
        web_title.pack()
        web_desc = tk.Label(web_frame, text="Web Recon\nVulnerability Scan\nHeaders & Ports", font=Theme.get_font('small'), bg=Theme.get_color('secondary'), fg=Theme.get_color('text_secondary'), justify='center')
        web_desc.pack(pady=(0, Theme.get_spacing('medium')))
        self.web_button = ModernButton(web_frame, text="Launch Web Analyzer", command=self.launch_web_analyzer, style='primary')
        self.web_button.pack(pady=(0, Theme.get_spacing('medium')))
        
    def create_footer(self):
        """Create footer with status information"""
        footer_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        footer_frame.pack(fill='x', pady=(Theme.get_spacing('large'), 0))
        
        # Status info
        status_label = tk.Label(footer_frame,
                               text=f"Forensics Toolkit v{Settings.APP_VERSION} | Ready",
                               font=Theme.get_font('small'),
                               bg=Theme.get_color('primary'),
                               fg=Theme.get_color('text_muted'))
        status_label.pack(side='left')
        
        # Copyright
        copyright_label = tk.Label(footer_frame,
                                  text="© 2024 Forensics Toolkit",
                                  font=Theme.get_font('small'),
                                  bg=Theme.get_color('primary'),
                                  fg=Theme.get_color('text_muted'))
        copyright_label.pack(side='right')
        
    def setup_layout(self):
        """Setup layout configuration"""
        self.main_frame.pack_configure(fill='both', expand=True)
        
    def apply_theme(self):
        """Apply current theme to all widgets"""
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
        
    def on_theme_change(self, event=None):
        """Handle theme change"""
        Theme.set_theme(self.theme_var.get())
        self.apply_theme()
        
    def show_main_menu(self):
        self.file_analyzer_frame.pack_forget()  # type: ignore
        self.photo_analyzer_frame.pack_forget()  # type: ignore
        self.crypto_frame.pack_forget()  # type: ignore
        self.main_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('large'), 
                           pady=Theme.get_spacing('large'))

    def open_file_analyzer(self):
        try:
            self.main_frame.pack_forget()
            self.photo_analyzer_frame.pack_forget()  # type: ignore
            self.crypto_frame.pack_forget()  # type: ignore
            self.file_analyzer_frame.pack(fill='both', expand=True)  # type: ignore
        except Exception as e:
            messagebox.showerror("Error", f"Error opening File Analyzer module: {str(e)}")

    def open_photo_analyzer(self):
        try:
            self.main_frame.pack_forget()
            self.file_analyzer_frame.pack_forget()  # type: ignore
            self.crypto_frame.pack_forget()  # type: ignore
            self.photo_analyzer_frame.pack(fill='both', expand=True)  # type: ignore
        except Exception as e:
            messagebox.showerror("Error", f"Error opening Photo Analyzer module: {str(e)}")

    def open_cryptography(self):
        try:
            self.main_frame.pack_forget()
            self.file_analyzer_frame.pack_forget()  # type: ignore
            self.photo_analyzer_frame.pack_forget()  # type: ignore
            self.crypto_frame.pack(fill='both', expand=True)  # type: ignore
        except Exception as e:
            messagebox.showerror("Error", f"Error opening Cryptography module: {str(e)}")

    def launch_web_analyzer(self):
        """Launch the Flask web analyzer in a separate thread and show a clickable hyperlink"""
        def run_flask():
            import webanalyzer
            webanalyzer.app.run(debug=True, use_reloader=False)
        threading.Thread(target=run_flask, daemon=True).start()

        # Create a new window with a clickable hyperlink
        link_window = tk.Toplevel(self.root)
        link_window.title("Web Analyzer Launched")
        link_window.geometry("350x120")
        link_window.configure(bg=Theme.get_color('primary'))

        info_label = tk.Label(link_window, text="Web Analyzer is running!", font=Theme.get_font('heading'), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        info_label.pack(pady=(20, 5))

        url = "http://127.0.0.1:5000"
        def open_link(event=None):
            webbrowser.open(url)

        link_label = tk.Label(link_window, text="Open Web Analyzer in Browser", font=Theme.get_font('default'), fg="blue", cursor="hand2", bg=Theme.get_color('primary'))
        link_label.pack()
        link_label.bind("<Button-1>", open_link)

        url_label = tk.Label(link_window, text=url, font=Theme.get_font('small'), fg=Theme.get_color('text_secondary'), bg=Theme.get_color('primary'))
        url_label.pack(pady=(5, 10)) 