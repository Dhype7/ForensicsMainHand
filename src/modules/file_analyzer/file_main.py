"""
File Analyzer Module Main Window
"""
import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys

# Add parent directories to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from ui.theme import Theme
from ui.widgets import ModernButton
from config.settings import Settings

class FileMainWindow:
    """Main window for File Analyzer module"""
    
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.theme_var = tk.StringVar(value=Theme.get_current_theme())
        
        self.setup_window()
        self.create_widgets()
        self.setup_layout()
        self.apply_theme()
        
    def setup_window(self):
        """Setup main window properties"""
        self.root.title(f"File Analyzer - {Settings.APP_NAME} v{Settings.APP_VERSION}")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
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
        
    def create_header(self):
        """Create application header"""
        header_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        header_frame.pack(fill='x', pady=(0, Theme.get_spacing('large')))
        
        # Title
        title_label = tk.Label(header_frame, 
                              text="File Analyzer Module",
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
                                 text="File Carving, String Analysis, and Binary Analysis Tools",
                                 font=Theme.get_font('default'),
                                 bg=Theme.get_color('primary'),
                                 fg=Theme.get_color('text_secondary'))
        subtitle_label.pack(anchor='w')
        
    def create_main_content(self):
        """Create main content area"""
        content_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        content_frame.pack(fill='both', expand=True, pady=Theme.get_spacing('large'))
        
        # Coming soon message
        coming_soon_label = tk.Label(content_frame,
                                    text="📁 File Analyzer Module",
                                    font=Theme.get_font('title'),
                                    bg=Theme.get_color('primary'),
                                    fg=Theme.get_color('accent'))
        coming_soon_label.pack(pady=(50, 20))
        
        status_label = tk.Label(content_frame,
                               text="Coming Soon!",
                               font=Theme.get_font('heading'),
                               bg=Theme.get_color('primary'),
                               fg=Theme.get_color('text_primary'))
        status_label.pack(pady=(0, 30))
        
        features_label = tk.Label(content_frame,
                                 text="This module will include:\n• File carving tools\n• String analysis\n• Binary analysis\n• File format detection\n• Memory analysis",
                                 font=Theme.get_font('default'),
                                 bg=Theme.get_color('primary'),
                                 fg=Theme.get_color('text_secondary'),
                                 justify='center')
        features_label.pack()
        
    def create_footer(self):
        """Create footer with status information"""
        footer_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        footer_frame.pack(fill='x', pady=(Theme.get_spacing('large'), 0))
        
        # Status info
        status_label = tk.Label(footer_frame,
                               text=f"File Analyzer Module v{Settings.APP_VERSION} | Under Development",
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