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
from PIL import Image, ImageTk

# Add the modules directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

from ui.theme import Theme
from ui.widgets import ModernButton, NYXBackground
from config.settings import Settings
from modules.file_analyzer.file_main import FileAnalyzerMainWindow
from modules.photo_analyzer.main_window import MainWindow as PhotoAnalyzerMainWindow
from modules.cryptography.crypto_main import CryptoMainWindow

class ForensicsToolkitWindow:
    """Main forensics toolkit window with three main modules"""
    
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.theme_var = tk.StringVar(value=Theme.get_current_theme())
        # Pass global theme change callback to submodules
        self.file_analyzer_frame = FileAnalyzerMainWindow(self.root, self.show_main_menu, theme_change_callback=self.global_on_theme_change, theme_var=self.theme_var)
        self.photo_analyzer_frame = PhotoAnalyzerMainWindow(self.root, self.show_main_menu, theme_change_callback=self.global_on_theme_change, theme_var=self.theme_var)
        self.crypto_frame = CryptoMainWindow(self.root, self.show_main_menu, theme_change_callback=self.global_on_theme_change, theme_var=self.theme_var)
        self.setup_window()
        self.create_widgets()
        self.setup_layout()
        self.apply_theme()
        
    def setup_window(self):
        """Setup main window properties"""
        self.root.title(f"{Settings.APP_NAME} - Forensics Toolkit v{Settings.APP_VERSION}")
        self.root.geometry("1200x1000")
        self.root.minsize(1000, 800)
        
        # Configure window
        self.root.configure(bg=Theme.get_color('primary'))
        
        # Center window on screen
        self.center_window()
        
    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = 1200
        height = 1000
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        self.main_frame = tk.Frame(self.root, bg=Theme.get_color('primary'))
        self.main_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('large'), 
                           pady=Theme.get_spacing('large'))
        # NYX background inside main_frame
        self.nyx_bg = NYXBackground(self.main_frame)
        self.nyx_bg.place(x=0, y=0, relwidth=1, relheight=1)
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
        header_frame = tk.Frame(self.main_frame)
        header_frame.pack(fill='x', pady=(0, Theme.get_spacing('large')))
        
        # Title with NYX logo
        try:
            logo_img = Image.open("pics/Picsart_25-07-01_17-15-32-191.png")
            logo_img = logo_img.resize((32, 32), Image.Resampling.LANCZOS)
            logo = ImageTk.PhotoImage(logo_img)
            logo_label = tk.Label(header_frame, image=logo, bg=Theme.get_color('primary'))
            setattr(logo_label, "image", logo)  # Keep reference
            logo_label.pack(side='left', padx=(0, 8))
        except Exception:
            logo_label = tk.Label(header_frame, text="NYX", font=("Arial", 16, "bold"), fg="#FFD600", bg=Theme.get_color('primary'))
            logo_label.pack(side='left', padx=(0, 8))
        title_label = tk.Label(header_frame, 
                              text="Forensics Toolkit",
                              font=Theme.get_font('title'),
                              fg=Theme.get_color('accent'),
                              bg=Theme.get_color('primary'))
        title_label.pack(side='left')
        
        # Theme selector
        theme_label = tk.Label(header_frame, 
                              text="Theme:", 
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
                                 fg=Theme.get_color('text_secondary'))
        subtitle_label.pack(anchor='w')
        
    def create_main_content(self):
        """Create main content area with four large square module buttons in a 2x2 grid and a Next button"""
        self.content_frame = tk.Frame(self.main_frame)
        self.content_frame.pack(fill='both', expand=True, pady=Theme.get_spacing('large'))

        # Welcome message
        welcome_label = tk.Label(self.content_frame,
                                text="Select a module to begin analysis:",
                                font=Theme.get_font('heading'),
                                fg=Theme.get_color('text_primary'),
                                bg=Theme.get_color('primary'))
        welcome_label.pack(pady=(0, Theme.get_spacing('large')))

        # Buttons container
        self.buttons_frame = tk.Frame(self.content_frame, bg=Theme.get_color('primary'))
        self.buttons_frame.pack(expand=True, fill='both')

        # Configure grid weights for a 2x2 square layout
        for i in range(2):
            self.buttons_frame.columnconfigure(i, weight=1, uniform='col')
            self.buttons_frame.rowconfigure(i, weight=1, uniform='row')

        square_size = 320  # Size for each module square
        icon_font = ('Arial', 64)
        title_font = Theme.get_font('title')
        desc_font = Theme.get_font('default')

        # Cryptography Module Button (Top Left)
        crypto_frame = tk.Frame(self.buttons_frame, relief='raised', bd=3, width=square_size, height=square_size, bg=Theme.get_color('secondary'))
        crypto_frame.grid(row=0, column=0, padx=Theme.get_spacing('large'), pady=Theme.get_spacing('large'), sticky='nsew')
        crypto_frame.grid_propagate(False)
        crypto_icon = tk.Label(crypto_frame, text="🔐", font=icon_font, fg=Theme.get_color('accent'), bg=Theme.get_color('secondary'))
        crypto_icon.pack(pady=(Theme.get_spacing('large'), Theme.get_spacing('small')))
        crypto_title = tk.Label(crypto_frame, text="Cryptography", font=title_font, fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        crypto_title.pack()
        crypto_desc = tk.Label(
            crypto_frame,
            text="Encrypt and decrypt messages using both classical and modern algorithms. Analyze hashes, manage cryptographic keys, and experiment with cipher techniques for secure communication and CTF challenges.",
            font=desc_font,
            fg=Theme.get_color('text_secondary'),
            bg=Theme.get_color('secondary'),
            wraplength=square_size-30,
            justify='center')
        crypto_desc.pack(pady=(Theme.get_spacing('small'), Theme.get_spacing('medium')))
        self.crypto_button = ModernButton(crypto_frame, text="Open Cryptography", command=self.open_cryptography, style='primary')
        self.crypto_button.pack(pady=(0, Theme.get_spacing('medium')))

        # Photo Analyzer Module Button (Top Right)
        photo_frame = tk.Frame(self.buttons_frame, relief='raised', bd=3, width=square_size, height=square_size, bg=Theme.get_color('secondary'))
        photo_frame.grid(row=0, column=1, padx=Theme.get_spacing('large'), pady=Theme.get_spacing('large'), sticky='nsew')
        photo_frame.grid_propagate(False)
        photo_icon = tk.Label(photo_frame, text="📷", font=icon_font, fg=Theme.get_color('accent'), bg=Theme.get_color('secondary'))
        photo_icon.pack(pady=(Theme.get_spacing('large'), Theme.get_spacing('small')))
        photo_title = tk.Label(photo_frame, text="Photo Analyzer", font=title_font, fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        photo_title.pack()
        photo_desc = tk.Label(
            photo_frame,
            text="Investigate images for hidden information. Extract and analyze EXIF metadata, perform steganography detection, run OCR, and uncover secrets embedded in photos for forensic or CTF use.",
            font=desc_font,
            fg=Theme.get_color('text_secondary'),
            bg=Theme.get_color('secondary'),
            wraplength=square_size-30,
            justify='center')
        photo_desc.pack(pady=(Theme.get_spacing('small'), Theme.get_spacing('medium')))
        self.photo_button = ModernButton(photo_frame, text="Open Photo Analyzer", command=self.open_photo_analyzer, style='primary')
        self.photo_button.pack(pady=(0, Theme.get_spacing('medium')))

        # File Analyzer Module Button (Bottom Left)
        file_frame = tk.Frame(self.buttons_frame, relief='raised', bd=3, width=square_size, height=square_size, bg=Theme.get_color('secondary'))
        file_frame.grid(row=1, column=0, padx=Theme.get_spacing('large'), pady=Theme.get_spacing('large'), sticky='nsew')
        file_frame.grid_propagate(False)
        file_icon = tk.Label(file_frame, text="📁", font=icon_font, fg=Theme.get_color('accent'), bg=Theme.get_color('secondary'))
        file_icon.pack(pady=(Theme.get_spacing('large'), Theme.get_spacing('small')))
        file_title = tk.Label(file_frame, text="File Analyzer", font=title_font, fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        file_title.pack()
        file_desc = tk.Label(
            file_frame,
            text="Analyze and extract data from any file. Carve embedded files, extract strings, detect file types, entropy, stego, and more.",
            font=desc_font,
            fg=Theme.get_color('text_secondary'),
            bg=Theme.get_color('secondary'),
            wraplength=square_size-30,
            justify='center')
        file_desc.pack(pady=(Theme.get_spacing('small'), Theme.get_spacing('medium')))
        self.file_button = ModernButton(file_frame, text="Open File Analyzer", command=self.open_file_analyzer, style='primary')
        self.file_button.pack(pady=(0, Theme.get_spacing('medium')))

        # Web Analyzer Module Button (Bottom Right)
        web_frame = tk.Frame(self.buttons_frame, relief='raised', bd=3, width=square_size, height=square_size, bg=Theme.get_color('secondary'))
        web_frame.grid(row=1, column=1, padx=Theme.get_spacing('large'), pady=Theme.get_spacing('large'), sticky='nsew')
        web_frame.grid_propagate(False)
        web_icon = tk.Label(web_frame, text="🌐", font=icon_font, fg=Theme.get_color('accent'), bg=Theme.get_color('secondary'))
        web_icon.pack(pady=(Theme.get_spacing('large'), Theme.get_spacing('small')))
        web_title = tk.Label(web_frame, text="Web Analyzer", font=title_font, fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        web_title.pack()
        web_desc = tk.Label(
            web_frame,
            text="Perform reconnaissance and vulnerability scanning on websites. Analyze HTTP headers, scan open ports, gather metadata, and identify potential security issues for digital forensics and CTFs.",
            font=desc_font,
            fg=Theme.get_color('text_secondary'),
            bg=Theme.get_color('secondary'),
            wraplength=square_size-30,
            justify='center')
        web_desc.pack(pady=(Theme.get_spacing('small'), Theme.get_spacing('medium')))
        self.web_button = ModernButton(web_frame, text="Launch Web Analyzer", command=self.launch_web_analyzer, style='primary')
        self.web_button.pack(pady=(0, Theme.get_spacing('medium')))

        # Small Next Button at the far right below the grid
        self.next_button = ModernButton(self.content_frame, text="Next →", command=self.show_osint_grid, style='secondary')
        self.next_button.pack(anchor='e', padx=Theme.get_spacing('large'), pady=(0, Theme.get_spacing('medium')))
            
    def create_footer(self):
        """Create footer with status information and credits button"""
        footer_frame = tk.Frame(self.main_frame)
        footer_frame.pack(fill='x', pady=(Theme.get_spacing('large'), 0))
        
        # Status info
        status_label = tk.Label(footer_frame,
                               text=f"Forensics Toolkit v{Settings.APP_VERSION} | Ready",
                               font=Theme.get_font('small'),
                               fg=Theme.get_color('text_muted'))
        status_label.pack(side='left')
        
        # Copyright
        copyright_label = tk.Label(footer_frame,
                                  text="© 2024 Forensics Toolkit",
                                  font=Theme.get_font('small'),
                                  fg=Theme.get_color('text_muted'))
        copyright_label.pack(side='right')

        # Credits & License Button (bottom right)
        credits_btn = tk.Button(
            footer_frame,
            text="Credits & License",
            font=Theme.get_font('button'),
            bg='#FFD600',  # Yellow
            fg='#222',
            activebackground='#FFEA00',
            activeforeground='#222',
            relief='raised',
            bd=1,
            cursor='hand2',
            command=self.show_credits_popup
        )
        credits_btn.pack(side='right', padx=(0, 10))

    def show_credits_popup(self):
        """Show a professional popup window with credits, license, and NYX logo"""
        popup = tk.Toplevel(self.root)
        popup.title("Credits & License")
        popup.configure(bg='white')
        popup.geometry('520x620')
        popup.resizable(False, False)

        # Load and show logo
        try:
            logo_img = Image.open("pics/Picsart_25-07-01_17-15-32-191.png")
            logo_img = logo_img.resize((120, 135), Image.Resampling.LANCZOS)
            logo = ImageTk.PhotoImage(logo_img)
            logo_label = tk.Label(popup, image=logo, bg='white')
            setattr(logo_label, "image", logo)  # Keep reference: required for Tkinter to display image  # Keep reference: required for Tkinter to display image
            logo_label.pack(pady=(24, 8))
        except Exception:
            logo_label = tk.Label(popup, text="NYX", font=("Arial", 32, "bold"), fg="#FFD600", bg='white')
            logo_label.pack(pady=(24, 8))

        # Project Title
        title_label = tk.Label(
            popup,
            text="Forensics Toolkit",
            font=("Segoe UI", 16, "bold"),
            fg="#222",
            bg="white"
        )
        title_label.pack(pady=(0, 6))

        # Credits Section (rewritten professionally)
        credits_text = (
            "Lead Developer: Abdullah Ibrahim (Dhype7)\n"
            "Web Analyzer developer: Saif Fadhil\n"
            "Team: NYX\n\n"
            "This project was created for the sake of helping the CTF beginners.\n"
            "Special thanks to all contributors and the open-source community."
        )
        credits_label = tk.Label(
            popup,
            text=credits_text,
            font=("Segoe UI", 11),
            fg="#333",
            bg="white",
            justify='center',
            wraplength=480
        )
        credits_label.pack(pady=(0, 18))

        # Divider
        divider = tk.Frame(popup, bg="#FFD600", height=2, width=420)
        divider.pack(pady=(0, 18))

        # License Section
        license_title = tk.Label(
            popup,
            text="License: MIT",
            font=("Segoe UI", 12, "bold"),
            fg="#FFD600",
            bg="white"
        )
        license_title.pack(pady=(0, 4))

        license_text = (
            "This software is released under the MIT License.\n\n"
            "You are free to use, modify, and distribute this software, "
            "provided that the original copyright and license notice "
            "are included in all copies or substantial portions of the software.\n\n"
            "THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND."
        )
        license_label = tk.Label(
            popup,
            text=license_text,
            font=("Segoe UI", 10),
            fg="#444",
            bg="white",
            wraplength=400,
            justify='left'
        )
        license_label.pack(pady=(0, 18), padx=20)

        # Close button
        close_btn = tk.Button(
            popup,
            text="Close",
            command=popup.destroy,
            bg='#FFD600',
            fg='#222',
            font=Theme.get_font('button'),
            relief='raised',
            bd=1,
            cursor='hand2',
            width=12
        )
        close_btn.pack(pady=(0, 24))
        
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
        
        # NYX background logic
        if Theme.get_current_theme() == 'nyx':
            self.nyx_bg.place(x=0, y=0, relwidth=1, relheight=1)
            # self.nyx_bg.lift()  # Removed to fix Tkinter error
            self.nyx_bg.redraw()
        else:
            self.nyx_bg.place_forget()
        
    def global_on_theme_change(self, *args, **kwargs):
        """Update theme everywhere when changed from any window"""
        Theme.set_theme(self.theme_var.get())
        self.apply_theme()
        # Only call theme change on frames if they exist and are not the source of the change
        if hasattr(self, 'file_analyzer_frame') and self.file_analyzer_frame:
            self.file_analyzer_frame._on_external_theme_change()
        if hasattr(self, 'photo_analyzer_frame') and self.photo_analyzer_frame:
            self.photo_analyzer_frame._on_external_theme_change()
        if hasattr(self, 'crypto_frame') and self.crypto_frame:
            self.crypto_frame._on_external_theme_change()
        self.root.update_idletasks()

    def on_theme_change(self, event=None):
        """Handle theme change (main window)"""
        self.global_on_theme_change()

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

    def show_osint_grid(self):
        # Hide main content
        self.content_frame.pack_forget()
        # Create OSINT grid frame
        self.osint_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        self.osint_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('large'), pady=Theme.get_spacing('large'))
        # Centered OSINT module box
        square_size = 320
        icon_font = ('Arial', 64)
        title_font = Theme.get_font('title')
        desc_font = Theme.get_font('default')
        osint_box = tk.Frame(self.osint_frame, relief='raised', bd=3, width=square_size, height=square_size, bg=Theme.get_color('secondary'))
        osint_box.pack(expand=True, pady=(Theme.get_spacing('large'), Theme.get_spacing('large')))
        osint_box.pack_propagate(False)
        osint_icon = tk.Label(osint_box, text="🕵️‍♂️", font=icon_font, fg=Theme.get_color('accent'), bg=Theme.get_color('secondary'))
        osint_icon.pack(pady=(Theme.get_spacing('large'), Theme.get_spacing('small')))
        osint_title = tk.Label(osint_box, text="--OSINT--", font=title_font, fg=Theme.get_color('text_primary'), bg=Theme.get_color('secondary'))
        osint_title.pack()
        osint_desc = tk.Label(
            osint_box,
            text="Open Source Intelligence tools for reconnaissance and investigation. (Coming Soon)",
            font=desc_font,
            fg=Theme.get_color('text_secondary'),
            bg=Theme.get_color('secondary'),
            wraplength=square_size-30,
            justify='center')
        osint_desc.pack(pady=(Theme.get_spacing('small'), Theme.get_spacing('medium')))
        osint_btn = ModernButton(osint_box, text="OSINT Toolkit (Coming Soon)", command=self.show_osint_coming_soon, style='primary')
        osint_btn.pack(pady=(0, Theme.get_spacing('medium')))
        # Previous Button below the box
        prev_btn = ModernButton(self.osint_frame, text="← Previous", command=self.show_main_grid, style='secondary')
        prev_btn.pack(pady=(Theme.get_spacing('medium'), 0))

    def show_osint_coming_soon(self):
        messagebox.showinfo("Coming Soon", "The OSINT module is coming soon! Stay tuned.")

    def show_main_grid(self):
        if hasattr(self, 'osint_frame') and self.osint_frame:
            self.osint_frame.pack_forget()
        self.content_frame.pack(fill='both', expand=True, pady=Theme.get_spacing('large'))

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