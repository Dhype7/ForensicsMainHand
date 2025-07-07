"""
Custom UI Widgets
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Callable, Optional, List, Any
from .theme import Theme
import random
from PIL import Image, ImageDraw, ImageFont, ImageTk, ImageFilter

class ModernButton(tk.Button):
    """Modern styled button with hover effects"""
    
    def __init__(self, parent, text: str, command=None, 
                 style: str = 'default', **kwargs):
        super().__init__(parent, text=text, command=command, **kwargs)  # type: ignore
        self._apply_style(style)
        self._bind_events()
    
    def _apply_style(self, style: str):
        """Apply button style"""
        if style == 'primary':
            self.configure(
                bg=Theme.get_color('accent'),
                fg=Theme.get_color('text_primary'),
                font=Theme.get_font('button'),
                relief='flat',
                bd=0,
                padx=Theme.get_spacing('medium'),
                pady=Theme.get_spacing('small'),
                cursor='hand2'
            )
        else:
            self.configure(**Theme.get_button_style())
    
    def _bind_events(self):
        """Bind hover events"""
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
    
    def _on_enter(self, event):
        """Mouse enter event"""
        if self.cget('bg') == Theme.get_color('accent'):
            self.configure(bg=Theme.get_color('accent_hover'))
        else:
            self.configure(bg=Theme.get_color('button_hover'))
    
    def _on_leave(self, event):
        """Mouse leave event"""
        if self.cget('bg') == Theme.get_color('accent_hover'):
            self.configure(bg=Theme.get_color('accent'))
        else:
            self.configure(bg=Theme.get_color('button_bg'))

class ModernEntry(tk.Entry):
    """Modern styled entry widget"""
    
    def __init__(self, parent, placeholder: str = "", **kwargs):
        super().__init__(parent, **kwargs)
        self.placeholder = placeholder
        self._apply_style()
        self._bind_events()
        
        if placeholder:
            self.insert(0, placeholder)
            self.configure(fg=Theme.get_color('text_muted'))
    
    def _apply_style(self):
        """Apply entry style"""
        self.configure(**Theme.get_entry_style())
    
    def _bind_events(self):
        """Bind focus events for placeholder"""
        if self.placeholder:
            self.bind('<FocusIn>', self._on_focus_in)
            self.bind('<FocusOut>', self._on_focus_out)
    
    def _on_focus_in(self, event):
        """Focus in event"""
        if self.get() == self.placeholder:
            self.delete(0, tk.END)
            self.configure(fg=Theme.get_color('entry_fg'))
    
    def _on_focus_out(self, event):
        """Focus out event"""
        if not self.get():
            self.insert(0, self.placeholder)
            self.configure(fg=Theme.get_color('text_muted'))

class ModernText(tk.Text):
    """Modern styled text widget"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self._apply_style()
        self._setup_tags()
    
    def _apply_style(self):
        """Apply text widget style"""
        self.configure(**Theme.get_text_style())
    
    def _setup_tags(self):
        """Setup text tags for syntax highlighting"""
        self.tag_configure("section", 
                          foreground=Theme.get_color('section_header'),
                          font=Theme.get_font('heading'))
        self.tag_configure("data", 
                          foreground=Theme.get_color('data_value'),
                          font=Theme.get_font('default'))
        self.tag_configure("metadata_key", 
                          foreground=Theme.get_color('metadata_key'),
                          font=Theme.get_font('default'))
        self.tag_configure("metadata_value", 
                          foreground=Theme.get_color('metadata_value'),
                          font=Theme.get_font('default'))
        self.tag_configure("error", 
                          foreground=Theme.get_color('error'),
                          font=Theme.get_font('default'))
        self.tag_configure("success", 
                          foreground=Theme.get_color('success'),
                          font=Theme.get_font('default'))
        self.tag_configure("warning", 
                          foreground=Theme.get_color('warning'),
                          font=Theme.get_font('default'))

class FileSelector(tk.Frame):
    """File selection widget with browse button"""
    
    def __init__(self, parent, title: str = "Select File", 
                 file_types: Optional[List[tuple]] = None, **kwargs):
        super().__init__(parent, **kwargs)
        self.file_types = file_types or [("All Files", "*.*")]
        self.selected_file = tk.StringVar()
        self._create_widgets(title)
    
    def _create_widgets(self, title: str):
        """Create file selector widgets"""
        # Title label
        title_label = tk.Label(self, text=title, 
                              font=Theme.get_font('heading'),
                              bg=Theme.get_color('primary'),
                              fg=Theme.get_color('text_primary'))
        title_label.pack(anchor='w', pady=(0, Theme.get_spacing('small')))
        
        # File path frame
        path_frame = tk.Frame(self, bg=Theme.get_color('primary'))
        path_frame.pack(fill='x', pady=Theme.get_spacing('small'))
        
        # Entry for file path
        self.path_entry = ModernEntry(path_frame, 
                                     placeholder="Enter file path or click Browse...",
                                     width=50)
        self.path_entry.pack(side='left', fill='x', expand=True, padx=(0, Theme.get_spacing('small')))
        self.path_entry.config(textvariable=self.selected_file)
        
        # Browse button
        self.browse_btn = ModernButton(path_frame, text="Browse", 
                                      command=self._browse_file,
                                      style='primary')
        self.browse_btn.pack(side='right')
    
    def _browse_file(self):
        """Open file dialog"""
        filename = filedialog.askopenfilename(
            title="Select File",
            filetypes=self.file_types
        )
        if filename:
            self.selected_file.set(filename)
    
    def get_selected_file(self) -> str:
        """Get selected file path"""
        return self.selected_file.get()
    
    def set_file(self, file_path: str):
        """Set file path"""
        self.selected_file.set(file_path)

class StatusBar(tk.Frame):
    """Status bar widget for displaying application status"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self._create_widgets()
    
    def _create_widgets(self):
        """Create status bar widgets"""
        self.configure(bg=Theme.get_color('secondary'), height=25)
        
        # Status label
        self.status_label = tk.Label(self, text="Ready", 
                                    font=Theme.get_font('default'),
                                    bg=Theme.get_color('secondary'),
                                    fg=Theme.get_color('text_secondary'))
        self.status_label.pack(side='left', padx=Theme.get_spacing('medium'))
        
        # Progress bar
        self.progress = ttk.Progressbar(self, mode='indeterminate', length=200)
        self.progress.pack(side='right', padx=Theme.get_spacing('medium'))
        self.progress.pack_forget()  # Hidden by default
    
    def set_status(self, message: str, status_type: str = 'info'):
        """Set status message"""
        self.status_label.configure(text=message)
        
        # Set color based on status type
        color_map = {
            'info': Theme.get_color('text_secondary'),
            'success': Theme.get_color('success'),
            'warning': Theme.get_color('warning'),
            'error': Theme.get_color('error')
        }
        self.status_label.configure(fg=color_map.get(status_type, Theme.get_color('text_secondary')))
    
    def show_progress(self):
        """Show progress bar"""
        self.progress.pack(side='right', padx=Theme.get_spacing('medium'))
        self.progress.start()
    
    def hide_progress(self):
        """Hide progress bar"""
        self.progress.stop()
        self.progress.pack_forget()

class ToolButton(tk.Frame):
    """Tool button with icon and description"""
    
    def __init__(self, parent, text: str, description: str, 
                 command=None, icon: str = "🔧", **kwargs):
        super().__init__(parent, **kwargs)
        self._enabled = True
        self._command = command
        self._widgets = []
        self._create_widgets(text, description, command, icon)
    
    def _create_widgets(self, text: str, description: str, command, icon: str):
        """Create tool button widgets"""
        self.configure(bg=Theme.get_color('primary'))
        
        # Main button frame
        btn_frame = tk.Frame(self, bg=Theme.get_color('button_bg'), 
                            relief='flat', bd=1)
        btn_frame.pack(fill='x', pady=Theme.get_spacing('small'))
        self._widgets.append(btn_frame)
        
        # Icon and text
        icon_label = tk.Label(btn_frame, text=icon, 
                             font=('Segoe UI', 16),
                             bg=Theme.get_color('button_bg'),
                             fg=Theme.get_color('text_primary'))
        icon_label.pack(side='left', padx=Theme.get_spacing('medium'))
        self._widgets.append(icon_label)
        
        # Text frame
        text_frame = tk.Frame(btn_frame, bg=Theme.get_color('button_bg'))
        text_frame.pack(side='left', fill='x', expand=True, padx=Theme.get_spacing('small'))
        self._widgets.append(text_frame)
        
        # Title
        title_label = tk.Label(text_frame, text=text,
                              font=Theme.get_font('heading'),
                              bg=Theme.get_color('button_bg'),
                              fg=Theme.get_color('text_primary'))
        title_label.pack(anchor='w')
        self._widgets.append(title_label)
        
        # Description
        desc_label = tk.Label(text_frame, text=description,
                             font=Theme.get_font('default'),
                             bg=Theme.get_color('button_bg'),
                             fg=Theme.get_color('text_secondary'))
        desc_label.pack(anchor='w')
        self._widgets.append(desc_label)
        
        # Bind click events
        for widget in [btn_frame, icon_label, text_frame, title_label, desc_label]:
            widget.bind('<Button-1>', lambda e: command() if command and self._enabled else None)
            widget.bind('<Enter>', lambda e: self._on_enter(btn_frame) if self._enabled else None)
            widget.bind('<Leave>', lambda e: self._on_leave(btn_frame) if self._enabled else None)
            widget.configure(cursor='hand2')
    
    def set_state(self, state: str):
        """Enable or disable the tool button visually and functionally."""
        self._enabled = (state == 'normal')
        cursor = 'hand2' if self._enabled else 'arrow'
        for widget in self.winfo_children():
            if isinstance(widget, (tk.Label, tk.Frame)):
                try:
                    widget.configure(cursor=cursor)
                except Exception:
                    pass
    
    def _on_enter(self, widget):
        """Mouse enter event"""
        if self._enabled:
            widget.configure(bg=Theme.get_color('button_hover'))
    
    def _on_leave(self, widget):
        """Mouse leave event"""
        if self._enabled:
            widget.configure(bg=Theme.get_color('button_bg'))

class NYXBackground(tk.Canvas):
    """Animated NYX background with random 0/1 digits, blue color, black border, blur, and random rotation."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, highlightthickness=0, bd=0, **kwargs)
        self.digits = []
        self.images = []
        self.bind('<Configure>', lambda e: self.redraw())
        self._last_theme = Theme.get_current_theme()
        self.redraw()

    def redraw(self):
        self.delete('all')
        self.images.clear()
        width = self.winfo_width()
        height = self.winfo_height()
        if width < 10 or height < 10:
            return
        if Theme.get_current_theme() != 'nyx':
            self.configure(bg=Theme.get_color('primary'))
            return
        self.configure(bg=Theme.get_color('primary'))
        # Draw semi-transparent overlay
        overlay = Image.new('RGBA', (width, height), (10, 10, 35, 220))  # RGBA, last value is alpha
        overlay_img = ImageTk.PhotoImage(overlay)
        self.images.append(overlay_img)
        self.create_image(0, 0, image=overlay_img, anchor='nw')
        # Parameters
        num_digits = (width * height) // 2500  # density
        font_size = 32
        font = None
        try:
            font = ImageFont.truetype("DejaVuSansMono.ttf", font_size)
        except Exception:
            font = ImageFont.load_default()
        for _ in range(num_digits):
            digit = random.choice(['0', '1'])
            x = random.randint(0, width)
            y = random.randint(0, height)
            angle = random.randint(0, 359)
            # Create digit image
            img = Image.new('RGBA', (font_size*2, font_size*2), (0,0,0,0))
            draw = ImageDraw.Draw(img)
            # Draw border
            draw.text((font_size//2-2, font_size//2-2), digit, font=font, fill=Theme.get_color('nyx_digit_border'), anchor='mm')
            # Draw digit
            draw.text((font_size//2, font_size//2), digit, font=font, fill=Theme.get_color('nyx_digit'), anchor='mm')
            # Blur
            img = img.filter(ImageFilter.GaussianBlur(radius=1.2))
            # Rotate
            img = img.rotate(angle, expand=1)
            tk_img = ImageTk.PhotoImage(img)
            self.images.append(tk_img)  # keep reference
            self.create_image(x, y, image=tk_img, anchor='center') 