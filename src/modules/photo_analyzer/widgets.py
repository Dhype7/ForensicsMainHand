"""
Custom UI Widgets
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Callable, Optional, List, Any
from .theme import Theme

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
        self._create_widgets(text, description, command, icon)
    
    def _create_widgets(self, text: str, description: str, command, icon: str):
        """Create tool button widgets"""
        self.configure(bg=Theme.get_color('primary'))
        
        # Main button frame
        btn_frame = tk.Frame(self, bg=Theme.get_color('button_bg'), 
                            relief='flat', bd=1)
        btn_frame.pack(fill='x', pady=Theme.get_spacing('small'))
        
        # Icon and text
        icon_label = tk.Label(btn_frame, text=icon, 
                             font=('Segoe UI', 16),
                             bg=Theme.get_color('button_bg'),
                             fg=Theme.get_color('text_primary'))
        icon_label.pack(side='left', padx=Theme.get_spacing('medium'))
        
        # Text frame
        text_frame = tk.Frame(btn_frame, bg=Theme.get_color('button_bg'))
        text_frame.pack(side='left', fill='x', expand=True, padx=Theme.get_spacing('small'))
        
        # Title
        title_label = tk.Label(text_frame, text=text,
                              font=Theme.get_font('heading'),
                              bg=Theme.get_color('button_bg'),
                              fg=Theme.get_color('text_primary'))
        title_label.pack(anchor='w')
        
        # Description
        desc_label = tk.Label(text_frame, text=description,
                             font=Theme.get_font('default'),
                             bg=Theme.get_color('button_bg'),
                             fg=Theme.get_color('text_secondary'))
        desc_label.pack(anchor='w')
        
        # Bind click events
        for widget in [btn_frame, icon_label, text_frame, title_label, desc_label]:
            widget.bind('<Button-1>', lambda e: command() if command else None)
            widget.bind('<Enter>', lambda e: self._on_enter(btn_frame))
            widget.bind('<Leave>', lambda e: self._on_leave(btn_frame))
            widget.configure(cursor='hand2')
    
    def _on_enter(self, widget):
        """Mouse enter event"""
        widget.configure(bg=Theme.get_color('button_hover'))
    
    def _on_leave(self, widget):
        """Mouse leave event"""
        widget.configure(bg=Theme.get_color('button_bg')) 