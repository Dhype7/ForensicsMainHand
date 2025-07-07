"""
UI Theme Configuration
"""
from typing import Dict, Any, Optional

class Theme:
    """Theme manager supporting multiple color themes"""
    
    # Theme definitions
    THEMES = {
        'dark': {
            # Primary colors
            'primary': '#1E1E1E',
            'secondary': '#2D2D2D',
            'accent': '#007ACC',
            'accent_hover': '#005A9E',
            # Text colors
            'text_primary': '#FFFFFF',
            'text_secondary': '#CCCCCC',
            'text_muted': '#888888',
            # UI elements
            'button_bg': '#3E3E3E',
            'button_fg': '#FFFFFF',
            'button_hover': '#4E4E4E',
            'entry_bg': '#2D2D2D',
            'entry_fg': '#FFFFFF',
            'text_bg': '#1E1E1E',
            'text_fg': '#FFFFFF',
            # Status colors
            'success': '#28A745',
            'warning': '#FFC107',
            'error': '#DC3545',
            'info': '#17A2B8',
            # Analysis results
            'section_header': '#007ACC',
            'data_value': '#28A745',
            'metadata_key': '#FFC107',
            'metadata_value': '#17A2B8',
            'highlight': '#222244',
        },
        'light': {
            'primary': '#F5F5F5',
            'secondary': '#E0E0E0',
            'accent': '#007ACC',
            'accent_hover': '#005A9E',
            'text_primary': '#222222',
            'text_secondary': '#444444',
            'text_muted': '#888888',
            'button_bg': '#FFFFFF',
            'button_fg': '#222222',
            'button_hover': '#E0E0E0',
            'entry_bg': '#FFFFFF',
            'entry_fg': '#222222',
            'text_bg': '#F5F5F5',
            'text_fg': '#222222',
            'success': '#28A745',
            'warning': '#FFC107',
            'error': '#DC3545',
            'info': '#17A2B8',
            'section_header': '#007ACC',
            'data_value': '#28A745',
            'metadata_key': '#FFC107',
            'metadata_value': '#17A2B8',
            'highlight': '#DDEEFF',
        },
        'nyx': {
            'primary': '#0a0a23',  # deep dark blue
            'secondary': '#101020',  # almost black
            'accent': '#00bfff',  # NYX blue for highlights
            'accent_hover': '#0080ff',
            'text_primary': '#e0e6f0',
            'text_secondary': '#7faaff',
            'text_muted': '#4a668a',
            'button_bg': '#101020',
            'button_fg': '#e0e6f0',
            'button_hover': '#1a1a2f',
            'entry_bg': '#101020',
            'entry_fg': '#e0e6f0',
            'text_bg': '#0a0a23',
            'text_fg': '#e0e6f0',
            'success': '#28A745',
            'warning': '#FFC107',
            'error': '#DC3545',
            'info': '#17A2B8',
            'section_header': '#00bfff',
            'data_value': '#28A745',
            'metadata_key': '#FFC107',
            'metadata_value': '#17A2B8',
            'highlight': '#0a0a40',
            'nyx_digit': '#1e90ff',  # special blue for 0/1 digits
            'nyx_digit_border': '#000000',
        }
    }
    
    # Font configurations
    FONTS = {
        'default': ('Segoe UI', 10),
        'heading': ('Segoe UI', 12, 'bold'),
        'title': ('Segoe UI', 14, 'bold'),
        'monospace': ('Consolas', 9),
        'button': ('Segoe UI', 10, 'bold'),
    }
    
    # Spacing and layout
    SPACING = {
        'small': 5,
        'medium': 10,
        'large': 15,
        'xlarge': 20,
    }
    
    # Border radius
    BORDER_RADIUS = 5
    
    # Current theme name
    _current_theme = 'nyx'
    
    @classmethod
    def get_color(cls, color_name: str) -> str:
        """Get color by name from the current theme"""
        return cls.THEMES[cls._current_theme].get(color_name, '#FFFFFF')
    
    @classmethod
    def get_font(cls, font_name: str) -> tuple:
        """Get font by name"""
        return cls.FONTS.get(font_name, cls.FONTS['default'])
    
    @classmethod
    def get_spacing(cls, spacing_name: str) -> int:
        """Get spacing by name"""
        return cls.SPACING.get(spacing_name, 10)
    
    @classmethod
    def apply_theme_to_widget(cls, widget, bg_color: Optional[str] = None, fg_color: Optional[str] = None):
        """Apply theme colors to a widget"""
        if bg_color:
            widget.configure(bg=cls.get_color(bg_color))
        if fg_color:
            widget.configure(fg=cls.get_color(fg_color))
    
    @classmethod
    def get_button_style(cls) -> Dict[str, Any]:
        """Get button style configuration"""
        return {
            'bg': cls.get_color('button_bg'),
            'fg': cls.get_color('button_fg'),
            'font': cls.get_font('button'),
            'relief': 'flat',
            'bd': 0,
            'padx': cls.get_spacing('medium'),
            'pady': cls.get_spacing('small'),
            'cursor': 'hand2'
        }
    
    @classmethod
    def get_entry_style(cls) -> Dict[str, Any]:
        """Get entry style configuration"""
        return {
            'bg': cls.get_color('entry_bg'),
            'fg': cls.get_color('entry_fg'),
            'font': cls.get_font('default'),
            'relief': 'flat',
            'bd': 1,
            'highlightthickness': 1,
            'highlightcolor': cls.get_color('accent'),
            'highlightbackground': cls.get_color('text_muted')
        }
    
    @classmethod
    def get_text_style(cls) -> Dict[str, Any]:
        """Get text widget style configuration"""
        return {
            'bg': cls.get_color('text_bg'),
            'fg': cls.get_color('text_fg'),
            'font': cls.get_font('monospace'),
            'relief': 'flat',
            'bd': 0,
            'insertbackground': cls.get_color('accent'),
            'selectbackground': cls.get_color('accent'),
            'selectforeground': cls.get_color('text_primary')
        }
    
    @classmethod
    def get_available_themes(cls) -> list:
        """Return a list of available theme names"""
        return list(cls.THEMES.keys())
    
    @classmethod
    def get_current_theme(cls) -> str:
        """Get the current theme name"""
        return cls._current_theme
    
    @classmethod
    def set_theme(cls, theme_name: str):
        """Set the current theme and trigger UI update if needed"""
        if theme_name in cls.THEMES:
            cls._current_theme = theme_name
        else:
            raise ValueError(f"Theme '{theme_name}' is not defined.") 