#!/usr/bin/env python3
"""
Simplified Crypto Popup Test
"""
import tkinter as tk
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from ui.theme import Theme

class SimpleCryptoPopup:
    """Simplified crypto popup for testing"""
    
    def __init__(self, parent):
        self.parent = parent
        
        # Create popup window
        self.window = tk.Toplevel(parent)
        self.window.title("Simple Crypto Analysis")
        self.window.geometry("500x400")
        self.window.resizable(True, True)
        self.window.transient(parent)
        self.window.grab_set()
        
        # Apply theme
        self.window.configure(bg=Theme.get_color('primary'))
        
        # Create widgets using pack instead of grid
        self.create_widgets()
        
    def create_widgets(self):
        """Create widgets using pack layout"""
        # Title
        title_label = tk.Label(
            self.window,
            text="🔓 Crypto Analysis",
            font=Theme.get_font('title'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary')
        )
        title_label.pack(pady=20)
        
        # Encryption type frame
        type_frame = tk.LabelFrame(
            self.window,
            text="Select Encryption Type",
            font=Theme.get_font('heading'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            relief='solid',
            bd=1
        )
        type_frame.pack(fill='x', padx=20, pady=10)
        
        self.encryption_type = tk.StringVar(value="auto")
        
        # Radio buttons
        tk.Radiobutton(
            type_frame,
            text="Auto Detect",
            variable=self.encryption_type,
            value="auto",
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            selectcolor=Theme.get_color('secondary')
        ).pack(anchor='w', padx=20, pady=5)
        
        tk.Radiobutton(
            type_frame,
            text="Base64",
            variable=self.encryption_type,
            value="base64",
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            selectcolor=Theme.get_color('secondary')
        ).pack(anchor='w', padx=20, pady=5)
        
        tk.Radiobutton(
            type_frame,
            text="Hex",
            variable=self.encryption_type,
            value="hex",
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            selectcolor=Theme.get_color('secondary')
        ).pack(anchor='w', padx=20, pady=5)
        
        # Input method frame
        input_frame = tk.LabelFrame(
            self.window,
            text="Input Method",
            font=Theme.get_font('heading'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            relief='solid',
            bd=1
        )
        input_frame.pack(fill='x', padx=20, pady=10)
        
        self.input_method = tk.StringVar(value="file")
        
        tk.Radiobutton(
            input_frame,
            text="Analyze loaded file",
            variable=self.input_method,
            value="file",
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            selectcolor=Theme.get_color('secondary')
        ).pack(anchor='w', padx=20, pady=5)
        
        tk.Radiobutton(
            input_frame,
            text="Enter text manually",
            variable=self.input_method,
            value="manual",
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('primary'),
            selectcolor=Theme.get_color('secondary')
        ).pack(anchor='w', padx=20, pady=5)
        
        # Manual text input
        self.manual_text = tk.Text(
            input_frame,
            height=3,
            font=Theme.get_font('default'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('secondary'),
            relief='solid',
            bd=1
        )
        self.manual_text.pack(fill='x', padx=20, pady=5)
        self.manual_text.insert("1.0", "Enter text here...")
        
        # Buttons
        button_frame = tk.Frame(self.window, bg=Theme.get_color('primary'))
        button_frame.pack(fill='x', padx=20, pady=20)
        
        tk.Button(
            button_frame,
            text="🔓 Analyze",
            font=Theme.get_font('button'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('accent'),
            relief='flat',
            bd=0,
            padx=20,
            pady=10,
            command=self.analyze
        ).pack(side='left', padx=(0, 10))
        
        tk.Button(
            button_frame,
            text="❌ Cancel",
            font=Theme.get_font('button'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('secondary'),
            relief='flat',
            bd=0,
            padx=20,
            pady=10,
            command=self.window.destroy
        ).pack(side='left')
        
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
        results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        self.results_text = tk.Text(
            results_frame,
            font=Theme.get_font('monospace'),
            fg=Theme.get_color('text_primary'),
            bg=Theme.get_color('secondary'),
            relief='flat',
            bd=0,
            wrap='word'
        )
        self.results_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.results_text.insert("1.0", "Results will appear here...")
        
    def analyze(self):
        """Simple analyze function"""
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert("1.0", f"Analysis complete!\nType: {self.encryption_type.get()}\nMethod: {self.input_method.get()}")

def test_simple_popup():
    """Test the simplified popup"""
    root = tk.Tk()
    root.withdraw()
    
    # Create test file
    test_file = "test_simple.txt"
    with open(test_file, 'w') as f:
        f.write("Test content")
    
    try:
        # Create popup
        popup = SimpleCryptoPopup(root)
        
        print("✅ Simple crypto popup created successfully!")
        print("🔓 Features:")
        print("  - Encryption type selection")
        print("  - Input method selection")
        print("  - Manual text input")
        print("  - Analyze and Cancel buttons")
        print("  - Results display")
        
        # Show the popup
        popup.window.deiconify()
        popup.window.focus_force()
        
        print("\n✅ Popup should be visible now!")
        
        # Clean up
        if os.path.exists(test_file):
            os.remove(test_file)
        
        return root, popup
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return None, None

if __name__ == "__main__":
    root, popup = test_simple_popup()
    if root:
        root.mainloop() 