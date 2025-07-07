#!/usr/bin/env python3
"""
Forensics Toolkit - Main Entry Point
A comprehensive digital forensics analysis suite
"""

import tkinter as tk
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from forensics_main import ForensicsToolkitWindow

def main():
    """Main application entry point"""
    # Create the main application window
    root = tk.Tk()
    
    # Initialize the forensics toolkit window
    app = ForensicsToolkitWindow(root)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main() 