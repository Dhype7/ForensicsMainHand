import sys
import os

# Ensure script is run as root
if os.geteuid() != 0:
    print("Error: Please run this script as root (e.g., with sudo) to ensure all dependencies are available.")
    sys.exit(1)

try:
    import tkinter as tk
except ImportError:
    print("Error: tkinter is not installed. Please install python3-tk.")
    sys.exit(1)

# Add src to sys.path
SRC_PATH = os.path.join(os.path.dirname(__file__), 'src')
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

try:
    from src.forensics_main import ForensicsToolkitWindow
except ImportError as e:
    print(f"Error: Could not import main window: {e}\nDid you run install.sh?")
    sys.exit(1)

def main():
    try:
        root = tk.Tk()
        app = ForensicsToolkitWindow(root)
        root.mainloop()
    except tk.TclError as e:
        print(f"Error: Unable to start GUI. {e}\nAre you running in a graphical environment?")
        sys.exit(1)

if __name__ == "__main__":
    main() 