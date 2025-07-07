import sys
import os
import argparse

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

def run_web_analyzer():
    from webanalyzer import app
    app.run(debug=True)

def main():
    try:
        root = tk.Tk()
        app = ForensicsToolkitWindow(root)
        root.mainloop()
    except tk.TclError as e:
        print(f"Error: Unable to start GUI. {e}\nAre you running in a graphical environment?")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--web', action='store_true', help='Run the web analyzer')
    args = parser.parse_args()

    if args.web:
        run_web_analyzer()
    else:
        main() 