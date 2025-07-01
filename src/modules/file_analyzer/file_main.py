"""
File Analyzer Module Main Window
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import sys
import threading
from typing import Optional, Callable, Any, Union

# Add parent directories to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from ui.theme import Theme
from ui.widgets import ModernButton, FileSelector, StatusBar, ToolButton
from config.settings import Settings
from .file_utils import FileAnalyzerUtils

class FileAnalyzerMainWindow(tk.Frame):
    """Main application frame for File Analyzer (CTF style)"""
    def __init__(self, parent, back_callback: Callable[[], None], *args, **kwargs) -> None:
        super().__init__(parent, *args, **kwargs)
        self.back_callback = back_callback
        self.selected_file_path: Optional[str] = None
        self.selected_wordlist_path: Optional[str] = None
        self.result_text: tk.Text
        self.status_bar: StatusBar
        self.file_selector: Optional[FileSelector] = None
        self.main_frame: Optional[tk.Frame] = None
        self.theme_var = tk.StringVar(value=Theme.get_current_theme())
        self.result_search_var = tk.StringVar()
        self.result_content = ""
        self.loading_overlay: Optional[tk.Frame] = None
        self.loading_label: Optional[tk.Label] = None
        self.loading_spinner: Optional[tk.Label] = None
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.spinner_index = 0
        self.loading_after_id = None
        self.tool_buttons = []
        self.create_widgets()
        self.setup_layout()
        self.apply_theme_to_all_widgets()

    def create_widgets(self):
        self.main_frame = tk.Frame(self, bg=Theme.get_color('primary'))
        self.main_frame.pack(fill='both', expand=True, padx=Theme.get_spacing('medium'), pady=Theme.get_spacing('medium'))
        self.create_header()
        self.create_file_selection()
        self.create_main_content()
        self.create_status_bar()

    def create_header(self):
        header_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        header_frame.pack(fill='x', pady=(0, Theme.get_spacing('large')))
        # Back button
        back_btn = ModernButton(header_frame, text="← Back", command=self.back_callback, style='secondary')
        back_btn.pack(side='left', padx=(0, 10))
        title_label = tk.Label(header_frame, text="File Analyzer", font=Theme.get_font('title'), bg=Theme.get_color('primary'), fg=Theme.get_color('accent'))
        title_label.pack(side='left')
        theme_label = tk.Label(header_frame, text="Theme:", bg=Theme.get_color('primary'), fg=Theme.get_color('text_secondary'), font=Theme.get_font('default'))
        theme_label.pack(side='right', padx=(0, 5))
        theme_dropdown = ttk.Combobox(header_frame, textvariable=self.theme_var, values=Theme.get_available_themes(), width=8, state='readonly')
        theme_dropdown.pack(side='right', padx=(0, 10))
        theme_dropdown.bind('<<ComboboxSelected>>', self.on_theme_change)
        subtitle_label = tk.Label(header_frame, text="CTF-Grade File Carving, Extraction, and Analysis", font=Theme.get_font('default'), bg=Theme.get_color('primary'), fg=Theme.get_color('text_secondary'))
        subtitle_label.pack(anchor='w')

    def create_file_selection(self):
        file_frame = tk.Frame(self.main_frame, bg=Theme.get_color('secondary'))
        file_frame.pack(fill='x', pady=Theme.get_spacing('medium'))
        self.file_selector = FileSelector(
            file_frame,
            title="Select File for Analysis",
            file_types=[("All Files", "*.*")]
        )
        self.file_selector.pack(fill='x', padx=Theme.get_spacing('medium'), pady=Theme.get_spacing('medium'))
        ModernButton(file_frame, text="Load File", command=self.load_file, style='primary').pack(pady=Theme.get_spacing('small'))

    def create_main_content(self):
        content_frame = tk.Frame(self.main_frame, bg=Theme.get_color('primary'))
        content_frame.pack(fill='both', expand=True, pady=Theme.get_spacing('medium'))
        self.create_tools_area(content_frame)
        self.create_results_area(content_frame)
        content_frame.columnconfigure(0, weight=1)
        content_frame.columnconfigure(1, weight=2)

    def create_tools_area(self, parent):
        tools_frame = tk.Frame(parent, bg=Theme.get_color('primary'))
        tools_frame.grid(row=0, column=0, sticky='nsew', padx=(0, Theme.get_spacing('medium')))
        tools_title = tk.Label(tools_frame, text="Analysis Tools", font=Theme.get_font('heading'), bg=Theme.get_color('primary'), fg=Theme.get_color('text_primary'))
        tools_title.pack(anchor='w', pady=(0, Theme.get_spacing('medium')))
        tools_grid = tk.Frame(tools_frame, bg=Theme.get_color('primary'))
        tools_grid.pack(fill='x')
        # Row 1
        btn1 = ToolButton(tools_grid, text="Type Detection", description="Detect file type (magic)", command=self.analyze_type, icon="📄")
        btn1.grid(row=0, column=0, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn1, "Detect file type using magic bytes and mimetypes")
        self.tool_buttons.append(btn1)
        btn2 = ToolButton(tools_grid, text="Extract Archive", description="Extract files from archives", command=self.analyze_extract, icon="🗜️")
        btn2.grid(row=0, column=1, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn2, "Extract all files from supported archive formats")
        self.tool_buttons.append(btn2)
        btn3 = ToolButton(tools_grid, text="Compress File", description="Compress file to archive", command=self.analyze_compress, icon="📦")
        btn3.grid(row=0, column=2, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn3, "Compress file or folder to archive")
        self.tool_buttons.append(btn3)
        # Row 2
        btn4 = ToolButton(tools_grid, text="String Extraction", description="Extract readable strings", command=self.analyze_strings, icon="🔍")
        btn4.grid(row=1, column=0, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn4, "Extract printable strings from file")
        self.tool_buttons.append(btn4)
        btn5 = ToolButton(tools_grid, text="File Carving", description="Carve files from binary", command=self.analyze_carve, icon="🪓")
        btn5.grid(row=1, column=1, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn5, "Carve embedded files from binary data")
        self.tool_buttons.append(btn5)
        btn6 = ToolButton(tools_grid, text="Metadata Analysis", description="Extract file metadata", command=self.analyze_metadata, icon="📋")
        btn6.grid(row=1, column=2, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn6, "Extract metadata from file")
        self.tool_buttons.append(btn6)
        # Row 3
        btn7 = ToolButton(tools_grid, text="Entropy Analysis", description="Detect packed/obfuscated data", command=self.analyze_entropy, icon="📊")
        btn7.grid(row=2, column=0, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn7, "Analyze file entropy for packing/obfuscation")
        self.tool_buttons.append(btn7)
        btn8 = ToolButton(tools_grid, text="Stego Analysis", description="Detect steganography", command=self.analyze_stego, icon="🕵️")
        btn8.grid(row=2, column=1, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn8, "Detect steganography in files")
        self.tool_buttons.append(btn8)
        btn9 = ToolButton(tools_grid, text="Ciphey Magic", description="Auto-decode/auto-decrypt", command=self.analyze_ciphey, icon="✨")
        btn9.grid(row=2, column=2, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn9, "Auto-decode/auto-decrypt using Ciphey")
        self.tool_buttons.append(btn9)
        # Row 4
        btn10 = ToolButton(tools_grid, text="Recursive Extraction", description="Extract files recursively", command=self.analyze_recursive, icon="🔁")
        btn10.grid(row=3, column=0, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn10, "Recursively extract nested archives")
        self.tool_buttons.append(btn10)
        btn11 = ToolButton(tools_grid, text="CTF Auto-Analyze", description="Run all CTF-relevant analyses", command=self.ctf_auto_analyze, icon="🚀")
        btn11.grid(row=3, column=1, padx=Theme.get_spacing('small'), pady=Theme.get_spacing('small'), sticky='ew')
        self.add_tooltip(btn11, "Run all CTF-relevant analyses automatically")
        self.tool_buttons.append(btn11)
        tools_grid.columnconfigure(0, weight=1)
        tools_grid.columnconfigure(1, weight=1)
        tools_grid.columnconfigure(2, weight=1)
        # Add Select Wordlist button
        wordlist_btn = ModernButton(tools_frame, text="Select Wordlist", command=self.select_wordlist, style='secondary')
        wordlist_btn.pack(pady=(Theme.get_spacing('small'), 0))
        self.add_tooltip(wordlist_btn, "Select a wordlist for password cracking (John the Ripper)")

    def add_tooltip(self, widget, text: str):
        try:
            import tkinter.ttk as ttk
            if hasattr(widget, 'bind'):
                def on_enter(event):
                    self.status_bar.set_status(text, status_type='info')
                def on_leave(event):
                    self.status_bar.set_status("", status_type='info')
                widget.bind('<Enter>', on_enter)
                widget.bind('<Leave>', on_leave)
        except Exception:
            pass

    def create_results_area(self, parent):
        self.result_frame = tk.Frame(parent, bg=Theme.get_color('secondary'), bd=3, relief='raised', highlightthickness=1, highlightbackground=Theme.get_color('accent'))
        self.result_frame.grid(row=0, column=1, sticky='nsew')
        header_frame = tk.Frame(self.result_frame, bg=Theme.get_color('accent'), height=40)
        header_frame.pack(fill='x', pady=(0, 2))
        header_frame.pack_propagate(False)
        title_label = tk.Label(header_frame, text="🔍 Analysis Results", font=('Segoe UI', 14, 'bold'), bg=Theme.get_color('accent'), fg='white')
        title_label.pack(side='left', padx=10, pady=5)
        controls_frame = tk.Frame(header_frame, bg=Theme.get_color('accent'))
        controls_frame.pack(side='right', padx=10, pady=5)
        # Save Results button
        save_btn = tk.Button(controls_frame, text="💾 Save Results", command=self.save_results, font=('Segoe UI', 10, 'bold'), bg=Theme.get_color('success'), fg='white', relief='flat', bd=0, padx=10, pady=3, cursor='hand2')
        save_btn.pack(side='right', padx=(0, 5))
        self.add_tooltip(save_btn, "Save the current analysis results to a text file")
        search_frame = tk.Frame(self.result_frame, bg=Theme.get_color('secondary'))
        search_frame.pack(fill='x', padx=10, pady=5)
        search_label = tk.Label(search_frame, text="Search:", font=('Segoe UI', 11, 'bold'), bg=Theme.get_color('secondary'), fg=Theme.get_color('text_primary'))
        search_label.pack(side='left', padx=(0, 5))
        search_entry = tk.Entry(search_frame, textvariable=self.result_search_var, font=('Segoe UI', 11), bg=Theme.get_color('entry_bg'), fg=Theme.get_color('entry_fg'), relief='solid', bd=1, width=25)
        search_entry.pack(side='left', padx=(0, 5))
        search_btn = tk.Button(search_frame, text="🔍 Search", command=self.search_in_results, font=('Segoe UI', 10, 'bold'), bg=Theme.get_color('accent'), fg='white', relief='flat', bd=0, padx=15, pady=3, cursor='hand2')
        search_btn.pack(side='left', padx=(0, 5))
        copy_btn = tk.Button(search_frame, text="📋 Copy", command=self.copy_results, font=('Segoe UI', 10, 'bold'), bg=Theme.get_color('success'), fg='white', relief='flat', bd=0, padx=15, pady=3, cursor='hand2')
        copy_btn.pack(side='left', padx=(0, 5))
        clear_btn = tk.Button(search_frame, text="🗑️ Clear", command=self.clear_results, font=('Segoe UI', 10, 'bold'), bg=Theme.get_color('error'), fg='white', relief='flat', bd=0, padx=15, pady=3, cursor='hand2')
        clear_btn.pack(side='left')
        text_container = tk.Frame(self.result_frame, bg=Theme.get_color('text_bg'), bd=2, relief='sunken')
        text_container.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.result_text = tk.Text(text_container, wrap='word', font=('Consolas', 12), bg=Theme.get_color('text_bg'), fg=Theme.get_color('text_primary'), relief='flat', bd=0)
        self.result_text.pack(fill='both', expand=True)
        self.result_text.config(state='disabled')
        # Loading overlay (hidden by default)
        self.loading_overlay = tk.Frame(self.result_frame, bg='#000000')
        self.loading_label = tk.Label(self.loading_overlay, text="Analyzing...", font=('Segoe UI', 16, 'bold'), fg='white', bg='#000000')
        self.loading_spinner = tk.Label(self.loading_overlay, text=self.spinner_chars[0], font=('Segoe UI', 32), fg='white', bg='#000000')

    def create_status_bar(self):
        self.status_bar = StatusBar(self)
        self.status_bar.pack(fill='x', side='bottom')

    def setup_layout(self):
        if self.main_frame is not None:
            self.main_frame.pack_configure(fill='both', expand=True)  # type: ignore

    def apply_theme_to_all_widgets(self):
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
        update_widget_colors(self)

    def on_theme_change(self, event=None):
        Theme.set_theme(self.theme_var.get())
        self.apply_theme_to_all_widgets()

    def load_file(self):
        if self.file_selector is None:
            messagebox.showerror("Error", "File selector not initialized.")
            return
        file_path = self.file_selector.get_selected_file()  # type: ignore
        if not file_path or not os.path.isfile(file_path):
            messagebox.showerror("Error", "Please select a valid file to analyze.")
            return
        self.selected_file_path = file_path
        self.status_bar.set_status(f"Loaded file: {file_path}", status_type='success')

    def search_in_results(self):
        query = self.result_search_var.get().strip()
        self.result_text.tag_remove('search', '1.0', tk.END)
        if not query:
            return
        idx = '1.0'
        while True:
            idx = self.result_text.search(query, idx, nocase=True, stopindex=tk.END)
            if not idx:
                break
            lastidx = f"{idx}+{len(query)}c"
            self.result_text.tag_add('search', idx, lastidx)
            idx = lastidx
        self.result_text.tag_config('search', background='yellow', foreground='black')

    def copy_results(self):
        self.clipboard_clear()
        self.clipboard_append(self.result_text.get('1.0', tk.END))
        self.status_bar.set_status("Results copied to clipboard!", status_type='success')

    def clear_results(self):
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.config(state='disabled')
        self.status_bar.set_status("Results cleared.", status_type='info')

    def display_results(self, result: str):
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, result)
        self.result_text.config(state='disabled')
        self.status_bar.set_status("Analysis complete.", status_type='success')

    def display_error(self, error: str):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, f"[Error] {error}\n")
        self.result_text.config(state='disabled')
        self.status_bar.set_status("Error occurred.", status_type='error')

    # --- Tool button handlers (stubs, to be implemented) ---
    def analyze_type(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: FileAnalyzerUtils.detect_file_type(str(self.selected_file_path)), "Type Detection")
    def analyze_extract(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: str(FileAnalyzerUtils.extract_archive(str(self.selected_file_path), 'file_analyzer_output')), "Extract Archive")
    def analyze_compress(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: str(FileAnalyzerUtils.compress_file(str(self.selected_file_path), os.path.join('file_analyzer_output', os.path.basename(str(self.selected_file_path)) + '.zip'), 'zip')), "Compress File")
    def analyze_strings(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: str(FileAnalyzerUtils.extract_strings(str(self.selected_file_path))), "String Extraction")
    def analyze_carve(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: str(FileAnalyzerUtils.carve_files(str(self.selected_file_path), 'file_analyzer_output')), "File Carving")
    def analyze_metadata(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: str(FileAnalyzerUtils.extract_metadata(str(self.selected_file_path))), "Metadata Analysis")
    def analyze_entropy(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: str(FileAnalyzerUtils.analyze_entropy(str(self.selected_file_path))), "Entropy Analysis")
    def analyze_stego(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: str(FileAnalyzerUtils.analyze_steganography(str(self.selected_file_path), 'file_analyzer_output')), "Stego Analysis")
    def analyze_ciphey(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: str(FileAnalyzerUtils.auto_decode(str(self.selected_file_path))), "Ciphey Magic")
    def analyze_recursive(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: str(FileAnalyzerUtils.recursive_extract(str(self.selected_file_path), 'file_analyzer_output')), "Recursive Extraction")
    def ctf_auto_analyze(self):
        if not self.selected_file_path:
            return
        self.run_analysis(lambda: str(FileAnalyzerUtils.analyze_file(str(self.selected_file_path), 'file_analyzer_output')), "CTF Auto-Analyze")

    def show_loading(self):
        if self.loading_overlay and self.loading_label and self.loading_spinner:
            self.loading_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.loading_label.place(relx=0.5, rely=0.4, anchor='center')
            self.loading_spinner.place(relx=0.5, rely=0.55, anchor='center')
            self.update_spinner()
        self.set_tool_buttons_state('disabled')

    def hide_loading(self):
        if self.loading_overlay and self.loading_label and self.loading_spinner:
            self.loading_overlay.place_forget()
            self.loading_label.place_forget()
            self.loading_spinner.place_forget()
            if self.loading_after_id:
                self.after_cancel(self.loading_after_id)
                self.loading_after_id = None
        self.set_tool_buttons_state('normal')

    def update_spinner(self):
        if self.loading_spinner:
            self.spinner_index = (self.spinner_index + 1) % len(self.spinner_chars)
            self.loading_spinner.config(text=self.spinner_chars[self.spinner_index])
            self.loading_after_id = self.after(100, self.update_spinner)

    def set_tool_buttons_state(self, state: str):
        for btn in self.tool_buttons:
            if hasattr(btn, 'config'):
                btn.config(state=state)

    def select_wordlist(self):
        path = filedialog.askopenfilename(title="Select Wordlist", filetypes=[("Wordlist Files", "*.txt *.lst *wordlist*"), ("All Files", "*.*")])
        if path:
            self.selected_wordlist_path = path
            self.status_bar.set_status(f"Selected wordlist: {os.path.basename(path)}", status_type='info')

    def analyze_crack_password(self):
        if not self.selected_file_path:
            return
        wordlist = self.selected_wordlist_path or '/usr/share/wordlists/rockyou.txt'
        self.run_analysis(lambda: str(FileAnalyzerUtils.crack_archive_password(str(self.selected_file_path), wordlist)), "Password Crack (John)")

    def save_results(self):
        result = self.result_text.get('1.0', tk.END)
        if not result.strip():
            messagebox.showinfo("Save Results", "No results to save.")
            return
        path = filedialog.asksaveasfilename(title="Save Results", defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(result)
            self.status_bar.set_status(f"Results saved to {os.path.basename(path)}", status_type='success')

    def run_analysis(self, analysis_func: Callable[[], str], label: str):
        if not self.selected_file_path or not os.path.isfile(self.selected_file_path):
            messagebox.showerror("Error", "Please select a valid file to analyze.")
            return
        self.status_bar.set_status(f"Running {label}...", status_type='info')
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.config(state='disabled')
        self.show_loading()
        def run():
            try:
                result = analysis_func()
                self.after(0, lambda: [self.hide_loading(), self.display_results(str(result))])
            except Exception as e:
                self.after(0, lambda: [self.hide_loading(), self.display_error(str(e))])
        threading.Thread(target=run, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileAnalyzerMainWindow(root, lambda: None)
    root.mainloop() 