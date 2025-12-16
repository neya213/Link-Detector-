import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.ttk import Notebook, Frame, Label, Button, Entry, Progressbar
from dfa_keywords import dfa_keywords 
from dfa_symbols import dfa_symbols   
from dfa_ip import dfa_ip             
from dfa_tld import dfa_tld           
from dfa_encoded import dfa_encoded   
import re

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.widget.bind('<Enter>', self.show_tip)
        self.widget.bind('<Leave>', self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True) 
        tw.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
        self.tip_window = None

def unified_phishing_detector(url):
    def dfa_keywords(u): return "login" in u.lower() or "bank" in u.lower()
    def dfa_symbols(u): return "@" in u or "//" in u[5:]
    def dfa_ip(u): 
        try:
            domain = url.split('//')[1].split('/')[0].split(':')[0]
            return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))
        except IndexError:
            return False
            
    def dfa_tld(u): return ".xyz" in u.lower() or ".cc" in u.lower() or ".online" in u.lower()
    def dfa_encoded(u): return "%" in u or "0x" in u.lower()

    results = {
        "Phishing Keywords": dfa_keywords(url),
        "Suspicious Symbols": dfa_symbols(url),
        "IP_Address in_Domain": dfa_ip(url),
        "Suspicious TLD": dfa_tld(url),
        "Obfuscated Encoding": dfa_encoded(url)
    }

    match_count = sum(1 for v in results.values() if v)
    total_dfas = len(results)

    if match_count == 0:
        risk = "SAFE"
        color = "#28A745"
    elif match_count <= 2:
        risk = "SUSPICIOUS"
        color = "#FFC107"
    else:
        risk = "HIGH RISK / PHISHING"
        color = "#DC3545"

    risk_score = (match_count / total_dfas) * 100 
    
    return match_count, results, risk, color, risk_score

def scan_url():
    url = url_entry.get().strip()
    
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL.")
        return
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    match_count, indicators, risk, color, risk_score = unified_phishing_detector(url)

    for widget in indicator_list_inner_frame.winfo_children():
        widget.destroy()

    style.configure("Rounded.TLabel", background=color, foreground=WHITE)
    risk_label.config(text=f"RISK LEVEL: {risk}")
    
    risk_bar.config(value=risk_score)
    
    style.configure("Custom.Horizontal.TProgressbar", background=color)
    
    match_count_label.config(text=f"Total Indicators Matched: {match_count} / 5", font=("Segoe UI", 11, "normal"))

    tk.Label(indicator_list_inner_frame, text="--- Individual DFA Status ---", font=("Segoe UI", 10, "underline", "bold"), foreground=DARK_GRAY, background=WHITE).grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 5))

    row_num = 1
    for name, value in indicators.items():
        status = "MATCH FOUND" if value else "CLEAN"
        fg_color = "#DC3545" if value else "#28A745"

        tk.Label(indicator_list_inner_frame, text=f"• {name}:", font=("Segoe UI", 10), background=WHITE, anchor="w").grid(row=row_num, column=0, sticky="w", padx=5, pady=4)
        
        tk.Label(indicator_list_inner_frame, text=status, font=("Segoe UI", 10, "bold"), foreground=fg_color, background=WHITE, anchor="w").grid(row=row_num, column=1, sticky="w", padx=5, pady=4)
        
        row_num += 1
        
    url_display.config(text=f"Scanning: {url}", foreground=ACCENT_COLOR)

app = tk.Tk()
app.title("DFA Phishing Detector - V3 (Rounded)")
app_width = 650
app_height = 550
app.geometry(f"{app_width}x{app_height}")
app.resizable(False, False)

MAIN_GRAY = "#E0E0E0"
DARK_GRAY = "#333333"
WHITE = "#FFFFFF"
ACCENT_COLOR = "#007BFF" 
ROUND_RADIUS = 10

style = ttk.Style(app)
style.theme_use("clam")

style.configure('.', font=('Segoe UI', 10))
style.configure('TNotebook.Tab', font=('Segoe UI', 10, 'bold'))
style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), foreground=WHITE, background=DARK_GRAY)
style.configure("Custom.Horizontal.TProgressbar", troughcolor=MAIN_GRAY, bordercolor=DARK_GRAY, background=ACCENT_COLOR, lightcolor=ACCENT_COLOR, darkcolor=ACCENT_COLOR)

style.element_create("RoundedLabel.background", "from", "clam") 
style.layout("Rounded.TLabel", 
             [("RoundedLabel.background", {"sticky": "nswe", "children": 
               [("RoundedLabel.padding", {"sticky": "nswe", "children": 
                 [("RoundedLabel.label", {"sticky": "nswe"})]})]})])
style.configure("Rounded.TLabel", borderwidth=0, relief="flat", padding=[10, 5], bordercolor=DARK_GRAY, borderradius=ROUND_RADIUS)

style.configure('Accent.TButton', background=ACCENT_COLOR, foreground=WHITE, borderradius=ROUND_RADIUS)
style.map('Accent.TButton',
          background=[('active', ACCENT_COLOR)],
          foreground=[('active', WHITE)])

style.configure('Rounded.TLabelframe', 
                background=MAIN_GRAY, 
                relief="flat",
                borderradius=ROUND_RADIUS)
style.configure('Rounded.TLabelframe.Label', 
                foreground=DARK_GRAY)
style.layout('Rounded.TLabelframe', 
             [('Rounded.TLabelframe.border', {'sticky': 'nswe', 'unit': '1', 'children': [
                 ('Rounded.TLabelframe.padding', {'sticky': 'nswe', 'children': [
                     ('Rounded.TLabelframe.label', {'sticky': 'nw'}),
                     ('Rounded.TLabelframe.contents', {'sticky': 'nswe'})
                 ]})
             ]})])

notebook = Notebook(app)
notebook.pack(pady=10, padx=10, fill="both", expand=True)

scanner_tab = Frame(notebook, padding="15", style='TFrame')
scanner_tab.config(style='TFrame')
notebook.add(scanner_tab, text="🔍 Phishing Scanner")

Label(
    scanner_tab,
    text="DFA URL Analysis System",
    style='Header.TLabel',
    anchor='center'
).pack(fill='x', pady=(0, 15))

input_frame = Frame(scanner_tab, padding="5")
input_frame.pack(pady=10, fill='x')

Label(input_frame, text="Enter URL:", font=("Segoe UI", 12), foreground=DARK_GRAY).grid(row=0, column=0, padx=5, pady=5, sticky='w')
url_entry = Entry(input_frame, width=50, font=("Segoe UI", 11))
url_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
input_frame.grid_columnconfigure(1, weight=1) 

scan_button = Button(
    input_frame,
    text="Analyze URL",
    command=scan_url,
    style='Accent.TButton'
)
scan_button.grid(row=0, column=2, padx=10, pady=5)
ToolTip(scan_button, "Click to run the URL through all 5 DFA models.")

url_display = Label(scanner_tab, text="Ready to scan...", font=("Segoe UI", 9, "italic"), foreground=MAIN_GRAY)
url_display.pack(pady=(0, 10))

output_labelframe = ttk.LabelFrame(
    scanner_tab,
    text="Analysis Report",
    padding=10,
    style='Rounded.TLabelframe'
)
output_labelframe.pack(fill='both', expand=True)

risk_frame = Frame(output_labelframe, padding="10")
risk_frame.pack(fill='x', pady=(0, 10))

risk_label = Label(
    risk_frame,
    text="RISK LEVEL: UNKNOWN",
    font=("Segoe UI", 14, "bold"),
    style="Rounded.TLabel", 
    relief=tk.FLAT,
    anchor='center',
    padding=(10, 5)
)
risk_label.pack(fill='x', pady=(0, 5))

risk_bar = Progressbar(risk_frame, orient='horizontal', length=500, mode='determinate', style="Custom.Horizontal.TProgressbar")
risk_bar.pack(fill='x')

match_count_label = Label(risk_frame, text="Total Indicators Matched: 0 / 5", font=("Segoe UI", 11, "normal"), anchor='center')
match_count_label.pack(pady=(5, 0))

indicator_list_canvas = tk.Canvas(output_labelframe, bg=MAIN_GRAY, highlightthickness=0)
indicator_list_canvas.pack(fill='both', expand=True, padx=5, pady=5)

indicator_list_canvas.create_rectangle(5, 5, app_width - 45, app_height - 325, 
                                       fill=WHITE, outline=MAIN_GRAY, width=1, tags="rounded_bg")

indicator_list_inner_frame = tk.Frame(indicator_list_canvas, padx=10, pady=10, bg=WHITE)
indicator_list_canvas.create_window((15, 15), window=indicator_list_inner_frame, anchor="nw")

tk.Label(indicator_list_inner_frame, text="Run the scan to see the detailed status of each DFA model.", font=("Segoe UI", 10, "italic"), foreground=DARK_GRAY, background=WHITE).grid(row=1, column=0, columnspan=2, padx=5, pady=30)
tk.Label(indicator_list_inner_frame, text=" ", font=("Segoe UI", 10, "underline", "bold"), foreground=DARK_GRAY, background=WHITE).grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 5))

help_tab = Frame(notebook, padding="15")
notebook.add(help_tab, text="ℹ️ Help & Info")

Label(help_tab, text="About the Detector", font=("Segoe UI", 16, "bold"), foreground=DARK_GRAY).pack(pady=(0, 10))

help_text = tk.Text(
    help_tab, 
    wrap=tk.WORD, 
    height=15, 
    width=70, 
    font=("Segoe UI", 10),
    relief=tk.FLAT,
    borderwidth=0,
    background=MAIN_GRAY 
)

help_text.insert(tk.END, """
This system utilizes five different Deterministic Finite Automata (DFA) models to analyze a URL for common phishing characteristics.

DFA Models:
1. Phishing Keywords: Looks for terms like 'login', 'secure', 'bank' combined with suspicious domain structure.
2. Suspicious Symbols: Checks for special characters like '@' (used to confuse users about the true domain).
3. IP Address in Domain: Flags URLs where an IP address is used instead of a human-readable domain name.
4. Suspicious TLD: Detects known risky Top-Level Domains (TLDs) often used for malicious purposes (e.g., .xyz, .cc).
5. Obfuscated Encoding: Identifies URL encoding (e.g., %20, 0x) used to hide the true nature of the address.

Risk Scoring:
• SAFE (0 Matches)
• SUSPICIOUS (1-2 Matches)
• HIGH RISK / PHISHING (3+ Matches)
""")

help_text.config(state=tk.DISABLED)

help_text.pack(fill='both', expand=True)

app.mainloop()