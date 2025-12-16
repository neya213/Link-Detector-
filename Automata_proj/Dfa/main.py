import tkinter as tk
from tkinter import ttk

from dfa_keywords import dfa_keywords
from dfa_symbols import dfa_symbols
from dfa_ip import dfa_ip
from dfa_tld import dfa_tld
from dfa_encoded import dfa_encoded


def unified_phishing_detector(url):
    results = {
        "Suspicious Keywords": dfa_keywords(url),
        "Symbol Abuse": dfa_symbols(url),
        "IP-Based URL": dfa_ip(url),
        "Suspicious TLD": dfa_tld(url),
        "Encoded Characters": dfa_encoded(url)
    }

    match_count = sum(results.values())

    if match_count == 0:
        risk = "SAFE"
    elif match_count <= 2:
        risk = "SUSPICIOUS"
    else:
        risk = "HIGH RISK / PHISHING"

    return match_count, results, risk


def scan_url():
    url = url_entry.get().strip()
    result_box.config(state="normal")
    result_box.delete("1.0", tk.END)

    if not url:
        result_box.insert(tk.END, "Please enter a URL.\n")
        result_box.config(state="disabled")
        return

    matches, indicators, risk = unified_phishing_detector(url)

    result_box.insert(tk.END, f"URL: {url}\n\n")
    for name, detected in indicators.items():
        status = "MATCH" if detected else "OK"
        result_box.insert(tk.END, f"{name:<25}: {status}\n")

    result_box.insert(tk.END, f"\nTotal Matches: {matches}")
    result_box.insert(tk.END, f"\nFinal Risk Level: {risk}")

    result_box.config(state="disabled")


app = tk.Tk()
app.title("DFA Phishing URL Detector")
app.geometry("520x420")
app.resizable(False, False)

title = ttk.Label(app, text="DFA-Based Phishing URL Detector",
                  font=("Segoe UI", 16, "bold"))
title.pack(pady=15)

url_entry = ttk.Entry(app, width=55)
url_entry.pack(pady=5)
url_entry.focus()

scan_btn = ttk.Button(app, text="Scan URL", command=scan_url)
scan_btn.pack(pady=10)

result_box = tk.Text(app, height=12, width=60, state="disabled")
result_box.pack(padx=10, pady=10)

app.mainloop()
