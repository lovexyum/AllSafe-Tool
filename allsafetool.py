import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import requests
import hashlib
import os
import datetime
import base64
import threading

VT_API_KEY = "YOUR VIRUSTOTAL API KEY HERE"

VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/{}"
VT_URL_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
VT_URL_REPORT_URL = "https://www.virustotal.com/api/v3/urls/{}"

COLORS = {
    "dark_blue": "#335765",
    "teal": "#74A8A4",
    "light_blue": "#B6D9E0",
    "off_white": "#DBE2DC",
    "brown": "#7F543D",
}


def hash_file_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_file(filepath):
    headers = {"x-apikey": VT_API_KEY}
    file_hash = hash_file_sha256(filepath)

    response = requests.get(VT_FILE_REPORT_URL.format(file_hash), headers=headers)
    if response.status_code == 200:
        return response.json()

    return None

def scan_url(url):
    headers = {"x-apikey": VT_API_KEY}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    response = requests.get(VT_URL_REPORT_URL.format(url_id), headers=headers)
    if response.status_code == 200:
        return response.json()

    return None

def parse_vt_response(response):
    if not response:
        return ("No existing VirusTotal report found.\n"
                "For a thorough scan, please consider uploading the file or URL directly on VirusTotal.com.\n"
                "The tool will notify if any suspicious behavior is detected in known reports.\n")

    try:
        data = response.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        verdict = "SAFE"
        if malicious > 0:
            verdict = "MALICIOUS"
        elif suspicious > 0:
            verdict = "SUSPICIOUS"

        details = f"Verdict: {verdict}\n"
        details += f"Malicious Detections: {malicious}\n"
        details += f"Suspicious Detections: {suspicious}\n"
        details += f"Harmless: {harmless}\n"

        if "last_analysis_results" in attributes:
            engines = attributes["last_analysis_results"]
            detected_engines = [eng for eng, res in engines.items() if res.get("category") in ["malicious", "suspicious"]]
            if detected_engines:
                details += "\nDetected by:\n"
                for eng in detected_engines:
                    details += f"- {eng}\n"

        details += "\nRecommendation: "
        if verdict == "SAFE":
            details += "File/URL appears safe."
        else:
            details += "Abort all activities with this file/link."

        return details

    except Exception as e:
        return f"Error parsing VirusTotal response: {str(e)}"

def log_scan(scan_type, input_data, result):
    try:
        with open("scan_log.txt", "a") as logfile:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            summary = result.splitlines()[0] if result else "No Result"
            logfile.write(f"{timestamp} | {scan_type} | {input_data} | Result: {summary}\n")
    except Exception as e:
        print(f"Logging error: {e}")

class AllSafeToolApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("The AllSafe Tool")
        self.geometry("650x520")
        self.configure(bg=COLORS["off_white"])

        self.create_widgets()

    def create_widgets(self):
        title_label = tk.Label(self, text="The AllSafe Tool", font=("Arial", 26, "bold"), fg=COLORS["brown"], bg=COLORS["off_white"])
        title_label.pack(pady=15)

        input_frame = tk.Frame(self, bg=COLORS["off_white"])
        input_frame.pack(pady=10)

        file_label = tk.Label(input_frame, text="Select file to scan:", bg=COLORS["off_white"], fg=COLORS["dark_blue"], font=("Arial", 12))
        file_label.grid(row=0, column=0, sticky="w")
        self.file_entry = tk.Entry(input_frame, width=45, font=("Arial", 12))
        self.file_entry.grid(row=0, column=1, padx=5)
        browse_button = tk.Button(input_frame, text="Browse", bg=COLORS["teal"], fg=COLORS["off_white"], font=("Arial", 11), command=self.browse_file)
        browse_button.grid(row=0, column=2, padx=5)

        self.scan_file_btn = tk.Button(input_frame, text="Scan File", bg=COLORS["dark_blue"], fg=COLORS["off_white"], font=("Arial", 12, "bold"), command=self.threaded_scan_file)
        self.scan_file_btn.grid(row=0, column=3, padx=10)

        url_label = tk.Label(input_frame, text="Enter URL to scan:", bg=COLORS["off_white"], fg=COLORS["dark_blue"], font=("Arial", 12))
        url_label.grid(row=1, column=0, sticky="w", pady=15)
        self.url_entry = tk.Entry(input_frame, width=45, font=("Arial", 12))
        self.url_entry.grid(row=1, column=1, padx=5, pady=15)

        self.scan_url_btn = tk.Button(input_frame, text="Scan URL", bg=COLORS["dark_blue"], fg=COLORS["off_white"], font=("Arial", 12, "bold"), command=self.threaded_scan_url)
        self.scan_url_btn.grid(row=1, column=3, padx=10, pady=15)

        self.status_label = tk.Label(self, text="Ready.", bg=COLORS["off_white"], fg=COLORS["brown"], font=("Arial", 11, "italic"))
        self.status_label.pack(pady=(5, 0))

        results_label = tk.Label(self, text="Scan Results:", bg=COLORS["off_white"], fg=COLORS["brown"], font=("Arial", 14, "bold"))
        results_label.pack(pady=(15, 5))

        self.results_text = scrolledtext.ScrolledText(self, width=75, height=18, font=("Courier New", 11), bg=COLORS["light_blue"], fg=COLORS["dark_blue"])
        self.results_text.pack(padx=10, pady=5)

    def browse_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filepath)

    def threaded_scan_file(self):
        threading.Thread(target=self.scan_file_action, daemon=True).start()

    def threaded_scan_url(self):
        threading.Thread(target=self.scan_url_action, daemon=True).start()

    def scan_file_action(self):
        filepath = self.file_entry.get().strip()
        if not filepath or not os.path.isfile(filepath):
            messagebox.showerror("Error", "Please select a valid file.")
            return

        self.toggle_buttons(False)
        self.status_label.config(text="Scanning file... Please wait.")
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, "Scanning file... Please wait.\n")

        try:
            response = scan_file(filepath)
            result_text = parse_vt_response(response)
        except Exception as e:
            result_text = f"Error during scan: {str(e)}"

        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, result_text)
        self.status_label.config(text="Scan completed.")
        log_scan("File", filepath, result_text)
        self.toggle_buttons(True)

    def scan_url_action(self):
        url = self.url_entry.get().strip()
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            messagebox.showerror("Error", "Please enter a valid URL starting with http:// or https://")
            return

        self.toggle_buttons(False)
        self.status_label.config(text="Scanning URL... Please wait.")
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, "Scanning URL... Please wait.\n")

        try:
            response = scan_url(url)
            result_text = parse_vt_response(response)
        except Exception as e:
            result_text = f"Error during scan: {str(e)}"

        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, result_text)
        self.status_label.config(text="Scan completed.")
        log_scan("URL", url, result_text)
        self.toggle_buttons(True)

    def toggle_buttons(self, enable=True):
        state = "normal" if enable else "disabled"
        self.scan_file_btn.config(state=state)
        self.scan_url_btn.config(state=state)

if __name__ == "__main__":
    app = AllSafeToolApp()
    app.mainloop()
