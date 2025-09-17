import tkinter as tk
from tkinter import ttk, filedialog
import email
from email.parser import BytesParser
from email.policy import default
import re
import os
import sys
from datetime import datetime
import hashlib

# --- Dependency Import ---
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: BeautifulSoup4 is required. Please install it using 'pip install beautifulsoup4'")
    sys.exit(1)

# --- Configuration & Hardening ---
MAX_ATTACHMENT_SIZE_BYTES = 50 * 1024 * 1024
HEADER_TRUNCATE_LIMIT = 200

# --- Color Formatting (with auto-disable) ---
class Colors:
    ENABLED = sys.stdout.isatty()
    HEADER = '\033[95m' if ENABLED else ''
    BLUE = '\033[94m' if ENABLED else ''
    GREEN = '\033[92m' if ENABLED else ''
    YELLOW = '\033[93m' if ENABLED else ''
    RED = '\033[91m' if ENABLED else ''
    ENDC = '\033[0m' if ENABLED else ''
    BOLD = '\033[1m' if ENABLED else ''

# --- Helper Functions ---
def print_section_header(title):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*20} {title.upper()} {'='*20}{Colors.ENDC}")

def defang_url(url):
    return url.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')

def format_bytes(size):
    if size is None: return "0 Bytes"
    power, n = 1024, 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power and n < len(power_labels):
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def normalize_body_for_ioc(text):
    text = text.replace('[.]', '.').replace('(.)', '.')
    text = text.replace('hxxp://', 'http://').replace('hxxps://', 'https://')
    return text

# --- Analysis Functions ---

def print_forensic_headers(msg):
    """Prints a detailed, grouped analysis of all headers."""
    all_headers = msg.items()
    
    # Groups for organized output
    groups = {
        'Trace': ['Received'],
        'Authentication': ['Received-SPF', 'Authentication-Results', 'DKIM-Signature', 'ARC-Seal', 'ARC-Message-Signature'],
        'Origin': ['X-Originating-IP', 'X-Sender-IP', 'X-Mailer', 'X-Sender'],
        'Anti-Spam': ['X-AntiSpam', 'X-Spam-Status', 'X-MSMail-Priority', 'X-Priority'],
        'Misc': [] # For everything else
    }
    
    # Categorize headers
    categorized = {key: [] for key in groups}
    processed_keys = set()

    for group_name, keys in groups.items():
        if group_name == 'Misc': continue
        for key in keys:
            for h_key, h_val in all_headers:
                if h_key.lower() == key.lower():
                    categorized[group_name].append((h_key, h_val))
                    processed_keys.add(h_key)

    # Add remaining headers to Misc
    for h_key, h_val in all_headers:
        if h_key not in processed_keys:
            categorized['Misc'].append((h_key, h_val))
    
    # Print categorized headers
    for group_name, items in categorized.items():
        if items:
            print(f"\n--- {group_name} ---")
            # Reverse the 'Received' trace to show path from origin to destination
            if group_name == 'Trace':
                items.reverse()
            for key, val in items:
                print(f"{Colors.BLUE}{key:<25}:{Colors.ENDC} {val.strip()}")


def run_analysis(file_path, mode):
    """The main analysis orchestrator."""
    if not file_path or not os.path.exists(file_path):
        print(f"{Colors.RED}Error: File not found or not selected.{Colors.ENDC}")
        return

    print(f"{Colors.GREEN}Analysis for: {os.path.basename(file_path)} | Mode: {mode}{Colors.ENDC}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=default).parse(f)

    # --- Standard Headers (shown in both modes) ---
    print_section_header("Key Headers")
    key_headers = ['Date', 'From', 'To', 'Reply-To', 'Cc', 'Subject']
    for header in key_headers:
        value = msg.get(header)
        display_value = (value[:HEADER_TRUNCATE_LIMIT] + '...') if value and len(value) > HEADER_TRUNCATE_LIMIT else value
        print(f"{Colors.BLUE}{header:<15}:{Colors.ENDC} {display_value or 'Not Found'}")
    
    # --- Detailed Forensic Dump (only in detailed mode) ---
    if mode == 'Detailed Forensics':
        print_section_header("Forensic Header Analysis")
        print_forensic_headers(msg)

    # --- Attachments ---
    print_section_header("Attachments")
    attachments = []

    # --- IOC Extraction  ---
    print_section_header("Indicators of Compromise (IOCs)")
    full_body_text = ""
    html_content = ""

# --- GUI Application Class ---
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("EML Analyzer")
        self.file_path = ""
        self.mode = tk.StringVar(value="Simple Triage")

        mainframe = ttk.Frame(root, padding="12 12 12 12")
        mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Mode Selection
        ttk.Label(mainframe, text="Select Analysis Mode:").grid(column=1, row=1, sticky=tk.W)
        mode_cb = ttk.Combobox(mainframe, textvariable=self.mode, values=["Simple Triage", "Detailed Forensics"])
        mode_cb.grid(column=2, row=1, sticky=(tk.W, tk.E))
        mode_cb.state(["readonly"])
        
        # File Selection
        ttk.Label(mainframe, text="Select EML File:").grid(column=1, row=2, sticky=tk.W)
        self.file_label = ttk.Label(mainframe, text="No file selected...")
        self.file_label.grid(column=2, row=2, sticky=tk.W)
        ttk.Button(mainframe, text="Browse...", command=self.select_file).grid(column=3, row=2, sticky=tk.W)
        
        # Analyze Button
        ttk.Button(mainframe, text="Analyze", command=self.start_analysis).grid(column=3, row=3, sticky=tk.E)

        for child in mainframe.winfo_children(): 
            child.grid_configure(padx=5, pady=5)

    def select_file(self):
        path = filedialog.askopenfilename(
            title="Select an EML file",
            filetypes=(("EML files", "*.eml"), ("All files", "*.*"))
        )
        if path:
            self.file_path = path
            self.file_label.config(text=os.path.basename(path))

    def start_analysis(self):
        if not self.file_path:
            print("Please select a file first.")
            return
        
        selected_mode = self.mode.get()
        self.root.destroy()  # Close the GUI
        
        # Run the console-based analysis
        run_analysis(self.file_path, selected_mode)


# Full run_analysis function to be placed before the App class
def run_analysis(file_path, mode):
    """The main analysis orchestrator."""
    if not file_path or not os.path.exists(file_path):
        print(f"{Colors.RED}Error: File not found or not selected.{Colors.ENDC}")
        return

    print(f"\n{'='*60}")
    print(f"{Colors.GREEN}Analysis for: {os.path.basename(file_path)} | Mode: {mode}{Colors.ENDC}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=default).parse(f)

    print_section_header("Key Headers")
    key_headers = ['Date', 'From', 'To', 'Reply-To', 'Cc', 'Subject']
    for header in key_headers:
        value = msg.get(header)
        display_value = (value[:HEADER_TRUNCATE_LIMIT] + '...') if value and len(value) > HEADER_TRUNCATE_LIMIT else value
        print(f"{Colors.BLUE}{header:<15}:{Colors.ENDC} {display_value or 'Not Found'}")

    if mode == 'Detailed Forensics':
        print_section_header("Forensic Header Analysis")
        print_forensic_headers(msg)

    print_section_header("Attachments")
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment' or part.get_filename():
            filename = part.get_filename()
            if filename:
                decoded_payload = part.get_payload(decode=True)
                size = len(decoded_payload)
                sha256_hash = f"SKIPPED (File > {format_bytes(MAX_ATTACHMENT_SIZE_BYTES)})" if size > MAX_ATTACHMENT_SIZE_BYTES else hashlib.sha256(decoded_payload).hexdigest()
                attachments.append({'filename': filename, 'type': part.get_content_type(), 'size': size, 'sha256': sha256_hash})
    if attachments:
        for att in attachments:
            print(f"- {Colors.YELLOW}{att['filename']}{Colors.ENDC} ({Colors.GREEN}{att['type']}{Colors.ENDC})")
            print(f"  Size: {Colors.BLUE}{format_bytes(att['size'])}{Colors.ENDC}")
            print(f"  SHA256: {Colors.RED if 'SKIPPED' in att['sha256'] else ''}{att['sha256']}{Colors.ENDC}")
    else:
        print("No attachments found.")

    print_section_header("Indicators of Compromise (IOCs)")
    full_body_text, html_content = "", ""
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get_content_disposition())
        if "attachment" not in content_disposition and content_type in ["text/plain", "text/html"]:
            try:
                payload_bytes = part.get_payload(decode=True)
                charset = part.get_content_charset() or 'utf-8'
                decoded_text = payload_bytes.decode(charset, errors='replace')
                if content_type == "text/html":
                    html_content += decoded_text
                else:
                    full_body_text += decoded_text + "\n"
            except Exception: continue
    
    urls = set()
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        # ** Extract URLs from href attributes **
        for a in soup.find_all('a', href=True):
            if a['href'].strip():
                urls.add(a['href'].strip())
        full_body_text += soup.get_text(separator='\n', strip=True)

    normalized_text = normalize_body_for_ioc(full_body_text)
    urls.update(re.findall(r'https?://[^\s"\'<>]+', normalized_text))
    ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', normalized_text))
    emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', full_body_text))

    if urls:
        print(f"\n{Colors.BLUE}URLs Found ({len(urls)}):{Colors.ENDC}")
        for url in sorted(urls): print(f"- {Colors.RED}{defang_url(url)}{Colors.ENDC}")
    else: print(f"\n{Colors.BLUE}No URLs Found.{Colors.ENDC}")

    if ips:
        print(f"\n{Colors.BLUE}IPv4 Addresses Found ({len(ips)}):{Colors.ENDC}")
        for ip in sorted(ips):
            if not ip.startswith(('192.168.', '10.', '172.16.', '127.0.0.')):
                print(f"- {Colors.RED}{ip}{Colors.ENDC}")
    else: print(f"\n{Colors.BLUE}No IPv4 Addresses Found.{Colors.ENDC}")

    if emails:
        print(f"\n{Colors.BLUE}Email Addresses Found ({len(emails)}):{Colors.ENDC}")
        for mail in sorted(emails): print(f"- {mail}")
    else: print(f"\n{Colors.BLUE}No other Email Addresses Found.{Colors.ENDC}")

    print_section_header("End of Analysis")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
