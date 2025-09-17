# EML Analyzer (`emlanalyzer.py`)

A powerful command-line tool with a simple GUI for the forensic analysis of `.eml` files. Designed for security analysts, incident responders, and anyone needing to quickly triage and inspect email files for malicious indicators.

The script parses an EML file to extract key headers, analyze the full header stack, identify and hash attachments, and extract Indicators of Compromise (IOCs) like URLs, IP addresses, and email addresses.

## Features

-   **Dual Analysis Modes:**
    -   **Simple Triage:** Provides a high-level summary including key headers, attachments, and IOCs. Perfect for quick initial assessments.
    -   **Detailed Forensics:** Includes everything in Simple Triage, plus a complete, categorized dump of all email headers (Trace, Authentication, Origin, etc.) for deep-dive analysis.
-   **Comprehensive Header Analysis:**
    -   Displays key headers (`From`, `To`, `Subject`, `Date`) for immediate context.
    -   In forensic mode, it logically groups headers and reverses the `Received` trace to show the email's path from origin to destination.
-   **Attachment Processing:**
    -   Lists all attachments found in the email.
    -   Provides filename, MIME type, and file size.
    -   Calculates the **SHA256 hash** of each attachment for threat intelligence lookups (e.g., on VirusTotal).
    -   Includes a safety mechanism to skip hashing for excessively large files (default > 50MB).
-   **Indicator of Compromise (IOC) Extraction:**
    -   Automatically parses the email body (both plain text and HTML) to find IOCs.
    -   Extracts and lists all **URLs**, **IPv4 addresses**, and **email addresses**.
-   **Security Focused:**
    -   **URL Defanging:** All extracted URLs are automatically "defanged" (e.g., `http://` becomes `hxxp://` and `domain.com` becomes `domain[.]com`) to prevent accidental clicks on malicious links.
    -   **Private IP Filtering:** Private/internal range IPv4 addresses (like `192.168.x.x`, `10.x.x.x`) are automatically filtered out to reduce noise.
-   **User-Friendly Output:**
    -   A simple Tkinter GUI allows for easy file and mode selection.
    -   The console output is clean, well-organized, and color-coded for enhanced readability.

## Requirements

-   Python 3.x
-   `BeautifulSoup4` library

## Installation

1.  Ensure you have Python 3 installed on your system.
2.  Clone this repository or download the `emlanalyzer.py` script.
3.  Install the required `BeautifulSoup4` dependency using pip:
    ```bash
    pip install beautifulsoup4
    ```

## Usage

1.  Run the script from your terminal:
    ```bash
    python emlanalyzer.py
    ```
2.  A small GUI window will appear.
    -   **Select Analysis Mode:** Choose between "Simple Triage" or "Detailed Forensics" from the dropdown.
    -   **Select EML File:** Click the "Browse..." button to open a file dialog and select the `.eml` file you want to analyze.
3.  Click the **"Analyze"** button.
4.  The GUI window will close, and the full analysis report will be printed directly to your console/terminal window.

## Example Output

The output in your terminal will look similar to this:

```bash
============================================================
Analysis for: suspicious-email.eml | Mode: Detailed Forensics
Time: 2025-09-17 00:07:49
============================================================

==================== KEY HEADERS ====================
Date           : Tue, 16 Sep 2025 14:30:15 +0000
From           : "Account Support" <support@bad-actor-domain.com>
To             : "Valued Customer" <victim@example.com>
Reply-To       : "No Reply" <noreply@bad-actor-domain.com>
Cc             : Not Found
Subject        : Urgent: Action Required on Your Account

==================== FORENSIC HEADER ANALYSIS ====================

--- Trace ---
Received          : from mail-server.legit.com (HELO mail.legit.com) by mx.example.com
Received          : from smtp.evil-relay.net ([198.51.100.123]) by mail-server.legit.com

--- Authentication ---
Authentication-Results: mx.example.com; spf=fail (sender IP is 198.51.100.123)
DKIM-Signature    : v=1; a=rsa-sha256; c=relaxed/relaxed; d=bad-actor-domain.com;

--- Origin ---
X-Originating-IP  : [198.51.100.123]
X-Mailer          : BadMailer v1.2

... (other headers) ...

==================== ATTACHMENTS ====================
- Invoice_Urgent.pdf (application/pdf)
  Size: 123.45 KB
  SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- image001.png (image/png)
  Size: 15.67 KB
  SHA256: f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2

==================== INDICATORS OF COMPROMISE (IOCS) ====================

URLs Found (3):
- hxxps://bad-actor-domain[.]com/login
- hxxp://tracking[.]evil-link[.]net/track?id=123
- hxxps://some-cdn[.]com/style[.]css

IPv4 Addresses Found (1):
- 198.51.100.123

Email Addresses Found (3):
- noreply@bad-actor-domain.com
- support@bad-actor-domain.com
- victim@example.com

==================== END OF ANALYSIS ====================
