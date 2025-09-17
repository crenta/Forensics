# Digital Forensics Toolkit

This repository serves as a personal collection of custom-built tools designed to assist in digital forensics and incident response (DFIR) investigations. Each tool is developed in Python and aims to simplify or automate common forensic analysis tasks.

---

## Tools Overview

Below is a list of the tools available in this collection. Each tool resides in its own directory and includes a detailed `README.md` with specific setup, prerequisite, and usage instructions.

### 📁 [EML Analyzer](./EMLanalyzer/)

A Python script with a simple GUI for parsing and analyzing `.eml` email files. It is designed for quick triage of suspicious emails to identify key metadata and potential threats.

**Core Features:**
* Extracts key headers, attachments (with SHA256 hashes), and Indicators of Compromise (IOCs).
* Offers both a "Simple Triage" and a "Detailed Forensics" mode for header analysis.
* Automatically defangs URLs and filters out private IP addresses to focus on actionable intelligence.

### 📁 [MFT and USN Journal Converter](./MFT_and_USNJournal_Converter/)

A graphical user interface (GUI) wrapper for Eric Zimmerman's powerful command-line tools, `MFTECmd.exe` and `JLECmd.exe`. This tool simplifies the process of parsing Windows Master File Table (`$MFT`) and USN Journal (`$J`) artifacts by providing an intuitive interface for filtering and exporting data.

**Core Features:**
* Provides a user-friendly frontend for two essential DFIR command-line tools.
* Supports multiple output formats, including CSV, JSON, and bodyfile.
* Allows for advanced filtering by date range, keywords, and artifact-specific flags.

---

## General Usage

To use a tool from this collection:
1.  Navigate into the tool's specific directory (e.g., `cd EMLanalyzer`).
2.  Read the `README.md` file within that directory for detailed instructions.
3.  Install any required dependencies listed in the tool's README.
4.  Run the Python script as instructed.

## Future Work

This collection is actively maintained. Future additions may include tools for:
* Windows Registry analysis (`NTUSER.DAT`, `SAM`, `SYSTEM`).
* Browser history parsing.
* Event Log (`.evtx`) processing.

## License

The entire collection of tools and code within this repository is governed by the license specified in the `LICENSE` file, located in the root of this directory. Please review the file for the full text and terms.
