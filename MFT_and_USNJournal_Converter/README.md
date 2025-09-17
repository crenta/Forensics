MFTConv - GUI Wrapper for Forensic Artifact Conversion

`MFTConv` is a user-friendly Python GUI application that acts as a frontend for two powerful forensic command-line tools: **MFTECmd.exe** and **JLECmd.exe** from Eric Zimmerman's forensic suite.

This tool simplifies the process of parsing Windows filesystem artifacts—the Master File Table (`$MFT`) and the USN Journal (`$J`)—by providing an intuitive interface to build and execute complex commands, eliminating the need to manually type them in a terminal.

## Features

-   **Simple Graphical Interface:** No more memorizing command-line flags.
-   **Dual Artifact Support:**
    -   Process **$MFT** files using `MFTECmd.exe`.
    -   Process **$J** (USN Journal) files using `JLECmd.exe`.
-   **Multiple Output Formats:** Convert artifacts to CSV, JSON, Bodyfile, or HTML for easy analysis and reporting.
-   **Advanced Filtering:**
    -   Filter results by a start and end date/time (`YYYY-MM-DD HH:MM:SS`).
    -   For USN Journals, filter by keyword search or specific "Reason" codes (e.g., `FileCreate`, `FileDelete`).
-   **Tool-Specific Options:**
    -   For MFT, toggle options to include "Dead Records" (`--dead`) or "Full Detail" (`--full`).
-   **Automatic Configuration:** On first run, the tool prompts you to locate the required `.exe` files and saves their paths in a `config.ini` for future use.
-   **Robust Error Handling:** If the underlying tool fails, a detailed error pop-up shows the exact command that was run and the error message, making troubleshooting simple.

## **CRITICAL** Prerequisites

This script **is a wrapper** and does not contain the parsing logic itself. You **must** download the necessary command-line tools for it to function.

1.  **Windows Operating System:** As this tool wraps `.exe` files, it is intended for a Windows environment.
2.  **Python 3.x:** Ensure you have a working Python 3 installation.
3.  **Eric Zimmerman's Tools:** You must download `MFTECmd.exe` and `JLECmd.exe`.
    -   **Download Link:** You can get them from the official KAPE repository under the `.\KAPE\Modules\bin` folder or as standalone executables from Eric Zimmerman's website.
    -   **Official Site:** [**https://ericzimmerman.github.io/**](https://ericzimmerman.github.io/)

## Installation & First-Time Setup

1.  Download the `mftconv.py` script to a folder on your computer.
2.  Ensure you have downloaded `MFTECmd.exe` and `JLECmd.exe` and placed them somewhere accessible.
3.  Run the script from your terminal:
    ```bash
    python mftconv.py
    ```
4.  **On the very first run**, the application will detect that it doesn't know where `MFTECmd.exe` is. It will show a warning pop-up.
5.  Click "OK" and a file browser will open. **Navigate to and select your `MFTECmd.exe` file.**
6.  The application will then do the same for `JLECmd.exe`. **Navigate to and select your `JLECmd.exe` file.**
7.  Once selected, the paths are saved to a new `config.ini` file in the same directory as the script. You will not be asked for these paths again unless you move the files.

## How to Use

1.  **Run the application:** `python mftconv.py`.
2.  **Select Artifact Type:** Choose "MFT" or "USN Journal" from the top dropdown menu. The interface will dynamically update to show relevant options.
3.  **Select Artifact File:** Click "Browse" to select the input `$MFT` or `$J` file you wish to process.
4.  **Select Output Folder:** Click "Browse" to choose the directory where the converted output file(s) will be saved.
5.  **Choose Output Format:** Select your desired format (CSV, JSON, etc.) from the dropdown.
6.  **(Optional) Set Filters and Options:**
    -   Enter a date range if needed. Use the format `YYYY-MM-DD HH:MM:SS`.
    -   Select any tool-specific checkboxes or fill in the filter fields.
7.  **Process Artifact:** Click the "Process Artifact" button.
8.  **Wait for Completion:** The status bar at the bottom will indicate that the tool is "Processing...". This can take a very long time for large files. The application may appear to be frozen, but it is working in the background.
9.  Upon completion, a "Success" message will pop up, and the status bar will update. If an error occurs, a detailed message will be displayed instead.

## License

This project is licensed under the APACHE 2.0 License.
