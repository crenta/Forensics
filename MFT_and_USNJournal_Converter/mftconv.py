import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
import subprocess
import os
import configparser
import datetime

CONFIG_FILE = "config.ini"
DATE_PLACEHOLDER = "YYYY-MM-DD HH:MM:SS"

def get_tool_path(tool_key, tool_exe_name):
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    if 'Paths' in config and tool_key in config['Paths']:
        path = config['Paths'][tool_key]
        if os.path.isfile(path):
            return path
    messagebox.showwarning("Setup Required", f"Could not find {tool_exe_name}. Please locate the file.")
    new_path = filedialog.askopenfilename(title=f"Locate {tool_exe_name}", filetypes=[("Executables", "*.exe")])
    if new_path and os.path.isfile(new_path):
        if 'Paths' not in config:
            config['Paths'] = {}
        config['Paths'][tool_key] = new_path
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
        return new_path
    else:
        messagebox.showerror("Error", f"No executable selected for {tool_exe_name}. Cannot proceed.")
        return None

def select_artifact_file():
    file = filedialog.askopenfilename(title="Select Artifact File", filetypes=[("All Files", "*.*")])
    if file:
        artifact_entry.delete(0, tk.END)
        artifact_entry.insert(0, file)

def select_output():
    path = filedialog.askdirectory(title="Select Output Folder")
    if path:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, path)

def update_ui(*args):
    selected_tool = tool_var.get()
    if selected_tool == 'MFT':
        artifact_label.config(text="MFT File:")
        mft_options_frame.grid()
        usn_options_frame.grid_remove()
    elif selected_tool == 'USN Journal':
        artifact_label.config(text="USN Journal ($J):")
        mft_options_frame.grid_remove()
        usn_options_frame.grid()

def on_focus_in(entry, placeholder):
    if entry.get() == placeholder:
        entry.delete(0, "end")
        entry.config(fg='black')

def on_focus_out(entry, placeholder):
    if not entry.get():
        entry.insert(0, placeholder)
        entry.config(fg='grey')

def convert():
    # --- 1. Provide Immediate Feedback and Disable Button ---
    status_var.set("Processing... This may take a long time. Please wait.")
    process_button.config(state=tk.DISABLED)
    root.config(cursor="watch")
    root.update_idletasks()

    try:
        # --- Gather all inputs from the GUI ---
        artifact_file = artifact_entry.get()
        out_path = output_entry.get()
        selected_format = format_var.get()
        selected_tool = tool_var.get()
        start_date = start_date_entry.get()
        end_date = end_date_entry.get()

        if not os.path.isfile(artifact_file):
            messagebox.showerror("Error", "Invalid or missing artifact file selected.")
            status_var.set("Error: Invalid artifact file.")
            return

        command = []
        tool_path = None

        if selected_tool == 'MFT':
            tool_path = get_tool_path('mft_cmd', 'MFTECmd.exe')
            if not tool_path: return
            command = [tool_path, "-f", artifact_file]
            if dead_var.get(): command.append('--dead')
            if full_var.get(): command.append('--full')

        elif selected_tool == 'USN Journal':
            tool_path = get_tool_path('jle_cmd', 'JLECmd.exe')
            if not tool_path: return
            command = [tool_path, "-f", artifact_file]
            keyword = usn_keyword_entry.get()
            if keyword: command.extend(['-q', keyword])
            reason = usn_reason_var.get()
            if reason and reason != "Any": command.extend(['--reason', reason])
        
        if start_date and start_date != DATE_PLACEHOLDER:
            command.extend(['--d_from', start_date])
        if end_date and end_date != DATE_PLACEHOLDER:
            command.extend(['--d_to', end_date])
            
        if selected_format == 'CSV': command.extend(['--csv', out_path])
        elif selected_format == 'JSON': command.extend(['--json', out_path])
        elif selected_format == 'Bodyfile': command.extend(['--body', out_path])
        elif selected_format == 'HTML': command.extend(['--html', out_path])
        
        # --- 2. Run subprocess with output capture ---
        result = subprocess.run(
            command, 
            check=True, 
            capture_output=True, 
            text=True, 
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        messagebox.showinfo("Success", f"Processing complete!\n\n{selected_format} file(s) for {selected_tool} created in:\n{out_path}")
        status_var.set(f"Success! Last operation completed at {current_time}")

    except subprocess.CalledProcessError as e:
        # --- 3. Provide detailed error messages ---
        error_message = (
            f"The tool failed to execute.\n\n"
            f"Exit Code: {e.returncode}\n\n"
            f"Command Run:\n{' '.join(e.cmd)}\n\n"
            f"Error Output:\n{e.stderr}"
        )
        messagebox.showerror("Processing Error", error_message)
        status_var.set("Error: Tool failed during execution. See pop-up for details.")
    except Exception as e:
        messagebox.showerror("An Error Occurred", str(e))
        status_var.set("Error: An unexpected error occurred.")
    finally:
        # --- 4. ALWAYS re-enable the button and reset the cursor ---
        process_button.config(state=tk.NORMAL)
        root.config(cursor="")
        if "status_var" in locals() and "Success" not in status_var.get() and "Error" not in status_var.get():
             status_var.set("Ready.")


# --- SETUP TKINTER GUI ---
root = tk.Tk()
root.title("Forensic Artifact Parser")
root.geometry("650x350")

main_frame = tk.Frame(root, padx=10, pady=10)
main_frame.pack(fill=tk.BOTH, expand=True)

tk.Label(main_frame, text="Artifact Type:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
tool_var = tk.StringVar()
tool_options = ['MFT', 'USN Journal']
tool_dropdown = ttk.Combobox(main_frame, textvariable=tool_var, values=tool_options, state='readonly', width=47)
tool_dropdown.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="w")
tool_dropdown.current(0)
tool_dropdown.bind('<<ComboboxSelected>>', update_ui)

artifact_label = tk.Label(main_frame, text="MFT File:")
artifact_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
artifact_entry = tk.Entry(main_frame, width=50)
artifact_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)
tk.Button(main_frame, text="Browse", command=select_artifact_file).grid(row=1, column=3, padx=5, pady=5)

tk.Label(main_frame, text="Output Folder:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
output_entry = tk.Entry(main_frame, width=50)
output_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)
tk.Button(main_frame, text="Browse", command=select_output).grid(row=2, column=3, padx=5, pady=5)

tk.Label(main_frame, text="Output Format:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
format_var = tk.StringVar()
format_options = ['CSV', 'JSON', 'Bodyfile', 'HTML']
format_dropdown = ttk.Combobox(main_frame, textvariable=format_var, values=format_options, state='readonly', width=47)
format_dropdown.grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky="w")
format_dropdown.current(0)

tk.Label(main_frame, text="Date Range:").grid(row=4, column=0, padx=5, pady=5, sticky="e")
start_date_entry = tk.Entry(main_frame, width=22, fg='grey')
start_date_entry.grid(row=4, column=1, padx=5, pady=5, sticky='w')
start_date_entry.insert(0, DATE_PLACEHOLDER)
start_date_entry.bind('<FocusIn>', lambda e: on_focus_in(start_date_entry, DATE_PLACEHOLDER))
start_date_entry.bind('<FocusOut>', lambda e: on_focus_out(start_date_entry, DATE_PLACEHOLDER))

end_date_entry = tk.Entry(main_frame, width=22, fg='grey')
end_date_entry.grid(row=4, column=2, padx=5, pady=5, sticky='w')
end_date_entry.insert(0, DATE_PLACEHOLDER)
end_date_entry.bind('<FocusIn>', lambda e: on_focus_in(end_date_entry, DATE_PLACEHOLDER))
end_date_entry.bind('<FocusOut>', lambda e: on_focus_out(end_date_entry, DATE_PLACEHOLDER))

tk.Label(main_frame, text="Tool Options:").grid(row=5, column=0, padx=5, pady=5, sticky="ne")
options_frame_container = tk.Frame(main_frame)
options_frame_container.grid(row=5, column=1, columnspan=3, sticky="w", pady=5)

mft_options_frame = tk.Frame(options_frame_container)
dead_var = tk.BooleanVar()
full_var = tk.BooleanVar()
tk.Checkbutton(mft_options_frame, text="Dead Records (--dead)", variable=dead_var).pack(side=tk.LEFT)
tk.Checkbutton(mft_options_frame, text="Full Detail (--full)", variable=full_var).pack(side=tk.LEFT, padx=10)

usn_options_frame = tk.Frame(options_frame_container)
usn_options_frame.grid_columnconfigure(1, weight=1)
tk.Label(usn_options_frame, text="Search (-q):").grid(row=0, column=0, sticky='w')
usn_keyword_entry = tk.Entry(usn_options_frame, width=15)
usn_keyword_entry.grid(row=0, column=1, sticky='w', padx=5)
tk.Label(usn_options_frame, text="Reason:").grid(row=0, column=2, sticky='w', padx=(10, 0))
usn_reason_var = tk.StringVar()
usn_reason_options = ["Any", "FileCreate", "FileDelete", "RenameOldName", "RenameNewName", "DataExtend", "DataOverwrite"]
usn_reason_dropdown = ttk.Combobox(usn_options_frame, textvariable=usn_reason_var, values=usn_reason_options, state='readonly', width=15)
usn_reason_dropdown.grid(row=0, column=3, sticky='w', padx=5)
usn_reason_dropdown.current(0)

process_button = tk.Button(main_frame, text="Process Artifact", command=convert, width=35)
process_button.grid(row=6, column=1, columnspan=2, pady=20)

status_var = tk.StringVar()
status_var.set("Ready.")
status_bar = tk.Label(root, textvariable=status_var, relief=tk.SUNKEN, anchor=tk.W, bd=1)
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

update_ui()
root.mainloop()
