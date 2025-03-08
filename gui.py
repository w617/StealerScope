import customtkinter as ctk
from tkinter import filedialog, messagebox, Toplevel
import threading
import logging
from settings_manager import SettingsManager
from tkinter import ttk
import tkinter as tk

# -------------------------------
# Tooltip Class for Enhanced UX
# -------------------------------
class Tooltip:
    def __init__(self, widget, text="widget info", waittime=500, wraplength=180):
        self.widget = widget
        self.text = text
        self.waittime = waittime
        self.wraplength = wraplength
        self.id = None
        self.tw = None
        self.widget.bind("<Enter>", self._enter)
        self.widget.bind("<Leave>", self._leave)
        self.widget.bind("<ButtonPress>", self._leave)

    def _enter(self, event=None):
        self.schedule()

    def _leave(self, event=None):
        self.unschedule()
        self.hidetip()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(self.waittime, self.showtip)

    def unschedule(self):
        if self.id:
            self.widget.after_cancel(self.id)
            self.id = None

    def showtip(self, event=None):
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(self.tw, text=self.text, justify='left', background="#ffffe0",
                         relief='solid', borderwidth=1, wraplength=self.wraplength)
        label.pack(ipadx=1)

    def hidetip(self):
        if self.tw:
            self.tw.destroy()
        self.tw = None

# -------------------------------------
# Parsed Data Viewer with Filter & Context
# -------------------------------------
class ParsedDataViewer(Toplevel):
    def __init__(self, master, parsed_data):
        super().__init__(master)
        self.title("Parsed Log Data")
        self.geometry("800x600")
        self.parsed_data = parsed_data
        self.create_widgets()
    
    def create_widgets(self):
        filter_frame = ctk.CTkFrame(self)
        filter_frame.pack(fill="x", padx=10, pady=5)
        filter_label = ctk.CTkLabel(filter_frame, text="Filter:")
        filter_label.grid(row=0, column=0, padx=5, pady=5)
        self.filter_var = ctk.StringVar()
        filter_entry = ctk.CTkEntry(filter_frame, textvariable=self.filter_var)
        filter_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        filter_frame.columnconfigure(1, weight=1)
        filter_button = ctk.CTkButton(filter_frame, text="Apply Filter", command=self.apply_filter)
        filter_button.grid(row=0, column=2, padx=5, pady=5)
        Tooltip(filter_entry, "Type text to filter entries (case-insensitive)")
        Tooltip(filter_button, "Click to filter the displayed data")
        
        tree_frame = ctk.CTkFrame(self)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.tree = ttk.Treeview(tree_frame)
        self.tree["columns"] = ("Detail",)
        self.tree.column("#0", width=150, minwidth=150)
        self.tree.column("Detail", width=600, minwidth=200)
        self.tree.heading("#0", text="Category", anchor="w")
        self.tree.heading("Detail", text="Detail", anchor="w")
        self.tree.pack(fill="both", expand=True, side="left")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.populate_tree()
    
    def populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        for category, entries in self.parsed_data.items():
            parent_id = self.tree.insert("", "end", text=category, values=("",))
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        details = ", ".join([f"{k}: {v}" for k, v in entry.items()])
                    else:
                        details = str(entry)
                    self.tree.insert(parent_id, "end", text="", values=(details,))
            elif isinstance(entries, dict):
                for key, value in entries.items():
                    self.tree.insert(parent_id, "end", text=key, values=(value,))
    
    def apply_filter(self):
        term = self.filter_var.get().lower().strip()
        self.tree.delete(*self.tree.get_children())
        for category, entries in self.parsed_data.items():
            filtered_entries = []
            if isinstance(entries, list):
                for entry in entries:
                    text = ""
                    if isinstance(entry, dict):
                        text = ", ".join([f"{k}: {v}" for k, v in entry.items()])
                    else:
                        text = str(entry)
                    if term in text.lower():
                        filtered_entries.append(text)
            elif isinstance(entries, dict):
                filtered_entries = [(k, v) for k, v in entries.items() if term in k.lower() or term in str(v).lower()]
            if filtered_entries:
                parent_id = self.tree.insert("", "end", text=category, values=("",))
                if isinstance(filtered_entries, list):
                    for text in filtered_entries:
                        self.tree.insert(parent_id, "end", text="", values=(text,))
                else:
                    for k, v in filtered_entries:
                        self.tree.insert(parent_id, "end", text=k, values=(v,))
    
    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Copy Detail", command=lambda: self.copy_detail(item))
            menu.tk_popup(event.x_root, event.y_root)
    
    def copy_detail(self, item):
        detail = self.tree.item(item, "values")[0]
        self.clipboard_clear()
        self.clipboard_append(detail)
        messagebox.showinfo("Copied", "Detail copied to clipboard.")

# -------------------------------------
# Main GUI Class
# -------------------------------------
class StealerScopeGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("StealerScope - Infostealer Log Analyzer")
        self.geometry("900x700")
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")
        self.settings_manager = SettingsManager()
        self.config = self.settings_manager.get_all()
        self.font_size = int(self.settings_manager.get("SETTINGS", "font_size", fallback="12"))
        
        top_frame = ctk.CTkFrame(self)
        top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        top_frame.columnconfigure((0,1,2,3,4,5), weight=1)
        
        self.settings_button = ctk.CTkButton(top_frame, text="⚙️ Settings", command=self.open_settings)
        self.settings_button.grid(row=0, column=0, padx=5)
        Tooltip(self.settings_button, "Open settings window")
        
        self.import_logs_button = ctk.CTkButton(top_frame, text="📂 Import Logs", command=self.import_logs)
        self.import_logs_button.grid(row=0, column=1, padx=5)
        Tooltip(self.import_logs_button, "Select a log folder")
        
        self.parse_button = ctk.CTkButton(top_frame, text="🔍 Parse Logs", command=self.run_log_parser)
        self.parse_button.grid(row=0, column=2, padx=5)
        Tooltip(self.parse_button, "Parse the selected logs")
        
        self.report_button = ctk.CTkButton(top_frame, text="📄 Generate Report", command=self.generate_report)
        self.report_button.grid(row=0, column=3, padx=5)
        Tooltip(self.report_button, "Generate a PDF report")
        
        self.export_button = ctk.CTkButton(top_frame, text="📜 Export Data", command=self.export_data)
        self.export_button.grid(row=0, column=4, padx=5)
        Tooltip(self.export_button, "Export parsed data to JSON")
        
        self.view_data_button = ctk.CTkButton(top_frame, text="🔎 View Parsed Data", command=self.view_parsed_data)
        self.view_data_button.grid(row=0, column=5, padx=5)
        Tooltip(self.view_data_button, "View parsed data in a structured tree")
        
        self.log_viewer = ctk.CTkTextbox(self, wrap="word", font=("Consolas", self.font_size), state="disabled")
        self.log_viewer.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        
        self.status_var = ctk.StringVar(value="Ready")
        self.status_bar = ctk.CTkLabel(self, textvariable=self.status_var, anchor="w")
        self.status_bar.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.insert_log("🔹 Log output will be displayed here...")
        self.bind_shortcuts()

    def bind_shortcuts(self):
        self.bind("<Control-p>", lambda event: self.run_log_parser())
        self.bind("<Control-r>", lambda event: self.generate_report())
        self.bind("<Control-e>", lambda event: self.export_data())
        self.bind("<Control-s>", lambda event: self.open_settings())

    def open_settings(self):
        settings_window = ctk.CTkToplevel(self)
        settings_window.title("Settings")
        settings_window.geometry("600x550")
        
        tab_view = ctk.CTkTabview(settings_window, width=580, height=400)
        tab_view.pack(pady=10, padx=10)
        
        tab_view.add("General")
        tab_view.add("API Keys")
        tab_view.add("Alerts")
        tab_view.add("Paths")
        
        # General Tab
        general_frame = tab_view.tab("General")
        auto_update = self.settings_manager.get("SETTINGS", "auto_update", fallback="True") == "True"
        self.auto_update_var = ctk.BooleanVar(value=auto_update)
        auto_update_checkbox = ctk.CTkCheckBox(general_frame, text="Auto Update", variable=self.auto_update_var)
        auto_update_checkbox.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        dark_mode = self.settings_manager.get("SETTINGS", "dark_mode", fallback="light")
        self.dark_mode_var = ctk.StringVar(value=dark_mode)
        dark_mode_label = ctk.CTkLabel(general_frame, text="Theme Mode:")
        dark_mode_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        dark_mode_option = ctk.CTkOptionMenu(general_frame, variable=self.dark_mode_var, values=["light", "dark"])
        dark_mode_option.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        
        font_size = self.settings_manager.get("SETTINGS", "font_size", fallback="12")
        self.font_size_var = ctk.StringVar(value=font_size)
        font_size_label = ctk.CTkLabel(general_frame, text="Font Size:")
        font_size_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        font_size_entry = ctk.CTkEntry(general_frame, textvariable=self.font_size_var, width=80)
        font_size_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        
        # API Keys Tab
        api_keys_frame = tab_view.tab("API Keys")
        hibp_api_key = self.settings_manager.get("API_KEYS", "hibp_api_key", fallback="your_hibp_api_key_here")
        self.hibp_api_key_var = ctk.StringVar(value=hibp_api_key)
        virus_api_key = self.settings_manager.get("API_KEYS", "virustotal_api_key", fallback="your_virustotal_api_key_here")
        self.virus_api_key_var = ctk.StringVar(value=virus_api_key)
        hibp_label = ctk.CTkLabel(api_keys_frame, text="HIBP API Key:")
        hibp_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        hibp_entry = ctk.CTkEntry(api_keys_frame, textvariable=self.hibp_api_key_var, width=400)
        hibp_entry.grid(row=0, column=1, padx=10, pady=5)
        virus_label = ctk.CTkLabel(api_keys_frame, text="VirusTotal API Key:")
        virus_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        virus_entry = ctk.CTkEntry(api_keys_frame, textvariable=self.virus_api_key_var, width=400)
        virus_entry.grid(row=1, column=1, padx=10, pady=5)
        
        # Alerts Tab
        alerts_frame = tab_view.tab("Alerts")
        email_alerts = self.settings_manager.get("ALERTS", "email_alerts", fallback="True") == "True"
        self.email_alerts_var = ctk.BooleanVar(value=email_alerts)
        email_alerts_checkbox = ctk.CTkCheckBox(alerts_frame, text="Email Alerts", variable=self.email_alerts_var)
        email_alerts_checkbox.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        desktop_alerts = self.settings_manager.get("ALERTS", "desktop_alerts", fallback="True") == "True"
        self.desktop_alerts_var = ctk.BooleanVar(value=desktop_alerts)
        desktop_alerts_checkbox = ctk.CTkCheckBox(alerts_frame, text="Desktop Alerts", variable=self.desktop_alerts_var)
        desktop_alerts_checkbox.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        email_recipient = self.settings_manager.get("ALERTS", "email_recipient", fallback="securityteam@example.com")
        self.email_recipient_var = ctk.StringVar(value=email_recipient)
        email_recipient_label = ctk.CTkLabel(alerts_frame, text="Email Recipient:")
        email_recipient_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        email_recipient_entry = ctk.CTkEntry(alerts_frame, textvariable=self.email_recipient_var, width=400)
        email_recipient_entry.grid(row=1, column=1, padx=10, pady=5)
        smtp_server = self.settings_manager.get("ALERTS", "smtp_server", fallback="smtp.gmail.com")
        self.smtp_server_var = ctk.StringVar(value=smtp_server)
        smtp_server_label = ctk.CTkLabel(alerts_frame, text="SMTP Server:")
        smtp_server_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        smtp_server_entry = ctk.CTkEntry(alerts_frame, textvariable=self.smtp_server_var, width=400)
        smtp_server_entry.grid(row=2, column=1, padx=10, pady=5)
        smtp_port = self.settings_manager.get("ALERTS", "smtp_port", fallback="465")
        self.smtp_port_var = ctk.StringVar(value=smtp_port)
        smtp_port_label = ctk.CTkLabel(alerts_frame, text="SMTP Port:")
        smtp_port_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")
        smtp_port_entry = ctk.CTkEntry(alerts_frame, textvariable=self.smtp_port_var, width=400)
        smtp_port_entry.grid(row=3, column=1, padx=10, pady=5)
        smtp_username = self.settings_manager.get("ALERTS", "smtp_username", fallback="your-email@example.com")
        self.smtp_username_var = ctk.StringVar(value=smtp_username)
        smtp_username_label = ctk.CTkLabel(alerts_frame, text="SMTP Username:")
        smtp_username_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")
        smtp_username_entry = ctk.CTkEntry(alerts_frame, textvariable=self.smtp_username_var, width=400)
        smtp_username_entry.grid(row=4, column=1, padx=10, pady=5)
        smtp_password = self.settings_manager.get("ALERTS", "smtp_password", fallback="your-password")
        self.smtp_password_var = ctk.StringVar(value=smtp_password)
        smtp_password_label = ctk.CTkLabel(alerts_frame, text="SMTP Password:")
        smtp_password_label.grid(row=5, column=0, padx=10, pady=5, sticky="w")
        smtp_password_entry = ctk.CTkEntry(alerts_frame, textvariable=self.smtp_password_var, width=400, show="*")
        smtp_password_entry.grid(row=5, column=1, padx=10, pady=5)
        
        # Paths Tab
        paths_frame = tab_view.tab("Paths")
        log_folder = self.settings_manager.get("PATHS", "log_folder", fallback="logs/")
        self.log_folder_var = ctk.StringVar(value=log_folder)
        log_folder_label = ctk.CTkLabel(paths_frame, text="Log Folder:")
        log_folder_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        log_folder_entry = ctk.CTkEntry(paths_frame, textvariable=self.log_folder_var, width=400)
        log_folder_entry.grid(row=0, column=1, padx=10, pady=5)
        browse_button = ctk.CTkButton(paths_frame, text="Browse", command=self.browse_folder)
        browse_button.grid(row=0, column=2, padx=10, pady=5)
        
        def save_settings():
            self.settings_manager.set("SETTINGS", "auto_update", self.auto_update_var.get())
            self.settings_manager.set("SETTINGS", "dark_mode", self.dark_mode_var.get())
            self.settings_manager.set("SETTINGS", "font_size", self.font_size_var.get())
            self.settings_manager.set("API_KEYS", "hibp_api_key", self.hibp_api_key_var.get())
            self.settings_manager.set("API_KEYS", "virustotal_api_key", self.virus_api_key_var.get())
            self.settings_manager.set("ALERTS", "email_alerts", self.email_alerts_var.get())
            self.settings_manager.set("ALERTS", "desktop_alerts", self.desktop_alerts_var.get())
            self.settings_manager.set("ALERTS", "email_recipient", self.email_recipient_var.get())
            self.settings_manager.set("ALERTS", "smtp_server", self.smtp_server_var.get())
            self.settings_manager.set("ALERTS", "smtp_port", self.smtp_port_var.get())
            self.settings_manager.set("ALERTS", "smtp_username", self.smtp_username_var.get())
            self.settings_manager.set("ALERTS", "smtp_password", self.smtp_password_var.get())
            self.settings_manager.set("PATHS", "log_folder", self.log_folder_var.get())
            self.insert_log("✅ Settings saved successfully.")
            ctk.set_appearance_mode(self.dark_mode_var.get())
            self.font_size = int(self.font_size_var.get())
            self.log_viewer.configure(font=("Consolas", self.font_size))
            settings_window.destroy()
        
        save_button = ctk.CTkButton(settings_window, text="Save Settings", command=save_settings)
        save_button.pack(pady=10)
        cancel_button = ctk.CTkButton(settings_window, text="Cancel", command=settings_window.destroy)
        cancel_button.pack(pady=5)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.log_folder_var.set(folder)
    
    def import_logs(self):
        folder = filedialog.askdirectory()
        if folder:
            self.settings_manager.set("PATHS", "log_folder", folder)
            self.insert_log(f"📂 Log folder set to: {folder}")
    
    def run_log_parser(self):
        def task():
            from stream_log_parser import StreamLogParser
            log_folder = self.settings_manager.get("PATHS", "log_folder", fallback="logs/")
            self.insert_log(f"🔍 Starting log parsing from folder: {log_folder}")
            self.status_var.set("Parsing logs...")
            progress = ctk.CTkProgressBar(self, width=280)
            progress.grid(row=3, column=0, pady=5)
            progress.start()
            parser = StreamLogParser(log_folder)
            try:
                parsed_data = parser.parse_logs_stream()
                self.parsed_data = parsed_data
                progress.stop()
                progress.destroy()
                self.insert_log("✅ Log parsing completed successfully.\n")
                self.status_var.set("Parsing complete")
                for cat in ["credentials", "brute_passwords", "detected_domains", "processes", "installed_software", "system_info"]:
                    self.insert_log(f"===== {cat.upper()} =====")
                    if isinstance(parsed_data[cat], list):
                        self.insert_log(f"Total items: {len(parsed_data[cat])}")
                        for i, item in enumerate(parsed_data[cat], start=1):
                            if cat == "credentials":
                                text_line = f"{i}. URL: {item.get('url', '')} | USER: {item.get('username', '')} | PASS: {item.get('password', '')}"
                            else:
                                text_line = f"{i}. {item}"
                            self.insert_log(text_line)
                    elif isinstance(parsed_data[cat], dict):
                        self.insert_log(f"Total entries: {len(parsed_data[cat])}")
                        for key, value in parsed_data[cat].items():
                            self.insert_log(f"{key}: {value}")
                    self.insert_log("")
                # Optional: Insert parsed data into database
                # from db_manager import DBManager
                # db = DBManager()
                # db.insert_parsed_data(parsed_data)
                # db.close()
            except Exception as e:
                progress.stop()
                progress.destroy()
                self.insert_log(f"❌ Error during log parsing: {e}")
                self.status_var.set("Parsing failed")
                messagebox.showerror("Parsing Error", f"An error occurred: {e}")
        threading.Thread(target=task).start()
    
    def generate_report(self):
        if not hasattr(self, 'parsed_data'):
            self.insert_log("❌ No parsed data available. Please run log parser first.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                                 filetypes=[("PDF files", "*.pdf")],
                                                 title="Save Report As")
        if not file_path:
            self.insert_log("⚠️ Report generation cancelled by user.")
            return
        self.insert_log("📄 Generating PDF report...")
        try:
            from report_generator import ReportGenerator
            generator = ReportGenerator(self.parsed_data)
            report_path = generator.generate_pdf_report(report_path=file_path)
            self.insert_log(f"✅ Report generated successfully: {report_path}")
        except Exception as e:
            self.insert_log(f"❌ Error generating report: {e}")
            messagebox.showerror("Report Error", f"An error occurred: {e}")
    
    def export_data(self):
        if not hasattr(self, 'parsed_data'):
            self.insert_log("❌ No parsed data available. Please run log parser first.")
            return
        self.insert_log("📜 Exporting parsed data to JSON...")
        try:
            import json
            output_file = "exported_parsed_data.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(self.parsed_data, f, indent=4)
            self.insert_log(f"✅ Data exported successfully to: {output_file}")
        except Exception as e:
            self.insert_log(f"❌ Error exporting data: {e}")
            messagebox.showerror("Export Error", f"An error occurred: {e}")
    
    def view_parsed_data(self):
        if not hasattr(self, 'parsed_data'):
            self.insert_log("❌ No parsed data available. Please run log parser first.")
            return
        ParsedDataViewer(self, self.parsed_data)
    
    def insert_log(self, message):
        self.log_viewer.configure(state="normal")
        self.log_viewer.insert("end", message + "\n")
        self.log_viewer.configure(state="disabled")
        self.log_viewer.see("end")

if __name__ == "__main__":
    app = StealerScopeGUI()
    app.mainloop()
