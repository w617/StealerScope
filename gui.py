import json
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import customtkinter as ctk

from settings_manager import SettingsManager


COLORS = {
    "nav": "#101828", "nav_hover": "#1d2939", "blue": "#1570ef",
    "green": "#079455", "amber": "#dc6803", "red": "#d92d20",
    "surface": "#ffffff", "canvas": "#f2f4f7", "border": "#e4e7ec",
    "text": "#101828", "muted": "#667085",
}


class Tooltip:
    def __init__(self, widget, text="", waittime=500):
        self.widget, self.text, self.waittime = widget, text, waittime
        self.after_id = self.tip = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._hide)

    def _schedule(self, _event=None):
        self._hide()
        self.after_id = self.widget.after(self.waittime, self._show)

    def _show(self):
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{self.widget.winfo_rootx()+20}+{self.widget.winfo_rooty()+self.widget.winfo_height()+5}")
        tk.Label(self.tip, text=self.text, background="#fffae6", relief="solid",
                 borderwidth=1, padx=7, pady=4).pack()

    def _hide(self, _event=None):
        if self.after_id:
            self.widget.after_cancel(self.after_id)
            self.after_id = None
        if self.tip:
            self.tip.destroy()
            self.tip = None


class StealerScopeGUI(ctk.CTk):
    NAV_ITEMS = (
        ("overview", "Overview"), ("credentials", "Credentials"),
        ("cookies", "Cookies"), ("system_records", "Systems"),
        ("host_artifacts", "Host Artifacts"), ("source_files", "Files"),
        ("warnings", "Warnings"),
    )

    def __init__(self):
        super().__init__()
        self.title("StealerScope — Infostealer Log Analyzer")
        self.geometry("1280x820")
        self.minsize(1040, 680)
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=COLORS["canvas"])
        self.settings_manager = SettingsManager()
        self.parsed_data = None
        self.archive_password = None
        self._parsing = False
        self.active_view = "overview"
        self.search_var = ctk.StringVar()
        self.show_secrets_var = ctk.BooleanVar(value=False)
        self.card_values = {}
        self.nav_buttons = {}
        self._build_layout()
        self.bind_shortcuts()
        self.refresh_dashboard()
        self.select_view("overview")

    def _build_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main()

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=232, corner_radius=0, fg_color=COLORS["nav"])
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        ctk.CTkLabel(sidebar, text="STEALERSCOPE", text_color="white",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w", padx=22, pady=(26, 2))
        ctk.CTkLabel(sidebar, text="FORENSIC LOG ANALYZER", text_color="#98a2b3",
                     font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=22, pady=(0, 24))

        for key, label in self.NAV_ITEMS:
            button = ctk.CTkButton(sidebar, text=label, anchor="w", height=42,
                                   fg_color="transparent", hover_color=COLORS["nav_hover"],
                                   command=lambda value=key: self.select_view(value))
            button.pack(fill="x", padx=12, pady=2)
            self.nav_buttons[key] = button

        ctk.CTkFrame(sidebar, height=1, fg_color="#344054").pack(fill="x", padx=18, pady=20)
        self.import_logs_button = ctk.CTkButton(sidebar, text="Import Archive", height=40,
                                                command=self.import_logs)
        self.import_logs_button.pack(fill="x", padx=16, pady=4)
        self.import_folder_button = ctk.CTkButton(sidebar, text="Import Folder", height=40,
                                                  fg_color="#344054", hover_color="#475467",
                                                  command=self.import_folder)
        self.import_folder_button.pack(fill="x", padx=16, pady=4)
        self.parse_button = ctk.CTkButton(sidebar, text="Analyze Evidence", height=42,
                                          fg_color=COLORS["green"], hover_color="#067647",
                                          command=self.run_log_parser)
        self.parse_button.pack(fill="x", padx=16, pady=(14, 4))
        self.settings_button = ctk.CTkButton(sidebar, text="Settings", height=38,
                                             fg_color="transparent", border_width=1,
                                             border_color="#475467", command=self.open_settings)
        self.settings_button.pack(fill="x", padx=16, pady=4)

        self.input_label = ctk.CTkLabel(sidebar, text="No evidence selected", wraplength=190,
                                        justify="left", text_color="#98a2b3", font=ctk.CTkFont(size=11))
        self.input_label.pack(side="bottom", anchor="w", padx=20, pady=22)

    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew", padx=24, pady=18)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1)

        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(2, 14))
        header.grid_columnconfigure(0, weight=1)
        self.page_title = ctk.CTkLabel(header, text="Investigation Overview", anchor="w",
                                       text_color=COLORS["text"], font=ctk.CTkFont(size=25, weight="bold"))
        self.page_title.grid(row=0, column=0, sticky="w")
        self.case_label = ctk.CTkLabel(header, text="No active case", text_color=COLORS["muted"])
        self.case_label.grid(row=1, column=0, sticky="w", pady=(2, 0))
        ctk.CTkButton(header, text="Generate Report", width=132, command=self.generate_report).grid(row=0, column=1, rowspan=2, padx=6)
        ctk.CTkButton(header, text="Export JSON", width=110, fg_color="#344054",
                      hover_color="#475467", command=self.export_data).grid(row=0, column=2, rowspan=2)

        cards = ctk.CTkFrame(main, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew")
        for column in range(6): cards.grid_columnconfigure(column, weight=1)
        specs = (("credentials", "Credentials", COLORS["blue"]), ("cookies", "Cookies", "#7f56d9"),
                 ("detected_domains", "Domains", COLORS["green"]), ("system_records", "Systems", "#0891b2"),
                 ("source_files", "Files", COLORS["amber"]), ("warnings", "Warnings", COLORS["red"]))
        for column, (key, label, accent) in enumerate(specs):
            card = ctk.CTkFrame(cards, fg_color=COLORS["surface"], border_width=1,
                                border_color=COLORS["border"], corner_radius=10)
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 5, 0 if column == 5 else 5))
            ctk.CTkFrame(card, width=4, height=60, fg_color=accent, corner_radius=4).pack(side="left", padx=(10, 8), pady=13)
            body = ctk.CTkFrame(card, fg_color="transparent")
            body.pack(side="left", pady=11)
            value = ctk.CTkLabel(body, text="0", anchor="w", text_color=COLORS["text"],
                                 font=ctk.CTkFont(size=23, weight="bold"))
            value.pack(anchor="w")
            ctk.CTkLabel(body, text=label, text_color=COLORS["muted"], font=ctk.CTkFont(size=11)).pack(anchor="w")
            self.card_values[key] = value

        tools = ctk.CTkFrame(main, fg_color="transparent")
        tools.grid(row=2, column=0, sticky="ew", pady=(16, 9))
        tools.grid_columnconfigure(0, weight=1)
        search = ctk.CTkEntry(tools, textvariable=self.search_var,
                              placeholder_text="Search current view…", height=38)
        search.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        search.bind("<KeyRelease>", lambda _event: self.refresh_table())
        self.secret_switch = ctk.CTkSwitch(tools, text="Reveal secrets", variable=self.show_secrets_var,
                                           command=self.refresh_table)
        self.secret_switch.grid(row=0, column=1, padx=8)

        panel = ctk.CTkFrame(main, fg_color=COLORS["surface"], border_width=1,
                             border_color=COLORS["border"], corner_radius=10)
        panel.grid(row=3, column=0, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)
        self.panel_title = ctk.CTkLabel(panel, text="Overview", anchor="w", text_color=COLORS["text"],
                                        font=ctk.CTkFont(size=16, weight="bold"))
        self.panel_title.grid(row=0, column=0, sticky="ew", padx=18, pady=(14, 10))
        table_frame = tk.Frame(panel, bg="white")
        table_frame.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        self.tree = ttk.Treeview(table_frame, show="headings")
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<Button-3>", self.show_context_menu)

        footer = ctk.CTkFrame(main, fg_color="transparent")
        footer.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        footer.grid_columnconfigure(0, weight=1)
        self.status_var = ctk.StringVar(value="Ready")
        ctk.CTkLabel(footer, textvariable=self.status_var, text_color=COLORS["muted"]).grid(row=0, column=0, sticky="w")
        self.progress = ctk.CTkProgressBar(footer, width=180, mode="indeterminate")
        self.progress.grid(row=0, column=1, sticky="e")
        self.progress.grid_remove()

    def bind_shortcuts(self):
        self.bind("<Control-p>", lambda _event: self.run_log_parser())
        self.bind("<Control-r>", lambda _event: self.generate_report())
        self.bind("<Control-e>", lambda _event: self.export_data())
        self.bind("<Control-s>", lambda _event: self.open_settings())

    def select_view(self, view):
        self.active_view = view
        names = dict(self.NAV_ITEMS)
        self.page_title.configure(text="Investigation " + names[view])
        self.panel_title.configure(text=names[view])
        self.secret_switch.grid() if view in ("credentials", "cookies") else self.secret_switch.grid_remove()
        for key, button in self.nav_buttons.items():
            button.configure(fg_color=COLORS["nav_hover"] if key == view else "transparent")
        self.refresh_table()

    def _set_table(self, columns, rows):
        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = tuple(key for key, _ in columns)
        for key, label in columns:
            self.tree.heading(key, text=label, anchor="w")
            self.tree.column(key, anchor="w", width=150, minwidth=80, stretch=True)
        for row in rows:
            self.tree.insert("", "end", values=row)

    def refresh_dashboard(self):
        data = self.parsed_data or {}
        for key, label in self.card_values.items():
            value = data.get(key, [])
            label.configure(text=str(len(value) if isinstance(value, (list, dict)) else 0))
        metadata = data.get("case_metadata", {})
        case_bits = [value for value in (metadata.get("case_id"), metadata.get("evidence_number")) if value]
        self.case_label.configure(text=" • ".join(case_bits) if case_bits else "No active case")
        self.refresh_table()

    def refresh_table(self):
        data = self.parsed_data or {}
        term = self.search_var.get().casefold().strip()
        reveal = self.show_secrets_var.get()
        view = self.active_view
        if view == "overview":
            summary = data.get("import_summary", {})
            assessment = data.get("family_assessment", {})
            metadata = data.get("case_metadata", {})
            rows = [
                ("Input", metadata.get("input_name", "No evidence selected"), metadata.get("input_sha256") or "—"),
                ("Import coverage", f"{summary.get('parsed', 0)} parsed / {summary.get('files_enumerated', 0)} files",
                 f"{summary.get('partial', 0)} partial, {summary.get('failed', 0)} failed"),
                ("Family assessment", assessment.get("status", "unknown"), assessment.get("reason", "No analysis loaded")),
                ("Processing", metadata.get("processed_utc", "—"), metadata.get("tool_version", "—")),
            ]
            rows.extend(("Family indicator", item.get("candidate", ""),
                         f"{item.get('source', '')}:{item.get('line', '')}")
                        for item in assessment.get("evidence", []))
            self._set_table((("item", "Summary"), ("value", "Value"), ("detail", "Detail")), self._filtered(rows, term))
        elif view == "credentials":
            rows = [(r.get("soft", ""), r.get("url", ""), r.get("username", ""),
                     r.get("password", "") if reveal else self._mask(r.get("password", "")),
                     r.get("source", ""), r.get("source_line", "")) for r in data.get("credentials", [])]
            self._set_table((("app", "Application"), ("url", "URL / Host"), ("user", "Username"),
                             ("password", "Password"), ("source", "Source"), ("line", "Line")), self._filtered(rows, term))
        elif view == "cookies":
            rows = [(r.get("domain", ""), r.get("name", ""), r.get("value", "") if reveal else self._mask(r.get("value", "")),
                     r.get("expires_epoch", ""), r.get("source", "")) for r in data.get("cookies", [])]
            self._set_table((("domain", "Domain"), ("name", "Name"), ("value", "Value"),
                             ("expires", "Expires"), ("source", "Source")), self._filtered(rows, term))
        elif view == "system_records":
            rows = [(r.get("source", ""), key, value) for r in data.get("system_records", [])
                    for key, value in r.get("fields", {}).items()]
            self._set_table((("source", "Source"), ("field", "Field"), ("value", "Value")), self._filtered(rows, term))
        elif view == "host_artifacts":
            rows = [("Domain", value, "") for value in data.get("detected_domains", [])]
            rows += [("Process", value, "") for value in data.get("processes", [])]
            rows += [("Installed software", value, "") for value in data.get("installed_software", [])]
            self._set_table((("category", "Category"), ("value", "Artifact"), ("detail", "Detail")), self._filtered(rows, term))
        elif view == "source_files":
            rows = [(r.get("relative_path", r.get("source", "")), r.get("status", ""),
                     r.get("detection", {}).get("format", ""), r.get("records_parsed", 0),
                     r.get("size_bytes", ""), r.get("sha256", "")) for r in data.get("source_files", [])]
            self._set_table((("path", "File"), ("status", "Status"), ("format", "Detected Format"),
                             ("records", "Records"), ("size", "Bytes"), ("hash", "SHA-256")), self._filtered(rows, term))
        else:
            rows = [(r.get("source", ""), r.get("line", ""), r.get("message", "")) for r in data.get("warnings", [])]
            self._set_table((("source", "Source"), ("line", "Line"), ("message", "Warning")), self._filtered(rows, term))

    @staticmethod
    def _filtered(rows, term):
        return rows if not term else [row for row in rows if term in " ".join(map(str, row)).casefold()]

    @staticmethod
    def _mask(value):
        return "•" * min(max(len(str(value)), 8), 20) if value != "" else ""

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Copy row", command=lambda: self.copy_detail(item))
            menu.tk_popup(event.x_root, event.y_root)

    def copy_detail(self, item):
        self.clipboard_clear()
        self.clipboard_append("\t".join(map(str, self.tree.item(item, "values"))))

    def open_settings(self):
        window = ctk.CTkToplevel(self)
        window.title("StealerScope Settings")
        window.geometry("620x430")
        tabs = ctk.CTkTabview(window, width=580, height=330)
        tabs.pack(fill="both", expand=True, padx=16, pady=14)
        for name in ("Case", "Appearance", "Input"):
            tabs.add(name)
        fields = (
            ("case_id", "Case ID"), ("examiner", "Examiner"),
            ("evidence_number", "Evidence Number"),
        )
        variables = {}
        case_tab = tabs.tab("Case")
        for row, (key, label) in enumerate(fields):
            variables[key] = ctk.StringVar(value=self.settings_manager.get("CASE", key, fallback=""))
            ctk.CTkLabel(case_tab, text=label).grid(row=row, column=0, sticky="w", padx=12, pady=10)
            ctk.CTkEntry(case_tab, textvariable=variables[key], width=350).grid(row=row, column=1, padx=12, pady=10)
        appearance = tabs.tab("Appearance")
        theme = ctk.StringVar(value=self.settings_manager.get("SETTINGS", "dark_mode", fallback="light"))
        ctk.CTkLabel(appearance, text="Theme").grid(row=0, column=0, padx=12, pady=12)
        ctk.CTkOptionMenu(appearance, variable=theme, values=["light", "dark", "system"]).grid(row=0, column=1, padx=12)
        input_tab = tabs.tab("Input")
        input_var = ctk.StringVar(value=self.settings_manager.get("PATHS", "log_folder", fallback=""))
        ctk.CTkLabel(input_tab, text="Current input").grid(row=0, column=0, padx=12, pady=12)
        ctk.CTkEntry(input_tab, textvariable=input_var, width=400).grid(row=0, column=1, padx=12)

        def save():
            for key, variable in variables.items():
                self.settings_manager.set("CASE", key, variable.get())
            self.settings_manager.set("SETTINGS", "dark_mode", theme.get())
            self.settings_manager.set("PATHS", "log_folder", input_var.get())
            ctk.set_appearance_mode(theme.get())
            window.destroy()
        ctk.CTkButton(window, text="Save Settings", command=save).pack(pady=(0, 14))

    def import_logs(self):
        selected = filedialog.askopenfilename(title="Select Infostealer Archive",
            filetypes=[("Supported archives", "*.zip *.7z *.rar"), ("All files", "*.*")])
        if selected:
            self.archive_password = simpledialog.askstring("Archive Password",
                "Enter the archive password, or leave blank if none:", show="*", parent=self)
            self.settings_manager.set("PATHS", "log_folder", selected)
            self.input_label.configure(text=selected)
            self.status_var.set("Archive selected — ready to analyze")

    def import_folder(self):
        folder = filedialog.askdirectory(title="Select Extracted Log Folder")
        if folder:
            self.archive_password = None
            self.settings_manager.set("PATHS", "log_folder", folder)
            self.input_label.configure(text=folder)
            self.status_var.set("Folder selected — ready to analyze")

    def run_log_parser(self):
        if self._parsing:
            return
        from case_processor import CaseProcessor
        log_folder = self.settings_manager.get("PATHS", "log_folder", fallback="logs/")
        case_id = self.settings_manager.get("CASE", "case_id", fallback="")
        examiner = self.settings_manager.get("CASE", "examiner", fallback="")
        evidence_number = self.settings_manager.get("CASE", "evidence_number", fallback="")
        self._parsing = True
        self.parsed_data = None
        for button in (self.parse_button, self.import_logs_button, self.settings_button):
            button.configure(state="disabled")
        self.status_var.set("Analyzing evidence…")
        if hasattr(self, "progress"):
            self.progress.grid()
            self.progress.start()
        results = queue.Queue()

        def task():
            try:
                results.put((CaseProcessor(log_folder, password=getattr(self, "archive_password", None),
                    case_id=case_id, examiner=examiner, evidence_number=evidence_number).process(), None))
            except Exception as error:
                results.put((None, str(error)))

        def poll():
            try:
                parsed_data, error = results.get_nowait()
            except queue.Empty:
                self.after(100, poll)
                return
            if hasattr(self, "progress"):
                self.progress.stop()
                self.progress.grid_remove()
            self._parsing = False
            for button in (self.parse_button, self.import_logs_button, self.settings_button):
                button.configure(state="normal")
            if error:
                self.status_var.set("Analysis failed")
                messagebox.showerror("Analysis Error", error)
                return
            self.parsed_data = parsed_data
            summary = parsed_data["import_summary"]
            self.status_var.set(f"Analysis complete — {summary['parsed']} parsed, {summary['partial']} partial, {summary['failed']} failed")
            self.refresh_dashboard()
            self.select_view("overview")

        threading.Thread(target=task, daemon=True).start()
        self.after(100, poll)

    def generate_report(self):
        if not self.parsed_data:
            messagebox.showinfo("No Analysis", "Analyze evidence before generating a report.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if path:
            try:
                from report_generator import ReportGenerator
                ReportGenerator(self.parsed_data).generate_pdf_report(report_path=path)
                self.status_var.set(f"Report saved: {path}")
            except Exception as error:
                messagebox.showerror("Report Error", str(error))

    def export_data(self):
        if not self.parsed_data:
            messagebox.showinfo("No Analysis", "Analyze evidence before exporting data.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if path:
            try:
                with open(path, "w", encoding="utf-8") as stream:
                    json.dump(self.parsed_data, stream, indent=2, ensure_ascii=False)
                self.status_var.set(f"JSON exported: {path}")
            except OSError as error:
                messagebox.showerror("Export Error", str(error))

    def insert_log(self, message):
        """Compatibility shim for callers that previously wrote to the activity log."""
        self.status_var.set(message)

    def view_parsed_data(self):
        self.select_view("overview")


if __name__ == "__main__":
    StealerScopeGUI().mainloop()
