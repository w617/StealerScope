import json
import os
import html
from fpdf import FPDF

# Custom PDF subclass for improved styling
class PDF(FPDF):
    def __init__(self, logo_path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logo_path = logo_path

    def header(self):
        # Draw a filled rectangle at the top for a header background
        self.set_fill_color(50, 100, 150)  # Blue-ish background
        self.rect(0, 0, self.w, 25, "F")
        # Insert logo (if available) on the left side
        if os.path.exists(self.logo_path):
            try:
                self.image(self.logo_path, x=10, y=5, w=20)
            except Exception as e:
                print(f"Header logo insertion failed: {e}")
        # Set header title
        self.set_font("Arial", "B", 16)
        self.set_text_color(255, 255, 255)
        self.cell(0, 25, "StealerScope Threat Report", border=0, ln=1, align="C")
        self.ln(2)
        # Reset text color for body content
        self.set_text_color(0, 0, 0)

    def footer(self):
        # Draw a horizontal line above the footer
        self.set_line_width(0.5)
        self.line(10, self.h - 20, self.w - 10, self.h - 20)
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")

class ReportGenerator:
    def __init__(self, parsed_data, output_folder="reports"):
        self.data = parsed_data
        self.output_folder = output_folder
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)

    def generate_pdf_report(self, report_path=None, logo_path="StealerScope.png"):
        """
        Generates a visually enhanced PDF report.
        logo_path: Path to your logo image (PNG or JPEG).
        """
        if not report_path:
            report_path = os.path.join(self.output_folder, "threat_report.pdf")

        pdf = PDF(logo_path, orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Set base font for the report content
        pdf.set_font("Arial", "", 12)
        if not any(self.data.values()):
            pdf.cell(0, 10, "No data available", ln=True, align="C")
        else:
            for category, entries in self.data.items():
                if not entries:
                    continue
                # Draw section header with a fill color
                pdf.set_fill_color(230, 230, 230)
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, category.replace("_", " ").title(), ln=True, fill=True)
                pdf.ln(2)
                pdf.set_font("Arial", "", 12)
                if isinstance(entries, list):
                    pdf.cell(0, 8, f"Total items: {len(entries)}", ln=True)
                    pdf.ln(1)
                    for i, entry in enumerate(entries, start=1):
                        if isinstance(entry, dict):
                            entry_text = json.dumps(entry, indent=2)
                        else:
                            entry_text = str(entry)
                        pdf.multi_cell(0, 8, f"{i}. {entry_text}", border=0)
                        pdf.ln(1)
                elif isinstance(entries, dict):
                    pdf.cell(0, 8, f"Total entries: {len(entries)}", ln=True)
                    pdf.ln(1)
                    for key, value in entries.items():
                        pdf.multi_cell(0, 8, f"{key}: {value}", border=0)
                        pdf.ln(1)
                pdf.ln(5)

        pdf.output(report_path)
        return report_path

    def generate_html_report(self, report_path=None, logo_path="StealerScope.png"):
        """
        Generates an HTML report with enhanced styling.
        """
        if not report_path:
            report_path = os.path.join(self.output_folder, "threat_report.html")

        css = """
        <style>
            body { font-family: 'Arial', sans-serif; background: #f4f4f4; margin: 20px; }
            .header { text-align: center; padding: 10px; }
            .header img { width: 150px; }
            h1 { text-align: center; color: #333; }
            h2 { background: #e6e6e6; padding: 10px; border-radius: 4px; }
            ul { list-style-type: none; padding-left: 0; }
            li { background: #fff; margin: 5px 0; padding: 10px; border-radius: 4px; box-shadow: 1px 1px 3px rgba(0,0,0,0.1); }
            pre { white-space: pre-wrap; word-wrap: break-word; }
            hr { border: 0; height: 1px; background: #ccc; margin: 20px 0; }
        </style>
        """
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("<html><head><title>StealerScope Threat Report</title>")
            f.write(css)
            f.write("</head><body>")
            f.write("<div class='header'>")
            f.write(f"<img src='{logo_path}' alt='StealerScope Logo'/>")
            f.write("</div>")
            f.write("<h1>StealerScope Threat Report</h1>")
            f.write("<hr/>")
            if not any(self.data.values()):
                f.write("<p>No data available</p>")
            else:
                for category, entries in self.data.items():
                    if not entries:
                        continue
                    safe_category = html.escape(category.replace('_', ' ').title())
                    f.write(f"<h2>{safe_category}</h2>")
                    if isinstance(entries, list):
                        f.write(f"<p>Total items: {len(entries)}</p>")
                        f.write("<ul>")
                        for entry in entries:
                            safe_entry = html.escape(json.dumps(entry, indent=2))
                            f.write(f"<li><pre>{safe_entry}</pre></li>")
                        f.write("</ul>")
                    elif isinstance(entries, dict):
                        f.write(f"<p>Total entries: {len(entries)}</p>")
                        f.write("<ul>")
                        for key, value in entries.items():
                            f.write(f"<li>{html.escape(str(key))}: {html.escape(str(value))}</li>")
                        f.write("</ul>")
            f.write("</body></html>")
        return report_path

    def generate_json_report(self, report_path=None):
        """
        Generates a JSON report summarizing extracted log threats.
        """
        if not report_path:
            report_path = os.path.join(self.output_folder, "threat_report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4)
        return report_path

# Example usage:
if __name__ == "__main__":
    # Dummy data for demonstration purposes:
    parsed_data = {
        "credentials": [
            {"source": "log1.txt", "url": "http://example.com", "username": "admin", "password": "1234"},
            {"source": "log2.txt", "url": "http://test.com", "username": "user", "password": "pass"}
        ],
        "brute_passwords": ["pass1", "pass2"],
        "detected_domains": ["example.com", "test.com"],
        "processes": ["chrome.exe", "explorer.exe"],
        "installed_software": ["Software A", "Software B"],
        "system_info": {"OS": "Windows 10", "CPU": "Intel i7"}
    }
    rg = ReportGenerator(parsed_data)
    pdf_report = rg.generate_pdf_report(report_path="enhanced_report.pdf", logo_path="StealerScope.png")
    html_report = rg.generate_html_report(report_path="enhanced_report.html", logo_path="StealerScope.png")
    print("Reports generated:", pdf_report, html_report)
