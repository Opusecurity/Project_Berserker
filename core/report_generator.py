import json
import os
from fpdf import FPDF
from fpdf.enums import XPos, YPos, Align

PENTEST_FILE = "data/pentest_results/pentest_results.json"
RANKING_DIR = "data/target_ranking_post"
META_FILE = "data/report_meta.json"
OUTPUT_FILE = "reports/final_report.pdf"
os.makedirs("reports", exist_ok=True)

def get_latest_ranking_file():
    files = [f for f in os.listdir(RANKING_DIR) if f.startswith("target_ranking_post_")]
    return os.path.join(RANKING_DIR, sorted(files)[-1]) if files else None

RANKING_FILE = get_latest_ranking_file()
if not os.path.exists(PENTEST_FILE) or not RANKING_FILE or not os.path.exists(META_FILE):
    raise FileNotFoundError("Required pentest, ranking, or meta file not found.")

with open(PENTEST_FILE) as f:
    pentest = json.load(f)
with open(RANKING_FILE) as f:
    rankings = json.load(f)
with open(META_FILE) as f:
    report_meta = json.load(f)

start_time = report_meta.get("start_time", '-')
end_time = report_meta.get("end_time", '-')

class StyledPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(0, 0, 80)
        self.cell(0, 10, "PROJECT BERSERKER - FINAL REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        self.ln(6)

    def section_title(self, title):
        self.ln(8)
        self.set_fill_color(240, 240, 240)
        self.set_text_color(0, 0, 0)
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 9, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.ln(3)

    def add_kv(self, key, value):
        self.set_font("Helvetica", "B", 10)
        self.cell(50, 6, f"{key}:", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 9)
        self.cell(0, 6, str(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def add_bullet(self, text):
        self.set_font("Helvetica", "", 9)
        self.multi_cell(0, 6, f"- {text}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def add_host_finding_title(self, ip, risk, score):
        self.set_fill_color(220, 220, 220)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 8, f"Host: {ip} | Risk: {risk} ({score})", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.ln(2)

    def add_summary_table(self, summary_data):
        total_width = self.w - self.l_margin - self.r_margin
        col_widths = [total_width * ratio for ratio in [0.25, 0.25, 0.30, 0.20]]
        headers_top = ["Brute-force Attacks", "SMB Shares", "Web Vulnerabilities", "MITM Interception"]
        headers_bottom = ["of Successful Logins", "of Shared Resources", "of Vulnerabilities Found", "of Intercepted Requests"]

        self.set_font("Helvetica", "B", 10)
        for i, header in enumerate(headers_top):
            x = self.get_x()
            y = self.get_y()
            self.multi_cell(col_widths[i], 6, header, border=1, align=Align.C, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_xy(x + col_widths[i], y)
        self.ln(6)

        self.set_font("Helvetica", "", 8)
        for i, sub in enumerate(headers_bottom):
            x = self.get_x()
            y = self.get_y()
            self.multi_cell(col_widths[i], 6, sub, border=1, align=Align.C, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_xy(x + col_widths[i], y)
        self.ln(6)

        self.set_font("Helvetica", "", 9)
        for row in summary_data:
            for i, cell in enumerate(row):
                x = self.get_x()
                y = self.get_y()
                self.multi_cell(col_widths[i], 8, str(cell), border=1, align=Align.C, new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.set_xy(x + col_widths[i], y)
            self.ln(8)

    def add_grouped_findings(self, findings_dict):
        label_map = {
            "Brute": "Brute-force Attacks",
            "SMB": "SMB Shares",
            "Web": "Web Vulnerabilities",
            "MITM": "MITM Interception"
        }

        for key in ["Brute", "SMB", "Web", "MITM"]:
            items = findings_dict.get(key, [])
            if not items:
                continue
            self.set_font("Helvetica", "B", 10)
            suffix = "requests" if key == "MITM" else "findings"
            self.cell(0, 6, f"{label_map[key]}: {len(items)} {suffix}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            self.set_font("Helvetica", "", 9)
            for item in items:
                if key == "MITM" and item.startswith("Intercepted Data:"):
                    self.multi_cell(0, 6, "  * Intercepted Data:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    lines = item.split("\n")[1:]
                    for line in lines:
                        line = line.strip()
                        if line:
                            self.multi_cell(0, 6, f"       - {line}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                else:
                    self.multi_cell(0, 6, f"  - {item}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

pdf = StyledPDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()

meta = pentest.get("metadata", {})
pdf.section_title("1. General Information")
pdf.add_kv("Scan ID", meta.get("scan_id", '-'))
pdf.add_kv("Start Time", start_time)
pdf.add_kv("End Time", end_time)
pdf.add_kv("Executed Modules", ', '.join(meta.get("executed_modules", [])))
pdf.add_kv("Hosts Attacked", len(rankings))

pdf.section_title("2. Summary Table")
findings = {r["ip"]: [] for r in rankings}
summary_table = []

for login in pentest.get("brute_force", {}).get("successful_logins", []):
    findings[login["ip"]].append(f"Brute-force on {login['service'].upper()}: {login['username']} / {login['password']}")

for smb in pentest.get("smb_enum", {}).get("results", []):
    if smb.get("shares"):
        findings[smb["ip"]].append(f"SMB Shares: {', '.join(smb['shares'])}")

for entry in pentest.get("web_attack", {}).get("results", []):
    ip = entry.get("target", "").split("//")[-1].split(":")[0]
    for vuln_type in ["sqli", "xss", "lfi"]:
        for vuln in entry.get(vuln_type, []):
            method = "POST" if "[form POST]" in vuln else "GET"
            path = vuln.split()[0]
            findings[ip].append(f"{vuln_type.upper()} ({method}) at {path}")

for mitm in pentest.get("mitm", []):
    ip = mitm.get("ip", "").strip()
    data = mitm.get("data", "").strip()
    if data:
        lines = [l.replace("=", ": ") for l in data.split("&")]
        findings[ip].append("Intercepted Data:\n" + "\n".join(lines))

for host in rankings:
    ip = host["ip"]
    grouped = {"Brute": [], "SMB": [], "Web": [], "MITM": []}
    for f in findings[ip]:
        if f.startswith("Brute-force"):
            grouped["Brute"].append(f)
        elif f.startswith("SMB"):
            grouped["SMB"].append(f)
        elif any(v in f for v in ["SQLI", "XSS", "LFI"]):
            grouped["Web"].append(f)
        elif f.startswith("Intercepted Data"):
            grouped["MITM"].append(f)
    summary_table.append([
        len(grouped["Brute"]),
        len(grouped["SMB"]),
        len(grouped["Web"]),
        len(grouped["MITM"])
    ])

pdf.add_summary_table(summary_table)

pdf.section_title("3. Risk Ranking Summary")
for host in rankings:
    pdf.add_bullet(f"{host['ip']} -> {host['label'].upper()} (Score: {host['risk_score']})")

pdf.section_title("4. Detailed Findings Per Host")
for host in rankings:
    ip = host["ip"]
    risk = host['label'].upper()
    score = host['risk_score']
    pdf.add_host_finding_title(ip, risk, score)

    grouped = {"Brute": [], "SMB": [], "Web": [], "MITM": []}
    for f in findings[ip]:
        if f.startswith("Brute-force"):
            grouped["Brute"].append(f)
        elif f.startswith("SMB"):
            grouped["SMB"].append(f)
        elif any(v in f for v in ["SQLI", "XSS", "LFI"]):
            grouped["Web"].append(f)
        elif f.startswith("Intercepted Data"):
            grouped["MITM"].append(f)

    pdf.add_grouped_findings(grouped)

pdf.section_title("5. Recommendations")
used_modules = set()
for val in findings.values():
    for item in val:
        if "Brute-force" in item:
            used_modules.add("brute")
        elif "SMB" in item:
            used_modules.add("smb")
        elif any(v in item for v in ["SQLI", "XSS", "LFI"]):
            used_modules.add("web")
        elif "Intercepted Data" in item:
            used_modules.add("mitm")

if "brute" in used_modules:
    pdf.add_bullet("Apply account lockout and rate-limiting to prevent brute-force attacks.")
if "smb" in used_modules:
    pdf.add_bullet("Disable or restrict anonymous SMB shares.")
if "web" in used_modules:
    pdf.add_bullet("Sanitize web inputs to prevent SQLi, XSS, and LFI vulnerabilities.")
if "mitm" in used_modules:
    pdf.add_bullet("Enforce HTTPS to protect credentials from interception.")
if not used_modules:
    pdf.add_bullet("No critical issues detected. Maintain system updates and monitoring.")

pdf.output(OUTPUT_FILE)
print(f"[+] Final PDF report generated: {OUTPUT_FILE}", flush=True)
