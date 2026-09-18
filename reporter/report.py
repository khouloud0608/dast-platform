#!/usr/bin/env python3
"""
DAST Platform - PDF Report Generator
=====================================
Reads scan results produced by the crawler / passive / active scanners
(and, when present, the AI module) and produces a professional pentest
report at output/report.pdf using fpdf2.

Inputs  (all under /app/output, mounted from /opt/dast-platform/output):
    active_results.json    - active scanner findings  (required-ish)
    passive_results.json   - passive scanner findings (required-ish)
    ai_summary.json        - AI module output         (OPTIONAL)
    /app/config.json       - target metadata

Output:
    output/report.pdf

Design notes:
  * Pure fpdf2, no system dependencies (matches project decision).
  * Core fonts are Latin-1 only, so ALL text is sanitized before it
    reaches the PDF (em-dashes, arrows, smart quotes -> ASCII).
  * If ai_summary.json is missing, an automated summary is generated
    from the finding counts. When the AI module later produces the
    file, the report picks it up with no code change.
"""

import json
import os
from datetime import datetime
from collections import Counter, defaultdict

from fpdf import FPDF

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
OUTPUT_DIR   = os.environ.get("OUTPUT_DIR", "/app/output")
INPUT_DIR    = os.environ.get("INPUT_DIR", "/app/output")   # scanners write here too
CONFIG_PATH  = os.environ.get("CONFIG_PATH", "/app/config.json")

ACTIVE_FILE  = os.path.join(INPUT_DIR, "active_results.json")
PASSIVE_FILE = os.path.join(INPUT_DIR, "passive_results.json")
AI_FILE      = os.path.join(INPUT_DIR, "ai_summary.json")
REPORT_PATH  = os.path.join(OUTPUT_DIR, "report.pdf")

# ---------------------------------------------------------------------------
# Severity handling
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_RANK  = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# RGB colors per severity (used for the severity chips / table cells)
SEVERITY_COLOR = {
    "Critical": (192, 57, 43),    # dark red
    "High":     (231, 76, 60),    # red
    "Medium":   (230, 126, 34),   # orange
    "Low":      (241, 196, 15),   # yellow
    "Info":     (52, 152, 219),   # blue
}

# Brand palette (dark navy to match the GUI)
NAVY      = (23, 42, 69)
NAVY_SOFT = (44, 62, 89)
LIGHT_BG  = (245, 247, 250)
GREY_TXT  = (90, 100, 110)
WHITE     = (255, 255, 255)

# ---------------------------------------------------------------------------
# Built-in remediation knowledge base (keyed by vuln_type substrings).
# Active findings have no 'recommendation' field, so we supply one here.
# Passive findings already carry their own 'recommendation'.
# ---------------------------------------------------------------------------
REMEDIATION_KB = {
    "sql injection": (
        "Use parameterized queries / prepared statements for every database "
        "call. Never concatenate user input into SQL. Apply least-privilege "
        "database accounts and validate input server-side."
    ),
    "cross-site scripting": (
        "Contextually output-encode all user-controlled data before rendering "
        "it in HTML, attributes, or JavaScript. Deploy a Content-Security-Policy "
        "and set the HttpOnly flag on session cookies."
    ),
    "command injection": (
        "Avoid passing user input to shell commands. Use language-native APIs, "
        "allow-list permitted values, and never invoke a shell interpreter with "
        "untrusted data."
    ),
    "file inclusion": (
        "Never build file paths from user input. Use an allow-list of permitted "
        "resources and disable remote file inclusion (allow_url_include=Off)."
    ),
    "csrf": (
        "Implement anti-CSRF tokens on all state-changing requests and set the "
        "SameSite attribute on cookies."
    ),
}

GENERIC_REMEDIATION = (
    "Review the affected endpoint, validate and sanitize all user input, and "
    "apply the relevant OWASP secure-coding controls for this vulnerability class."
)


def remediation_for(vuln_type: str) -> str:
    key = (vuln_type or "").lower()
    for needle, advice in REMEDIATION_KB.items():
        if needle in key:
            return advice
    return GENERIC_REMEDIATION


# ---------------------------------------------------------------------------
# Text sanitizing (fpdf2 core fonts are Latin-1 only)
# ---------------------------------------------------------------------------
_REPLACEMENTS = {
    "\u2014": "-",   # em dash
    "\u2013": "-",   # en dash
    "\u2192": "->",  # right arrow
    "\u2018": "'", "\u2019": "'",   # smart single quotes
    "\u201c": '"', "\u201d": '"',   # smart double quotes
    "\u2026": "...",  # ellipsis
    "\u2022": "-",    # bullet
    "\u00a0": " ",    # non-breaking space
}


def clean(text) -> str:
    """Make any value safe for fpdf2 core fonts."""
    if text is None:
        return ""
    s = str(text)
    for bad, good in _REPLACEMENTS.items():
        s = s.replace(bad, good)
    # Drop anything still outside Latin-1
    return s.encode("latin-1", "replace").decode("latin-1")


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_json(path, default):
    if os.path.isdir(path):
        print(f"[WARN] {path} is a directory, using default")
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, IsADirectoryError, json.JSONDecodeError, OSError) as e:
        print(f"[WARN] Could not load {path}: {e}")
        return default


def load_config():
    cfg = load_json(CONFIG_PATH, {})
    target = cfg.get("target_url") or "Not specified"
    app_type = cfg.get("app_type") or "generic"
    # Derive a readable host label from the target URL (e.g. for the cover title)
    try:
        from urllib.parse import urlparse
        host = urlparse(target).hostname or target
    except Exception:
        host = target
    return {
        "target_url": target,
        "app_type":   app_type,
        "scan_id":    cfg.get("scan_id") or "N/A",
        "target_host": host,
    }


def normalize_severity(s: str) -> str:
    s = (s or "").strip().capitalize()
    return s if s in SEVERITY_RANK else "Info"


# ---------------------------------------------------------------------------
# PDF class
# ---------------------------------------------------------------------------
class ReportPDF(FPDF):
    def __init__(self, meta):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.meta = meta
        self.set_auto_page_break(auto=True, margin=18)
        self.set_title("DAST Security Assessment Report")
        self.set_author("DAST Platform")
        self._on_cover = False

    # --- running header / footer (skipped on the cover page) ---------------
    def header(self):
        if self._on_cover:
            return
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*GREY_TXT)
        self.cell(0, 6, "DAST Security Assessment Report", align="L")
        self.cell(0, 6, clean(self.meta["target_url"]), align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*NAVY)
        self.set_line_width(0.3)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def footer(self):
        if self._on_cover:
            return
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*GREY_TXT)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    # --- reusable building blocks -----------------------------------------
    def section_title(self, text):
        self.ln(2)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*NAVY)
        self.cell(0, 9, clean(text), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*NAVY)
        self.set_line_width(0.4)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)

    def sub_title(self, text):
        self.ln(1)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*NAVY_SOFT)
        self.cell(0, 7, clean(text), new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body_text(self, text):
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(30, 30, 30)
        full_w = self.w - self.l_margin - self.r_margin
        self.multi_cell(full_w, 5.5, clean(text),
                        new_x="LMARGIN", new_y="NEXT", max_line_height=5.5)
        self.ln(1)

    def severity_chip(self, severity, count, x, y, w=34, h=18):
        color = SEVERITY_COLOR.get(severity, SEVERITY_COLOR["Info"])
        self.set_xy(x, y)
        self.set_fill_color(*color)
        self.set_draw_color(*color)
        self.rect(x, y, w, h, style="F")
        self.set_xy(x, y + 2)
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*WHITE)
        self.cell(w, 8, str(count), align="C")
        self.set_xy(x, y + 10)
        self.set_font("Helvetica", "B", 8)
        self.cell(w, 5, severity.upper(), align="C")


# ---------------------------------------------------------------------------
# Page builders
# ---------------------------------------------------------------------------
def build_cover(pdf: ReportPDF, meta, totals):
    pdf._on_cover = True
    pdf.add_page()

    # Full navy banner
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, pdf.w, 90, style="F")

    pdf.set_xy(0, 30)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 14, "DAST Security Assessment", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 15)
    pdf.cell(0, 10, "Web Application Vulnerability Report", align="C", new_x="LMARGIN", new_y="NEXT")

    # Metadata block
    pdf.set_xy(0, 110)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(40, 40, 40)
    rows = [
        ("Target",        meta["target_url"]),
        ("Application",   meta["app_type"].upper()),
        ("Scan ID",       meta["scan_id"]),
        ("Report date",   datetime.now().strftime("%Y-%m-%d %H:%M")),
        ("Total findings", str(totals["all"])),
    ]
    for label, value in rows:
        pdf.set_x(55)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*NAVY)
        pdf.cell(45, 8, clean(label))
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(40, 40, 40)
        pdf.cell(0, 8, clean(value), new_x="LMARGIN", new_y="NEXT")

    # Confidentiality note
    pdf.set_xy(0, 250)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*GREY_TXT)
    pdf.cell(0, 6, "CONFIDENTIAL - For internal security review only.",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, "Generated automatically by the DAST Platform.",
             align="C")

    pdf._on_cover = False


def build_executive_summary(pdf: ReportPDF, meta, active, passive, totals, ai):
    pdf.add_page()
    pdf.section_title("1. Executive Summary")

    # Severity chips row
    y = pdf.get_y() + 2
    chip_w, gap = 34, 3
    total_w = len(SEVERITY_ORDER) * chip_w + (len(SEVERITY_ORDER) - 1) * gap
    x = (pdf.w - total_w) / 2
    for sev in SEVERITY_ORDER:
        pdf.severity_chip(sev, totals["by_severity"].get(sev, 0), x, y)
        x += chip_w + gap
    pdf.set_y(y + 24)

    # Narrative: AI summary if available, else generated
    pdf.sub_title("Overview")
    if ai and ai.get("executive_summary"):
        pdf.body_text(ai["executive_summary"])
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*GREY_TXT)
        pdf.multi_cell(pdf.w - pdf.l_margin - pdf.r_margin, 4.5,
                       clean("Summary generated by the local AI module."),
                       new_x="LMARGIN", new_y="NEXT", max_line_height=4.5)
        pdf.ln(1)
    else:
        crit = totals["by_severity"].get("Critical", 0)
        high = totals["by_severity"].get("High", 0)
        posture = ("critical" if crit else
                   "poor" if high else
                   "moderate" if totals["all"] else "clean")
        summary = (
            f"An automated dynamic application security test (DAST) was "
            f"performed against {meta['target_url']} ({meta['app_type'].upper()}). "
            f"The scan produced {totals['all']} findings in total: "
            f"{len(active)} confirmed by active injection testing and "
            f"{len(passive)} raised by passive analysis of HTTP responses. "
            f"The assessment identified {crit} Critical and {high} High "
            f"severity issues, indicating a {posture} overall security posture. "
            f"Priority should be given to the Critical and High findings detailed "
            f"in the sections below."
        )
        pdf.body_text(summary)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*GREY_TXT)
        pdf.multi_cell(pdf.w - pdf.l_margin - pdf.r_margin, 4.5, clean(
            "Note: this summary was generated automatically from finding counts. "
            "A richer AI-generated analysis appears here once the AI module has run."
        ), new_x="LMARGIN", new_y="NEXT", max_line_height=4.5)
        pdf.ln(1)

    # Breakdown by module
    pdf.sub_title("Findings by module")
    pdf.body_text(
        f"Active scanner (SQLi / XSS injection): {len(active)} findings.\n"
        f"Passive scanner (headers / cookies / disclosure): {len(passive)} findings."
    )


def build_scan_metadata(pdf: ReportPDF, meta, active, passive):
    pdf.section_title("2. Scan Metadata")
    rows = [
        ("Target URL",        meta["target_url"]),
        ("Application type",  meta["app_type"]),
        ("Scan ID",           meta["scan_id"]),
        ("Report generated",  datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Active findings",   str(len(active))),
        ("Passive findings",  str(len(passive))),
        ("Methodology",       "OWASP-aligned DAST: crawl, passive analysis, active injection"),
    ]
    label_w = 55
    value_w = pdf.w - pdf.l_margin - pdf.r_margin - label_w
    pdf.set_font("Helvetica", "", 10)
    for label, value in rows:
        y0 = pdf.get_y()
        # label cell
        pdf.set_fill_color(*LIGHT_BG)
        pdf.set_text_color(*NAVY)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_xy(pdf.l_margin, y0)
        pdf.multi_cell(label_w, 8, clean(label), border=0, fill=True,
                       new_x="RIGHT", new_y="TOP", max_line_height=8)
        # value cell (reset X to just after the label column)
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_xy(pdf.l_margin + label_w, y0)
        pdf.multi_cell(value_w, 8, clean(value), border=0,
                       new_x="LMARGIN", new_y="NEXT", max_line_height=8)
    pdf.ln(2)


def _finding_card(pdf: ReportPDF, index, severity, title, fields):
    """Render one finding as a bordered card."""
    # Estimate: keep the header + first lines together
    if pdf.get_y() > pdf.h - 55:
        pdf.add_page()

    full_w = pdf.w - pdf.l_margin - pdf.r_margin
    color = SEVERITY_COLOR.get(severity, SEVERITY_COLOR["Info"])
    # Severity bar + title
    pdf.set_x(pdf.l_margin)
    pdf.set_fill_color(*color)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(22, 7, f" {severity.upper()}", fill=True)
    pdf.set_fill_color(*LIGHT_BG)
    pdf.set_text_color(*NAVY)
    title_txt = clean(f"  #{index}  {title}")
    pdf.multi_cell(full_w - 22, 7, title_txt, fill=True,
                   new_x="LMARGIN", new_y="NEXT", max_line_height=7)

    pdf.set_text_color(30, 30, 30)
    for label, value in fields:
        if not value:
            continue
        # Label on its own line
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*NAVY_SOFT)
        pdf.cell(0, 5, clean(label), new_x="LMARGIN", new_y="NEXT")
        # Value on the next line(s), full width from the left margin
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(30, 30, 30)
        pdf.multi_cell(full_w, 5, clean(value),
                       new_x="LMARGIN", new_y="NEXT", max_line_height=5)
    pdf.ln(3)


def build_active_findings(pdf: ReportPDF, active):
    pdf.add_page()
    pdf.section_title("3. Active Findings (Confirmed Vulnerabilities)")
    if not active:
        pdf.body_text("No confirmed vulnerabilities were reported by the active scanner.")
        return

    active_sorted = sorted(
        active, key=lambda f: SEVERITY_RANK.get(normalize_severity(f.get("severity")), 99)
    )
    for i, f in enumerate(active_sorted, 1):
        sev = normalize_severity(f.get("severity"))
        _finding_card(
            pdf, i, sev, f.get("vuln_type", "Vulnerability"),
            [
                ("URL",         f.get("url", "")),
                ("Parameter",   f.get("parameter", "")),
                ("Method",      f.get("method", "")),
                ("Technique",   f.get("technique", "")),
                ("Payload",     f.get("payload", "")),
                ("Evidence",    f.get("evidence", "")),
                ("Remediation", remediation_for(f.get("vuln_type", ""))),
            ],
        )


def build_passive_findings(pdf: ReportPDF, passive):
    pdf.add_page()
    pdf.section_title("4. Passive Findings (Configuration & Disclosure)")
    if not passive:
        pdf.body_text("No findings were reported by the passive scanner.")
        return

    # Passive findings are numerous (hundreds) -> summarize by check type,
    # then list one representative example per check with the affected count.
    pdf.body_text(
        f"The passive scanner produced {len(passive)} findings. To keep this "
        f"report readable they are grouped by check type below, with the number "
        f"of affected URLs and a representative example for each."
    )

    grouped = defaultdict(list)
    for f in passive:
        grouped[f.get("check", "Unknown check")].append(f)

    # Sort groups by worst severity then by size
    def group_key(item):
        check, items = item
        worst = min(SEVERITY_RANK.get(normalize_severity(x.get("severity")), 99)
                    for x in items)
        return (worst, -len(items))

    pdf.sub_title("Summary table")
    # Table header
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(*NAVY)
    pdf.set_text_color(*WHITE)
    pdf.cell(95, 7, " Check", border=0, fill=True)
    pdf.cell(28, 7, "Severity", border=0, fill=True, align="C")
    pdf.cell(0, 7, "Affected URLs", border=0, fill=True, align="C",
             new_x="LMARGIN", new_y="NEXT")

    fill = False
    for check, items in sorted(grouped.items(), key=group_key):
        sev = normalize_severity(items[0].get("severity"))
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(30, 30, 30)
        pdf.set_fill_color(*(LIGHT_BG if fill else WHITE))
        # check name may be long -> truncate for the cell
        name = clean(check)
        if len(name) > 62:
            name = name[:59] + "..."
        pdf.cell(95, 6.5, " " + name, border=0, fill=True)
        col = SEVERITY_COLOR.get(sev, SEVERITY_COLOR["Info"])
        pdf.set_text_color(*col)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(28, 6.5, sev, border=0, fill=True, align="C")
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6.5, str(len(items)), border=0, fill=True, align="C",
                 new_x="LMARGIN", new_y="NEXT")
        fill = not fill
    pdf.ln(4)

    # Detail: one representative card per check type
    pdf.sub_title("Representative details")
    for i, (check, items) in enumerate(sorted(grouped.items(), key=group_key), 1):
        rep = items[0]
        sev = normalize_severity(rep.get("severity"))
        _finding_card(
            pdf, i, sev, check,
            [
                ("Affected",    f"{len(items)} URL(s), e.g. {rep.get('url','')}"),
                ("Detail",      rep.get("detail", "")),
                ("Evidence",    rep.get("evidence", "")),
                ("Remediation", rep.get("recommendation", "") or GENERIC_REMEDIATION),
            ],
        )


def build_remediation_table(pdf: ReportPDF, active, passive):
    pdf.add_page()
    pdf.section_title("5. Consolidated Remediation Plan")
    pdf.body_text(
        "The table below consolidates recommended fixes across all findings, "
        "ordered by severity. Address Critical and High items first."
    )

    # Build unique (severity, issue, remediation) rows
    seen = set()
    rows = []
    for f in active:
        sev = normalize_severity(f.get("severity"))
        issue = f.get("vuln_type", "Vulnerability")
        rem = remediation_for(issue)
        key = (sev, issue)
        if key not in seen:
            seen.add(key)
            rows.append((sev, issue, rem))
    for f in passive:
        sev = normalize_severity(f.get("severity"))
        issue = f.get("check", "Issue")
        rem = f.get("recommendation", "") or GENERIC_REMEDIATION
        key = (sev, issue)
        if key not in seen:
            seen.add(key)
            rows.append((sev, issue, rem))

    rows.sort(key=lambda r: SEVERITY_RANK.get(r[0], 99))

    for sev, issue, rem in rows:
        if pdf.get_y() > pdf.h - 40:
            pdf.add_page()
        col = SEVERITY_COLOR.get(sev, SEVERITY_COLOR["Info"])
        pdf.set_fill_color(*col)
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(22, 6, f" {sev.upper()}", fill=True)
        pdf.set_text_color(*NAVY)
        pdf.set_fill_color(*LIGHT_BG)
        pdf.set_font("Helvetica", "B", 9)
        name = clean(issue)
        if len(name) > 70:
            name = name[:67] + "..."
        pdf.cell(0, 6, "  " + name, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_x(pdf.l_margin)
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(pdf.w - pdf.l_margin - pdf.r_margin, 5, clean(rem),
                       new_x="LMARGIN", new_y="NEXT", max_line_height=5)
        pdf.ln(2)


def build_annex(pdf: ReportPDF):
    pdf.add_page()
    pdf.section_title("6. Technical Annex")
    pdf.sub_title("Methodology")
    pdf.body_text(
        "This assessment was produced by the DAST Platform, a modular dynamic "
        "application security testing pipeline consisting of:\n"
        "- A Scrapy-based crawler that authenticates to the target (when "
        "credentials are provided) and maps reachable URLs, forms and parameters.\n"
        "- A passive scanner that inspects HTTP responses for missing security "
        "headers, insecure cookie flags and information disclosure.\n"
        "- An active scanner that injects attack payloads (including SQL "
        "injection and cross-site scripting) to confirm exploitable "
        "vulnerabilities.\n"
        "- An optional local AI module that generates contextual explanations "
        "and remediation guidance for the findings.\n"
        "- Results are indexed in Elasticsearch and visualized in Kibana."
    )
    pdf.sub_title("Severity scale")
    pdf.body_text(
        "Critical - direct compromise of data or system integrity.\n"
        "High - serious weakness that is likely exploitable.\n"
        "Medium - weakness that increases risk under certain conditions.\n"
        "Low - minor hardening or best-practice gap.\n"
        "Info - informational observation, no direct risk."
    )
    pdf.sub_title("Limitations")
    pdf.body_text(
        "Elasticsearch indices accumulate results across scans, so historical "
        "runs may contribute to dashboard totals. Findings in this PDF are read "
        "from the JSON output of the most recent scan. This is an automated "
        "assessment and does not replace a manual penetration test."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("[*] DAST PDF reporter starting")
    meta    = load_config()
    active  = load_json(ACTIVE_FILE, [])
    passive = load_json(PASSIVE_FILE, [])
    ai      = load_json(AI_FILE, None)

    # Only keep active findings that are actually vulnerable
    active = [f for f in active if f.get("vulnerable", True)]

    print(f"[*] Active findings : {len(active)}")
    print(f"[*] Passive findings: {len(passive)}")
    print(f"[*] AI summary      : {'present' if ai else 'not found (using generated summary)'}")

    # Totals
    by_sev = Counter()
    for f in active + passive:
        by_sev[normalize_severity(f.get("severity"))] += 1
    totals = {
        "all": len(active) + len(passive),
        "by_severity": by_sev,
    }

    pdf = ReportPDF(meta)
    build_cover(pdf, meta, totals)
    build_executive_summary(pdf, meta, active, passive, totals, ai)
    build_scan_metadata(pdf, meta, active, passive)
    build_active_findings(pdf, active)
    build_passive_findings(pdf, passive)
    build_remediation_table(pdf, active, passive)
    build_annex(pdf)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    pdf.output(REPORT_PATH)
    print(f"[+] Report written to {REPORT_PATH}")


if __name__ == "__main__":
    main()
