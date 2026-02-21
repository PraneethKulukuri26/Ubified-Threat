"""
PDF Report Generator
====================
Generates a professional threat intelligence PDF report with:
  - Executive summary
  - Risk-ranked IOC tables
  - Campaign details per actor
  - MITRE ATT&CK TTPs
  - Attacker graph (embedded PNG)
  - Recommended actions
"""

import logging
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional

from fpdf import FPDF

logger = logging.getLogger(__name__)


# ── Color Palette ────────────────────────────────────────────────────────
COLORS = {
    "header_bg": (30, 41, 59),        # Dark slate
    "header_text": (255, 255, 255),    # White
    "critical_bg": (220, 38, 38),      # Red
    "high_bg": (234, 88, 12),          # Orange
    "medium_bg": (202, 138, 4),        # Yellow
    "low_bg": (22, 163, 74),           # Green
    "severity_text": (255, 255, 255),  # White
    "table_header": (51, 65, 85),      # Slate 700
    "table_alt": (241, 245, 249),      # Slate 100
    "text": (30, 41, 59),              # Slate 800
    "subtext": (100, 116, 139),        # Slate 500
    "accent": (59, 130, 246),          # Blue 500
    "border": (203, 213, 225),         # Slate 300
}


class ThreatReportPDF(FPDF):
    """Custom PDF class for threat intelligence reports."""

    def __init__(self):
        super().__init__('P', 'mm', 'A4')
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        if self.page_no() > 1:
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(*COLORS["subtext"])
            self.cell(0, 8, 'Unified Threat Intelligence & SIEM Fusion Report', align='L')
            self.cell(0, 8, f'Page {self.page_no()}', align='R', new_x="LMARGIN", new_y="NEXT")
            self.set_draw_color(*COLORS["border"])
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 7)
        self.set_text_color(*COLORS["subtext"])
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        self.cell(0, 10, f'Generated: {ts}  |  CONFIDENTIAL', align='C')

    def section_title(self, title: str):
        self.ln(4)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(*COLORS["accent"])
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*COLORS["accent"])
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def subsection_title(self, title: str):
        self.ln(2)
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(*COLORS["text"])
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body_text(self, text: str):
        self.set_font('Helvetica', '', 9)
        self.set_text_color(*COLORS["text"])
        self.multi_cell(0, 5, text)
        self.ln(2)

    def severity_badge(self, label: str, x: float, y: float, w: float = 18, h: float = 5):
        """Draw a colored severity badge."""
        color_map = {
            "Critical": COLORS["critical_bg"],
            "High": COLORS["high_bg"],
            "Medium": COLORS["medium_bg"],
            "Low": COLORS["low_bg"],
        }
        bg = color_map.get(label, COLORS["low_bg"])
        self.set_fill_color(*bg)
        self.set_text_color(*COLORS["severity_text"])
        self.set_font('Helvetica', 'B', 7)
        self.set_xy(x, y)
        self.cell(w, h, label, fill=True, align='C')


def generate_pdf_report(
    scored_iocs: list,
    stix_parser,
    enrichment_summary: dict,
    risk_summary: dict,
    output_path: str,
    graph_png_path: Optional[str] = None
):
    """Generate a comprehensive PDF threat intelligence report."""

    pdf = ThreatReportPDF()

    # ── Cover Page ───────────────────────────────────────────────────
    pdf.add_page()

    # Title block
    pdf.ln(40)
    pdf.set_font('Helvetica', 'B', 28)
    pdf.set_text_color(*COLORS["header_bg"])
    pdf.cell(0, 14, 'Threat Intelligence', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 14, 'Fusion Report', align='C', new_x="LMARGIN", new_y="NEXT")

    pdf.ln(8)
    pdf.set_draw_color(*COLORS["accent"])
    pdf.set_line_width(0.8)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.ln(8)

    pdf.set_font('Helvetica', '', 11)
    pdf.set_text_color(*COLORS["subtext"])
    ts = datetime.now(timezone.utc).strftime("%B %d, %Y  |  %H:%M UTC")
    pdf.cell(0, 8, ts, align='C', new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 7, f'Total IOCs: {len(scored_iocs)}  |  '
             f'Actors: {len(stix_parser.actors)}  |  '
             f'Alerts: {enrichment_summary.get("total_alerts", 0)}',
             align='C', new_x="LMARGIN", new_y="NEXT")

    # Severity summary boxes on cover
    pdf.ln(10)
    box_w = 35
    start_x = (210 - 4 * box_w - 3 * 5) / 2  # centered with 5mm gaps
    box_y = pdf.get_y()

    severity_data = [
        ("CRITICAL", risk_summary.get("critical_count", 0), COLORS["critical_bg"]),
        ("HIGH", risk_summary.get("high_count", 0), COLORS["high_bg"]),
        ("MEDIUM", risk_summary.get("medium_count", 0), COLORS["medium_bg"]),
        ("LOW", risk_summary.get("low_count", 0), COLORS["low_bg"]),
    ]

    for i, (label, count, color) in enumerate(severity_data):
        x = start_x + i * (box_w + 5)
        pdf.set_fill_color(*color)
        pdf.set_draw_color(*color)
        pdf.rect(x, box_y, box_w, 18, style='F')

        pdf.set_font('Helvetica', 'B', 18)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(x, box_y + 1)
        pdf.cell(box_w, 10, str(count), align='C')

        pdf.set_font('Helvetica', '', 7)
        pdf.set_xy(x, box_y + 11)
        pdf.cell(box_w, 5, label, align='C')

    pdf.ln(30)
    pdf.set_font('Helvetica', 'I', 8)
    pdf.set_text_color(*COLORS["subtext"])
    pdf.cell(0, 6, 'Generated by Unified Threat Intelligence & SIEM Fusion System v1.0.0',
             align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, 'CONFIDENTIAL - For authorized personnel only',
             align='C', new_x="LMARGIN", new_y="NEXT")

    # ── Executive Summary Page ───────────────────────────────────────
    pdf.add_page()
    pdf.section_title('Executive Summary')

    actors = list(stix_parser.actors.keys()) if stix_parser.actors else ["None detected"]
    total_alerts = enrichment_summary.get("total_alerts", 0)
    critical = risk_summary.get("critical_count", 0)
    high = risk_summary.get("high_count", 0)

    summary_text = (
        f"This report presents the findings from automated threat intelligence fusion analysis. "
        f"A total of {len(scored_iocs)} indicators of compromise (IOCs) were identified across "
        f"{len(stix_parser.actors)} threat actor(s): {', '.join(actors)}. "
        f"Of these, {critical} are rated Critical and {high} are rated High severity. "
        f"{total_alerts} SIEM log entries matched known threat indicators, "
        f"suggesting active compromise or reconnaissance activity."
    )
    pdf.body_text(summary_text)

    # Key findings bullets
    pdf.subsection_title('Key Findings')
    findings = [
        f"{len(scored_iocs)} unique IOCs ingested from STIX bundles and OSINT feeds",
        f"{total_alerts} malicious connections detected in SIEM logs",
        f"Threat actors identified: {', '.join(actors)}",
        f"{len(stix_parser.malware)} malware families associated with campaigns",
        f"{len(stix_parser.attack_patterns)} MITRE ATT&CK techniques mapped",
    ]
    for finding in findings:
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(*COLORS["text"])
        pdf.cell(5, 5, '-')  # bullet
        pdf.cell(0, 5, f"  {finding}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # ── Risk-Ranked IOC Table ────────────────────────────────────────
    pdf.section_title('Risk-Ranked Indicators of Compromise')

    # Table header
    col_widths = [14, 45, 60, 18, 16, 16]
    headers = ['Type', 'Value', 'Description', 'Severity', 'Score', 'Sightings']

    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(*COLORS["table_header"])
    pdf.set_text_color(255, 255, 255)

    for j, (header, w) in enumerate(zip(headers, col_widths)):
        pdf.cell(w, 7, header, border=1, fill=True, align='C')
    pdf.ln()

    # Table rows
    for i, ioc in enumerate(scored_iocs):
        # Check page break
        if pdf.get_y() > 260:
            pdf.add_page()
            # Re-draw header
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_fill_color(*COLORS["table_header"])
            pdf.set_text_color(255, 255, 255)
            for j, (header, w) in enumerate(zip(headers, col_widths)):
                pdf.cell(w, 7, header, border=1, fill=True, align='C')
            pdf.ln()

        # Alternating row colors
        if i % 2 == 0:
            pdf.set_fill_color(255, 255, 255)
        else:
            pdf.set_fill_color(*COLORS["table_alt"])

        pdf.set_font('Helvetica', '', 7)
        pdf.set_text_color(*COLORS["text"])

        ioc_type = getattr(ioc, 'ioc_type', str(getattr(ioc, 'ioc', ioc)).split(':')[0] if hasattr(ioc, 'ioc') else '')
        value = getattr(ioc, 'value', '')
        desc = getattr(ioc, 'description', '')
        severity = getattr(ioc, 'severity_label', 'Low')
        score = getattr(ioc, 'risk_score', 0)
        sightings = getattr(ioc, 'sightings', 0)

        # Truncate long values
        if len(value) > 22:
            value = value[:19] + '...'
        if len(desc) > 30:
            desc = desc[:27] + '...'

        pdf.cell(col_widths[0], 6, ioc_type, border=1, fill=True, align='C')
        pdf.cell(col_widths[1], 6, value, border=1, fill=True)
        pdf.cell(col_widths[2], 6, desc, border=1, fill=True)

        # Severity with color
        sev_x = pdf.get_x()
        sev_y = pdf.get_y()
        severity_colors = {
            "Critical": COLORS["critical_bg"],
            "High": COLORS["high_bg"],
            "Medium": COLORS["medium_bg"],
            "Low": COLORS["low_bg"],
        }
        sev_bg = severity_colors.get(severity, COLORS["low_bg"])
        pdf.set_fill_color(*sev_bg)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 7)
        pdf.cell(col_widths[3], 6, severity, border=1, fill=True, align='C')

        pdf.set_font('Helvetica', '', 7)
        pdf.set_text_color(*COLORS["text"])
        if i % 2 == 0:
            pdf.set_fill_color(255, 255, 255)
        else:
            pdf.set_fill_color(*COLORS["table_alt"])
        pdf.cell(col_widths[4], 6, f"{score:.3f}", border=1, fill=True, align='C')
        pdf.cell(col_widths[5], 6, str(sightings), border=1, fill=True, align='C')
        pdf.ln()

    # ── Campaign Details ─────────────────────────────────────────────
    pdf.add_page()
    pdf.section_title('Campaign Details')

    for actor_name, actor in stix_parser.actors.items():
        pdf.subsection_title(f'Threat Actor: {actor_name}')

        desc = getattr(actor, 'description', 'No description available.')
        pdf.body_text(desc)

        # Actor metadata
        info_items = []
        aliases = getattr(actor, 'aliases', [])
        if aliases:
            info_items.append(f"Aliases: {', '.join(aliases)}")
        soph = getattr(actor, 'sophistication', '')
        if soph:
            info_items.append(f"Sophistication: {soph}")
        motivation = getattr(actor, 'primary_motivation', '')
        if motivation:
            info_items.append(f"Motivation: {motivation}")

        if info_items:
            for item in info_items:
                pdf.set_font('Helvetica', '', 8)
                pdf.set_text_color(*COLORS["subtext"])
                pdf.cell(5, 5, '-')
                pdf.cell(0, 5, f"  {item}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

        # Actor's IOCs
        actor_iocs = [i for i in scored_iocs if getattr(i, 'actor', '') == actor_name]
        if actor_iocs:
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_text_color(*COLORS["text"])
            pdf.cell(0, 6, f"Associated IOCs ({len(actor_iocs)}):", new_x="LMARGIN", new_y="NEXT")
            for ioc in actor_iocs:
                value = getattr(ioc, 'value', '')
                score = getattr(ioc, 'risk_score', 0)
                severity = getattr(ioc, 'severity_label', 'Low')
                pdf.set_font('Helvetica', '', 8)
                pdf.set_text_color(*COLORS["text"])
                pdf.cell(5, 5, '-')
                pdf.cell(0, 5, f"  {value}  (Score: {score:.3f}, {severity})",
                         new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

    # ── Malware Families ─────────────────────────────────────────────
    if stix_parser.malware:
        pdf.section_title('Malware Families')
        for name, mal in stix_parser.malware.items():
            pdf.subsection_title(name)
            desc = getattr(mal, 'description', 'No description.')
            pdf.body_text(desc)
            mal_types = getattr(mal, 'malware_types', [])
            if mal_types:
                pdf.set_font('Helvetica', 'I', 8)
                pdf.set_text_color(*COLORS["subtext"])
                pdf.cell(0, 5, f"Types: {', '.join(mal_types)}", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)

    # ── MITRE ATT&CK TTPs ───────────────────────────────────────────
    if stix_parser.attack_patterns:
        pdf.section_title('MITRE ATT&CK Techniques')

        ttp_cols = [25, 50, 110]
        ttp_headers = ['Technique ID', 'Name', 'Description']

        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(*COLORS["table_header"])
        pdf.set_text_color(255, 255, 255)
        for header, w in zip(ttp_headers, ttp_cols):
            pdf.cell(w, 7, header, border=1, fill=True, align='C')
        pdf.ln()

        for i, (ttp_id, ttp) in enumerate(stix_parser.attack_patterns.items()):
            if i % 2 == 0:
                pdf.set_fill_color(255, 255, 255)
            else:
                pdf.set_fill_color(*COLORS["table_alt"])

            pdf.set_font('Helvetica', '', 8)
            pdf.set_text_color(*COLORS["text"])

            tid = ttp_id
            name = getattr(ttp, 'name', 'Unknown')
            desc = getattr(ttp, 'description', '')
            if len(desc) > 55:
                desc = desc[:52] + '...'

            pdf.cell(ttp_cols[0], 6, tid, border=1, fill=True, align='C')
            pdf.cell(ttp_cols[1], 6, name, border=1, fill=True)
            pdf.cell(ttp_cols[2], 6, desc, border=1, fill=True)
            pdf.ln()

    # ── Attacker Infrastructure Graph ────────────────────────────────
    if graph_png_path and os.path.exists(graph_png_path):
        pdf.add_page()
        pdf.section_title('Attacker Infrastructure Graph')
        pdf.body_text(
            'The following graph visualizes the relationships between threat actors, '
            'malware families, indicators of compromise, and MITRE ATT&CK techniques.'
        )

        # Fit graph image to page width
        img_w = 180
        try:
            pdf.image(graph_png_path, x=15, y=pdf.get_y(), w=img_w)
        except Exception as e:
            logger.warning(f"Could not embed graph image: {e}")
            pdf.body_text(f"[Graph image could not be embedded: {e}]")

    # ── Recommendations ──────────────────────────────────────────────
    pdf.add_page()
    pdf.section_title('Recommended Actions')

    recommendations = [
        ("Immediate", "Block all Critical and High severity IOCs at perimeter firewalls, "
         "web proxies, and DNS resolvers."),
        ("Investigate", "Conduct forensic analysis on internal hosts that communicated with "
         "known C2 infrastructure. Preserve evidence for incident response."),
        ("Hunt", "Execute the auto-generated SIEM queries (SPL, KQL, Elasticsearch DSL) "
         "to identify additional compromised hosts and lateral movement."),
        ("Patch", "Review MITRE ATT&CK techniques identified and ensure corresponding "
         "security controls and patches are applied."),
        ("Monitor", "Set up continuous monitoring and alerting rules for all IOCs. "
         "Configure IOC feeds for automatic updates."),
        ("Share", "Share relevant threat intelligence with sector ISACs and trusted "
         "partners via STIX/TAXII or MISP."),
    ]

    for i, (title, desc) in enumerate(recommendations, 1):
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(*COLORS["accent"])
        pdf.cell(8, 7, f"{i}.")
        pdf.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_x(18)
        pdf.body_text(desc)

    # ── Save ─────────────────────────────────────────────────────────
    pdf.output(output_path)
    logger.info(f"PDF report saved to {output_path}")
    return output_path
