import os
import sys
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable,
)
from reportlab.pdfgen import canvas

PAGE_W, PAGE_H = A4

# Color Palette for Utilitarian Security Audit
DARK_NAVY    = colors.HexColor('#0f172a')
SLATE_BORDER = colors.HexColor('#cbd5e1')
BG_HEADER    = colors.HexColor('#1e293b')
BG_ROW_ALT   = colors.HexColor('#f8fafc')
TEXT_PRIMARY = colors.HexColor('#0f172a')
TEXT_MUTED   = colors.HexColor('#64748b')
LINK_BLUE    = colors.HexColor('#0284c7')

# Severity Color Tokens
SEV_COLORS = {
    'critical': colors.HexColor('#991b1b'),
    'high':     colors.HexColor('#c2410c'),
    'medium':   colors.HexColor('#854d0e'),
    'low':      colors.HexColor('#0369a1'),
    'info':     colors.HexColor('#475569'),
}

SEV_BG_TINTS = {
    'critical': colors.HexColor('#fef2f2'),
    'high':     colors.HexColor('#fff7ed'),
    'medium':   colors.HexColor('#fefce8'),
    'low':      colors.HexColor('#f0f9ff'),
    'info':     colors.HexColor('#f8fafc'),
}

SEV_CVSS_DEFAULTS = {
    'critical': 9.8,
    'high':     7.5,
    'medium':   5.3,
    'low':      3.5,
    'info':     1.0,
}

# Table geometry: Sum = 184 mm (fits A4 with 13 mm margins)
COL_WIDTHS = [9 * mm, 34 * mm, 26 * mm, 21 * mm, 56 * mm, 38 * mm]


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for professional 'Page X of Y' header/footer."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        # Top running header on pages > 1
        if self._pageNumber > 1:
            self.setFont('Helvetica', 6.5)
            self.setFillColor(TEXT_MUTED)
            self.drawString(13 * mm, PAGE_H - 10 * mm, 'WEBVULNSCANNER ENTERPRISE // INTERNAL IT SECURITY AUDIT DOSSIER')
            self.drawRightString(PAGE_W - 13 * mm, PAGE_H - 10 * mm, 'RESTRICTED / CONFIDENTIAL')
            self.setStrokeColor(SLATE_BORDER)
            self.setLineWidth(0.3)
            self.line(13 * mm, PAGE_H - 12 * mm, PAGE_W - 13 * mm, PAGE_H - 12 * mm)

        # Bottom footer on all pages
        self.setFont('Helvetica', 6.5)
        self.setFillColor(TEXT_MUTED)
        self.drawString(13 * mm, 8 * mm, 'RESTRICTED // INTERNAL IT AUDIT RECORD — STRICTLY FOR AUTHORIZED PERSONNEL ONLY')
        self.drawRightString(PAGE_W - 13 * mm, 8 * mm, f'Page {self._pageNumber} of {page_count}')
        self.setStrokeColor(SLATE_BORDER)
        self.setLineWidth(0.3)
        self.line(13 * mm, 11 * mm, PAGE_W - 13 * mm, 11 * mm)
        self.restoreState()


def _get_styles():
    """Generates precise typographic styles for the audit report."""
    base_styles = getSampleStyleSheet()

    styles = {
        'BannerTitle': ParagraphStyle(
            'BannerTitle',
            parent=base_styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=colors.white,
        ),
        'BannerSub': ParagraphStyle(
            'BannerSub',
            parent=base_styles['Normal'],
            fontName='Helvetica',
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor('#94a3b8'),
        ),
        'SectionHeader': ParagraphStyle(
            'SectionHeader',
            parent=base_styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=12,
            textColor=DARK_NAVY,
            spaceAfter=4,
        ),
        'MetaKey': ParagraphStyle(
            'MetaKey',
            parent=base_styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor('#334155'),
        ),
        'MetaVal': ParagraphStyle(
            'MetaVal',
            parent=base_styles['Normal'],
            fontName='Helvetica',
            fontSize=7.5,
            leading=10,
            textColor=TEXT_PRIMARY,
        ),
        'MetaValCode': ParagraphStyle(
            'MetaValCode',
            parent=base_styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=10,
            textColor=DARK_NAVY,
        ),
        'ThCell': ParagraphStyle(
            'ThCell',
            parent=base_styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7,
            leading=9,
            textColor=colors.white,
            alignment=0,
        ),
        'ThCellCenter': ParagraphStyle(
            'ThCellCenter',
            parent=base_styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7,
            leading=9,
            textColor=colors.white,
            alignment=1,
        ),
        'TdIdx': ParagraphStyle(
            'TdIdx',
            parent=base_styles['Normal'],
            fontName='Helvetica',
            fontSize=6.8,
            leading=8.5,
            textColor=TEXT_MUTED,
            alignment=1,
        ),
        'TdVuln': ParagraphStyle(
            'TdVuln',
            parent=base_styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=9.5,
            textColor=TEXT_PRIMARY,
        ),
        'TdEvidence': ParagraphStyle(
            'TdEvidence',
            parent=base_styles['Normal'],
            fontName='Helvetica',
            fontSize=6,
            leading=7.5,
            textColor=TEXT_MUTED,
        ),
        'TdCve': ParagraphStyle(
            'TdCve',
            parent=base_styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=9.5,
            textColor=DARK_NAVY,
        ),
        'TdRemediation': ParagraphStyle(
            'TdRemediation',
            parent=base_styles['Normal'],
            fontName='Helvetica',
            fontSize=6.8,
            leading=8.5,
            textColor=colors.HexColor('#1e293b'),
        ),
        'TdLink': ParagraphStyle(
            'TdLink',
            parent=base_styles['Normal'],
            fontName='Helvetica',
            fontSize=6.5,
            leading=8,
            textColor=LINK_BLUE,
        ),
    }

    return styles


def _build_cvss_cell(score: float, severity: str) -> Paragraph:
    """
    Renders CVSS Score with strict typographic hierarchy:
    Critical and High scores are visibly larger (9.5-10.5pt) and bolder
    with distinct background highlighting than Low/Info findings (7-7.5pt).
    """
    sev = severity.lower()
    score_str = f"{score:.1f}"

    if sev == 'critical' or score >= 9.0:
        html = f"""<div align="center">
            <font name="Helvetica-Bold" size="10.5" color="#991b1b"><b>{score_str}</b></font><br/>
            <font name="Helvetica-Bold" size="6.5" color="#991b1b"><b>CRITICAL</b></font>
        </div>"""
    elif sev == 'high' or score >= 7.0:
        html = f"""<div align="center">
            <font name="Helvetica-Bold" size="9.5" color="#c2410c"><b>{score_str}</b></font><br/>
            <font name="Helvetica-Bold" size="6.5" color="#c2410c"><b>HIGH</b></font>
        </div>"""
    elif sev == 'medium' or score >= 4.0:
        html = f"""<div align="center">
            <font name="Helvetica-Bold" size="8" color="#854d0e"><b>{score_str}</b></font><br/>
            <font name="Helvetica-Bold" size="6" color="#854d0e">MEDIUM</font>
        </div>"""
    elif sev == 'low':
        html = f"""<div align="center">
            <font name="Helvetica" size="7.5" color="#0369a1">{score_str}</font><br/>
            <font name="Helvetica" size="6" color="#0369a1">LOW</font>
        </div>"""
    else:
        html = f"""<div align="center">
            <font name="Helvetica" size="7" color="#475569">{score_str}</font><br/>
            <font name="Helvetica" size="5.5" color="#475569">INFO</font>
        </div>"""

    style = ParagraphStyle('CvssInner', fontName='Helvetica', fontSize=7, leading=8.5, alignment=1)
    return Paragraph(html, style)


def _resolve_rule_metadata(finding: dict) -> dict:
    """Enriches finding with database rule metadata if missing."""
    try:
        from database.db_handler import get_vulnerability_rule
        rule = get_vulnerability_rule(finding.get('vuln_type', ''))
    except Exception:
        rule = None

    ref_id = finding.get('ref_id') or finding.get('cve_id')
    if not ref_id and rule:
        ref_id = rule.get('ref_id') or rule.get('cve_id')
    if not ref_id and finding.get('cves'):
        ref_id = finding['cves'][0]

    cvss_score = finding.get('cvss_score')
    if cvss_score is None and rule:
        cvss_score = rule.get('cvss_score')
    if cvss_score is None:
        sev = finding.get('severity', 'info').lower()
        cvss_score = SEV_CVSS_DEFAULTS.get(sev, 3.0)

    remediation = finding.get('remediation_steps') or finding.get('remediation')
    if not remediation and rule:
        remediation = rule.get('remediation_steps')
    if not remediation:
        remediation = 'Review target server configuration or update vulnerable library component.'

    reference_link = finding.get('reference_link')
    if not reference_link and rule:
        reference_link = rule.get('reference_link')
    if not reference_link and ref_id and ref_id.startswith('CVE-'):
        reference_link = f"https://nvd.nist.gov/vuln/detail/{ref_id}"
    elif not reference_link and ref_id and ref_id.startswith('CWE-'):
        cwe_num = ref_id.replace('CWE-', '')
        reference_link = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"

    cve_id = ref_id if (ref_id and ref_id.startswith('CVE-')) else None
    return {
        'ref_id': ref_id or 'N/A (Policy)',
        'cve_id': cve_id,
        'cvss_score': float(cvss_score),
        'remediation': remediation,
        'reference_link': reference_link or 'N/A',
    }


def _build_section_banner(section_num: int, title: str, subtitle: str, count: int, accent_hex: str, styles: dict) -> Table:
    """Renders a distinguished chapter/section header banner for the audit report."""
    title_html = (
        f"<font name='Helvetica-Bold' size='9' color='#ffffff'>SECTION {section_num}: {title.upper()}</font><br/>"
        f"<font name='Helvetica' size='6.8' color='#94a3b8'>{subtitle}</font>"
    )
    count_html = (
        f"<div align='right'><font name='Helvetica-Bold' size='7.5' color='{accent_hex}'>"
        f"<b>{count} FINDING{'S' if count != 1 else ''}</b></font></div>"
    )

    p_title = Paragraph(title_html, styles['BannerTitle'])
    p_count = Paragraph(count_html, styles['BannerSub'])

    banner_table = Table([[p_title, p_count]], colWidths=[140 * mm, 44 * mm])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), DARK_NAVY),
        ('BOX', (0, 0), (-1, -1), 0.5, SLATE_BORDER),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    return banner_table


def _build_findings_table(findings: list, prefix: str, styles: dict) -> Table:
    """
    Renders a distinct audit table for a vulnerability section.
    Columns:
        1. '#'               — Finding identifier (e.g. HDR-01, JS-01)
        2. 'Vulnerability Type' — Finding title & observed evidence
        3. 'CVE ID'          — Assigned CVE with clickable hyperlink
        4. 'CVSS Score'      — Bold, hierarchical score with High/Critical distinction
        5. 'Remediation'     — Mandatory technical fix steps
        6. 'Reference Link'  — Clickable NVD or advisory link
    """
    table_rows = [
        [
            Paragraph("#", styles['ThCellCenter']),
            Paragraph("Vulnerability Type", styles['ThCell']),
            Paragraph("Reference / CVE", styles['ThCell']),
            Paragraph("CVSS Score", styles['ThCellCenter']),
            Paragraph("Remediation", styles['ThCell']),
            Paragraph("Reference Link", styles['ThCell']),
        ]
    ]

    t_styles = [
        ('BACKGROUND', (0, 0), (-1, 0), BG_HEADER),
        ('BOX', (0, 0), (-1, -1), 0.5, SLATE_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.35, colors.HexColor('#cbd5e1')),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (0, 0), (0, -1), 'CENTER'),
        ('ALIGN', (3, 0), (3, -1), 'CENTER'),
    ]

    for idx, finding in enumerate(findings, start=1):
        vuln_type = finding.get('vuln_type', finding.get('name', 'Security Misconfiguration'))
        severity = finding.get('severity', 'info').lower()
        evidence = finding.get('evidence', '')

        meta = _resolve_rule_metadata(finding)
        cvss_score = meta['cvss_score']
        ref_id = meta['ref_id']
        remediation = meta['remediation']
        ref_link = meta['reference_link']

        # Col 1: Index
        p_idx = Paragraph(f"{prefix}-{idx:02d}", styles['TdIdx'])

        # Col 2: Vulnerability Title & Evidence snippet
        evidence_clean = (evidence[:80] + '...') if len(evidence) > 80 else evidence
        ev_escaped = evidence_clean.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        vuln_html = f"<b>{vuln_type}</b>"
        if ev_escaped:
            vuln_html += f"<br/><font size='5.5' color='#64748b'>Obs: {ev_escaped}</font>"
        p_vuln = Paragraph(vuln_html, styles['TdVuln'])

        # Col 3: Reference / CVE ID
        cves_list = finding.get('cves', [])
        if ref_id.startswith('CWE-'):
            cwe_num = ref_id.replace('CWE-', '')
            cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
            ref_html = f"<font size='5.5' color='#64748b'>Reference:</font><br/><a href='{cwe_url}' color='#0f172a'><u><b>{ref_id}</b></u></a>"
        elif ref_id.startswith('CVE-'):
            cve_url = f"https://nvd.nist.gov/vuln/detail/{ref_id}"
            ref_html = f"<font size='5.5' color='#64748b'>CVE:</font><br/><a href='{cve_url}' color='#0f172a'><u><b>{ref_id}</b></u></a>"
            extra_cves = [c for c in cves_list if c != ref_id]
            if extra_cves:
                ref_html += f"<br/><font size='5.5' color='#64748b'>+{len(extra_cves)} more</font>"
        else:
            ref_html = f"<font color='#64748b'>{ref_id}</font>"
        p_cve = Paragraph(ref_html, styles['TdCve'])

        # Col 4: CVSS Score Module (Typographic hierarchy applied)
        p_cvss = _build_cvss_cell(cvss_score, severity)

        # Col 5: Exact Remediation Steps
        p_remed = Paragraph(remediation, styles['TdRemediation'])

        # Col 6: Reference Link (Clickable hyperlink)
        if ref_link and ref_link.startswith('http'):
            display_link = ref_link.replace('https://', '').replace('http://', '')
            display_link = (display_link[:26] + '...') if len(display_link) > 26 else display_link
            ref_html = f"<a href='{ref_link}' color='#0284c7'><u>{display_link}</u></a>"
        else:
            ref_html = "<font color='#94a3b8'>N/A</font>"
        p_link = Paragraph(ref_html, styles['TdLink'])

        table_rows.append([p_idx, p_vuln, p_cve, p_cvss, p_remed, p_link])

        row_idx = idx
        bg_tint = SEV_BG_TINTS.get(severity, BG_ROW_ALT) if idx % 2 == 1 else colors.white
        t_styles.append(('BACKGROUND', (0, row_idx), (-1, row_idx), bg_tint))

        # Visually distinct styling for Critical / High scores
        if severity == 'critical' or cvss_score >= 9.0:
            t_styles.append(('BACKGROUND', (3, row_idx), (3, row_idx), colors.HexColor('#fee2e2')))
        elif severity == 'high' or cvss_score >= 7.0:
            t_styles.append(('BACKGROUND', (3, row_idx), (3, row_idx), colors.HexColor('#ffedd5')))

    table = Table(table_rows, colWidths=COL_WIDTHS, repeatRows=1)
    table.setStyle(TableStyle(t_styles))
    return table


def _build_empty_table(message: str, styles: dict) -> Table:
    """Renders a verified compliant message box for empty findings."""
    empty_box = Table(
        [[Paragraph(f"<font color='#16a34a'><b>VERIFIED COMPLIANT:</b> {message}</font>", styles['MetaVal'])]],
        colWidths=[184 * mm]
    )
    empty_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f0fdf4')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#86efac')),
        ('PADDING', (0, 0), (-1, -1), 7),
    ]))
    return empty_box


def generate_audit_report(scan_data: dict, output_filename: str):
    """
    Compiles an A4 PDF vulnerability audit report with two separate chapters/sections:
      - Chapter 1: 'HTTP Header Misconfigurations'
      - Chapter 2: 'Client-Side JavaScript Vulnerabilities'

    Columns included in both tables:
        1. '#'               — Finding identifier
        2. 'Vulnerability Type' — Policy rule or library name with observed evidence
        3. 'CVE ID'          — Assigned identifier with clickable link
        4. 'CVSS Score'      — Bold, hierarchical score with High/Critical distinction
        5. 'Remediation'     — Exact technical fix steps
        6. 'Reference Link'  — Clickable NVD / advisory link
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_filename)), exist_ok=True)

    doc = SimpleDocTemplate(
        output_filename,
        pagesize=A4,
        leftMargin=13 * mm,
        rightMargin=13 * mm,
        topMargin=14 * mm,
        bottomMargin=15 * mm,
    )

    styles = _get_styles()
    story = []

    # -------------------------------------------------------------------------
    # 0. Extract Categorized Findings from scan_data
    # -------------------------------------------------------------------------
    headers_findings = (
        scan_data.get('headers') or
        scan_data.get('http_headers') or
        scan_data.get('headers_findings') or
        (scan_data.get('vulnerabilities', {}).get('headers') if isinstance(scan_data.get('vulnerabilities'), dict) else None)
    )

    js_findings = (
        scan_data.get('javascript') or
        scan_data.get('javascript_versions') or
        scan_data.get('js_findings') or
        (scan_data.get('vulnerabilities', {}).get('javascript') if isinstance(scan_data.get('vulnerabilities'), dict) else None)
    )

    # Fallback partition if scan_data provided a single flat list
    if headers_findings is None or js_findings is None:
        flat = scan_data.get('vulnerabilities') or scan_data.get('findings') or []
        if isinstance(flat, list):
            h_list = []
            j_list = []
            for f in flat:
                vtype = f.get('vuln_type', '').lower()
                if any(k in vtype for k in [
                    'header', 'x-powered-by', 'server', 'hsts', 'csp',
                    'content-security-policy', 'strict-transport-security',
                    'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'
                ]):
                    h_list.append(f)
                else:
                    j_list.append(f)
            if headers_findings is None:
                headers_findings = h_list
            if js_findings is None:
                js_findings = j_list

    headers_findings = headers_findings or []
    js_findings = js_findings or []
    total_exceptions = len(headers_findings) + len(js_findings)

    # -------------------------------------------------------------------------
    # 1. Utilitarian Header Banner
    # -------------------------------------------------------------------------
    header_data = [
        [
            Paragraph("WEBVULNSCANNER ENTERPRISE // IT SECURITY AUDIT REPORT", styles['BannerTitle']),
            Paragraph(
                f"AUDIT ID: #{scan_data.get('id', 'N/A')}<br/>"
                f"TIMESTAMP: {scan_data.get('date', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))} UTC",
                styles['BannerSub']
            ),
        ]
    ]
    header_table = Table(header_data, colWidths=[118 * mm, 66 * mm])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), DARK_NAVY),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 9),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 4 * mm))

    # -------------------------------------------------------------------------
    # 2. Target Telemetry & Evaluation Summary
    # -------------------------------------------------------------------------
    target_url = scan_data.get('url', 'N/A')
    target_ip = scan_data.get('target_ip', 'N/A')
    risk_level = scan_data.get('risk_level', 'info').upper()

    risk_badge_color = '#dc2626' if risk_level == 'CRITICAL' else ('#ea580c' if risk_level == 'HIGH' else ('#ca8a04' if risk_level == 'MEDIUM' else '#0284c7'))

    status_str = str(scan_data.get('scan_status', 'COMPLETE')).upper()
    coverage = scan_data.get('scan_coverage', {})
    waf_info = f" [WAF Blocked: {coverage.get('waf_reason')[:28]}...]" if coverage.get('is_waf_blocked') else " [All Checks Executed]"

    meta_rows = [
        [
            Paragraph("Target Endpoint", styles['MetaKey']),
            Paragraph(f"<b>{target_url}</b>", styles['MetaValCode']),
            Paragraph("Risk Posture", styles['MetaKey']),
            Paragraph(f"<font color='{risk_badge_color}'><b>{risk_level} RISK</b></font>", styles['MetaValCode']),
        ],
        [
            Paragraph("Resolved IPv4", styles['MetaKey']),
            Paragraph(f"{target_ip}", styles['MetaValCode']),
            Paragraph("Policy Violations", styles['MetaKey']),
            Paragraph(f"<b>{total_exceptions} Detected Exceptions</b> ({len(headers_findings)} Headers, {len(js_findings)} JS)", styles['MetaValCode']),
        ],
        [
            Paragraph("Scan Coverage", styles['MetaKey']),
            Paragraph(f"<b>{status_str}</b><font color='#64748b'>{waf_info}</font>", styles['MetaVal']),
            Paragraph("Classification", styles['MetaKey']),
            Paragraph("Internal Technical IT Audit", styles['MetaVal']),
        ],
    ]

    meta_table = Table(meta_rows, colWidths=[32 * mm, 60 * mm, 32 * mm, 60 * mm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, SLATE_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 4.5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 5 * mm))

    # -------------------------------------------------------------------------
    # 3. Chapter / Section 1: HTTP Header Misconfigurations
    # -------------------------------------------------------------------------
    sec1_banner = _build_section_banner(
        section_num=1,
        title="HTTP Header Misconfigurations",
        subtitle="Evaluation of HTTP response headers, transport security, and information disclosure policies.",
        count=len(headers_findings),
        accent_hex="#38bdf8",
        styles=styles
    )
    story.append(sec1_banner)
    story.append(Spacer(1, 2 * mm))

    if headers_findings:
        story.append(_build_findings_table(headers_findings, prefix="HDR", styles=styles))
    else:
        story.append(_build_empty_table(
            "Zero HTTP header misconfigurations detected. All evaluated response headers conform to baseline security policies.",
            styles=styles
        ))

    story.append(Spacer(1, 6 * mm))

    # -------------------------------------------------------------------------
    # 4. Chapter / Section 2: Client-Side JavaScript Vulnerabilities
    # -------------------------------------------------------------------------
    sec2_banner = _build_section_banner(
        section_num=2,
        title="Client-Side JavaScript Vulnerabilities",
        subtitle="Software Composition Analysis (Retire.js), client library CVEs, DOM-based sinks, and credential patterns.",
        count=len(js_findings),
        accent_hex="#facc15",
        styles=styles
    )
    story.append(sec2_banner)
    story.append(Spacer(1, 2 * mm))

    if js_findings:
        story.append(_build_findings_table(js_findings, prefix="JS", styles=styles))
    else:
        story.append(_build_empty_table(
            "Zero client-side JavaScript vulnerabilities detected. No outdated libraries, DOM XSS sinks, or exposed credentials identified.",
            styles=styles
        ))

    # -------------------------------------------------------------------------
    # 5. Build Document via Two-Pass NumberedCanvas
    # -------------------------------------------------------------------------
    doc.build(story, canvasmaker=NumberedCanvas)
