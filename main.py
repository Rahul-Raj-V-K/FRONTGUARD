import sys
import os
import json
import logging
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()  # Loads FLASK_SECRET_KEY and FLASK_DEBUG from .env

from flask import Flask, render_template, request, redirect, url_for, flash, make_response, abort
from database.db_handler import init_db, insert_scan_record, get_scan_history, get_vulnerability_rule, clear_scan_history
from scanner.extractor import extract_target_data
from scanner.matcher import run_matcher
from scanner.retirejs import scan_retirejs
from reporting.pdf_builder import generate_audit_report
from scanner.reliability import BoundedTTLCache, ScanBudget, GLOBAL_SCAN_BUDGET, ScanStatus

logger = logging.getLogger(__name__)

app = Flask(__name__)
# Secret key is loaded from .env if present, or automatically generated using os.urandom
# to ensure zero-configuration execution for evaluators and standalone zip deployments.
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32).hex()

REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'reports')

# Thread-safe bounded TTL in-memory findings cache (max 100 entries, 2 hour TTL)
_findings_cache = BoundedTTLCache(maxsize=100, ttl=7200.0)


@app.before_request
def setup_db():
    if not hasattr(app, '_db_ready'):
        init_db()
        os.makedirs(REPORTS_DIR, exist_ok=True)
        app._db_ready = True


# ---------------------------------------------------------------------------
# Core scan orchestration
# ---------------------------------------------------------------------------

def dummy_scan(url: str) -> dict:
    """
    Orchestrates the full scan pipeline and persists results.

    Steps:
        1. extract_target_data()   — fetch headers, scripts, public IP, comments, forms
        2. run_matcher()           — security headers, Retire.js SCA, secrets, XSS sinks
        3. scan_retirejs()         — complete component inventory & CVE analysis
        4. generate_audit_report() — write PDF audit report to /reports
        5. insert_scan_record()    — log scan event and target public IP to scanner.db
        6. Return finalized data dict for the Flask frontend
    """
    # Step 1 — Extraction & IP Resolution
    target_data = extract_target_data(url)
    headers = target_data.get('headers', {})
    scripts = target_data.get('script_srcs', [])
    inline_scripts = target_data.get('inline_scripts', [])
    comments = target_data.get('comments', [])
    forms = target_data.get('forms', [])
    target_ip = target_data.get('target_ip', 'N/A')
    # Findings from comparing HTTP-redirect headers vs final HTTPS headers
    header_diff_findings = target_data.get('header_diff_findings', [])
    scan_coverage = target_data.get('scan_coverage', {})
    is_waf_blocked = target_data.get('is_waf_blocked', False)
    scan_status = ScanStatus.BLOCKED if is_waf_blocked else ScanStatus.COMPLETE

    # Enforce SSRF protection
    if target_data.get('is_ssrf_blocked'):
        return {
            'status':  'failed',
            'error':   f'Target blocked for SSRF prevention (Resolved IP: {target_ip} in private or loopback range).',
            'url':     url,
            'target_ip': target_ip,
        }

    if not headers:
        return {
            'status':  'failed',
            'error':   f'Target endpoint unreachable (Resolved IP: {target_ip}) — verify network ingress, DNS propagation, and remote service availability.',
            'url':     url,
            'target_ip': target_ip,
        }

    # Step 2 — Matching & Retire.js Software Composition Analysis
    vulnerabilities = run_matcher(
        headers=headers,
        scripts=scripts,
        inline_scripts=inline_scripts,
        target_url=url,
        comments=comments,
        forms=forms
    )

    # Prepend HTTP/HTTPS header comparison findings (already structured correctly)
    vulnerabilities = header_diff_findings + vulnerabilities

    # Enrich vulnerabilities with database rules (Reference/CVE, CVSS, remediation, reference)
    sev_cvss = {'critical': 9.8, 'high': 7.5, 'medium': 5.3, 'low': 3.7, 'info': 1.0}
    for v in vulnerabilities:
        rule = get_vulnerability_rule(v.get('vuln_type', ''))
        if rule:
            ref = rule.get('ref_id')
            cve = rule.get('cve_id')
            if not v.get('ref_id'):
                v['ref_id'] = ref or cve
            if not v.get('cve_id') and cve and str(cve).startswith('CVE-'):
                v['cve_id'] = cve
            if not v.get('cvss_score'):
                v['cvss_score'] = rule.get('cvss_score')
            if not v.get('remediation_steps'):
                v['remediation_steps'] = rule.get('remediation_steps')
            if not v.get('reference_link'):
                v['reference_link'] = rule.get('reference_link')
        if not v.get('ref_id') and v.get('cves'):
            v['ref_id'] = v['cves'][0]
        if not v.get('cve_id') and v.get('cves') and str(v['cves'][0]).startswith('CVE-'):
            v['cve_id'] = v['cves'][0]
        if not v.get('remediation_steps'):
            v['remediation_steps'] = v.get('remediation', 'Review server configuration or patch vulnerable package dependency.')
        if not v.get('cvss_score'):
            v['cvss_score'] = sev_cvss.get(v.get('severity', 'info').lower(), 3.0)

    # Comprehensive component inventory (both vulnerable and safe libraries)
    _, components_inventory = scan_retirejs(scripts, inline_scripts, base_url=url)

    # Derive risk level from highest finding severity
    sev_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    worst = max((sev_rank.get(v['severity'], 0) for v in vulnerabilities), default=0)
    risk_level = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'}[worst]

    scan_date = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    header_vulns = []
    js_vulns = []
    for v in vulnerabilities:
        vtype = v.get('vuln_type', '').lower()
        if any(k in vtype for k in [
            'header', 'x-powered-by', 'server', 'hsts', 'csp',
            'content-security-policy', 'strict-transport-security',
            'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'
        ]):
            header_vulns.append(v)
        else:
            js_vulns.append(v)

    scan_data = {
        'url':                 url,
        'target_ip':           target_ip,
        'date':                scan_date,
        'risk_level':          risk_level,
        'headers':             header_vulns,
        'javascript':          js_vulns,
        'http_headers':        header_vulns,
        'javascript_versions': js_vulns,
        'vulnerabilities':     vulnerabilities,
        'components':          components_inventory,
        'scan_status':         scan_status,
        'scan_coverage':       scan_coverage,
        'is_waf_blocked':      is_waf_blocked,
    }

    # Step 3 — PDF generation (save directly to /reports)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    domain_slug = url.replace('https://', '').replace('http://', '').split('/')[0].replace(':', '_')
    pdf_filename = f'scan_{domain_slug}_{timestamp}.pdf'
    final_pdf_path = os.path.join(REPORTS_DIR, pdf_filename)
    generate_audit_report(scan_data, final_pdf_path)

    # Step 4 — Persist scan record with resolved target IP
    row_id = insert_scan_record(
        target_url=url,
        findings_count=len(vulnerabilities),
        risk_level=risk_level,
        pdf_path=final_pdf_path,
        target_ip=target_ip,
    )

    # Persist findings & components to JSON in reports directory
    findings_json_path = os.path.join(REPORTS_DIR, f'scan_{row_id}_findings.json')
    cache_payload = {
        'findings': vulnerabilities,
        'components': components_inventory,
        'target_ip': target_ip,
        'scan_status': scan_status,
        'scan_coverage': scan_coverage,
    }
    try:
        with open(findings_json_path, 'w', encoding='utf-8') as f:
            json.dump(cache_payload, f, indent=2)
    except Exception as exc:
        logger.warning("Failed to write findings JSON %s: %s", findings_json_path, exc)

    # Cache findings and components in memory
    _findings_cache.set(str(row_id), cache_payload)

    # Step 5 — Return finalized dict to the Flask frontend
    return {
        'status':       scan_status,
        'scan_id':      row_id,
        'url':          url,
        'target_ip':    target_ip,
        'date':         scan_date,
        'risk_level':   risk_level,
        'findings':     vulnerabilities,
        'components':   components_inventory,
        'total':        len(vulnerabilities),
        'pdf_path':     final_pdf_path,
        'scan_coverage': scan_coverage,
    }


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route('/', methods=['GET'])
def index():
    scans = get_scan_history()
    return render_template('index.html', scans=scans)


@app.route('/clear-history', methods=['POST'])
@app.route('/clear_history', methods=['POST'])
def clear_history():
    deleted_count = clear_scan_history()
    flash(f'Audit Ledger successfully cleared ({deleted_count} record{"s" if deleted_count != 1 else ""} removed).', 'info')
    return redirect(url_for('index'))


@app.route('/scan', methods=['POST'])
def trigger_scan():
    target_url = request.form.get('target_url', '').strip()
    if not target_url:
        flash('Target endpoint parameter required. Specify a valid FQDN or IP address to initiate an audit.', 'error')
        return redirect(url_for('index'))

    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    result = dummy_scan(target_url)

    if result['status'] == 'failed':
        flash(result.get('error', 'Vulnerability audit aborted due to an unhandled target error.'), 'error')
        return redirect(url_for('index'))

    return redirect(url_for('scan_result', scan_id=result['scan_id']))


@app.route('/result/<int:scan_id>')
def scan_result(scan_id):
    scans = get_scan_history()
    scan = next((s for s in scans if s['id'] == scan_id), None)
    if not scan:
        abort(404)

    hit, cached_data = _findings_cache.get(str(scan_id))
    if not hit or cached_data is None:
        findings_json_path = os.path.join(REPORTS_DIR, f'scan_{scan_id}_findings.json')
        if os.path.isfile(findings_json_path):
            try:
                with open(findings_json_path, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                    _findings_cache.set(str(scan_id), cached_data)
            except Exception:
                cached_data = []
        else:
            cached_data = []

    if isinstance(cached_data, dict):
        findings = cached_data.get('findings', [])
        components = cached_data.get('components', [])
    else:
        findings = cached_data or []
        components = [
            {
                'name': f.get('component', f.get('vuln_type', 'Unknown')),
                'version': f.get('version', 'N/A'),
                'source': f.get('evidence', ''),
                'status': 'VULNERABLE',
                'severity': f.get('severity', 'high'),
                'cves': f.get('cves', []),
                'remediation': f.get('remediation', '')
            }
            for f in findings
            if 'Retire.js' in f.get('vuln_type', '') or 'Outdated Component' in f.get('vuln_type', '')
        ]

    # Ensure all findings have rule details (ref_id, cve_id, cvss_score, remediation_steps)
    sev_cvss = {'critical': 9.8, 'high': 7.5, 'medium': 5.3, 'low': 3.7, 'info': 1.0}
    for f in findings:
        rule = get_vulnerability_rule(f.get('vuln_type', ''))
        if rule:
            ref = rule.get('ref_id')
            cve = rule.get('cve_id')
            if not f.get('ref_id'):
                f['ref_id'] = ref or cve
            if not f.get('cve_id') and cve and str(cve).startswith('CVE-'):
                f['cve_id'] = cve
            if not f.get('cvss_score'):
                f['cvss_score'] = rule.get('cvss_score')
            if not f.get('remediation_steps'):
                f['remediation_steps'] = rule.get('remediation_steps')
            if not f.get('reference_link'):
                f['reference_link'] = rule.get('reference_link')
        if not f.get('ref_id') and f.get('cves'):
            f['ref_id'] = f['cves'][0]
        if not f.get('cve_id') and f.get('cves') and str(f['cves'][0]).startswith('CVE-'):
            f['cve_id'] = f['cves'][0]
        if not f.get('remediation_steps'):
            f['remediation_steps'] = f.get('remediation', 'Harden application configuration or update vulnerable dependencies.')
        if not f.get('cvss_score'):
            f['cvss_score'] = sev_cvss.get(f.get('severity', 'info').lower(), 3.0)

    header_vulns = []
    js_vulns = []
    for f in findings:
        vtype = f.get('vuln_type', '').lower()
        if any(k in vtype for k in [
            'header', 'x-powered-by', 'server', 'hsts', 'csp',
            'content-security-policy', 'strict-transport-security',
            'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'
        ]):
            header_vulns.append(f)
        else:
            js_vulns.append(f)

    vulnerabilities = {
        'headers': header_vulns,
        'javascript': js_vulns
    }

    return render_template(
        'result.html',
        scan=scan,
        vulnerabilities=vulnerabilities,
        findings=findings,
        components=components
    )


@app.route('/report/<int:scan_id>/pdf')
def download_pdf(scan_id):
    scans = get_scan_history()
    scan = next((s for s in scans if s['id'] == scan_id), None)
    if not scan:
        abort(404)

    hit, cached_data = _findings_cache.get(str(scan_id))
    if not hit or cached_data is None:
        findings_json_path = os.path.join(REPORTS_DIR, f'scan_{scan_id}_findings.json')
        if os.path.isfile(findings_json_path):
            try:
                with open(findings_json_path, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                    _findings_cache.set(str(scan_id), cached_data)
            except Exception:
                cached_data = []
        else:
            cached_data = []

    if isinstance(cached_data, dict):
        findings = cached_data.get('findings', [])
    else:
        findings = cached_data or []

    sev_cvss = {'critical': 9.8, 'high': 7.5, 'medium': 5.3, 'low': 3.7, 'info': 1.0}
    for f in findings:
        rule = get_vulnerability_rule(f.get('vuln_type', ''))
        if rule:
            ref = rule.get('ref_id')
            cve = rule.get('cve_id')
            if not f.get('ref_id'):
                f['ref_id'] = ref or cve
            if not f.get('cve_id') and cve and str(cve).startswith('CVE-'):
                f['cve_id'] = cve
            if not f.get('cvss_score'):
                f['cvss_score'] = rule.get('cvss_score')
            if not f.get('remediation_steps'):
                f['remediation_steps'] = rule.get('remediation_steps')
            if not f.get('reference_link'):
                f['reference_link'] = rule.get('reference_link')
        if not f.get('ref_id') and f.get('cves'):
            f['ref_id'] = f['cves'][0]
        if not f.get('cve_id') and f.get('cves') and str(f['cves'][0]).startswith('CVE-'):
            f['cve_id'] = f['cves'][0]
        if not f.get('remediation_steps'):
            f['remediation_steps'] = f.get('remediation', 'Harden application configuration or update vulnerable dependencies.')
        if not f.get('cvss_score'):
            f['cvss_score'] = sev_cvss.get(f.get('severity', 'info').lower(), 3.0)

    header_vulns = []
    js_vulns = []
    for f in findings:
        vtype = f.get('vuln_type', '').lower()
        if any(k in vtype for k in [
            'header', 'x-powered-by', 'server', 'hsts', 'csp',
            'content-security-policy', 'strict-transport-security',
            'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'
        ]):
            header_vulns.append(f)
        else:
            js_vulns.append(f)

    scan_data = {
        'id':                  scan['id'],
        'url':                 scan['target_url'],
        'target_ip':           scan.get('target_ip', 'N/A'),
        'date':                scan['scan_date'],
        'risk_level':          scan['risk_level'],
        'headers':             header_vulns,
        'javascript':          js_vulns,
        'http_headers':        header_vulns,
        'javascript_versions': js_vulns,
        'vulnerabilities':     findings,
    }
    report_pdf_path = os.path.join(REPORTS_DIR, f'scan_{scan_id}_audit_report.pdf')
    generate_audit_report(scan_data, report_pdf_path)

    with open(report_pdf_path, 'rb') as f:
        pdf_bytes = f.read()

    resp = make_response(pdf_bytes)
    resp.headers['Content-Type'] = 'application/pdf'
    resp.headers['Content-Disposition'] = f'attachment; filename="scan_{scan_id}_audit_report.pdf"'
    return resp


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, port=5000)
