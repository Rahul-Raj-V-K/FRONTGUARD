import socket
import urllib.parse
import ipaddress
import requests
from bs4 import BeautifulSoup, Comment

from scanner.reliability import (
    detect_waf_or_block,
    retry_get,
    is_private_ip,
    ScanBudget,
    CoverageSummary,
    ScanStatus,
    CONNECT_TIMEOUT_TARGET,
    READ_TIMEOUT_TARGET,
)

TIMEOUT = 6
TARGET_TIMEOUT = (CONNECT_TIMEOUT_TARGET, READ_TIMEOUT_TARGET)
MAX_HTML_BYTES = 512 * 1024  # 512 KB hard streaming cap
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/124.0.0.0 Safari/537.36'
)

# Security headers whose behaviour differs meaningfully between HTTP and HTTPS
# responses; we surface differences as informational findings.
_SECURITY_HEADERS_TO_COMPARE = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'cross-origin-embedder-policy',
]


class TargetData(dict):
    """
    Dictionary container for extracted target data.
    Provides backwards-compatible 2-element tuple unpacking:
        headers, script_srcs = extract_target_data(url)
    while also supporting full dictionary key access:
        data['target_ip'], data['inline_scripts'], etc.
    """
    def __iter__(self):
        return iter([self.get('headers', {}), self.get('script_srcs', [])])


def resolve_target_ip(url: str) -> str:
    """
    Resolves ALL public IPv4 addresses for the target hostname using
    gethostbyname_ex(), which fetches every A-record in one DNS query.

    Results are sorted alphabetically so the output is deterministic even
    when the DNS server uses round-robin and returns records in different
    orders on successive queries.

    Returns a comma-separated string of IPs, or 'N/A' / 'Resolution Failed'.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            clean = url.replace('https://', '').replace('http://', '')
            hostname = clean.split('/')[0].split(':')[0]
        if not hostname:
            return 'N/A'

        # gethostbyname_ex returns (name, aliases, [ip1, ip2, ...])
        _, _, addresses = socket.gethostbyname_ex(hostname)

        if not addresses:
            return 'N/A'

        # Sort so ordering is stable across round-robin DNS rotations
        unique_sorted = sorted(set(addresses))
        return ', '.join(unique_sorted)

    except socket.gaierror:
        return 'Resolution Failed'
    except Exception:
        return 'N/A'



def _probe_http_headers(url: str) -> dict:
    """
    WHY: Security headers must be checked on the *final* HTTPS response, but some
    misconfigurations only appear if you compare the HTTP and HTTPS sides:
      - HSTS set on the HTTP redirect (wrong — HSTS is meaningless over HTTP).
      - Headers present on HTTP but absent from the canonical HTTPS URL.

    This function makes a single non-redirecting GET to the plain-HTTP version of
    the URL so we can capture those redirect-response headers separately.
    It applies the same URL validation, timeout, SSRF protection, and error handling
    as the main extraction pipeline.
    Returns a dict of lowercase header name → value (empty dict on failure).
    """
    if not url or not isinstance(url, str):
        return {}

    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc and not parsed.path:
            return {}
        # Ensure host is present
        hostname = parsed.hostname or parsed.netloc.split(':')[0]
        if not hostname:
            return {}

        # Prevent SSRF on internal/loopback addresses
        if is_private_ip(hostname):
            return {}

        # Force scheme to http:// to inspect redirect response headers
        http_url = parsed._replace(scheme='http').geturl()
        if not http_url.startswith(('http://', 'https://')):
            return {}

        resp = requests.get(
            http_url,
            timeout=TARGET_TIMEOUT,
            headers={'User-Agent': USER_AGENT},
            allow_redirects=False,   # capture the redirect response headers directly
            verify=False,
        )
        return {k.lower(): v for k, v in resp.headers.items()}
    except (requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.TooManyRedirects,
            requests.exceptions.InvalidURL,
            requests.exceptions.MissingSchema,
            ValueError,
            Exception):
        return {}


def _compare_http_https_headers(http_headers: dict, https_headers: dict) -> list[dict]:
    """
    Compares security headers between the HTTP redirect response and the final
    HTTPS response.  Emits informational findings for notable differences so the
    caller can surface them without affecting severity scoring.
    """
    findings = []

    # HSTS on the HTTP response is a misconfiguration — browsers ignore it there.
    if 'strict-transport-security' in http_headers and 'strict-transport-security' not in https_headers:
        findings.append({
            'vuln_type': 'HSTS Header Misconfiguration: Present on HTTP, Missing on HTTPS',
            'severity': 'medium',
            'description': (
                'Strict-Transport-Security is set on the plain-HTTP response but NOT on the '
                'final HTTPS response. Browsers only honour HSTS from HTTPS responses — '
                'the HTTP-side header is silently ignored, giving a false sense of security.'
            ),
            'evidence': f"HTTP response HSTS: {http_headers['strict-transport-security']}\nHTTPS response HSTS: (absent)",
            'attack_prevented': 'SSL stripping / downgrade attack',
            'recommended_value': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
        })

    # Check headers that appear on HTTP but not HTTPS (or vice-versa)
    for hdr in _SECURITY_HEADERS_TO_COMPARE:
        in_http = hdr in http_headers
        in_https = hdr in https_headers
        if in_http and not in_https:
            findings.append({
                'vuln_type': f'Header Present on HTTP Only: {hdr}',
                'severity': 'info',
                'description': (
                    f"'{hdr}' is returned by the HTTP redirect response but NOT by the "
                    f"final HTTPS response. The protection is effectively absent for HTTPS visitors."
                ),
                'evidence': f"HTTP value: {http_headers[hdr]}\nHTTPS value: (absent)",
                'attack_prevented': 'Depends on header; see individual header findings.',
                'recommended_value': 'Set the header on the HTTPS origin response.',
                'reference': 'https://owasp.org/www-project-secure-headers/',
            })

    return findings



def extract_target_data(url: str) -> TargetData:
    """
    Fetches `url` and extracts:
        - raw_headers:          dict of HTTPS response headers (lowercase keys)
        - http_headers:         dict of HTTP redirect response headers (lowercase keys)
        - header_diff_findings: list of info findings from HTTP vs HTTPS header comparison
        - script_srcs:          list of external <script src="..."> URLs
        - inline_scripts:       list of inline <script>...</script> code contents
        - comments:             list of HTML comments
        - forms:                list of form dictionaries
        - target_ip:            resolved public IP address of the website
        - html_text:            raw HTML response string

    Returns a TargetData object (supports both dict access and tuple unpacking).
    """
    target_ip = resolve_target_ip(url)

    # 1. SSRF & Private IP Protection
    if target_ip and target_ip not in ('N/A', 'Resolution Failed'):
        ips = [ip.strip() for ip in target_ip.split(',')]
        if any(is_private_ip(ip) for ip in ips):
            return TargetData({
                'headers': {},
                'http_headers': {},
                'header_diff_findings': [{
                    'vuln_type': 'SSRF Protection: Access Blocked',
                    'severity': 'high',
                    'description': f'Target hostname resolved to a private or loopback IP address ({target_ip}). Automated scanning blocked to prevent Server-Side Request Forgery (SSRF).',
                    'evidence': f'Resolved private IP: {target_ip}',
                    'attack_prevented': 'Server-Side Request Forgery (SSRF) against internal network infrastructure',
                    'recommended_value': 'Configure scanner target with a public, routable FQDN or external IP.',
                    'reference': 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
                    'ref_id': 'CWE-918',
                    'cvss_score': 8.6,
                }],
                'script_srcs': [],
                'inline_scripts': [],
                'comments': [],
                'forms': [],
                'target_ip': target_ip,
                'html_text': '',
                'is_ssrf_blocked': True,
                'scan_coverage': {
                    'scan_status': ScanStatus.BLOCKED,
                    'checks_ran': ['dns_resolution'],
                    'checks_skipped': [{'check': 'all', 'reason': 'Target IP in private network range (SSRF prevention)'}],
                    'is_waf_blocked': False,
                    'waf_reason': '',
                }
            })

    # Probe plain-HTTP side (non-redirecting) for header comparison.
    http_headers = _probe_http_headers(url)

    # 2. TLS Validation by Default with Fallback
    tls_findings = []
    is_unverified_tls = False
    resp = None

    try:
        # First attempt: enforce certificate verification
        resp = requests.get(
            url,
            timeout=TARGET_TIMEOUT,
            headers={'User-Agent': USER_AGENT},
            allow_redirects=True,
            verify=True,
            stream=True
        )
    except requests.exceptions.SSLError as ssl_err:
        is_unverified_tls = True
        err_msg = str(ssl_err)
        tls_findings.append({
            'vuln_type': 'TLS Certificate Validation Failed',
            'severity': 'high',
            'description': f'TLS certificate verification failed: {err_msg[:160]}. Target is vulnerable to Man-in-the-Middle (MitM) attacks.',
            'evidence': f'SSLError: {err_msg[:200]}\nRetrying scan with unverified TLS (findings labeled accordingly).',
            'attack_prevented': 'Man-in-the-Middle (MitM) interception and credential sniffing',
            'recommended_value': 'Deploy a valid, trusted TLS certificate from a recognized public Certificate Authority.',
            'reference': 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html',
            'ref_id': 'CWE-295',
            'cvss_score': 7.4,
        })
        # Retry with verify=False so scanner can evaluate headers
        try:
            resp = requests.get(
                url,
                timeout=TARGET_TIMEOUT,
                headers={'User-Agent': USER_AGENT},
                allow_redirects=True,
                verify=False,
                stream=True
            )
        except Exception:
            resp = None
    except (requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.TooManyRedirects,
            requests.exceptions.InvalidURL,
            requests.exceptions.MissingSchema,
            Exception):
        resp = None

    if resp is None:
        return TargetData({
            'headers': {},
            'http_headers': http_headers,
            'header_diff_findings': tls_findings,
            'script_srcs': [],
            'inline_scripts': [],
            'comments': [],
            'forms': [],
            'target_ip': target_ip,
            'html_text': '',
            'scan_coverage': {
                'scan_status': ScanStatus.FAILED,
                'checks_ran': ['dns_resolution'],
                'checks_skipped': [{'check': 'http_fetch', 'reason': 'Connection failed or timed out'}],
                'is_waf_blocked': False,
                'waf_reason': '',
            }
        })

    raw_headers = {k.lower(): v for k, v in resp.headers.items()}

    # 3. Stream HTML with hard byte cap (512 KB)
    html_chunks = []
    total_len = 0
    html_truncated = False
    try:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                html_chunks.append(chunk)
                total_len += len(chunk)
                if total_len >= MAX_HTML_BYTES:
                    html_truncated = True
                    break
        raw_bytes = b''.join(html_chunks)
        html_text = raw_bytes.decode('utf-8', errors='ignore')
    except Exception:
        html_text = getattr(resp, 'text', '')

    # 4. Compare HTTP redirect headers vs final HTTPS headers
    header_diff_findings = tls_findings + _compare_http_https_headers(http_headers, raw_headers)

    # 5. WAF & Challenge Page Detection
    is_waf_blocked, waf_reason = detect_waf_or_block(resp)
    if is_waf_blocked:
        header_diff_findings.append({
            'vuln_type': 'Target Access Blocked or WAF Challenge Detected',
            'severity': 'info',
            'description': f'The target returned a WAF challenge or block response ({waf_reason}). Observed response headers and HTML body do not represent origin application code.',
            'evidence': f'WAF/Block Diagnostic: {waf_reason}\nHTTP Status: {resp.status_code}',
            'attack_prevented': 'N/A (Automated Diagnostic)',
            'recommended_value': 'Whitelist scanner IP or authenticate past WAF challenge for comprehensive origin analysis.',
            'reference': 'https://owasp.org/www-community/attacks/Web_Application_Firewall',
            'ref_id': 'WAF-CHALLENGE',
            'cvss_score': 0.0,
        })

    soup = BeautifulSoup(html_text, 'html.parser')

    # External scripts
    script_srcs = [
        tag['src'].strip()
        for tag in soup.find_all('script')
        if tag.get('src') and tag['src'].strip()
    ]

    # Inline scripts
    inline_scripts = [
        tag.get_text()
        for tag in soup.find_all('script')
        if not tag.get('src') and tag.get_text()
    ]

    # HTML comments
    comments = [
        str(c).strip()
        for c in soup.find_all(string=lambda text: isinstance(text, Comment))
        if str(c).strip()
    ]

    # HTML forms
    forms = []
    for form in soup.find_all('form'):
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            inputs.append({
                'name': inp.get('name', ''),
                'type': inp.get('type', 'text').lower(),
            })
        forms.append({
            'action': action,
            'method': method,
            'inputs': inputs
        })

    coverage = {
        'scan_status': ScanStatus.BLOCKED if is_waf_blocked else ScanStatus.COMPLETE,
        'checks_ran': ['dns_resolution', 'tls_verification', 'http_probe', 'html_extraction', 'script_extraction'],
        'checks_skipped': [{'check': 'origin_analysis', 'reason': f'WAF challenge: {waf_reason}'}] if is_waf_blocked else [],
        'is_waf_blocked': is_waf_blocked,
        'waf_reason': waf_reason,
    }

    return TargetData({
        'headers': raw_headers,
        'http_headers': http_headers,
        'header_diff_findings': header_diff_findings,
        'script_srcs': script_srcs,
        'inline_scripts': inline_scripts,
        'comments': comments,
        'forms': forms,
        'target_ip': target_ip,
        'html_text': html_text,
        'html_truncated': html_truncated,
        'is_unverified_tls': is_unverified_tls,
        'is_waf_blocked': is_waf_blocked,
        'waf_reason': waf_reason,
        'scan_coverage': coverage,
    })

