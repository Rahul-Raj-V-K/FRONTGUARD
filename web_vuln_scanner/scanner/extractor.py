import socket
import urllib.parse
import requests
from bs4 import BeautifulSoup, Comment

TIMEOUT = 6
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
    It applies the same URL validation, timeout (TIMEOUT = 6), and error handling
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

        # Force scheme to http:// to inspect redirect response headers
        http_url = parsed._replace(scheme='http').geturl()
        if not http_url.startswith(('http://', 'https://')):
            return {}

        resp = requests.get(
            http_url,
            timeout=TIMEOUT,
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

    # Probe plain-HTTP side (non-redirecting) for header comparison.
    # Best-effort: failures produce an empty dict, not an error.
    http_headers = _probe_http_headers(url)

    try:
        resp = requests.get(
            url,
            timeout=TIMEOUT,
            headers={'User-Agent': USER_AGENT},
            allow_redirects=True,
            verify=False
        )
    except (requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.TooManyRedirects,
            requests.exceptions.InvalidURL,
            requests.exceptions.MissingSchema,
            Exception):
        return TargetData({
            'headers': {},
            'http_headers': http_headers,
            'header_diff_findings': [],
            'script_srcs': [],
            'inline_scripts': [],
            'comments': [],
            'forms': [],
            'target_ip': target_ip,
            'html_text': '',
        })

    raw_headers = {k.lower(): v for k, v in resp.headers.items()}
    html_text = resp.text

    # Compare HTTP redirect headers vs final HTTPS headers
    header_diff_findings = _compare_http_https_headers(http_headers, raw_headers)

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
    })

