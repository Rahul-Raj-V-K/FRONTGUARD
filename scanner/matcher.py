import re
from scanner.retirejs import scan_retirejs, detect_components

# -----------------------------------------------------------------------
# PHASE 2 CHANGE SUMMARY
# -----------------------------------------------------------------------
# Previously every header check was a pure key-in-dict lookup (present = pass).
# That meant CSP: *, HSTS: max-age=0, X-Content-Type-Options: sniff all passed.
#
# Now every header is also value-validated:
#   - CSP  : parsed into directives; flagged for unsafe-inline/eval, wildcards,
#             data: sources, and missing critical directives.
#   - HSTS : max-age parsed and checked (>=31536000); includeSubDomains and
#             preload eligibility reported.
#   - X-Content-Type-Options : only 'nosniff' is valid.
#   - X-Frame-Options : only DENY or SAMEORIGIN are valid.
#   - Referrer-Policy : 'unsafe-url' is flagged as worse-than-absent.
#   - frame-ancestors in CSP is now treated as equivalent to X-Frame-Options.
#   - CSP-Report-Only is flagged as "present but not enforced".
#   - COOP, CORP, COEP are new checks.
#   - Deprecated headers (X-XSS-Protection, Expect-CT) reported as info.
#   - Server header only flagged when it discloses a version number.
#   - Duplicate / conflicting header detection added.
#
# Each finding now carries: severity, attack_prevented, recommended_value, reference.
# -----------------------------------------------------------------------


# -----------------------------------------------------------------------
# Dangerous informational headers
# -----------------------------------------------------------------------
DANGEROUS_HEADERS = [
    # X-Powered-By: always flag its presence (leaks framework name + version)
    ('x-powered-by', 'medium',
     'X-Powered-By discloses the backend framework and version to attackers.',
     'Fingerprinting / targeted exploitation',
     'Remove this header entirely in your framework or reverse-proxy config.',
     'https://owasp.org/www-project-secure-headers/'),
]

# -----------------------------------------------------------------------
# Deprecated headers — report as 'info', not a missing-header finding
# -----------------------------------------------------------------------
DEPRECATED_HEADERS = [
    ('x-xss-protection',
     'X-XSS-Protection is deprecated in all modern browsers (removed in Chrome 78+). '
     'Certain values (e.g. mode=block) can introduce new vulnerabilities. '
     'Remove it and rely on a strong Content-Security-Policy instead.',
     'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'),
    ('expect-ct',
     'Expect-CT is deprecated since Chrome 100 (April 2022) and is no longer processed. '
     'Certificate Transparency is now enforced directly by browsers. Remove this header.',
     'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT'),
]

# -----------------------------------------------------------------------
# JS / inline secret patterns
# -----------------------------------------------------------------------
SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,})["\']'),
     'Exposed API Key', 'critical'),
    (re.compile(r'(?i)(secret|password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{6,})["\']'),
     'Hardcoded Secret / Password', 'critical'),
    (re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{16,})["\']'),
     'AWS Credential Exposure', 'critical'),
    (re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}=*'),
     'Exposed Bearer Token', 'high'),
    (re.compile(r'(?i)private[_-]?key\s*[:=]\s*["\']([^\s"\']{8,})["\']'),
     'Private Key Exposure', 'critical'),
]

# -----------------------------------------------------------------------
# XSS sink patterns in JS (DOM-based indicators)
# -----------------------------------------------------------------------
XSS_SINKS = [
    (re.compile(r'document\.write\s*\('), 'document.write()'),
    (re.compile(r'\.innerHTML\s*='), '.innerHTML assignment'),
    # WHY: eval() pattern is tuned to catch:
    #   1. Variable / non-literal arguments: eval(userInput), eval(foo.bar)
    #   2. Concatenation: eval("a" + x), eval(x + "b")
    #   3. Template literals with variables: eval(`a${x}`)
    # Plain string literals without variables (eval("var a=1;"), eval('...'), eval(`plain`))
    # used by module bundlers (Webpack/esbuild) are NOT flagged.
    (re.compile(r'\beval\s*\(\s*(?:[^"\'\s`)]|["\'][^"\']*["\']\s*\+|`[^`]*\$\{[^}]+\})'),
     'eval() with dynamic argument / concatenation'),
    (re.compile(r'setTimeout\s*\(\s*["\']'), 'string-based setTimeout()'),
    (re.compile(r'location\.href\s*=\s*.*(?:document\.URL|location\.search|location\.hash)'),
     'unvalidated location.href redirection'),
]

# HTML comment patterns that suggest info leakage
SENSITIVE_COMMENT_PATTERNS = [
    re.compile(r'(?i)(todo|fixme|password|credentials|secret|hack|temp|debug|admin)'),
]

# Valid X-Frame-Options values per spec (stored uppercase for direct comparison)
_VALID_XFO = {'DENY', 'SAMEORIGIN'}

# Referrer-Policy values that are unsafe (leak full URL cross-origin)
_UNSAFE_REFERRER_POLICIES = {'unsafe-url'}

# Valid X-Content-Type-Options value
_VALID_XCTO = 'nosniff'

# HSTS min max-age for preload eligibility (hstspreload.org requirement)
_HSTS_PRELOAD_MIN_AGE = 31_536_000   # 1 year in seconds
# Practical minimum max-age to consider HSTS meaningful
_HSTS_MIN_MEANINGFUL_AGE = 86_400    # 24 hours


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _parse_csp_directives(csp_value: str) -> dict[str, list[str]]:
    """
    Splits a CSP header value into a dict of {directive_name: [source, ...]} pairs.

    WHY: The old code never looked at the CSP value at all. We now need to
    check for dangerous sources like 'unsafe-inline', wildcards, and missing
    critical directives such as default-src and object-src.

    Example:
        "default-src 'self'; script-src 'unsafe-inline' cdn.com"
        → {'default-src': ["'self'"], 'script-src': ["'unsafe-inline'", 'cdn.com']}
    """
    directives = {}
    for part in csp_value.split(';'):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            name = tokens[0].lower()
            sources = [s.lower() for s in tokens[1:]]
            directives[name] = sources
    return directives


def _csp_effective_source(directives: dict, directive_name: str) -> list[str] | None:
    """
    Returns the effective source list for a directive, falling back to
    default-src when the specific directive is absent (per CSP spec).
    Returns None if neither is present.
    """
    if directive_name in directives:
        return directives[directive_name]
    return directives.get('default-src')


def _server_discloses_version(value: str) -> bool:
    """
    Returns True only when the Server header value contains a version number
    (digit sequences separated by dots or slashes).

    WHY: 'Server: cloudflare' or 'Server: nginx' are low-signal; the real risk
    is 'Server: Apache/2.4.49' or 'Server: nginx/1.18.0' which reveals a
    patchable version string. We now only flag those.

    Examples:
        'nginx/1.18.0'  → True  (has version)
        'Apache/2.4.49' → True  (has version)
        'cloudflare'    → False (no version)
        'nginx'         → False (no version)
    """
    return bool(re.search(r'[/\s][0-9]+\.[0-9]', value))


# -----------------------------------------------------------------------
# Main header check functions
# -----------------------------------------------------------------------

def _check_csp(raw_headers: dict) -> list[dict]:
    """
    WHY: Previously CSP was checked for presence only.
    Now we parse the value and flag every dangerous directive or missing
    critical directive individually, with a specific recommended fix.

    Checks performed:
      1. Header absent entirely
      2. Report-Only present instead of enforced
      3. 'unsafe-inline' in script-src or default-src
      4. 'unsafe-eval' in script-src or default-src
      5. Wildcard (*) in script-src, default-src, frame-src, or frame-ancestors
      6. data: in script-src or default-src
      7. Missing object-src (allows plugin/Flash execution)
      8. Missing base-uri (open-redirect via <base> tag injection)
      9. Missing frame-ancestors (clickjacking — equivalent to X-Frame-Options)
      10. Missing default-src (no fallback policy)
    """
    findings = []
    has_csp = 'content-security-policy' in raw_headers
    has_report_only = 'content-security-policy-report-only' in raw_headers

    if not has_csp and not has_report_only:
        findings.append({
            'vuln_type': 'Missing Security Header: content-security-policy',
            'severity': 'high',
            'description': 'Content-Security-Policy (CSP) header is absent, leaving the app unprotected against XSS and data injection.',
            'evidence': "Neither 'content-security-policy' nor 'content-security-policy-report-only' was returned.",
            'attack_prevented': 'Cross-Site Scripting (XSS), data injection',
            'recommended_value': "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
        })
        return findings

    if has_report_only and not has_csp:
        # Report-Only is present but not enforced — it only logs, it doesn't block.
        findings.append({
            'vuln_type': 'CSP Present But Not Enforced (Report-Only)',
            'severity': 'medium',
            'description': (
                'Content-Security-Policy-Report-Only is set, but no enforced '
                'Content-Security-Policy header is present. The browser logs violations '
                'but does NOT block them — XSS attacks are still executed.'
            ),
            'evidence': f"content-security-policy-report-only: {raw_headers['content-security-policy-report-only'][:200]}",
            'attack_prevented': 'Cross-Site Scripting (XSS)',
            'recommended_value': "Add an enforced 'Content-Security-Policy' header in addition to the report-only header.",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only',
        })
        # Don't parse value further — the report-only value is for logging only
        return findings

    csp_value = raw_headers['content-security-policy']
    directives = _parse_csp_directives(csp_value)

    # Per CSP spec: default-src only governs scripts when script-src is absent.
    has_script_src = 'script-src' in directives
    script_sources = directives['script-src'] if has_script_src else directives.get('default-src', [])

    # --- 3: 'unsafe-inline' in script context ---
    # Per CSP Level 2/3 spec: modern browsers ignore 'unsafe-inline' when a nonce,
    # a hash (sha256/384/512), or 'strict-dynamic' is present in script sources.
    if "'unsafe-inline'" in script_sources:
        has_nonce_or_hash_or_strict = any(
            s.startswith("'nonce-") or
            s.startswith("'sha256-") or
            s.startswith("'sha384-") or
            s.startswith("'sha512-") or
            s == "'strict-dynamic'"
            for s in script_sources
        )
        if not has_nonce_or_hash_or_strict:
            origin = 'script-src' if has_script_src else 'default-src (governing scripts)'
            findings.append({
                'vuln_type': f"CSP: 'unsafe-inline' in {origin}",
                'severity': 'high',
                'description': "Allows inline <script> blocks and event handlers without nonce or hash protection.",
                'evidence': f"{origin}: {' '.join(script_sources)}",
                'attack_prevented': 'Cross-Site Scripting (XSS) via inline script injection',
                'recommended_value': "Remove 'unsafe-inline' or protect inline scripts with nonces/hashes.",
                'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src',
            })

    # --- 4: 'unsafe-eval' in script context ---
    if "'unsafe-eval'" in script_sources:
        origin = 'script-src' if has_script_src else 'default-src (governing scripts)'
        findings.append({
            'vuln_type': f"CSP: 'unsafe-eval' in {origin}",
            'severity': 'high',
            'description': "Allows eval(), setTimeout(string), and new Function(string). Enables code injection from string data.",
            'evidence': f"{origin}: {' '.join(script_sources)}",
            'attack_prevented': 'Code injection via eval-based sinks',
            'recommended_value': "Remove 'unsafe-eval' and refactor dynamic code execution.",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src',
        })

    # --- 5: Wildcard (*) in script-src or default-src ---
    # If script-src exists, it governs scripts. A wildcard in default-src is downgraded
    # to Medium because script execution is restricted by script-src.
    default_src_sources = directives.get('default-src', [])
    if has_script_src:
        if '*' in script_sources:
            findings.append({
                'vuln_type': "CSP: Wildcard (*) in script-src",
                'severity': 'high',
                'description': "Wildcard (*) in script-src allows scripts to be loaded from ANY origin, nullifying CSP XSS defense.",
                'evidence': f"script-src: {' '.join(script_sources)}",
                'attack_prevented': 'Cross-Site Scripting (XSS) via arbitrary external scripts',
                'recommended_value': "Replace * with explicit trusted origins, e.g. 'self' https://cdn.example.com",
                'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src',
            })
        elif '*' in default_src_sources:
            findings.append({
                'vuln_type': "CSP: Wildcard (*) in default-src",
                'severity': 'medium',
                'description': (
                    "default-src contains a wildcard (*). While script-src is explicitly specified, "
                    "other resource types (connect-src, font-src, img-src) remain unrestricted."
                ),
                'evidence': f"default-src: {' '.join(default_src_sources)}",
                'attack_prevented': 'Open cross-origin resource loading and data exfiltration',
                'recommended_value': "Replace wildcard in default-src with 'self' or explicit origins.",
                'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src',
            })
    else:
        # default-src governs scripts!
        if '*' in default_src_sources:
            findings.append({
                'vuln_type': "CSP: Wildcard (*) in default-src (governing scripts)",
                'severity': 'high',
                'description': "script-src is absent and default-src contains a wildcard (*), allowing scripts from ANY origin.",
                'evidence': f"default-src: {' '.join(default_src_sources)}",
                'attack_prevented': 'Cross-Site Scripting (XSS) via arbitrary external scripts',
                'recommended_value': "Define script-src 'self' or restrict default-src to explicit origins.",
                'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src',
            })

    # --- 6: data: in script-src (allows data URI script execution) ---
    if 'data:' in script_sources:
        origin = 'script-src' if has_script_src else 'default-src'
        findings.append({
            'vuln_type': f"CSP: 'data:' URI in {origin}",
            'severity': 'high',
            'description': "Allowing 'data:' URIs in script sources permits execution of base64-encoded scripts.",
            'evidence': f"{origin} effective value: {' '.join(script_sources)}",
            'attack_prevented': 'CSP bypass via data-URI script injection',
            'recommended_value': f"Remove 'data:' from {origin}.",
            'reference': 'https://www.w3.org/TR/CSP3/#directive-script-src',
        })

    # --- 7: Missing object-src ---
    if 'object-src' not in directives:
        obj_fallback = directives.get('default-src', [])
        if "'none'" not in obj_fallback:
            findings.append({
                'vuln_type': "CSP: Missing 'object-src' directive",
                'severity': 'medium',
                'description': (
                    "object-src is not set. Without it, <object> and <embed> elements can load "
                    "plugins (Flash, Java) from any origin, bypassing script-src restrictions."
                ),
                'evidence': f"CSP has no object-src. default-src fallback: {' '.join(obj_fallback) if obj_fallback else '(none)'}",
                'attack_prevented': 'Plugin-based XSS and content injection',
                'recommended_value': "Add object-src 'none' to your CSP.",
                'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src',
            })

    # --- 8: Missing base-uri ---
    if 'base-uri' not in directives:
        findings.append({
            'vuln_type': "CSP: Missing 'base-uri' directive",
            'severity': 'medium',
            'description': (
                "base-uri is not set. An attacker who can inject an HTML comment or partial tag "
                "can add <base href='https://evil.com'> and redirect all relative resource loads."
            ),
            'evidence': 'No base-uri directive found in Content-Security-Policy.',
            'attack_prevented': 'Base tag hijacking (relative URL redirection)',
            'recommended_value': "Add base-uri 'self' to your CSP.",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri',
        })

    # --- 9: Missing frame-ancestors (suppressed if valid X-Frame-Options exists) ---
    has_valid_xfo = raw_headers.get('x-frame-options', '').strip().upper() in _VALID_XFO
    if 'frame-ancestors' not in directives and not has_valid_xfo:
        findings.append({
            'vuln_type': "CSP: Missing 'frame-ancestors' directive",
            'severity': 'medium',
            'description': (
                "Neither frame-ancestors in CSP nor a valid X-Frame-Options header is set. "
                "The page can be embedded in an iframe by any origin, enabling clickjacking attacks."
            ),
            'evidence': 'No frame-ancestors in CSP and no valid X-Frame-Options header present.',
            'attack_prevented': 'Clickjacking',
            'recommended_value': "Add frame-ancestors 'none' (or 'self') to your CSP.",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors',
        })

    # --- 10: Missing default-src (no fallback policy) ---
    if 'default-src' not in directives:
        findings.append({
            'vuln_type': "CSP: Missing 'default-src' directive",
            'severity': 'medium',
            'description': (
                "No default-src is set. Without a fallback directive, any resource type not "
                "explicitly listed in CSP is unrestricted — effectively an open policy for "
                "font-src, img-src, connect-src, etc."
            ),
            'evidence': 'No default-src directive found in Content-Security-Policy.',
            'attack_prevented': 'Cross-origin resource loading, mixed-content injection',
            'recommended_value': "Add default-src 'self' as a safe fallback.",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src',
        })

    return findings


def _check_hsts(raw_headers: dict) -> list[dict]:
    """
    WHY: Previously HSTS was checked for presence only.
    Now we parse max-age and check for meaningful protection and preload eligibility.

    Checks:
      1. Header absent
      2. max-age=0 (explicitly disables HSTS)
      3. max-age present but below 24 h (too short to be meaningful)
      4. max-age < 31536000 (not preload-eligible)
      5. Missing includeSubDomains
      6. Missing preload directive (informational)
    """
    findings = []
    if 'strict-transport-security' not in raw_headers:
        findings.append({
            'vuln_type': 'Missing Security Header: strict-transport-security',
            'severity': 'high',
            'description': 'HSTS header is absent. Browsers will not enforce HTTPS, enabling SSL-stripping and downgrade attacks.',
            'evidence': "Header 'strict-transport-security' was not returned by the server.",
            'attack_prevented': 'SSL stripping / HTTPS downgrade attack (MITM)',
            'recommended_value': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
        })
        return findings

    hsts_value = raw_headers['strict-transport-security'].lower()

    # Parse max-age from the value string
    max_age_match = re.search(r'max-age\s*=\s*(\d+)', hsts_value)
    if not max_age_match:
        findings.append({
            'vuln_type': 'HSTS: max-age directive missing or unparseable',
            'severity': 'high',
            'description': 'Strict-Transport-Security header is present but has no valid max-age directive. Browsers will ignore it.',
            'evidence': f"strict-transport-security: {raw_headers['strict-transport-security']}",
            'attack_prevented': 'SSL stripping / HTTPS downgrade attack (MITM)',
            'recommended_value': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
        })
        return findings

    max_age = int(max_age_match.group(1))
    evidence_base = f"strict-transport-security: {raw_headers['strict-transport-security']}"

    if max_age == 0:
        # max-age=0 is a deliberate HSTS deletion signal — effectively disables it
        findings.append({
            'vuln_type': 'HSTS: max-age=0 Disables HSTS',
            'severity': 'high',
            'description': (
                'max-age=0 instructs browsers to immediately forget the HSTS policy for this domain. '
                'This actively disables HSTS protection and reverts the site to being accessible over HTTP.'
            ),
            'evidence': evidence_base,
            'attack_prevented': 'SSL stripping / HTTPS downgrade attack (MITM)',
            'recommended_value': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
        })
        return findings

    if max_age < _HSTS_MIN_MEANINGFUL_AGE:
        findings.append({
            'vuln_type': 'HSTS: max-age Too Short (< 24 hours)',
            'severity': 'medium',
            'description': (
                f'HSTS max-age is only {max_age} seconds ({max_age // 3600}h). '
                'This is too short for meaningful protection — after the policy expires, '
                'the browser reverts to plaintext HTTP, enabling short-window SSL-stripping attacks.'
            ),
            'evidence': evidence_base,
            'attack_prevented': 'SSL stripping (short window after expiry)',
            'recommended_value': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'reference': 'https://hstspreload.org/',
        })

    elif max_age < _HSTS_PRELOAD_MIN_AGE:
        # Present and meaningful, but not preload-eligible
        findings.append({
            'vuln_type': 'HSTS: max-age Below Preload Minimum (< 1 year)',
            'severity': 'low',
            'description': (
                f'HSTS max-age is {max_age} seconds ({max_age // 86400} days). '
                f'Minimum for preload list submission is {_HSTS_PRELOAD_MIN_AGE} seconds (1 year). '
                'Without preloading, first-time visitors can still be downgraded before the '
                'HSTS policy is received.'
            ),
            'evidence': evidence_base,
            'attack_prevented': 'First-visit SSL stripping (preload closes this gap)',
            'recommended_value': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'reference': 'https://hstspreload.org/',
        })

    # Check includeSubDomains
    if 'includesubdomains' not in hsts_value:
        findings.append({
            'vuln_type': 'HSTS: includeSubDomains Missing',
            'severity': 'low',
            'description': (
                'includeSubDomains is not set. Subdomains (e.g. api.example.com, mail.example.com) '
                'are not covered by HSTS and can be targeted for cookie theft via SSL-stripping '
                'or MITM attacks.'
            ),
            'evidence': evidence_base,
            'attack_prevented': 'Subdomain cookie theft via SSL stripping',
            'recommended_value': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
        })

    # Preload is informational: not having it is not a vulnerability by itself,
    # but it means first-time visitors have no HSTS protection
    if max_age >= _HSTS_PRELOAD_MIN_AGE and 'includesubdomains' in hsts_value and 'preload' not in hsts_value:
        findings.append({
            'vuln_type': 'HSTS: preload Directive Missing (Informational)',
            'severity': 'info',
            'description': (
                'HSTS is well-configured (max-age ≥ 1 year, includeSubDomains present) but the '
                'preload directive is absent. Adding preload and submitting to hstspreload.org '
                'prevents first-visit SSL-stripping for new users.'
            ),
            'evidence': evidence_base,
            'attack_prevented': 'First-visit HTTPS downgrade (preload eliminates the gap)',
            'recommended_value': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'reference': 'https://hstspreload.org/',
        })

    return findings


def _check_xfo(raw_headers: dict) -> list[dict]:
    """
    WHY: Previously X-Frame-Options was checked for presence only.
    Now we validate the value AND treat CSP frame-ancestors as equivalent,
    so a site using only frame-ancestors in CSP is not double-flagged.

    Logic:
      - If CSP frame-ancestors is set → X-Frame-Options is redundant but fine.
      - If neither frame-ancestors nor X-Frame-Options → flag missing.
      - If X-Frame-Options is present but has an invalid value → flag bad value.
    """
    findings = []
    csp_value = raw_headers.get('content-security-policy', '')
    csp_directives = _parse_csp_directives(csp_value)
    has_frame_ancestors = 'frame-ancestors' in csp_directives

    xfo_value = raw_headers.get('x-frame-options', '').strip().upper()

    if not xfo_value and not has_frame_ancestors:
        findings.append({
            'vuln_type': 'Missing Security Header: x-frame-options',
            'severity': 'medium',
            'description': (
                'Neither X-Frame-Options nor CSP frame-ancestors is set. The page can be '
                'embedded in an iframe by any origin, enabling clickjacking attacks where '
                'a victim is tricked into clicking UI elements on the invisible embedded page.'
            ),
            'evidence': "Headers 'x-frame-options' and CSP 'frame-ancestors' are both absent.",
            'attack_prevented': 'Clickjacking',
            'recommended_value': "X-Frame-Options: DENY  (or add frame-ancestors 'none' to CSP — preferred)",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
        })
    elif xfo_value and xfo_value not in _VALID_XFO:
        # Value is present but is not DENY or SAMEORIGIN (e.g. ALLOWALL, ALLOW-FROM [deprecated])
        findings.append({
            'vuln_type': 'X-Frame-Options: Invalid Value',
            'severity': 'medium',
            'description': (
                f"X-Frame-Options is set to '{xfo_value}', which is not a valid value. "
                "Browsers only recognise DENY and SAMEORIGIN. An invalid value is treated "
                "as absent — the page may still be frameable."
            ),
            'evidence': f"x-frame-options: {raw_headers.get('x-frame-options', '')}",
            'attack_prevented': 'Clickjacking',
            'recommended_value': "X-Frame-Options: DENY  (or CSP frame-ancestors 'none')",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
        })

    return findings


def _check_xcto(raw_headers: dict) -> list[dict]:
    """
    WHY: Previously any value for X-Content-Type-Options passed.
    The only valid value is 'nosniff'. A typo or wrong value gives false safety.

    Checks:
      1. Header absent
      2. Header present but value != 'nosniff'
    """
    findings = []
    xcto_raw = raw_headers.get('x-content-type-options', '')

    if not xcto_raw:
        findings.append({
            'vuln_type': 'Missing Security Header: x-content-type-options',
            'severity': 'low',
            'description': (
                'X-Content-Type-Options is absent. Browsers may MIME-sniff response bodies '
                'and execute scripts served as text/plain or other non-script MIME types.'
            ),
            'evidence': "Header 'x-content-type-options' was not returned by the server.",
            'attack_prevented': 'MIME-type confusion attacks (drive-by download, script execution)',
            'recommended_value': 'X-Content-Type-Options: nosniff',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
        })
    elif xcto_raw.strip().lower() != _VALID_XCTO:
        # Header is present but with a wrong value — provides no protection
        findings.append({
            'vuln_type': 'X-Content-Type-Options: Invalid Value',
            'severity': 'low',
            'description': (
                f"X-Content-Type-Options is set to '{xcto_raw}', not the required 'nosniff'. "
                "Browsers may ignore an unrecognised value and still perform MIME-sniffing."
            ),
            'evidence': f"x-content-type-options: {xcto_raw}",
            'attack_prevented': 'MIME-type confusion attacks',
            'recommended_value': 'X-Content-Type-Options: nosniff',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
        })

    return findings


def _check_referrer_policy(raw_headers: dict) -> list[dict]:
    """
    WHY: 'unsafe-url' sends the full URL (path + query params) to every cross-origin
    request — worse than having no header at all (which defaults to a safer browser
    heuristic). We now catch this.
    """
    findings = []
    rp_raw = raw_headers.get('referrer-policy', '')

    if not rp_raw:
        findings.append({
            'vuln_type': 'Missing Security Header: referrer-policy',
            'severity': 'low',
            'description': (
                'Referrer-Policy is absent. The browser falls back to its default referrer '
                'behaviour, which may send full URLs (including query parameters with tokens, '
                'user IDs, etc.) as the HTTP Referer header to third-party sites.'
            ),
            'evidence': "Header 'referrer-policy' was not returned by the server.",
            'attack_prevented': 'Sensitive URL parameter leakage to third parties',
            'recommended_value': 'Referrer-Policy: strict-origin-when-cross-origin',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
        })
    else:
        # Check for the explicitly unsafe value
        rp_value = rp_raw.strip().lower()
        if rp_value in _UNSAFE_REFERRER_POLICIES:
            findings.append({
                'vuln_type': "Referrer-Policy: 'unsafe-url' Is Worse Than Absent",
                'severity': 'medium',
                'description': (
                    "Referrer-Policy is set to 'unsafe-url', which sends the FULL URL "
                    "(scheme, host, path, and query string) as the Referer header on every "
                    "request including cross-origin ones. This actively leaks sensitive tokens, "
                    "paths, and parameters to third-party servers and is worse than having no header."
                ),
                'evidence': f"referrer-policy: {rp_raw}",
                'attack_prevented': 'Sensitive URL / token leakage to cross-origin servers',
                'recommended_value': 'Referrer-Policy: strict-origin-when-cross-origin',
                'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
            })

    return findings


def _check_permissions_policy(raw_headers: dict) -> list[dict]:
    """Checks for presence of Permissions-Policy (no value parsing needed for Phase 2)."""
    findings = []
    if 'permissions-policy' not in raw_headers:
        findings.append({
            'vuln_type': 'Missing Security Header: permissions-policy',
            'severity': 'low',
            'description': (
                'Permissions-Policy is absent. Without it, any script (including third-party '
                'and injected scripts) can request access to camera, microphone, geolocation, '
                'payment, and other sensitive browser features.'
            ),
            'evidence': "Header 'permissions-policy' was not returned by the server.",
            'attack_prevented': 'Unauthorized access to camera, mic, geolocation by third-party scripts',
            'recommended_value': 'Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
        })
    return findings


def _check_coop(raw_headers: dict) -> list[dict]:
    """
    NEW in Phase 2.
    WHY: Cross-Origin-Opener-Policy (COOP) prevents cross-origin windows (opened via
    window.open or <a target=_blank>) from keeping a reference back to your page.
    Without it, a page opened from yours can access window.opener and perform
    Spectre-style cross-origin data leaks if SharedArrayBuffer is also available.
    """
    findings = []
    if 'cross-origin-opener-policy' not in raw_headers:
        findings.append({
            'vuln_type': 'Missing Security Header: cross-origin-opener-policy',
            'severity': 'low',
            'description': (
                'Cross-Origin-Opener-Policy (COOP) is not set. Without it, documents opened '
                'in a new tab can retain a reference to this page via window.opener, enabling '
                'cross-origin Spectre-style timing attacks and tabnapping.'
            ),
            'evidence': "Header 'cross-origin-opener-policy' was not returned by the server.",
            'attack_prevented': 'Spectre-based cross-origin data leaks, tabnapping via window.opener',
            'recommended_value': 'Cross-Origin-Opener-Policy: same-origin',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy',
        })
    return findings


def _check_corp(raw_headers: dict) -> list[dict]:
    """
    NEW in Phase 2.
    WHY: Cross-Origin-Resource-Policy (CORP) prevents other origins from loading this
    resource (e.g. images, scripts) using no-cors fetches — required for COEP isolation
    and also defends against Spectre-style side-channel reads of your resources.
    """
    findings = []
    if 'cross-origin-resource-policy' not in raw_headers:
        findings.append({
            'vuln_type': 'Missing Security Header: cross-origin-resource-policy',
            'severity': 'info',
            'description': (
                'Cross-Origin-Resource-Policy (CORP) is not set. Without it, any cross-origin '
                'page can load this resource via a no-cors fetch and potentially read its '
                'contents via Spectre-style side channels.'
            ),
            'evidence': "Header 'cross-origin-resource-policy' was not returned by the server.",
            'attack_prevented': 'Spectre-based cross-origin resource reads',
            'recommended_value': 'Cross-Origin-Resource-Policy: same-origin  (or same-site for CDN resources)',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy',
        })
    return findings


def _check_coep(raw_headers: dict) -> list[dict]:
    """
    NEW in Phase 2.
    WHY: Cross-Origin-Embedder-Policy (COEP) is required alongside COOP to enable
    cross-origin isolation — necessary to safely use SharedArrayBuffer and high-resolution
    timers. Without it those APIs are blocked or throttled by default.
    """
    findings = []
    if 'cross-origin-embedder-policy' not in raw_headers:
        findings.append({
            'vuln_type': 'Missing Security Header: cross-origin-embedder-policy',
            'severity': 'info',
            'description': (
                'Cross-Origin-Embedder-Policy (COEP) is not set. Without COEP (combined with '
                'COOP: same-origin), the document is not cross-origin isolated and '
                'SharedArrayBuffer / high-resolution timers are not available, reducing the '
                'application\'s ability to use performance-sensitive APIs safely.'
            ),
            'evidence': "Header 'cross-origin-embedder-policy' was not returned by the server.",
            'attack_prevented': 'Spectre-class timing attacks using high-resolution timers',
            'recommended_value': 'Cross-Origin-Embedder-Policy: require-corp',
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy',
        })
    return findings


def _check_dangerous_headers(raw_headers: dict) -> list[dict]:
    """
    Checks for headers that disclose sensitive information.

    WHY for Server change: Previously ANY Server: value was flagged at 'low'.
    'Server: cloudflare' or 'Server: nginx' are normal and low-risk — the real
    risk is when the value includes a version number (e.g. 'Apache/2.4.49')
    because that enables targeted CVE lookups. We now only flag version-containing values.
    """
    findings = []

    # X-Powered-By — flag any presence (always leaks framework info)
    for header, severity, description, attack_prevented, recommended_value, reference in DANGEROUS_HEADERS:
        if header in raw_headers:
            findings.append({
                'vuln_type': f'Information Disclosure: {header}',
                'severity': severity,
                'description': description,
                'evidence': f"{header}: {raw_headers[header]}",
                'attack_prevented': attack_prevented,
                'recommended_value': recommended_value,
                'reference': reference,
            })

    # Server — only flag when the value contains a version number
    server_value = raw_headers.get('server', '')
    if server_value and _server_discloses_version(server_value):
        findings.append({
            'vuln_type': 'Information Disclosure: server version',
            'severity': 'low',
            'description': (
                'The Server header discloses the web server software and its version number. '
                'Attackers can use this to look up known CVEs for that specific version.'
            ),
            'evidence': f"server: {server_value}",
            'attack_prevented': 'Targeted CVE-based exploitation using disclosed version',
            'recommended_value': 'Remove or sanitize the version from the Server header (e.g. "Server: nginx").',
            'reference': 'https://owasp.org/www-project-secure-headers/',
        })

    return findings


def _check_deprecated_headers(raw_headers: dict) -> list[dict]:
    """
    NEW in Phase 2.
    WHY: Deprecated headers provide no security benefit and in some cases actively
    harm security (X-XSS-Protection mode=block can introduce new XSS vectors).
    We report them as 'info' so the operator knows to remove them.
    """
    findings = []
    for header, description, reference in DEPRECATED_HEADERS:
        if header in raw_headers:
            findings.append({
                'vuln_type': f'Deprecated Security Header: {header}',
                'severity': 'info',
                'description': description,
                'evidence': f"{header}: {raw_headers[header]}",
                'attack_prevented': 'N/A (this header should be removed, not kept)',
                'recommended_value': f'Remove this header. Reference: {reference}',
                'reference': reference,
            })
    return findings


def _check_duplicate_headers(raw_headers: dict) -> list[dict]:
    """
    NEW in Phase 2.
    WHY: The requests library joins multiple values of the same header with ', '.
    When a response returns two different CSP or HSTS headers, the browser uses
    the intersection (for CSP) or the first (for HSTS) — both can be more
    permissive than intended.

    We detect this by scanning for the separator pattern introduced by requests.
    Note: we cannot distinguish a legitimate comma-separated single value (e.g.
    cache-control has commas) from two separate headers, so we limit this check
    to headers where multiple values are almost always a mistake.
    """
    findings = []
    # Headers where duplicate values are almost always a misconfiguration
    CHECK_HEADERS = [
        'strict-transport-security',
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'referrer-policy',
        'cross-origin-opener-policy',
        'cross-origin-resource-policy',
        'cross-origin-embedder-policy',
    ]
    for hdr in CHECK_HEADERS:
        value = raw_headers.get(hdr, '')
        # requests joins duplicate headers with ', ' — if we see what looks like
        # two distinct directive-sets separated by a ', ' boundary that starts a
        # keyword (not a continuation of the first), treat it as duplicates.
        if hdr == 'strict-transport-security' and value.count('max-age') > 1:
            findings.append({
                'vuln_type': f'Duplicate Header Detected: {hdr}',
                'severity': 'info',
                'description': (
                    f"The server sent multiple '{hdr}' headers. Browsers use the first value; "
                    "the second is ignored. This is likely a misconfiguration in a reverse proxy "
                    "or middleware stack. Consolidate to a single header."
                ),
                'evidence': f"{hdr}: {value[:300]}",
                'attack_prevented': 'Header injection / policy confusion',
                'recommended_value': f'Ensure only one {hdr} header is emitted per response.',
                'reference': 'https://owasp.org/www-project-secure-headers/',
            })
        elif hdr == 'content-security-policy' and value.count('default-src') > 1:
            findings.append({
                'vuln_type': f'Duplicate Header Detected: {hdr}',
                'severity': 'info',
                'description': (
                    f"The server sent multiple '{hdr}' headers. For CSP, browsers apply the "
                    "intersection of all policies — meaning the most restrictive wins — but "
                    "this is frequently unintentional and should be consolidated."
                ),
                'evidence': f"{hdr}: {value[:300]}",
                'attack_prevented': 'Policy confusion / unexpected policy intersection',
                'recommended_value': f'Merge directives into a single {hdr} header.',
                'reference': 'https://www.w3.org/TR/CSP3/#multiple-policies',
            })

    return findings


def check_security_headers(raw_headers: dict) -> list[dict]:
    """
    Master security header check function.
    Delegates to per-header validators and returns all findings.

    WHY this structure: each header has different validation logic; keeping them
    separate makes it easy to test, extend, and explain each one individually.
    """
    findings = []
    findings.extend(_check_csp(raw_headers))
    findings.extend(_check_hsts(raw_headers))
    findings.extend(_check_xfo(raw_headers))
    findings.extend(_check_xcto(raw_headers))
    findings.extend(_check_referrer_policy(raw_headers))
    findings.extend(_check_permissions_policy(raw_headers))
    findings.extend(_check_coop(raw_headers))
    findings.extend(_check_corp(raw_headers))
    findings.extend(_check_coep(raw_headers))
    findings.extend(_check_dangerous_headers(raw_headers))
    findings.extend(_check_deprecated_headers(raw_headers))
    findings.extend(_check_duplicate_headers(raw_headers))
    return findings


# -----------------------------------------------------------------------
# JS / secret / XSS / form / comment checks (unchanged from Phase 1)
# -----------------------------------------------------------------------

def check_js_secrets(inline_scripts: list[str]) -> list[dict]:
    findings = []
    for block in inline_scripts:
        if not block:
            continue
        for pattern, vuln_name, severity in SECRET_PATTERNS:
            match = pattern.search(block)
            if match:
                snippet = match.group(0)[:120]
                findings.append({
                    'vuln_type': f'Information Disclosure: {vuln_name}',
                    'severity': severity,
                    'description': f"Potential sensitive credential/secret found in client-side script.",
                    'evidence': f"Snippet: {snippet}"
                })
    return findings


def check_xss_sinks(inline_scripts: list[str]) -> list[dict]:
    findings = []
    for block in inline_scripts:
        if not block:
            continue
        for pattern, sink_name in XSS_SINKS:
            match = pattern.search(block)
            if match:
                snippet = match.group(0)[:120]
                findings.append({
                    'vuln_type': f'Potential DOM XSS Sink: {sink_name}',
                    'severity': 'medium',
                    'description': (
                        f"Dangerous JavaScript sink detected: `{sink_name}`. "
                        "If untrusted or user-controlled input reaches this sink, it can result in DOM-based Cross-Site Scripting."
                    ),
                    'evidence': f"Pattern: {sink_name}\nSnippet: {snippet}"
                })
    return findings


def check_html_comments(comments: list[str]) -> list[dict]:
    findings = []
    for comment in comments:
        for pattern in SENSITIVE_COMMENT_PATTERNS:
            if pattern.search(comment):
                findings.append({
                    'vuln_type': 'Information Disclosure in HTML Comment',
                    'severity': 'low',
                    'description': 'HTML comment contains developer keywords (TODO, fixme, credentials, admin).',
                    'evidence': f"Comment: {comment[:200]}"
                })
                break
    return findings


def check_forms(forms: list[dict]) -> list[dict]:
    findings = []
    for form in forms:
        if form.get('method') == 'get':
            sensitive_inputs = [
                i for i in form.get('inputs', [])
                if i.get('type') in ('password', 'email', 'hidden')
            ]
            if sensitive_inputs:
                findings.append({
                    'vuln_type': 'Sensitive Data in HTTP GET Form',
                    'severity': 'medium',
                    'description': (
                        f"Form with action '{form.get('action')}' uses GET method with "
                        f"sensitive input types: {[i.get('type') for i in sensitive_inputs]}. "
                        "Sensitive data will be logged in server logs, browser history, and HTTP referrers."
                    ),
                    'evidence': f"Action: {form.get('action')}, Inputs: {[i.get('name') for i in sensitive_inputs]}"
                })
    return findings


# -----------------------------------------------------------------------
# Orchestrators
# -----------------------------------------------------------------------

def run_all_checks(raw_headers: dict, script_srcs: list[str], inline_scripts: list[str] = None,
                   base_url: str = '', comments: list[str] = None, forms: list[dict] = None) -> list[dict]:
    """
    Runs all security checks:
    - HTTP Security Headers (with value validation — Phase 2)
    - Retire.js Outdated Client-Side Components
    - Insecure Script Sources (HTTP)
    - Inline JS Secret Leakage
    - DOM XSS Sinks
    - Sensitive HTML Comments
    - Insecure Forms
    """
    findings = []

    # 1. Security Headers (now value-validated)
    findings.extend(check_security_headers(raw_headers))

    # 2. Retire.js Outdated Components Detection
    retirejs_findings, _ = scan_retirejs(script_srcs or [], inline_scripts or [], base_url=base_url)
    findings.extend(retirejs_findings)

    # 3. Insecure plain HTTP script loading
    for src in (script_srcs or []):
        if src.startswith('http://'):
            findings.append({
                'vuln_type': 'Insecure Script Source (Plain HTTP)',
                'severity': 'medium',
                'description': (
                    'A <script> tag loads an external resource over unencrypted HTTP. '
                    'Man-in-the-Middle (MitM) attackers can tamper with or inject malicious scripts.'
                ),
                'evidence': src[:200]
            })

    # 4. Inline Secrets & Credentials
    if inline_scripts:
        findings.extend(check_js_secrets(inline_scripts))
        findings.extend(check_xss_sinks(inline_scripts))

    # 5. Comments & Forms
    if comments:
        findings.extend(check_html_comments(comments))
    if forms:
        findings.extend(check_forms(forms))

    return findings


def run_matcher(headers: dict, scripts: list[str] = None, inline_scripts: list[str] = None,
                target_url: str = '', comments: list[str] = None, forms: list[dict] = None) -> list[dict]:
    """
    Public entry point called by dummy_scan() in main.py.
    """
    scripts = scripts or []
    inline_scripts = inline_scripts or []
    comments = comments or []
    forms = forms or []

    return run_all_checks(
        raw_headers=headers,
        script_srcs=scripts,
        inline_scripts=inline_scripts,
        base_url=target_url,
        comments=comments,
        forms=forms
    )
