import re
import urllib.parse
import requests
from scanner.reliability import BoundedTTLCache, CONNECT_TIMEOUT_API, READ_TIMEOUT_API

# ---------------------------------------------------------------------------
# Custom Version Comparer (CustomVersion / SemVer)
# ---------------------------------------------------------------------------
# A custom version parser and rich comparator supporting up to 4-part numeric
# versions (e.g. 1.2.3.4), pre-release tags (e.g. 1.12.4-rc1, 2.0.0-beta.2,
# rc.2 vs rc.10), and build metadata (e.g. +build.2024).
# NOTE: This is a specialized custom comparator tailored for web JavaScript
# library versioning, not a full strict SemVer 2.0.0 implementation.
# Precedence rules:
#   1. Numeric segments take primary precedence (1.9.0 < 1.12.0).
#   2. Pre-release tags have lower precedence than the final release:
#      1.12.4-rc.1 < 1.12.4-rc.10 < 1.12.4.
#   3. Pre-release numeric segments compare numerically (rc.2 < rc.10).
#   4. Build metadata (+build) is ignored for precedence comparisons:
#      1.2.3+20130313144700 == 1.2.3.
# ---------------------------------------------------------------------------

class SemVer:
    """
    Custom version parser and rich comparator for web library dependencies.
    Supports 4-part versions, pre-release tags, and ignores build metadata.
    """
    def __init__(self, v_str):
        self.raw = str(v_str or '').strip()
        cleaned = self.raw.lstrip('v').lstrip('V')
        if not cleaned or cleaned.lower() in ('unknown', 'n/a', 'none', 'version unknown'):
            self.parts = ()
            self.prerelease = None
            self.build = None
            self.is_valid = False
            return

        # Strip and ignore +build metadata per specification
        version_no_build, _, build_part = cleaned.partition('+')
        self.build = build_part if build_part else None

        main_part, _, pre_part = version_no_build.partition('-')
        nums = [int(x) for x in re.findall(r'\d+', main_part)]
        if not nums:
            self.parts = ()
            self.prerelease = None
            self.is_valid = False
            return

        while len(nums) < 3:
            nums.append(0)
        self.parts = tuple(nums)

        if pre_part:
            pre_tokens = []
            # Tokenize pre-release string on '.' and '-'
            raw_tokens = re.split(r'[.-]', pre_part)
            for token in raw_tokens:
                if not token:
                    continue
                # Split alphanumeric tokens like rc2 or beta10 into text and numeric components
                sub_parts = re.findall(r'[a-zA-Z]+|\d+', token)
                for sp in sub_parts:
                    if sp.isdigit():
                        pre_tokens.append((0, int(sp)))
                    elif sp:
                        pre_tokens.append((1, sp.lower()))
            self.prerelease = tuple(pre_tokens) if pre_tokens else None
        else:
            self.prerelease = None
        self.is_valid = True

    def __lt__(self, other):
        if not isinstance(other, SemVer):
            other = SemVer(other)
        if not self.is_valid or not other.is_valid:
            return False
        if self.parts != other.parts:
            return self.parts < other.parts
        # Same numeric parts: a version without a prerelease has higher precedence
        if self.prerelease is None and other.prerelease is None:
            return False
        if self.prerelease is not None and other.prerelease is None:
            return True  # 1.2.3-rc1 < 1.2.3
        if self.prerelease is None and other.prerelease is not None:
            return False # 1.2.3 > 1.2.3-rc1
        return self.prerelease < other.prerelease

    def __le__(self, other):
        if not isinstance(other, SemVer):
            other = SemVer(other)
        if not self.is_valid or not other.is_valid:
            return False
        return self < other or self == other

    def __eq__(self, other):
        if not isinstance(other, SemVer):
            other = SemVer(other)
        if not self.is_valid or not other.is_valid:
            return False
        return self.parts == other.parts and self.prerelease == other.prerelease

    def __gt__(self, other):
        if not isinstance(other, SemVer):
            other = SemVer(other)
        if not self.is_valid or not other.is_valid:
            return False
        return other < self

    def __ge__(self, other):
        if not isinstance(other, SemVer):
            other = SemVer(other)
        if not self.is_valid or not other.is_valid:
            return False
        return not (self < other)

    def __repr__(self):
        return f"CustomVersion('{self.raw}')"

    def __str__(self):
        return self.raw or 'unknown'


# Alias for clarity in documentation and code
CustomVersion = SemVer


def parse_version(ver_str: str) -> tuple[int, int, int]:
    """
    Backwards-compatible helper returning (major, minor, patch) integer tuple.
    """
    v = SemVer(ver_str)
    if not v.is_valid or not v.parts:
        return (0, 0, 0)
    p = list(v.parts[:3])
    while len(p) < 3:
        p.append(0)
    return tuple(p[:3])


def is_version_vulnerable(ver: SemVer | str | tuple, below: str = None, at_least: str = None) -> bool:
    """
    Checks if a version falls into [at_least, below) using proper SemVer comparison.
    """
    if isinstance(ver, tuple):
        ver_str = '.'.join(str(x) for x in ver)
        v = SemVer(ver_str)
    elif isinstance(ver, SemVer):
        v = ver
    else:
        v = SemVer(ver)

    if not v.is_valid:
        return False
    if at_least and v < SemVer(at_least):
        return False
    if below and v >= SemVer(below):
        return False
    return True


# ---------------------------------------------------------------------------
# Explicit Retire.js to NPM / OSV Package Mapping & Live Caches
# ---------------------------------------------------------------------------

RETIREJS_TO_NPM_MAP = {
    'jquery': 'jquery',
    'bootstrap': 'bootstrap',
    'jquery-validation': 'jquery-validation',
    'angularjs': 'angular',
    'lodash': 'lodash',
    'moment': 'moment',
    'vue': 'vue',
    'react': 'react',
    'axios': 'axios',
    'handlebars': 'handlebars',
    'dompurify': 'dompurify',
    'tinymce': 'tinymce',
    'underscore': 'underscore',
    'sweetalert': 'sweetalert',
    'swiper': 'swiper',
    'popper': 'popper.js',
}

# Alias for backwards compatibility
NPM_PACKAGE_MAP = RETIREJS_TO_NPM_MAP

_OSV_CACHE = BoundedTTLCache(maxsize=512, ttl=3600.0)
_NPM_LATEST_CACHE = BoundedTTLCache(maxsize=256, ttl=3600.0)
_RETIREJS_REPO_CACHE: dict | None = None
_RETIREJS_REPO_TIMESTAMP: float = 0.0


def fetch_retirejs_repository(timeout: tuple[float, float] = (2.5, 4.0)) -> tuple[dict, bool]:
    """
    Fetches the official Retire.js vulnerability repository (jsrepository.json) live.
    Caches the parsed repository in memory for up to 1 hour.
    Returns:
        (repo_dict, is_live_success: bool)
    If network is unavailable or request fails, returns ({}, False).
    """
    global _RETIREJS_REPO_CACHE, _RETIREJS_REPO_TIMESTAMP
    import time
    now = time.time()
    if _RETIREJS_REPO_CACHE is not None and (now - _RETIREJS_REPO_TIMESTAMP < 3600):
        return (_RETIREJS_REPO_CACHE, True)

    url = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json'
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; WebVulnScanner/2.0)'}
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                _RETIREJS_REPO_CACHE = data
                _RETIREJS_REPO_TIMESTAMP = now
                return (data, True)
    except Exception:
        pass
    return ({}, False)


def query_retirejs_repo_vulnerabilities(lib_key: str, version_str: str, repo_data: dict) -> list[dict]:
    """
    Evaluates a detected library version against the live Retire.js jsrepository.json dataset.
    """
    if not repo_data or lib_key not in repo_data:
        return []

    lib_meta = repo_data[lib_key]
    vulns = lib_meta.get('vulnerabilities', [])
    matched = []
    sem_ver = SemVer(version_str)
    if not sem_ver.is_valid:
        return []

    for v in vulns:
        below = v.get('below')
        at_or_above = v.get('atOrAbove')
        if is_version_vulnerable(sem_ver, below=below, at_least=at_or_above):
            identifiers = v.get('identifiers', {})
            cve_ids = identifiers.get('CVE', [])
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            summary = identifiers.get('issue') or identifiers.get('summary') or 'Vulnerability reported in Retire.js repository'
            info_links = v.get('info', [])
            ref_link = info_links[0] if info_links else (f"https://nvd.nist.gov/vuln/detail/{cve_ids[0]}" if cve_ids else 'https://retirejs.github.io/retire.js/')
            sev = v.get('severity', 'medium').lower()
            matched.append({
                'id': cve_ids[0] if cve_ids else f"RETIREJS-{lib_key}-{below}",
                'cves': cve_ids,
                'primary_cve': cve_ids[0] if cve_ids else f"RETIREJS-{lib_key}-{below}",
                'summary': summary,
                'fixed_version': below,
                'reference_link': ref_link,
                'severity': sev,
            })
    return matched


def query_osv_vulnerabilities(npm_package: str, version_str: str, timeout: float = 4.0) -> tuple[list[dict], bool]:
    """
    Queries OSV.dev (https://api.osv.dev/v1/query) for live CVE / advisory data.
    Returns:
        (findings_list, is_live_success: bool)
    If the network call fails or times out, returns ([], False).
    """
    if not npm_package or not version_str or version_str.lower() in ('unknown', 'version unknown'):
        return ([], False)

    cache_key = f"{npm_package}::{version_str}"
    hit, cached = _OSV_CACHE.get(cache_key)
    if hit:
        return (cached, True)

    payload = {
        'package': {
            'name': npm_package,
            'ecosystem': 'npm'
        },
        'version': version_str
    }

    try:
        resp = requests.post(
            'https://api.osv.dev/v1/query',
            json=payload,
            timeout=(CONNECT_TIMEOUT_API, READ_TIMEOUT_API),
            headers={'User-Agent': 'Mozilla/5.0 (compatible; WebVulnScanner/2.0)'}
        )
        if resp.status_code != 200:
            return ([], False)

        data = resp.json()
        vulns = data.get('vulns', [])
        parsed_vulns = []

        for v in vulns:
            vid = v.get('id', '')
            aliases = v.get('aliases', [])
            cve_ids = [a for a in aliases if a.startswith('CVE-')]
            if not cve_ids and vid.startswith('CVE-'):
                cve_ids = [vid]

            # Primary reference link
            refs = v.get('references', [])
            ref_link = None
            for r in refs:
                url = r.get('url', '')
                if 'nvd.nist.gov' in url or 'github.com/advisories' in url:
                    ref_link = url
                    break
            if not ref_link:
                ref_link = refs[0].get('url') if refs else f"https://osv.dev/vulnerability/{vid}"

            # Extract fixed version from ranges
            fixed_version = None
            for aff in v.get('affected', []):
                for r in aff.get('ranges', []):
                    for ev in r.get('events', []):
                        if 'fixed' in ev:
                            fixed_version = ev['fixed']
                            break
                    if fixed_version:
                        break
                if fixed_version:
                    break

            # Severity calculation
            sev = 'high'
            db_spec = v.get('database_specific', {})
            if db_spec and 'severity' in db_spec:
                sev = db_spec['severity'].lower()
            elif 'HIGH' in str(v):
                sev = 'high'
            elif 'CRITICAL' in str(v):
                sev = 'critical'
            elif 'MEDIUM' in str(v) or 'MODERATE' in str(v):
                sev = 'medium'

            parsed_vulns.append({
                'id': vid,
                'cves': cve_ids,
                'primary_cve': cve_ids[0] if cve_ids else vid,
                'summary': v.get('summary') or v.get('details', 'Known security advisory published in OSV.')[:200],
                'fixed_version': fixed_version,
                'reference_link': ref_link,
                'severity': sev,
            })

        _OSV_CACHE.set(cache_key, parsed_vulns)
        return (parsed_vulns, True)

    except Exception:
        return ([], False)


def query_npm_latest_version(npm_package: str, timeout: float = 3.0) -> str | None:
    """
    Fetches the latest official version from npm registry.
    """
    if not npm_package:
        return None
    if npm_package in _NPM_LATEST_CACHE:
        return _NPM_LATEST_CACHE[npm_package]

    try:
        resp = requests.get(
            f"https://registry.npmjs.org/{npm_package}/latest",
            timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; WebVulnScanner/2.0)'}
        )
        if resp.status_code == 200:
            ver = resp.json().get('version')
            if ver:
                _NPM_LATEST_CACHE[npm_package] = ver
                return ver
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Offline Component Signatures & Local Fallback Vulnerability Database
# ---------------------------------------------------------------------------
# Note: Used ONLY as an offline fallback when live lookups to OSV.dev and
# Retire.js jsrepository.json are unavailable. All rules have been verified
# against official advisories.
# ---------------------------------------------------------------------------

RETIREJS_DB = {
    # -------------------------------------------------------------------------
    # jQuery
    # -------------------------------------------------------------------------
    'jquery': {
        'name': 'jQuery',
        'url_patterns': [
            re.compile(r'(?:/|^)jquery[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min|\.slim|\.pack)?\.js', re.IGNORECASE),
            re.compile(r'/jquery/([0-9]+(?:\.[0-9]+)+)/jquery(?:\.min|\.slim)?\.js', re.IGNORECASE),
            re.compile(r'code\.jquery\.com/jquery-([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'npm/jquery@([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*jQuery\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'jQuery\.fn\.jquery\s*=\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
            re.compile(r'/\*!\s*jQuery\s+JavaScript\s+Library\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'\bexpando:\s*["\']jQuery[^"\']*["\'][^;{}]{0,120}\bjquery:\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '1.9.0',
                'severity': 'high',
                'cves': ['CVE-2012-6708', 'CVE-2011-4969'],
                'summary': 'Prone to XSS via location.hash selector manipulation and cross-domain script execution.',
                'remediation': 'Upgrade to jQuery 3.7.1 or newer.',
                'fixed_in': '1.9.0',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2012-6708',
            },
            {
                'at_least': '1.9.0',
                'below': '3.0.0',
                'severity': 'high',
                'cves': ['CVE-2015-9251', 'CVE-2019-11358'],
                'summary': '3rd-party CORS XSS via $.parseHTML() and Prototype Pollution via jQuery.extend(true, {}, ...).',
                'remediation': 'Upgrade to jQuery 3.7.1 or newer.',
                'fixed_in': '3.0.0',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-11358',
            },
            {
                'at_least': '1.0.0',
                'below': '3.0.0',
                'severity': 'low',
                'cves': ['EOL-JQUERY-1X-2X'],
                'summary': 'jQuery 1.x and 2.x are End-of-Life and no longer receiving security updates.',
                'remediation': 'Upgrade to jQuery 3.7.1 or newer.',
                'fixed_in': '3.7.1',
                'source_link': 'https://blog.jquery.com/',
            },
            {
                'at_least': '3.0.0',
                'below': '3.4.0',
                'severity': 'high',
                'cves': ['CVE-2019-11358'],
                'summary': 'Prototype Pollution vulnerability in jQuery.extend(true, {}, ...).',
                'remediation': 'Upgrade to jQuery 3.7.1 or newer.',
                'fixed_in': '3.4.0',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-11358',
            },
            {
                'at_least': '3.4.0',
                'below': '3.5.0',
                'severity': 'medium',
                'cves': ['CVE-2020-11022', 'CVE-2020-11023'],
                'summary': 'HTML Prefilter regex bypass allows XSS when passing untrusted HTML to DOM manipulation methods.',
                'remediation': 'Upgrade to jQuery 3.7.1 or newer.',
                'fixed_in': '3.5.0',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2020-11022',
            },
        ],
        'safe_version': '3.7.1'
    },

    # -------------------------------------------------------------------------
    # Bootstrap
    # -------------------------------------------------------------------------
    'bootstrap': {
        'name': 'Bootstrap',
        'url_patterns': [
            re.compile(r'(?:/|^)bootstrap[.-]([0-9]+(?:\.[0-9]+)+)(?:\.bundle|\.min)?\.js', re.IGNORECASE),
            re.compile(r'/bootstrap/([0-9]+(?:\.[0-9]+)+)/(?:js/)?bootstrap(?:\.bundle|\.min)?\.js', re.IGNORECASE),
            re.compile(r'npm/bootstrap@([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'(?:/\*!?|^\s*\*)\s*Bootstrap\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE | re.MULTILINE),
            re.compile(r'(?:tooltip|bootstrap)\.VERSION\s*[=:]\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
            re.compile(r'Bootstrap v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '3.4.0',
                'severity': 'medium',
                'cves': [
                    'CVE-2016-10735',
                    'CVE-2018-14040',
                    'CVE-2018-14042',
                    'CVE-2024-6485',
                ],
                'summary': 'Multiple XSS vulnerabilities in data-target, tooltip, and collapse plugins.',
                'remediation': 'Upgrade to Bootstrap 4.6.2+ or 5.3.3+.',
                'fixed_in': '3.4.0',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2016-10735',
            },
            {
                'at_least': '3.4.0',
                'below': '3.4.1',
                'severity': 'medium',
                'cves': ['CVE-2019-8331'],
                'summary': 'XSS in collapse data-parent attribute.',
                'remediation': 'Upgrade to Bootstrap 4.6.2+ or 5.3.3+.',
                'fixed_in': '3.4.1',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-8331',
            },
            {
                'at_least': '4.0.0',
                'below': '4.3.1',
                'severity': 'medium',
                'cves': ['CVE-2019-8331', 'CVE-2018-14041'],
                'summary': 'XSS in tooltip and popover plugins when rendering HTML content.',
                'remediation': 'Upgrade to Bootstrap 4.6.2+ or 5.3.3+.',
                'fixed_in': '4.3.1',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-8331',
            },
        ],
        'safe_version': '5.3.3'
    },

    # -------------------------------------------------------------------------
    # jquery-validation (Generic version: pattern removed to prevent FP)
    # -------------------------------------------------------------------------
    'jquery-validation': {
        'name': 'jquery-validation',
        'url_patterns': [
            re.compile(r'(?:/|^)jquery[._-]?valid(?:ate|ation)[._-]?([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'jQuery\s+Validation\s+Plugin\s*[-–]\s*v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'jQuery\s+Validation\s+Plugin\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'jquery-validation\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'(?:validator|validation)[^;{}]{0,80}\.version\s*[=:]\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '1.19.3',
                'severity': 'high',
                'cves': ['CVE-2021-21252', 'CVE-2021-43306'],
                'summary': 'Regular Expression Denial of Service (ReDoS) in URL validation methods.',
                'remediation': 'Upgrade to jquery-validation 1.20.0 or newer.',
                'fixed_in': '1.19.3',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-21252',
            },
            {
                'at_least': '1.19.3',
                'below': '1.19.6',
                'severity': 'high',
                'cves': ['CVE-2022-31147'],
                'summary': 'ReDoS vulnerability in URL2 validation regex.',
                'remediation': 'Upgrade to jquery-validation 1.20.0 or newer.',
                'fixed_in': '1.19.6',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2022-31147',
            },
            {
                'below': '1.20.0',
                'severity': 'medium',
                'cves': ['CVE-2025-3573'],
                'summary': 'Cross-Site Scripting (XSS) via showLabel error injection.',
                'remediation': 'Upgrade to jquery-validation 1.21.0 or newer.',
                'fixed_in': '1.20.0',
                'source_link': 'https://osv.dev/vulnerability/CVE-2025-3573',
            },
        ],
        'safe_version': '1.21.0'
    },

    # -------------------------------------------------------------------------
    # AngularJS
    # -------------------------------------------------------------------------
    'angularjs': {
        'name': 'AngularJS (1.x)',
        'url_patterns': [
            re.compile(r'(?:/|^)angular(?:js)?[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'/angular(?:js)?/([0-9]+(?:\.[0-9]+)+)/angular(?:\.min)?\.js', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*AngularJS\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'angular\.version\s*=\s*\{[^}]*full:\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '1.8.0',
                'severity': 'critical',
                'cves': ['CVE-2019-10768', 'CVE-2020-7676', 'CVE-2022-25869'],
                'summary': 'Universal Expression Sandbox Escape leading to arbitrary code execution / XSS.',
                'remediation': 'Migrate to modern Angular (v17+) or React/Vue.',
                'fixed_in': '1.8.0',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2020-7676',
            },
            {
                'at_least': '1.8.0',
                'below': '2.0.0',
                'severity': 'high',
                'cves': ['CVE-2022-25869', 'EOL-ANGULARJS'],
                'summary': 'AngularJS 1.x is officially End-of-Life (EOL) since January 2022.',
                'remediation': 'Migrate away from AngularJS 1.x to modern Angular or React.',
                'fixed_in': 'Migrate',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2022-25869',
            },
        ],
        'safe_version': 'Migrate to Angular 17+'
    },

    # -------------------------------------------------------------------------
    # Lodash (Generic var VERSION = pattern removed to prevent FP)
    # -------------------------------------------------------------------------
    'lodash': {
        'name': 'Lodash',
        'url_patterns': [
            re.compile(r'(?:/|^)lodash[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'/lodash(?:\.js)?/([0-9]+(?:\.[0-9]+)+)/lodash(?:\.min|\.compat)?\.js', re.IGNORECASE),
            re.compile(r'npm/lodash@([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'(?:/\*!*?|\b|\*)\s*(?:Lo-Dash|Lodash)\s+(?:Modularize\s+)?v?([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'lodash\.VERSION\s*=\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
            re.compile(r'/\*!*?\s*Lo-Dash\s+([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'(?:lodash|lo-dash)[^;{}]{0,100}VERSION\s*=\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '4.17.12',
                'severity': 'critical',
                'cves': ['CVE-2018-3721', 'CVE-2018-16487', 'CVE-2019-10744'],
                'summary': 'Critical Prototype Pollution in _.merge(), _.defaultsDeep(), and _.zipObjectDeep().',
                'remediation': 'Upgrade to Lodash 4.18.0 or newer.',
                'fixed_in': '4.17.12',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-10744',
            },
            {
                'at_least': '4.17.12',
                'below': '4.17.21',
                'severity': 'high',
                'cves': ['CVE-2020-8203', 'CVE-2021-23337'],
                'summary': 'Prototype Pollution in _.zipObjectDeep and Command Injection in _.template().',
                'remediation': 'Upgrade to Lodash 4.18.0 or newer.',
                'fixed_in': '4.17.21',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2020-8203',
            },
            {
                'at_least': '4.17.21',
                'below': '4.18.0',
                'severity': 'medium',
                'cves': ['CVE-2026-2950', 'GHSA-f23m-r3pf-42rh'],
                'summary': 'Prototype pollution bypass in _.unset and _.omit via array-wrapped path segments.',
                'remediation': 'Upgrade to Lodash 4.18.0 or newer.',
                'fixed_in': '4.18.0',
                'source_link': 'https://osv.dev/vulnerability/GHSA-f23m-r3pf-42rh',
            },
        ],
        'safe_version': '4.18.0'
    },

    # -------------------------------------------------------------------------
    # Moment.js
    # -------------------------------------------------------------------------
    'moment': {
        'name': 'Moment.js',
        'url_patterns': [
            re.compile(r'(?:/|^)moment[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'/moment(?:.js)?/([0-9]+(?:\.[0-9]+)+)/moment(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'npm/moment@([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*Moment\.js\s+([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'moment\.version\s*=\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '2.29.2',
                'severity': 'high',
                'cves': ['CVE-2022-24785'],
                'summary': 'Path Traversal vulnerability when loading locale files with user-controlled input.',
                'remediation': 'Upgrade to Moment.js 2.30.1 or migrate to date-fns/Luxon.',
                'fixed_in': '2.29.2',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2022-24785',
            },
            {
                'at_least': '2.29.2',
                'below': '2.29.4',
                'severity': 'high',
                'cves': ['CVE-2022-31129'],
                'summary': 'Regular Expression Denial of Service (ReDoS) vulnerability in date format parsing.',
                'remediation': 'Upgrade to Moment.js 2.30.1 or migrate to date-fns/Luxon.',
                'fixed_in': '2.29.4',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2022-31129',
            },
        ],
        'safe_version': '2.30.1'
    },

    # -------------------------------------------------------------------------
    # Vue.js
    # -------------------------------------------------------------------------
    'vue': {
        'name': 'Vue.js',
        'url_patterns': [
            re.compile(r'(?:/|^)vue[.-]([0-9]+(?:\.[0-9]+)+)(?:\.runtime|\.min|\.global)?\.js', re.IGNORECASE),
            re.compile(r'/vue/([0-9]+(?:\.[0-9]+)+)/vue(?:\.runtime|\.min)?\.js', re.IGNORECASE),
            re.compile(r'npm/vue@([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*Vue\.js\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'Vue\.version\s*=\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '2.6.14',
                'severity': 'medium',
                'cves': ['CVE-2024-6783'],
                'summary': 'XSS vulnerabilities during server-side template compilation and expression evaluation.',
                'remediation': 'Upgrade to Vue 3.4+.',
                'fixed_in': '2.6.14',
                'source_link': 'https://osv.dev/vulnerability/CVE-2024-6783',
            },
            {
                'at_least': '2.0.0',
                'below': '3.0.0',
                'severity': 'low',
                'cves': ['EOL-VUE2'],
                'summary': 'Vue 2 reached End-of-Life on Dec 31, 2023, and no longer receives official security updates.',
                'remediation': 'Upgrade to Vue 3.4+.',
                'fixed_in': '3.4.0',
                'source_link': 'https://v2.vuejs.org/eol/',
            },
        ],
        'safe_version': '3.4.0'
    },

    # -------------------------------------------------------------------------
    # React (node-fetch CVE-2020-15168 removed; clean rules)
    # -------------------------------------------------------------------------
    'react': {
        'name': 'React',
        'url_patterns': [
            re.compile(r'(?:/|^)react(?:-dom)?[.-]([0-9]+(?:\.[0-9]+)+)(?:\.production|\.development|\.min)?\.js', re.IGNORECASE),
            re.compile(r'/react/([0-9]+(?:\.[0-9]+)+)/react(?:\.production|\.development|\.min)?\.js', re.IGNORECASE),
            re.compile(r'npm/react@([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*React\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'React\.version\s*=\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
        ],
        'rules': [],
        'safe_version': '18.3.1'
    },

    # -------------------------------------------------------------------------
    # Axios
    # -------------------------------------------------------------------------
    'axios': {
        'name': 'Axios',
        'url_patterns': [
            re.compile(r'(?:/|^)axios[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'/axios/([0-9]+(?:\.[0-9]+)+)/axios(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'npm/axios@([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*axios\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '0.21.1',
                'severity': 'high',
                'cves': ['CVE-2020-28168'],
                'summary': 'Server-Side Request Forgery (SSRF) and header leakage via follow-redirects.',
                'remediation': 'Upgrade to Axios 1.7+.',
                'fixed_in': '0.21.1',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2020-28168',
            },
            {
                'at_least': '0.21.1',
                'below': '1.6.0',
                'severity': 'medium',
                'cves': ['CVE-2023-45857'],
                'summary': 'Cross-site request header leakage during HTTP redirects.',
                'remediation': 'Upgrade to Axios 1.7+.',
                'fixed_in': '1.6.0',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2023-45857',
            },
        ],
        'safe_version': '1.7.0'
    },

    # -------------------------------------------------------------------------
    # Handlebars
    # -------------------------------------------------------------------------
    'handlebars': {
        'name': 'Handlebars',
        'url_patterns': [
            re.compile(r'(?:/|^)handlebars[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'/handlebars(?:.js)?/([0-9]+(?:\.[0-9]+)+)/handlebars(?:\.min)?\.js', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*Handlebars\.js\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '4.7.7',
                'severity': 'critical',
                'cves': ['CVE-2021-23383', 'CVE-2019-19919'],
                'summary': 'Prototype Pollution leading to Arbitrary Code Execution via template compilation.',
                'remediation': 'Upgrade to Handlebars 4.7.8+.',
                'fixed_in': '4.7.7',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-23383',
            },
        ],
        'safe_version': '4.7.8'
    },

    # -------------------------------------------------------------------------
    # DOMPurify
    # -------------------------------------------------------------------------
    'dompurify': {
        'name': 'DOMPurify',
        'url_patterns': [
            re.compile(r'(?:/|^)purify[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'/dompurify/([0-9]+(?:\.[0-9]+)+)/purify(?:\.min)?\.js', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*DOMPurify\s+([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '2.4.0',
                'severity': 'high',
                'cves': ['CVE-2020-26870', 'CVE-2022-36034'],
                'summary': 'HTML Sanitization Bypass and mutation XSS (mXSS) allowing malicious script execution.',
                'remediation': 'Upgrade to DOMPurify 3.1+.',
                'fixed_in': '2.4.0',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2020-26870',
            },
        ],
        'safe_version': '3.1.0'
    },

    # -------------------------------------------------------------------------
    # TinyMCE
    # -------------------------------------------------------------------------
    'tinymce': {
        'name': 'TinyMCE',
        'url_patterns': [
            re.compile(r'(?:/|^)tinymce[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'/tinymce/([0-9]+(?:\.[0-9]+)+)/tinymce(?:\.min)?\.js', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*TinyMCE\s+([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '5.10.0',
                'severity': 'high',
                'cves': ['CVE-2022-23494'],
                'summary': 'Stored Cross-Site Scripting (XSS) via editor content filters.',
                'remediation': 'Upgrade to TinyMCE 6.8+.',
                'fixed_in': '5.10.0',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2022-23494',
            },
        ],
        'safe_version': '6.8.0'
    },

    # -------------------------------------------------------------------------
    # Underscore.js
    # -------------------------------------------------------------------------
    'underscore': {
        'name': 'Underscore.js',
        'url_patterns': [
            re.compile(r'(?:/|^)underscore[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
            re.compile(r'/underscore\.js/([0-9]+(?:\.[0-9]+)+)/underscore(?:-min)?\.js', re.IGNORECASE),
            re.compile(r'npm/underscore@([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'Underscore\.js\s+([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
            re.compile(r'_\.VERSION\s*=\s*["\']([0-9]+(?:\.[0-9]+)+)["\']', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '1.12.1',
                'severity': 'high',
                'cves': ['CVE-2021-23358'],
                'summary': 'Arbitrary code execution via the _.template function with user-controlled input.',
                'remediation': 'Upgrade to Underscore.js 1.13.7+.',
                'fixed_in': '1.12.1',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-23358',
            },
        ],
        'safe_version': '1.13.7'
    },

    # -------------------------------------------------------------------------
    # SweetAlert
    # -------------------------------------------------------------------------
    'sweetalert': {
        'name': 'SweetAlert',
        'url_patterns': [
            re.compile(r'(?:/|^)sweetalert[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*SweetAlert\s+v?([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '2.0.0',
                'severity': 'medium',
                'cves': ['CVE-2020-14013'],
                'summary': 'SweetAlert 1.x is unmaintained and susceptible to DOM XSS in modal content.',
                'remediation': 'Migrate to SweetAlert2 latest.',
                'fixed_in': '2.0.0',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2020-14013',
            },
        ],
        'safe_version': 'SweetAlert2 latest'
    },

    # -------------------------------------------------------------------------
    # Swiper
    # -------------------------------------------------------------------------
    'swiper': {
        'name': 'Swiper',
        'url_patterns': [
            re.compile(r'(?:/|^)swiper[.-]([0-9]+(?:\.[0-9]+)+)(?:\.bundle|\.min)?\.js', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*Swiper\s+([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '6.5.1',
                'severity': 'high',
                'cves': ['CVE-2021-23366'],
                'summary': 'DOM-based XSS vulnerability in Swiper carousel initialization.',
                'remediation': 'Upgrade to Swiper 11.0+.',
                'fixed_in': '6.5.1',
                'source_link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-23366',
            },
        ],
        'safe_version': '11.0.0'
    },

    # -------------------------------------------------------------------------
    # Popper.js
    # -------------------------------------------------------------------------
    'popper': {
        'name': 'Popper.js',
        'url_patterns': [
            re.compile(r'(?:/|^)popper[.-]([0-9]+(?:\.[0-9]+)+)(?:\.min)?\.js', re.IGNORECASE),
        ],
        'banner_patterns': [
            re.compile(r'/\*!*?\s*Popper\.js\s+v([0-9]+(?:\.[0-9]+)+)', re.IGNORECASE),
        ],
        'rules': [
            {
                'below': '2.0.0',
                'severity': 'low',
                'cves': ['EOL-POPPER1'],
                'summary': 'Popper 1.x is End-of-Life and deprecated in favor of Floating UI.',
                'remediation': 'Upgrade to Popper 2.x or Floating UI.',
                'fixed_in': '2.0.0',
                'source_link': 'https://floating-ui.com/',
            },
        ],
        'safe_version': '2.11.8'
    },
}


# ---------------------------------------------------------------------------
# Script Fetching & Content Scanning
# ---------------------------------------------------------------------------

def _fetch_script_content(src: str, base_url: str = '', max_bytes: int = 262144) -> tuple[str, bool]:
    """
    Fetches up to `max_bytes` (256 KB) of an external script with streaming.
    Handles relative and protocol-relative URLs (`//example.com/...`).
    Returns:
        (content_string: str, is_truncated: bool)
    """
    try:
        # Protocol-relative URL handling
        if src.startswith('//'):
            base_scheme = urllib.parse.urlparse(base_url).scheme or 'https'
            full_url = f"{base_scheme}:{src}"
        elif not src.startswith(('http://', 'https://')):
            full_url = urllib.parse.urljoin(base_url, src)
        else:
            full_url = src

        resp = requests.get(
            full_url,
            timeout=4.0,
            stream=True,
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; WebVulnScanner/2.0)'}
        )
        content_chunks = []
        total_len = 0
        is_truncated = False

        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                content_chunks.append(chunk)
                total_len += len(chunk)
                if total_len >= max_bytes:
                    is_truncated = True
                    break

        raw_bytes = b''.join(content_chunks)
        decoded = raw_bytes.decode('utf-8', errors='ignore')
        return (decoded, is_truncated)
    except Exception:
        return ('', False)


def _extract_query_version(url_str: str) -> str | None:
    """
    Extracts version from query string parameters: ?ver=, ?v=, ?version=, ?release=
    """
    try:
        parsed = urllib.parse.urlparse(url_str)
        if not parsed.query:
            return None
        params = urllib.parse.parse_qs(parsed.query)
        for key in ('ver', 'v', 'version', 'release'):
            if key in params and params[key]:
                candidate = params[key][0].strip().lstrip('v').lstrip('V')
                if re.match(r'^[0-9]+(?:\.[0-9]+)+', candidate):
                    return candidate
    except Exception:
        pass
    return None


def _is_plugin_or_theme_path(url_str: str) -> bool:
    """Detects CMS plugin or theme paths where ?ver= is often modified."""
    u = url_str.lower()
    return any(p in u for p in ('/plugins/', '/themes/', '/wp-content/plugins/', '/wp-content/themes/', '/assets/plugins/'))


def _is_known_core_path(url_str: str) -> bool:
    """Detects authoritative vendor/core library directories."""
    u = url_str.lower()
    return any(p in u for p in ('/wp-includes/', '/libs/', '/vendor/', '/cdn/', '/node_modules/'))


def _calculate_confidence(signals: list[str], has_conflict: bool = False) -> str:
    """
    Calculates component detection confidence: High, Medium, or Low.
    Rules:
      - Conflicting signals for the same library downgrade confidence to Low.
      - URL path and query string count as ONE signal source (Location).
      - High confidence requires agreement between independent sources (Location vs File Content).
      - A banner alone is Medium.
      - A URL path alone is Medium.
      - A query string alone (or on plugin/theme paths) is Low.
    """
    if has_conflict:
        return 'Low'

    plugin_theme_query = any('Plugin/Theme Path' in s for s in signals)
    has_location = any(s.startswith(('URL Path', 'Query String')) for s in signals)
    has_content = any(s.startswith(('Banner', 'Content')) for s in signals)
    content_count = sum(1 for s in signals if s.startswith(('Banner', 'Content')))

    # Query string on plugin/theme paths without content verification is capped at Low
    if plugin_theme_query and not has_content:
        return 'Low'

    # High requires agreement between independent sources (Location + File Content)
    if has_location and has_content:
        return 'High'

    # Multiple distinct content-level confirmations
    if content_count >= 2:
        return 'High'

    # A banner alone is Medium
    if has_content:
        return 'Medium'

    # A URL path regex alone is Medium
    if any(s.startswith('URL Path') for s in signals):
        return 'Medium'

    # Core path query string alone is trusted as library version: Medium
    if any('Core Path' in s for s in signals):
        return 'Medium'

    # Query string alone (or plugin/theme path) is Low
    return 'Low'


# ---------------------------------------------------------------------------
# Multi-Signal Component Detection
# ---------------------------------------------------------------------------

def detect_components(script_srcs: list[str], inline_scripts: list[str] = None, base_url: str = '') -> list[dict]:
    """
    Scans script URLs, query strings, inline scripts, and script content.
    Supports bundled vendor files (detecting multiple libraries per file).
    Identifies version conflicts and assigns confidence levels based on
    independent signal verification.
    """
    # Keyed by (lib_key, version) to capture all observed versions
    detected: dict[tuple[str, str], dict] = {}
    inline_scripts = inline_scripts or []

    # 1. URL Path & Query String Inspection
    for src in script_srcs:
        src_clean = src.split('?')[0]
        q_ver = _extract_query_version(src)

        matched_lib = False
        for lib_key, meta in RETIREJS_DB.items():
            # Check URL regex patterns
            for pat in meta['url_patterns']:
                m = pat.search(src_clean)
                if m and m.lastindex and m.lastindex >= 1:
                    v_str = m.group(1)
                    if re.match(r'^[0-9]+\.[0-9]+', v_str):
                        matched_lib = True
                        sig = f"URL Path: {src_clean.split('/')[-1]}"
                        dkey = (lib_key, v_str)
                        if dkey not in detected:
                            detected[dkey] = {
                                'key': lib_key,
                                'name': meta['name'],
                                'version': v_str,
                                'source': src,
                                'signals': [sig],
                                'truncated': False,
                            }
                        elif sig not in detected[dkey]['signals']:
                            detected[dkey]['signals'].append(sig)

            # Check query-string version on recognized library filenames
            fname = src_clean.rstrip('/').split('/')[-1].lower()
            if q_ver and (lib_key in fname or lib_key.replace('-', '') in fname.replace('-', '')):
                matched_lib = True
                if _is_plugin_or_theme_path(src):
                    sig = f"Query String (Plugin/Theme Path): ?ver={q_ver}"
                elif _is_known_core_path(src):
                    sig = f"Query String (Core Path): ?ver={q_ver}"
                else:
                    sig = f"Query String: ?ver={q_ver}"

                dkey = (lib_key, q_ver)
                if dkey not in detected:
                    detected[dkey] = {
                        'key': lib_key,
                        'name': meta['name'],
                        'version': q_ver,
                        'source': src,
                        'signals': [sig],
                        'truncated': False,
                    }
                elif sig not in detected[dkey]['signals']:
                    detected[dkey]['signals'].append(sig)

        # Unnamed / generic file with query version (e.g. bundle.js?ver=2.1.0)
        if q_ver and not matched_lib:
            fname = src_clean.rstrip('/').split('/')[-1]
            dkey = ('unnamed-script', q_ver)
            if dkey not in detected:
                detected[dkey] = {
                    'key': 'unnamed-script',
                    'name': f'Script Component ({fname})',
                    'version': q_ver,
                    'source': src,
                    'signals': [f"Query String on unnamed file: ?ver={q_ver}"],
                    'truncated': False,
                    'is_unnamed': True,
                }

    # 2. Inline Scripts Scanning
    for block in inline_scripts:
        if not block:
            continue
        snippet = block[:16384]
        for lib_key, meta in RETIREJS_DB.items():
            for pat in meta['banner_patterns']:
                m = pat.search(snippet)
                if m and m.lastindex and m.lastindex >= 1:
                    v_str = m.group(1)
                    sig = "Banner: Inline Script Tag"
                    dkey = (lib_key, v_str)
                    if dkey not in detected:
                        detected[dkey] = {
                            'key': lib_key,
                            'name': meta['name'],
                            'version': v_str,
                            'source': 'Inline Script Tag',
                            'signals': [sig],
                            'truncated': False,
                        }
                    elif sig not in detected[dkey]['signals']:
                        detected[dkey]['signals'].append(sig)

    # 3. External Script Content Inspection (concurrent with bounded ThreadPoolExecutor)
    # Allows bundled vendor scripts to match multiple libraries
    scripts_to_fetch = script_srcs[:16]
    fetched_contents = {}
    if scripts_to_fetch:
        import concurrent.futures
        def _fetch_worker(s):
            return s, _fetch_script_content(s, base_url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_src = {executor.submit(_fetch_worker, s): s for s in scripts_to_fetch}
            for fut in concurrent.futures.as_completed(future_to_src):
                try:
                    s, (content, is_truncated) = fut.result()
                    fetched_contents[s] = (content, is_truncated)
                except Exception:
                    pass

    for src in scripts_to_fetch:
        if src not in fetched_contents:
            continue
        content, is_truncated = fetched_contents[src]
        if not content:
            continue

        for lib_key, meta in RETIREJS_DB.items():
            for pat in meta['banner_patterns']:
                m = pat.search(content)
                if m and m.lastindex and m.lastindex >= 1:
                    v_str = m.group(1)
                    sig = "Banner: Script File Content"
                    dkey = (lib_key, v_str)
                    if dkey not in detected:
                        detected[dkey] = {
                            'key': lib_key,
                            'name': meta['name'],
                            'version': v_str,
                            'source': src,
                            'signals': [sig],
                            'truncated': is_truncated,
                        }
                    else:
                        if sig not in detected[dkey]['signals']:
                            detected[dkey]['signals'].append(sig)
                        if is_truncated:
                            detected[dkey]['truncated'] = True

    # 4. Check for Conflicting Signals Across Detections for Each Library
    lib_versions_map: dict[str, set[str]] = {}
    for (lib_k, ver_k) in detected.keys():
        if lib_k != 'unnamed-script':
            lib_versions_map.setdefault(lib_k, set()).add(ver_k)

    result = []
    for (lib_k, ver_k), item in detected.items():
        all_versions_for_lib = lib_versions_map.get(lib_k, {ver_k})
        has_conflict = len(all_versions_for_lib) > 1

        if has_conflict:
            sorted_vers = sorted(all_versions_for_lib)
            item['has_conflict'] = True
            item['conflicting_versions'] = sorted_vers
            conflict_sig = f"Conflict: {', '.join(sorted_vers)}"
            if conflict_sig not in item['signals']:
                item['signals'].append(conflict_sig)
        else:
            item['has_conflict'] = False
            item['conflicting_versions'] = [ver_k]

        item['confidence'] = _calculate_confidence(item['signals'], has_conflict=item['has_conflict'])
        item['method'] = ' + '.join(item['signals'])
        result.append(item)

    return result


# ---------------------------------------------------------------------------
# Main Scan Pipeline (scan_retirejs)
# ---------------------------------------------------------------------------

def scan_retirejs(script_srcs: list[str], inline_scripts: list[str] = None, base_url: str = '') -> tuple[list[dict], list[dict]]:
    """
    Main Retire.js analysis function.
    Performs component identification, queries live OSV.dev vulnerabilities,
    and falls back to local database when offline.
    Returns:
        findings:              list of vulnerability findings ready for the scanner pipeline
        components_inventory:  list of all detected components with security status
    """
    detected_list = detect_components(script_srcs, inline_scripts, base_url)
    findings = []
    components_inventory = []

    for item in detected_list:
        lib_key = item['key']
        ver_str = item['version']
        name = item['name']
        source = item['source']
        method = item.get('method', 'Unknown')
        confidence = item.get('confidence', 'Medium')
        is_truncated = item.get('truncated', False)
        is_unnamed = item.get('is_unnamed', False)

        # Unnamed script handling
        if is_unnamed:
            components_inventory.append({
                'name': name,
                'version': ver_str,
                'source': source,
                'method': method,
                'confidence': confidence,
                'is_vulnerable': False,
                'severity': 'info',
                'cves': [],
                'remediation': 'Verify third-party script source and integrity.',
                'status': 'REVIEW_REQUIRED',
                'data_source': 'Query String Analysis',
                'is_truncated': is_truncated,
            })
            continue

        # Unmapped library handling
        if lib_key not in RETIREJS_TO_NPM_MAP:
            components_inventory.append({
                'name': name,
                'version': ver_str,
                'source': source,
                'method': method,
                'confidence': confidence,
                'is_vulnerable': False,
                'severity': 'info',
                'cves': [],
                'fixed_in': 'N/A',
                'remediation': f"Package name mapping not found for '{lib_key}'. Manual dependency verification required.",
                'status': 'LOOKUP_FAILED',
                'data_source': 'Resolution Failed',
                'is_truncated': is_truncated,
            })
            continue

        meta = RETIREJS_DB.get(lib_key, {})
        npm_pkg = RETIREJS_TO_NPM_MAP.get(lib_key)
        sem_ver = SemVer(ver_str)

        # Check latest version on npm
        latest_npm = query_npm_latest_version(npm_pkg) if npm_pkg else None
        safe_version = latest_npm or meta.get('safe_version', 'Latest stable')

        # Live lookups: Retire.js jsrepository.json & OSV.dev
        repo_data, is_repo_live = fetch_retirejs_repository()
        repo_vulns = query_retirejs_repo_vulnerabilities(lib_key, ver_str, repo_data) if is_repo_live else []

        osv_vulns, is_osv_live = query_osv_vulnerabilities(npm_pkg, ver_str) if npm_pkg and sem_ver.is_valid else ([], False)
        is_live = is_osv_live or is_repo_live

        if is_live:
            # Combine and deduplicate live advisories from OSV.dev and Retire.js
            seen_ids = set()
            live_vulns = []
            for v in osv_vulns + repo_vulns:
                vid = v.get('primary_cve') or v.get('id')
                if vid not in seen_ids:
                    seen_ids.add(vid)
                    live_vulns.append(v)

            if live_vulns:
                all_cves = []
                for ov in live_vulns:
                    for c in ov.get('cves', []):
                        if c not in all_cves:
                            all_cves.append(c)

                sev_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                worst_ov = max(live_vulns, key=lambda v: sev_rank.get(v.get('severity', 'medium'), 0))
                fixed_in = worst_ov.get('fixed_version') or safe_version
                remediation = f"Upgrade to {name} {fixed_in} or newer."
                ref_link = worst_ov.get('reference_link') or f"https://osv.dev/vulnerability/{worst_ov['id']}"

                evidence_text = (
                    f"Component: {name} v{ver_str}\n"
                    f"Confidence: {confidence}\n"
                    f"Detection Signals: {method}\n"
                    f"Identified in: {source}\n"
                    f"Known CVEs: {', '.join(all_cves) if all_cves else worst_ov['id']}\n"
                    f"Fixed in Version: {fixed_in}\n"
                    f"Advisory Link: {ref_link}\n"
                    f"Data Source: OSV.dev / Retire.js (Live Lookup)"
                )
                if is_truncated:
                    evidence_text += "\nNote: Remote file was truncated at 256KB during analysis."

                findings.append({
                    'vuln_type': f'Outdated Component: {name} v{ver_str} (Live Lookup)',
                    'severity': worst_ov.get('severity', 'medium'),
                    'description': (
                        f"Live security advisory lookup detected vulnerabilities in '{name}' (version {ver_str}). "
                        f"{worst_ov['summary']} Fixed in: {fixed_in}. Remediation: {remediation}"
                    ),
                    'evidence': evidence_text,
                    'component': name,
                    'version': ver_str,
                    'confidence': confidence,
                    'cves': all_cves or [worst_ov['id']],
                    'cve_id': all_cves[0] if all_cves else worst_ov['id'],
                    'ref_id': all_cves[0] if all_cves else worst_ov['id'],
                    'fixed_in': fixed_in,
                    'source_link': ref_link,
                    'reference_link': ref_link,
                    'remediation': remediation,
                    'detection_method': f"{method} (Confidence: {confidence})",
                    'data_source': 'OSV.dev / Retire.js (Live)',
                })

                components_inventory.append({
                    'name': name,
                    'version': ver_str,
                    'source': source,
                    'method': method,
                    'confidence': confidence,
                    'is_vulnerable': True,
                    'severity': worst_ov.get('severity', 'medium'),
                    'cves': all_cves or [worst_ov['id']],
                    'fixed_in': fixed_in,
                    'remediation': remediation,
                    'status': 'VULNERABLE',
                    'data_source': 'OSV.dev / Retire.js (Live)',
                    'is_truncated': is_truncated,
                })
            else:
                # No vulnerabilities found in live databases
                components_inventory.append({
                    'name': name,
                    'version': ver_str,
                    'source': source,
                    'method': method,
                    'confidence': confidence,
                    'is_vulnerable': False,
                    'severity': 'info',
                    'cves': [],
                    'fixed_in': 'N/A',
                    'remediation': 'Up-to-date according to live security databases.',
                    'status': 'UP-TO-DATE',
                    'data_source': 'OSV.dev / Retire.js (Live)',
                    'is_truncated': is_truncated,
                })

        else:
            # Fallback to local offline RETIREJS_DB rules
            matched_rules = []
            if sem_ver.is_valid:
                for rule in meta.get('rules', []):
                    if is_version_vulnerable(sem_ver, below=rule.get('below'), at_least=rule.get('at_least')):
                        matched_rules.append(rule)

            vuln_rules = [r for r in matched_rules if not all(c.startswith('EOL-') for c in r.get('cves', []))]
            eol_rules  = [r for r in matched_rules if all(c.startswith('EOL-') for c in r.get('cves', []))]

            if matched_rules:
                sev_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                active_rules = vuln_rules if vuln_rules else eol_rules
                worst_rule = max(active_rules, key=lambda r: sev_rank.get(r['severity'], 0))

                all_cves = []
                for r in matched_rules:
                    for cve in r.get('cves', []):
                        if cve not in all_cves:
                            all_cves.append(cve)

                display_cves = [c for c in all_cves if not c.startswith('EOL-')]
                combined_summary = ' '.join(r['summary'] for r in matched_rules)
                remediation = worst_rule['remediation']
                fixed_in = worst_rule.get('fixed_in') or safe_version
                source_link = worst_rule.get('source_link') or (f"https://nvd.nist.gov/vuln/detail/{display_cves[0]}" if display_cves else 'https://owasp.org/')

                evidence_text = (
                    f"Component: {name} v{ver_str}\n"
                    f"Confidence: {confidence}\n"
                    f"Detection Signals: {method}\n"
                    f"Identified in: {source}\n"
                    f"Known CVEs: {', '.join(display_cves) if display_cves else 'EOL Advisory'}\n"
                    f"Fixed in Version: {fixed_in}\n"
                    f"Advisory Link: {source_link}\n"
                    f"Data Source: Local Offline Database (Fallback - live lookup unavailable; data may be outdated)"
                )
                if is_truncated:
                    evidence_text += "\nNote: Remote file was truncated at 256KB during analysis."

                findings.append({
                    'vuln_type': f'Outdated Component: {name} v{ver_str} (Local Offline Fallback)',
                    'severity': worst_rule['severity'],
                    'description': (
                        f"Retire.js local offline database detected vulnerable library '{name}' (version {ver_str}). "
                        f"{combined_summary} Fixed in: {fixed_in}. Remediation: {remediation} "
                        "(Note: Sourced from local offline fallback database; live lookup unavailable)."
                    ),
                    'evidence': evidence_text,
                    'component': name,
                    'version': ver_str,
                    'confidence': confidence,
                    'cves': display_cves,
                    'cve_id': display_cves[0] if display_cves else None,
                    'ref_id': display_cves[0] if display_cves else 'EOL-POLICY',
                    'fixed_in': fixed_in,
                    'source_link': source_link,
                    'reference_link': source_link,
                    'remediation': remediation,
                    'detection_method': f"{method} (Confidence: {confidence})",
                    'data_source': 'Local Offline Database (Fallback)',
                })

                components_inventory.append({
                    'name': name,
                    'version': ver_str,
                    'source': source,
                    'method': method,
                    'confidence': confidence,
                    'is_vulnerable': True,
                    'severity': worst_rule['severity'],
                    'cves': display_cves,
                    'fixed_in': fixed_in,
                    'remediation': remediation,
                    'status': 'VULNERABLE',
                    'data_source': 'Local Offline Database (Fallback)',
                    'is_truncated': is_truncated,
                })
            else:
                components_inventory.append({
                    'name': name,
                    'version': ver_str,
                    'source': source,
                    'method': method,
                    'confidence': confidence,
                    'is_vulnerable': False,
                    'severity': 'info',
                    'cves': [],
                    'fixed_in': 'N/A',
                    'remediation': 'Up-to-date according to local fallback rules (offline mode).',
                    'status': 'UP-TO-DATE',
                    'data_source': 'Local Offline Database (Fallback)',
                    'is_truncated': is_truncated,
                })

    return findings, components_inventory
