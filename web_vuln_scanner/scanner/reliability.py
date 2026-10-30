"""
reliability.py — Reliability helpers for the web vulnerability scanner.

Provides:
  - WAF/block detection from HTTP responses
  - Bounded exponential backoff retry for idempotent GETs
  - Global scan time budget tracking
  - Bounded TTL cache for OSV/npm/retire.js lookups
  - Scan status/coverage summary builder
"""
import time
import threading
import random
import requests
from collections import OrderedDict


# ─────────────────────────────────────────────────────────────────────────────
# Timeouts
# ─────────────────────────────────────────────────────────────────────────────
CONNECT_TIMEOUT_TARGET  = 4.0   # seconds to establish TCP connection to scanned site
READ_TIMEOUT_TARGET     = 8.0   # seconds to read the full response body
CONNECT_TIMEOUT_SCRIPT  = 3.0
READ_TIMEOUT_SCRIPT     = 6.0
CONNECT_TIMEOUT_API     = 2.5   # OSV / npm / retire.js
READ_TIMEOUT_API        = 5.0
GLOBAL_SCAN_BUDGET      = 45.0  # total seconds allowed for one full scan


# ─────────────────────────────────────────────────────────────────────────────
# WAF / Block Detection
# ─────────────────────────────────────────────────────────────────────────────
_WAF_STATUS_CODES = {403, 406, 429, 503}

_WAF_HEADER_MARKERS = [
    ('cf-mitigated', None),          # Cloudflare challenge/block
    ('x-amzn-waf-action', None),     # AWS WAF
    ('x-akamai-edgescape', None),    # Akamai
    ('x-cdn', 'imperva'),            # Imperva
]

_WAF_BODY_MARKERS = [
    'just a moment',                 # Cloudflare challenge page text
    'please wait while we verify',  # Cloudflare JS challenge
    'enable javascript',
    'checking your browser',
    '_cf_chl_',                      # Cloudflare challenge form field
    'g-recaptcha',                   # reCAPTCHA
    'ddos-guard',
    'sucuri website firewall',
    'incapsula incident id',         # Imperva/Incapsula
    'sorry, you have been blocked',
]


class ScanStatus:
    COMPLETE = 'complete'
    PARTIAL  = 'partial_timeout'
    BLOCKED  = 'blocked'
    FAILED   = 'failed'


def detect_waf_or_block(response: requests.Response) -> tuple:
    """
    Inspects a requests.Response and returns (is_blocked, reason_str).
    Checks: HTTP status codes, WAF-specific headers, and challenge-page body markers.
    """
    # Status-code check
    if response.status_code in _WAF_STATUS_CODES:
        status_reasons = {
            403: 'Access Forbidden (403)',
            406: 'Not Acceptable / WAF block (406)',
            429: 'Rate Limited (429)',
            503: 'Service Unavailable / WAF challenge (503)',
        }
        reason = status_reasons.get(response.status_code, f'HTTP {response.status_code}')
        return True, reason

    # Header-based WAF markers
    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
    for header, value in _WAF_HEADER_MARKERS:
        if header in headers_lower:
            if value is None or value in headers_lower[header]:
                return True, f'WAF header detected: {header}'

    # Body-based challenge page markers
    try:
        body_lower = response.text[:8192].lower()
        for marker in _WAF_BODY_MARKERS:
            if marker in body_lower:
                return True, f'Challenge page detected: "{marker}"'
        # Tiny HTML with no <script> tags is suspicious
        if len(response.text) < 2048 and '<script' not in body_lower:
            return True, 'Suspiciously small HTML response with no scripts (possible challenge page)'
    except Exception:
        pass

    return False, ''


# ─────────────────────────────────────────────────────────────────────────────
# Retry with exponential backoff + jitter
# ─────────────────────────────────────────────────────────────────────────────
def retry_get(
    url,
    *,
    timeout,
    max_retries=2,
    base_delay=1.0,
    headers=None,
    verify=True,
    stream=False,
    allow_redirects=True,
    budget=None,
):
    """
    Performs a GET request with bounded exponential backoff and jitter.
    Only retries on network errors and 429/503 with Retry-After; never on 4xx/5xx otherwise.
    Returns None if all attempts fail or the budget is exhausted.
    """
    headers = headers or {'User-Agent': 'Mozilla/5.0 (compatible; WebVulnScanner/2.0)'}
    for attempt in range(max_retries + 1):
        if budget and budget.is_expired():
            return None
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers=headers,
                verify=verify,
                stream=stream,
                allow_redirects=allow_redirects,
            )
            # Honor Retry-After on 429 and 503
            if resp.status_code in (429, 503) and attempt < max_retries:
                retry_after = _parse_retry_after(resp.headers.get('Retry-After'))
                delay = retry_after if retry_after else (base_delay * (2 ** attempt) + random.uniform(0, 1))
                if budget and not budget.can_sleep(delay):
                    return resp   # return what we have
                time.sleep(delay)
                continue
            return resp
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            if attempt < max_retries:
                delay = base_delay * (2 ** attempt) + random.uniform(0, 0.5)
                if budget and not budget.can_sleep(delay):
                    return None
                time.sleep(delay)
            else:
                return None
        except Exception:
            return None
    return None


def _parse_retry_after(header_val):
    """Returns the Retry-After value as seconds (float), or None if unparseable."""
    if not header_val:
        return None
    try:
        return float(header_val)
    except (ValueError, TypeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Global Scan Budget
# ─────────────────────────────────────────────────────────────────────────────
class ScanBudget:
    """
    Tracks total wall-clock time for one scan. When the budget expires, callers
    should return partial results rather than continuing.
    """
    def __init__(self, total_seconds=GLOBAL_SCAN_BUDGET):
        self._deadline = time.monotonic() + total_seconds
        self._total = total_seconds

    def is_expired(self):
        return time.monotonic() >= self._deadline

    def remaining(self):
        return max(0.0, self._deadline - time.monotonic())

    def can_sleep(self, seconds):
        """Returns True if sleeping for `seconds` would not exceed the deadline."""
        return (time.monotonic() + seconds) < self._deadline

    def clamp_timeout(self, connect, read):
        """Reduces timeouts to fit within the remaining budget."""
        rem = self.remaining()
        return (min(connect, rem * 0.4), min(read, rem * 0.6))


# ─────────────────────────────────────────────────────────────────────────────
# Bounded TTL Cache
# ─────────────────────────────────────────────────────────────────────────────
class BoundedTTLCache:
    """
    Thread-safe in-memory cache with a max-size limit and TTL expiry.
    Evicts oldest entries when full (LRU-style).
    """
    def __init__(self, maxsize=256, ttl=3600.0):
        self._store = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl
        self._lock = threading.Lock()

    def get(self, key):
        """Returns (hit, value). Returns (False, None) on miss or expiry."""
        with self._lock:
            if key not in self._store:
                return False, None
            ts, val = self._store[key]
            if time.monotonic() - ts > self._ttl:
                del self._store[key]
                return False, None
            self._store.move_to_end(key)
            return True, val

    def set(self, key, value):
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (time.monotonic(), value)
            while len(self._store) > self._maxsize:
                self._store.popitem(last=False)

    def __contains__(self, key):
        hit, _ = self.get(key)
        return hit

    def __getitem__(self, key):
        hit, val = self.get(key)
        if not hit:
            raise KeyError(key)
        return val

    def __setitem__(self, key, value):
        self.set(key, value)

    def __len__(self):
        return len(self._store)


# ─────────────────────────────────────────────────────────────────────────────
# SSRF & Private IP Protection
# ─────────────────────────────────────────────────────────────────────────────
import ipaddress


def is_private_ip(ip_str: str) -> bool:
    """Checks whether an IP address belongs to private, loopback, or link-local blocks."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_multicast or
            ip.is_unspecified
        )
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Coverage Summary
# ─────────────────────────────────────────────────────────────────────────────
class CoverageSummary:
    """
    Tracks which checks ran, which were skipped, and why — for display in the
    UI result page and the PDF report.
    """
    def __init__(self):
        self._ran = []
        self._skipped = []  # list of (check_name, reason)
        self.scan_status = ScanStatus.COMPLETE
        self.is_waf_blocked = False
        self.waf_reason = ''

    def mark_ran(self, check_name):
        self._ran.append(check_name)

    def mark_skipped(self, check_name, reason):
        self._skipped.append((check_name, reason))

    def to_dict(self):
        return {
            'scan_status': self.scan_status,
            'checks_ran': self._ran,
            'checks_skipped': [{'check': n, 'reason': r} for n, r in self._skipped],
            'is_waf_blocked': self.is_waf_blocked,
            'waf_reason': self.waf_reason,
        }
