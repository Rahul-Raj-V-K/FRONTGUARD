"""
test_phase4_reliability.py
===========================
Comprehensive unit tests for Phase 4 Reliability & Phase 5 Verifications:
- WAF and challenge page detection (Cloudflare, Akamai, Imperva, 403, 429, 503)
- Bounded exponential backoff retry and Retry-After header honoring
- Global scan time budget tracking and timeout handling
- Bounded TTL thread-safe caching with LRU eviction
- SSRF prevention (private and loopback IP blocking)
- Coverage summary tracking
- Real-world pinned fixture verification (jQuery, Bootstrap, Lodash)
"""

import time
import os
import sys
import threading
import unittest.mock as mock
import pytest
import requests

sys.path.insert(0, os.path.dirname(__file__))

from scanner.reliability import (
    detect_waf_or_block,
    retry_get,
    ScanBudget,
    BoundedTTLCache,
    CoverageSummary,
    ScanStatus,
    is_private_ip,
    _parse_retry_after,
)
from scanner.retirejs import detect_components


# ---------------------------------------------------------------------------
# 1. WAF & Challenge Page Detection
# ---------------------------------------------------------------------------

class TestWAFDetection:
    def _make_resp(self, status=200, headers=None, body='<html><head></head><body><script>var x=1;</script></body></html>'):
        resp = mock.MagicMock(spec=requests.Response)
        resp.status_code = status
        resp.headers = headers or {}
        resp.text = body
        return resp

    def test_403_is_blocked(self):
        resp = self._make_resp(status=403)
        blocked, reason = detect_waf_or_block(resp)
        assert blocked is True
        assert '403' in reason

    def test_429_is_rate_limited(self):
        resp = self._make_resp(status=429)
        blocked, reason = detect_waf_or_block(resp)
        assert blocked is True
        assert '429' in reason

    def test_503_is_blocked(self):
        resp = self._make_resp(status=503)
        blocked, reason = detect_waf_or_block(resp)
        assert blocked is True
        assert '503' in reason

    def test_cloudflare_mitigated_header_detected(self):
        resp = self._make_resp(headers={'cf-mitigated': 'challenge'})
        blocked, reason = detect_waf_or_block(resp)
        assert blocked is True
        assert 'cf-mitigated' in reason

    def test_cloudflare_challenge_body_detected(self):
        resp = self._make_resp(body='<html><head><title>Just a moment...</title></head><body>Please wait</body></html>')
        blocked, reason = detect_waf_or_block(resp)
        assert blocked is True
        assert 'just a moment' in reason.lower()

    def test_tiny_html_no_scripts_detected(self):
        resp = self._make_resp(body='<html><body>Access denied by security policy</body></html>')
        blocked, reason = detect_waf_or_block(resp)
        assert blocked is True

    def test_normal_page_not_blocked(self):
        body = '<html><head></head><body>' + '<p>Legitimate content</p>' * 60 + '<script>var app = {};</script></body></html>'
        resp = self._make_resp(status=200, body=body)
        blocked, _ = detect_waf_or_block(resp)
        assert blocked is False

    def test_recaptcha_body_detected(self):
        resp = self._make_resp(body='<html><body><div class="g-recaptcha" data-sitekey="123"></div></body></html>')
        blocked, reason = detect_waf_or_block(resp)
        assert blocked is True


# ---------------------------------------------------------------------------
# 2. Retry with Exponential Backoff & Retry-After Header
# ---------------------------------------------------------------------------

class TestRetryGet:
    def test_success_on_first_attempt(self):
        mock_resp = mock.MagicMock(spec=requests.Response)
        mock_resp.status_code = 200
        with mock.patch('scanner.reliability.requests.get', return_value=mock_resp) as mock_get:
            result = retry_get('https://example.com', timeout=(2.0, 4.0), max_retries=2)
        assert result is mock_resp
        assert mock_get.call_count == 1

    def test_retries_on_connection_error(self):
        mock_resp = mock.MagicMock(spec=requests.Response)
        mock_resp.status_code = 200
        side_effects = [requests.exceptions.ConnectionError('Network unreachable'), mock_resp]
        with mock.patch('scanner.reliability.requests.get', side_effect=side_effects):
            with mock.patch('scanner.reliability.time.sleep'):
                result = retry_get('https://example.com', timeout=(2.0, 4.0), max_retries=2)
        assert result is mock_resp

    def test_gives_up_after_max_retries(self):
        with mock.patch('scanner.reliability.requests.get', side_effect=requests.exceptions.ConnectionError('fail')):
            with mock.patch('scanner.reliability.time.sleep'):
                result = retry_get('https://example.com', timeout=(2.0, 4.0), max_retries=1)
        assert result is None

    def test_honors_retry_after_header(self):
        mock_429 = mock.MagicMock(spec=requests.Response)
        mock_429.status_code = 429
        mock_429.headers = {'Retry-After': '3'}
        mock_200 = mock.MagicMock(spec=requests.Response)
        mock_200.status_code = 200

        sleep_calls = []
        with mock.patch('scanner.reliability.requests.get', side_effect=[mock_429, mock_200]):
            with mock.patch('scanner.reliability.time.sleep', side_effect=lambda s: sleep_calls.append(s)):
                result = retry_get('https://example.com', timeout=(2.0, 4.0), max_retries=2)
        assert result is mock_200
        assert any(s == 3.0 for s in sleep_calls)

    def test_budget_stops_retry(self):
        budget = ScanBudget(total_seconds=0.001)
        time.sleep(0.003)  # Expire budget
        with mock.patch('scanner.reliability.requests.get', side_effect=requests.exceptions.ConnectionError('fail')):
            result = retry_get('https://example.com', timeout=(2.0, 4.0), max_retries=2, budget=budget)
        assert result is None


# ---------------------------------------------------------------------------
# 3. Scan Time Budget Tracking
# ---------------------------------------------------------------------------

class TestScanBudget:
    def test_not_expired_initially(self):
        budget = ScanBudget(total_seconds=15)
        assert budget.is_expired() is False

    def test_expires_after_time(self):
        budget = ScanBudget(total_seconds=0.001)
        time.sleep(0.01)
        assert budget.is_expired() is True

    def test_remaining_positive_initially(self):
        budget = ScanBudget(total_seconds=15)
        assert budget.remaining() > 14.0

    def test_can_sleep_true_within_budget(self):
        budget = ScanBudget(total_seconds=15)
        assert budget.can_sleep(2.0) is True

    def test_can_sleep_false_when_exceeding(self):
        budget = ScanBudget(total_seconds=0.01)
        time.sleep(0.005)
        assert budget.can_sleep(100.0) is False


# ---------------------------------------------------------------------------
# 4. Bounded TTL Cache
# ---------------------------------------------------------------------------

class TestBoundedTTLCache:
    def test_miss_returns_false(self):
        cache = BoundedTTLCache(maxsize=10, ttl=60)
        hit, val = cache.get('nonexistent')
        assert hit is False
        assert val is None

    def test_set_and_get(self):
        cache = BoundedTTLCache(maxsize=10, ttl=60)
        cache.set('key1', 'value1')
        hit, val = cache.get('key1')
        assert hit is True
        assert val == 'value1'

    def test_dict_interface_support(self):
        cache = BoundedTTLCache(maxsize=10, ttl=60)
        cache['foo'] = 'bar'
        assert 'foo' in cache
        assert cache['foo'] == 'bar'
        assert 'missing' not in cache

    def test_ttl_expiry(self):
        cache = BoundedTTLCache(maxsize=10, ttl=0.01)
        cache.set('temp', 123)
        time.sleep(0.03)
        hit, val = cache.get('temp')
        assert hit is False

    def test_maxsize_lru_eviction(self):
        cache = BoundedTTLCache(maxsize=3, ttl=60)
        cache.set('a', 1)
        cache.set('b', 2)
        cache.set('c', 3)
        cache.set('d', 4)  # Must evict 'a'
        assert len(cache) == 3
        hit, _ = cache.get('a')
        assert hit is False
        assert cache['d'] == 4

    def test_thread_safety(self):
        cache = BoundedTTLCache(maxsize=100, ttl=60)
        errors = []

        def worker(idx):
            try:
                cache.set(f'k_{idx}', idx)
                _ = cache.get(f'k_{idx}')
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# 5. SSRF / Private IP Protection
# ---------------------------------------------------------------------------

class TestSSRFProtection:
    def test_loopback_is_private(self):
        assert is_private_ip('127.0.0.1') is True
        assert is_private_ip('127.0.1.1') is True
        assert is_private_ip('::1') is True

    def test_rfc1918_private_ips(self):
        assert is_private_ip('10.0.0.1') is True
        assert is_private_ip('172.16.0.5') is True
        assert is_private_ip('192.168.1.1') is True
        assert is_private_ip('169.254.169.254') is True  # AWS metadata

    def test_public_ips_are_allowed(self):
        assert is_private_ip('8.8.8.8') is False
        assert is_private_ip('1.1.1.1') is False
        assert is_private_ip('93.184.216.34') is False

    def test_invalid_ips_handled_safely(self):
        assert is_private_ip('invalid-ip') is False
        assert is_private_ip('') is False
        assert is_private_ip(None) is False


# ---------------------------------------------------------------------------
# 6. Real-World Fixture Verification Tests
# ---------------------------------------------------------------------------

class TestFixtureDetections:
    """Verifies that pinned real-world JS files are accurately detected."""

    def _read_fixture(self, name):
        fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', name)
        with open(fixture_path, 'r', encoding='utf-8') as f:
            return f.read()

    def test_real_jquery_fixture_detected(self):
        content = self._read_fixture('jquery-3.5.1.min.js')
        with mock.patch('scanner.retirejs._fetch_script_content', return_value=(content, False)):
            detected = detect_components(['https://example.com/assets/jquery-3.5.1.min.js'])
        jq = next((d for d in detected if d['key'] == 'jquery'), None)
        assert jq is not None
        assert jq['version'] == '3.5.1'
        # Combined URL path + File content banner => High confidence
        assert jq['confidence'] == 'High'

    def test_real_bootstrap_fixture_detected(self):
        content = self._read_fixture('bootstrap-4.6.0.js')
        with mock.patch('scanner.retirejs._fetch_script_content', return_value=(content, False)):
            detected = detect_components(['https://example.com/assets/bootstrap-4.6.0.js'])
        bs = next((d for d in detected if d['key'] == 'bootstrap'), None)
        assert bs is not None
        assert bs['version'] == '4.6.0'
        assert bs['confidence'] == 'High'

    def test_real_lodash_fixture_detected(self):
        content = self._read_fixture('lodash-4.17.20.js')
        with mock.patch('scanner.retirejs._fetch_script_content', return_value=(content, False)):
            detected = detect_components(['https://example.com/assets/lodash-4.17.20.js'])
        ld = next((d for d in detected if d['key'] == 'lodash'), None)
        assert ld is not None
        assert ld['version'] == '4.17.20'
        assert ld['confidence'] == 'High'

    def test_fixture_banner_alone_is_medium_confidence(self):
        """When the file URL has no version (e.g. bundle.js), banner alone yields Medium."""
        content = self._read_fixture('jquery-3.5.1.min.js')
        with mock.patch('scanner.retirejs._fetch_script_content', return_value=(content, False)):
            detected = detect_components(['https://example.com/app.js'])
        jq = next((d for d in detected if d['key'] == 'jquery'), None)
        assert jq is not None
        assert jq['version'] == '3.5.1'
        assert jq['confidence'] == 'Medium'


# ---------------------------------------------------------------------------
# 7. Coverage Summary
# ---------------------------------------------------------------------------

class TestCoverageSummary:
    def test_coverage_tracking(self):
        cov = CoverageSummary()
        cov.mark_ran('dns_resolution')
        cov.mark_ran('tls_verification')
        cov.mark_skipped('script_fetch', 'WAF challenge presented')
        cov.is_waf_blocked = True
        cov.waf_reason = 'Cloudflare challenge'
        cov.scan_status = ScanStatus.BLOCKED

        d = cov.to_dict()
        assert d['scan_status'] == 'blocked'
        assert 'dns_resolution' in d['checks_ran']
        assert d['checks_skipped'][0]['check'] == 'script_fetch'
        assert d['is_waf_blocked'] is True
        assert d['waf_reason'] == 'Cloudflare challenge'


# ---------------------------------------------------------------------------
# 8. Local Test Pages & Benchmarks (Expected vs Actual Verification)
# ---------------------------------------------------------------------------

class TestLocalBenchmarks:
    """
    Executes scanner logic against the 3 reference test pages:
      1. Weak CSP & Info Disclosure (weak_csp.html)
      2. Outdated Library (old_jquery.html)
      3. Hardened Production Controls (hardened_page.html)
    """

    def test_weak_csp_benchmark_page(self):
        from scanner.matcher import run_matcher
        weak_headers = {
            'content-security-policy': "default-src * 'unsafe-inline' 'unsafe-eval';",
            'strict-transport-security': 'max-age=0',
            'server': 'Apache/2.4.41 (Ubuntu)',
            'x-powered-by': 'PHP/7.4.3',
        }
        findings = run_matcher(
            headers=weak_headers,
            scripts=[],
            inline_scripts=["eval(\"var test = 'insecure';\");"],
            target_url="https://benchmark.local/weak_csp.html"
        )
        types = [f['vuln_type'] for f in findings]
        # Must flag: 'unsafe-inline', 'unsafe-eval', wildcard default-src, HSTS max-age=0, Server disclosure, X-Powered-By
        assert any("'unsafe-inline'" in t for t in types)
        assert any("'unsafe-eval'" in t for t in types)
        assert any("Wildcard" in t for t in types)
        assert any("max-age=0" in t for t in types)
        assert any("server" in t.lower() for t in types)
        assert any("x-powered-by" in t.lower() for t in types)

    def test_old_jquery_benchmark_page(self):
        from scanner.retirejs import detect_components, scan_retirejs
        url = "https://benchmark.local/old_jquery.html"
        scripts = ["https://code.jquery.com/jquery-1.8.2.min.js"]
        inline = ["/*! jQuery v1.8.2 jquery.com | jquery.org/license */\nvar appVersion = '1.0.0';"]
        
        detected = detect_components(scripts, inline_scripts=inline)
        jq = next((d for d in detected if d['key'] == 'jquery'), None)
        assert jq is not None
        assert jq['version'] == '1.8.2'
        assert jq['confidence'] == 'High'

        findings, inventory = scan_retirejs(scripts, inline_scripts=inline)
        assert len(findings) >= 1
        vuln_cves = findings[0]['cves']
        assert 'CVE-2012-6708' in vuln_cves or 'CVE-2015-9251' in vuln_cves

    def test_hardened_page_benchmark(self):
        from scanner.matcher import run_matcher
        hardened_headers = {
            'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-rAnd0m123'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
            'x-frame-options': 'DENY',
            'x-content-type-options': 'nosniff',
            'referrer-policy': 'strict-origin-when-cross-origin',
            'permissions-policy': 'geolocation=(), camera=(), microphone=(), payment=()',
            'cross-origin-opener-policy': 'same-origin',
            'cross-origin-resource-policy': 'same-origin',
            'cross-origin-embedder-policy': 'require-corp',
        }
        findings = run_matcher(
            headers=hardened_headers,
            scripts=[],
            inline_scripts=[],
            target_url="https://benchmark.local/hardened_page.html"
        )
        # Should have ZERO security header findings on a fully hardened page
        assert len(findings) == 0, f"Expected 0 findings on hardened page, got: {[f['vuln_type'] for f in findings]}"


# ---------------------------------------------------------------------------
# 8. Audit Ledger & Target History Clearing Tests
# ---------------------------------------------------------------------------

class TestAuditLedgerClearing:
    def test_clear_scan_history_deletes_records(self):
        from database.db_handler import insert_scan_record, get_scan_history, clear_scan_history
        insert_scan_record('https://example.com/test-clear', findings_count=2, risk_level='medium', pdf_path='/fake/path.pdf')
        history_before = get_scan_history()
        assert len(history_before) >= 1

        deleted_count = clear_scan_history()
        assert deleted_count >= 1

        history_after = get_scan_history()
        assert len(history_after) == 0

    def test_clear_history_flask_route(self):
        from main import app
        from database.db_handler import insert_scan_record
        insert_scan_record('https://example.com/test-flask-clear', findings_count=1, risk_level='low', pdf_path='/fake/path2.pdf')

        client = app.test_client()
        resp = client.post('/clear-history', follow_redirects=True)
        assert resp.status_code == 200
        assert 'Audit Ledger successfully cleared' in resp.data.decode()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
