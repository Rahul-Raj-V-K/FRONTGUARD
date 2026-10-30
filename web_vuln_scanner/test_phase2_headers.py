"""
test_phase2_headers.py
======================
Unit tests for Phase 2 header accuracy improvements.

Every test uses only in-process dict inputs — no network calls, no mocking needed.
Run with:  python -m pytest web_vuln_scanner/test_phase2_headers.py -v

Structure
---------
Each test class covers one header or feature.
Each test method documents WHAT it tests, WHAT the expected result is, and WHY.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from scanner.matcher import (
    check_security_headers,
    check_xss_sinks,
    _check_csp,
    _check_hsts,
    _check_xfo,
    _check_xcto,
    _check_referrer_policy,
    _check_permissions_policy,
    _check_coop,
    _check_corp,
    _check_coep,
    _check_dangerous_headers,
    _check_deprecated_headers,
    _check_duplicate_headers,
    _parse_csp_directives,
    _server_discloses_version,
)
from scanner.extractor import _probe_http_headers


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def vuln_types(findings):
    """Return the set of vuln_type strings from a findings list."""
    return {f['vuln_type'] for f in findings}


def has_vuln(findings, substring):
    """True if any finding's vuln_type contains the substring."""
    return any(substring.lower() in f['vuln_type'].lower() for f in findings)


# ---------------------------------------------------------------------------
# _parse_csp_directives
# ---------------------------------------------------------------------------

class TestParseCspDirectives:
    def test_basic_parsing(self):
        result = _parse_csp_directives("default-src 'self'; script-src 'self' cdn.com")
        assert result['default-src'] == ["'self'"]
        assert result['script-src'] == ["'self'", 'cdn.com']

    def test_empty_string(self):
        assert _parse_csp_directives('') == {}

    def test_trailing_semicolon(self):
        result = _parse_csp_directives("default-src 'self';")
        assert 'default-src' in result

    def test_case_insensitive_directive_names(self):
        result = _parse_csp_directives("Default-Src 'self'")
        assert 'default-src' in result

    def test_multiple_sources(self):
        result = _parse_csp_directives("script-src 'self' 'unsafe-inline' cdn.example.com")
        assert "'unsafe-inline'" in result['script-src']
        assert 'cdn.example.com' in result['script-src']


# ---------------------------------------------------------------------------
# _server_discloses_version
# ---------------------------------------------------------------------------

class TestServerVersionDetection:
    def test_versioned_apache(self):
        assert _server_discloses_version('Apache/2.4.49 (Ubuntu)') is True

    def test_versioned_nginx(self):
        assert _server_discloses_version('nginx/1.18.0') is True

    def test_unversioned_cloudflare(self):
        # 'cloudflare' alone is NOT a version disclosure
        assert _server_discloses_version('cloudflare') is False

    def test_unversioned_nginx(self):
        assert _server_discloses_version('nginx') is False

    def test_empty_string(self):
        assert _server_discloses_version('') is False

    def test_openresty_versioned(self):
        assert _server_discloses_version('openresty/1.21.4.1') is True


# ---------------------------------------------------------------------------
# CSP checks
# ---------------------------------------------------------------------------

class TestCSPAbsent:
    def test_no_csp_at_all_is_flagged(self):
        findings = _check_csp({})
        assert has_vuln(findings, 'missing security header: content-security-policy')

    def test_report_only_without_enforced_is_medium(self):
        """
        BEFORE: report-only was treated as absent (would fire 'missing CSP').
        AFTER:  report-only triggers a separate 'present but not enforced' finding at medium.
        """
        findings = _check_csp({
            'content-security-policy-report-only': "default-src 'self'"
        })
        assert has_vuln(findings, 'not enforced')
        assert findings[0]['severity'] == 'medium'
        # Must NOT fire the 'missing' finding too
        assert not has_vuln(findings, 'missing security header: content-security-policy')


class TestCSPUnsafeInline:
    def test_unsafe_inline_in_script_src_flagged(self):
        """
        BEFORE: 'unsafe-inline' in CSP value was never checked → false negative.
        AFTER:  flagged at high severity.
        """
        findings = _check_csp({
            'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'"
        })
        assert has_vuln(findings, "'unsafe-inline'")
        inline_finding = next(f for f in findings if "'unsafe-inline'" in f['vuln_type'])
        assert inline_finding['severity'] == 'high'

    def test_unsafe_inline_via_default_src_fallback(self):
        """When script-src is absent, default-src is the fallback per spec."""
        findings = _check_csp({
            'content-security-policy': "default-src 'self' 'unsafe-inline'"
        })
        assert has_vuln(findings, "'unsafe-inline'")

    def test_safe_csp_no_unsafe_inline_finding(self):
        findings = _check_csp({
            'content-security-policy': (
                "default-src 'self'; script-src 'self'; object-src 'none'; "
                "base-uri 'self'; frame-ancestors 'none'"
            )
        })
        assert not has_vuln(findings, "'unsafe-inline'")

    def test_unsafe_inline_ignored_with_nonce(self):
        """Per CSP Level 2/3 spec: modern browsers ignore 'unsafe-inline' if nonce is present."""
        findings = _check_csp({
            'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-rAnd0m123'"
        })
        assert not has_vuln(findings, "'unsafe-inline'")

    def test_unsafe_inline_ignored_with_hash(self):
        """Per CSP Level 2/3 spec: modern browsers ignore 'unsafe-inline' if sha256 hash is present."""
        findings = _check_csp({
            'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'sha256-abc123xyz'"
        })
        assert not has_vuln(findings, "'unsafe-inline'")

    def test_unsafe_inline_ignored_with_strict_dynamic(self):
        """Per CSP Level 3 spec: modern browsers ignore 'unsafe-inline' if 'strict-dynamic' is present."""
        findings = _check_csp({
            'content-security-policy': "default-src 'self'; script-src 'unsafe-inline' 'strict-dynamic'"
        })
        assert not has_vuln(findings, "'unsafe-inline'")


class TestCSPUnsafeEval:
    def test_unsafe_eval_flagged(self):
        """
        BEFORE: never checked.
        AFTER: flagged at high severity.
        """
        findings = _check_csp({
            'content-security-policy': "default-src 'self'; script-src 'unsafe-eval'"
        })
        assert has_vuln(findings, "'unsafe-eval'")
        finding = next(f for f in findings if "'unsafe-eval'" in f['vuln_type'])
        assert finding['severity'] == 'high'


class TestCSPWildcard:
    def test_wildcard_in_script_src_flagged(self):
        """* in script-src flagged at high severity."""
        findings = _check_csp({
            'content-security-policy': "default-src 'self'; script-src *"
        })
        assert has_vuln(findings, 'wildcard (*)')
        finding = next(f for f in findings if 'wildcard' in f['vuln_type'].lower())
        assert finding['severity'] == 'high'

    def test_wildcard_in_default_src_downgraded_to_medium_when_script_src_exists(self):
        """
        When script-src exists, scripts are governed by script-src.
        A wildcard in default-src leaves non-script resources open, so severity is Medium.
        """
        findings = _check_csp({
            'content-security-policy': "default-src *; script-src 'self'"
        })
        assert has_vuln(findings, 'wildcard (*)')
        finding = next(f for f in findings if 'wildcard' in f['vuln_type'].lower())
        assert finding['severity'] == 'medium'

    def test_wildcard_in_default_src_high_when_script_src_absent(self):
        """When script-src is absent, default-src governs scripts, so wildcard is High."""
        findings = _check_csp({
            'content-security-policy': "default-src *"
        })
        assert has_vuln(findings, 'wildcard (*)')
        finding = next(f for f in findings if 'wildcard' in f['vuln_type'].lower())
        assert finding['severity'] == 'high'

    def test_explicit_origin_no_wildcard_finding(self):
        findings = _check_csp({
            'content-security-policy': "default-src 'self' https://cdn.example.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        })
        assert not has_vuln(findings, 'wildcard')


class TestCSPDataURI:
    def test_data_uri_in_script_src_flagged(self):
        findings = _check_csp({
            'content-security-policy': "script-src 'self' data:"
        })
        assert has_vuln(findings, "data:")


class TestCSPMissingDirectives:
    def test_missing_object_src_flagged(self):
        """
        BEFORE: never checked.
        AFTER: missing object-src (without 'none' fallback) → medium.
        """
        findings = _check_csp({
            'content-security-policy': "default-src 'self'"
        })
        assert has_vuln(findings, "object-src")

    def test_object_src_none_in_default_satisfies(self):
        """default-src 'none' covers object-src, so no finding expected."""
        findings = _check_csp({
            'content-security-policy': "default-src 'none'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'"
        })
        assert not has_vuln(findings, 'object-src')

    def test_missing_base_uri_flagged(self):
        findings = _check_csp({
            'content-security-policy': "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
        })
        assert has_vuln(findings, "base-uri")

    def test_missing_frame_ancestors_flagged_without_xfo(self):
        findings = _check_csp({
            'content-security-policy': "default-src 'self'; object-src 'none'; base-uri 'self'"
        })
        assert has_vuln(findings, "frame-ancestors")

    def test_missing_frame_ancestors_suppressed_when_valid_xfo_exists(self):
        """When valid X-Frame-Options (DENY/SAMEORIGIN) is present, do not flag missing frame-ancestors."""
        findings = _check_csp({
            'content-security-policy': "default-src 'self'; object-src 'none'; base-uri 'self'",
            'x-frame-options': 'DENY'
        })
        assert not has_vuln(findings, "frame-ancestors")

    def test_missing_default_src_flagged(self):
        findings = _check_csp({
            'content-security-policy': "script-src 'self'; object-src 'none'"
        })
        assert has_vuln(findings, "default-src")

    def test_fully_hardened_csp_no_directive_findings(self):
        """A fully hardened CSP should produce zero findings."""
        findings = _check_csp({
            'content-security-policy': (
                "default-src 'self'; "
                "script-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'none'"
            )
        })
        assert findings == [], f"Expected no findings but got: {[f['vuln_type'] for f in findings]}"


# ---------------------------------------------------------------------------
# HSTS checks
# ---------------------------------------------------------------------------

class TestHSTS:
    def test_missing_hsts_is_high(self):
        findings = _check_hsts({})
        assert has_vuln(findings, 'missing security header: strict-transport-security')
        assert findings[0]['severity'] == 'high'

    def test_max_age_zero_disables_hsts(self):
        """
        BEFORE: max-age=0 passed silently.
        AFTER: flagged as high — it actively deletes HSTS.
        """
        findings = _check_hsts({'strict-transport-security': 'max-age=0'})
        assert has_vuln(findings, 'max-age=0')
        assert findings[0]['severity'] == 'high'

    def test_max_age_too_short(self):
        """
        BEFORE: any max-age passed.
        AFTER: < 24 hours flagged at medium.
        """
        findings = _check_hsts({'strict-transport-security': 'max-age=3600'})
        assert has_vuln(findings, 'too short')
        assert findings[0]['severity'] == 'medium'

    def test_max_age_below_preload_minimum(self):
        """max-age=86400 (1 day) is meaningful but not preload-eligible."""
        findings = _check_hsts({'strict-transport-security': 'max-age=86400; includeSubDomains'})
        assert has_vuln(findings, 'below preload minimum')
        assert findings[0]['severity'] == 'low'

    def test_good_hsts_missing_include_subdomains(self):
        findings = _check_hsts({'strict-transport-security': 'max-age=31536000'})
        assert has_vuln(findings, 'includesubdomains')

    def test_good_hsts_no_preload_is_info(self):
        """max-age ≥ 1yr + includeSubDomains but no preload → info only."""
        findings = _check_hsts({'strict-transport-security': 'max-age=31536000; includeSubDomains'})
        assert has_vuln(findings, 'preload')
        assert all(f['severity'] == 'info' for f in findings if 'preload' in f['vuln_type'].lower())

    def test_fully_correct_hsts_no_findings(self):
        """
        BEFORE: would produce no findings (passes presence check) — correct.
        AFTER: still produces no findings — correctly passes value check too.
        """
        findings = _check_hsts({
            'strict-transport-security': 'max-age=31536000; includeSubDomains; preload'
        })
        assert findings == [], f"Expected no findings but got: {[f['vuln_type'] for f in findings]}"

    def test_hsts_missing_max_age_directive(self):
        findings = _check_hsts({'strict-transport-security': 'includeSubDomains; preload'})
        assert has_vuln(findings, 'max-age')


# ---------------------------------------------------------------------------
# X-Frame-Options
# ---------------------------------------------------------------------------

class TestXFrameOptions:
    def test_missing_xfo_and_no_frame_ancestors_flagged(self):
        """
        BEFORE: absence was flagged (correct).
        AFTER: still flagged, but only when frame-ancestors is also absent.
        """
        findings = _check_xfo({})
        assert has_vuln(findings, 'missing security header: x-frame-options')

    def test_csp_frame_ancestors_satisfies_xfo(self):
        """
        BEFORE: frame-ancestors was not recognised — sites with only frame-ancestors
                in CSP were incorrectly flagged for missing X-Frame-Options.
        AFTER: frame-ancestors in CSP counts as equivalent → no XFO missing finding.
        """
        findings = _check_xfo({
            'content-security-policy': "default-src 'self'; frame-ancestors 'none'"
        })
        # Should NOT flag X-Frame-Options as missing
        assert not has_vuln(findings, 'missing security header: x-frame-options')

    def test_valid_deny_value_no_finding(self):
        findings = _check_xfo({'x-frame-options': 'DENY'})
        assert findings == []

    def test_valid_sameorigin_value_no_finding(self):
        findings = _check_xfo({'x-frame-options': 'SAMEORIGIN'})
        assert findings == []

    def test_invalid_xfo_value_flagged(self):
        """
        BEFORE: any value passed.
        AFTER: invalid values (e.g. 'ALLOWALL') are flagged.
        """
        findings = _check_xfo({'x-frame-options': 'ALLOWALL'})
        assert has_vuln(findings, 'invalid value')

    def test_allow_from_flagged_as_invalid(self):
        """ALLOW-FROM is deprecated and not supported in modern browsers."""
        findings = _check_xfo({'x-frame-options': 'ALLOW-FROM https://example.com'})
        assert has_vuln(findings, 'invalid value')


# ---------------------------------------------------------------------------
# X-Content-Type-Options
# ---------------------------------------------------------------------------

class TestXContentTypeOptions:
    def test_missing_flagged(self):
        findings = _check_xcto({})
        assert has_vuln(findings, 'missing security header: x-content-type-options')

    def test_correct_nosniff_passes(self):
        """
        BEFORE: any value passed.
        AFTER: 'nosniff' passes cleanly.
        """
        findings = _check_xcto({'x-content-type-options': 'nosniff'})
        assert findings == []

    def test_wrong_value_flagged(self):
        """
        BEFORE: 'sniff' would pass silently → false negative.
        AFTER: anything other than 'nosniff' is flagged.
        """
        findings = _check_xcto({'x-content-type-options': 'sniff'})
        assert has_vuln(findings, 'invalid value')

    def test_typo_flagged(self):
        """A common typo 'nosnif' provides no protection."""
        findings = _check_xcto({'x-content-type-options': 'nosnif'})
        assert has_vuln(findings, 'invalid value')

    def test_case_insensitive_nosniff(self):
        """Header values are case-insensitive per HTTP spec."""
        findings = _check_xcto({'x-content-type-options': 'NoSniff'})
        assert findings == []


# ---------------------------------------------------------------------------
# Referrer-Policy
# ---------------------------------------------------------------------------

class TestReferrerPolicy:
    def test_missing_is_low(self):
        findings = _check_referrer_policy({})
        assert has_vuln(findings, 'missing security header: referrer-policy')
        assert findings[0]['severity'] == 'low'

    def test_safe_policy_passes(self):
        findings = _check_referrer_policy({'referrer-policy': 'strict-origin-when-cross-origin'})
        assert findings == []

    def test_no_referrer_passes(self):
        findings = _check_referrer_policy({'referrer-policy': 'no-referrer'})
        assert findings == []

    def test_unsafe_url_flagged_at_medium(self):
        """
        BEFORE: 'unsafe-url' passed (it IS a valid value syntactically) → false negative.
        AFTER:  flagged at medium — it's actively harmful.
        """
        findings = _check_referrer_policy({'referrer-policy': 'unsafe-url'})
        assert has_vuln(findings, "'unsafe-url'")
        assert findings[0]['severity'] == 'medium'


# ---------------------------------------------------------------------------
# COOP / CORP / COEP — new checks
# ---------------------------------------------------------------------------

class TestCOOP:
    def test_missing_is_low(self):
        """
        BEFORE: not checked at all → false negative.
        AFTER:  missing COOP flagged at low severity.
        """
        findings = _check_coop({})
        assert has_vuln(findings, 'cross-origin-opener-policy')
        assert findings[0]['severity'] == 'low'

    def test_present_passes(self):
        findings = _check_coop({'cross-origin-opener-policy': 'same-origin'})
        assert findings == []


class TestCORP:
    def test_missing_is_info(self):
        findings = _check_corp({})
        assert has_vuln(findings, 'cross-origin-resource-policy')
        assert findings[0]['severity'] == 'info'

    def test_present_passes(self):
        findings = _check_corp({'cross-origin-resource-policy': 'same-origin'})
        assert findings == []


class TestCOEP:
    def test_missing_is_info(self):
        findings = _check_coep({})
        assert has_vuln(findings, 'cross-origin-embedder-policy')
        assert findings[0]['severity'] == 'info'

    def test_present_passes(self):
        findings = _check_coep({'cross-origin-embedder-policy': 'require-corp'})
        assert findings == []


# ---------------------------------------------------------------------------
# Dangerous headers (Server / X-Powered-By)
# ---------------------------------------------------------------------------

class TestDangerousHeaders:
    def test_server_with_version_flagged(self):
        """
        BEFORE: ANY Server: value was flagged.
        AFTER:  only flagged when a version number is disclosed.
        """
        findings = _check_dangerous_headers({'server': 'nginx/1.18.0'})
        assert has_vuln(findings, 'server version')

    def test_server_without_version_not_flagged(self):
        """
        BEFORE: 'Server: cloudflare' was flagged → false positive.
        AFTER:  not flagged — no version disclosed.
        """
        findings = _check_dangerous_headers({'server': 'cloudflare'})
        assert not has_vuln(findings, 'server')

    def test_server_nginx_no_version_not_flagged(self):
        findings = _check_dangerous_headers({'server': 'nginx'})
        assert not has_vuln(findings, 'server')

    def test_x_powered_by_always_flagged(self):
        """X-Powered-By discloses framework regardless of version."""
        findings = _check_dangerous_headers({'x-powered-by': 'Express'})
        assert has_vuln(findings, 'x-powered-by')

    def test_no_info_headers_no_findings(self):
        findings = _check_dangerous_headers({'content-type': 'text/html'})
        assert findings == []


# ---------------------------------------------------------------------------
# Deprecated headers
# ---------------------------------------------------------------------------

class TestDeprecatedHeaders:
    def test_x_xss_protection_flagged_as_info(self):
        """
        BEFORE: not checked.
        AFTER:  detected and reported as 'info' with advice to remove.
        """
        findings = _check_deprecated_headers({'x-xss-protection': '1; mode=block'})
        assert has_vuln(findings, 'x-xss-protection')
        assert findings[0]['severity'] == 'info'

    def test_expect_ct_flagged_as_info(self):
        findings = _check_deprecated_headers({'expect-ct': 'max-age=86400, enforce'})
        assert has_vuln(findings, 'expect-ct')
        assert findings[0]['severity'] == 'info'

    def test_modern_headers_not_flagged(self):
        findings = _check_deprecated_headers({
            'content-security-policy': "default-src 'self'",
            'strict-transport-security': 'max-age=31536000',
        })
        assert findings == []


# ---------------------------------------------------------------------------
# Duplicate header detection
# ---------------------------------------------------------------------------

class TestDuplicateHeaders:
    def test_duplicate_hsts_detected(self):
        """
        BEFORE: not checked.
        AFTER:  multiple max-age values in HSTS are detected as a duplicate.
        """
        findings = _check_duplicate_headers({
            'strict-transport-security': 'max-age=31536000, max-age=86400'
        })
        assert has_vuln(findings, 'duplicate')

    def test_duplicate_csp_detected(self):
        findings = _check_duplicate_headers({
            'content-security-policy': "default-src 'self', default-src *"
        })
        assert has_vuln(findings, 'duplicate')

    def test_single_hsts_no_duplicate_finding(self):
        findings = _check_duplicate_headers({
            'strict-transport-security': 'max-age=31536000; includeSubDomains; preload'
        })
        assert not has_vuln(findings, 'duplicate')


# ---------------------------------------------------------------------------
# Integration — full check_security_headers on a realistic response
# ---------------------------------------------------------------------------

class TestIntegration:
    IDEAL_HEADERS = {
        'content-security-policy': (
            "default-src 'self'; "
            "script-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        ),
        'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': "geolocation=(), camera=(), microphone=()",
        'cross-origin-opener-policy': 'same-origin',
        'cross-origin-resource-policy': 'same-origin',
        'cross-origin-embedder-policy': 'require-corp',
    }

    def test_ideal_response_no_high_or_critical_findings(self):
        """A fully hardened response should produce zero high/critical header findings."""
        findings = check_security_headers(self.IDEAL_HEADERS)
        bad = [f for f in findings if f['severity'] in ('high', 'critical')]
        assert bad == [], f"Unexpected high/critical: {[f['vuln_type'] for f in bad]}"

    def test_empty_headers_all_required_flagged(self):
        """An empty header dict should flag every required header."""
        findings = check_security_headers({})
        vt = vuln_types(findings)
        assert any('content-security-policy' in v for v in vt)
        assert any('strict-transport-security' in v for v in vt)
        assert any('x-frame-options' in v for v in vt)
        assert any('x-content-type-options' in v for v in vt)
        assert any('referrer-policy' in v for v in vt)
        assert any('permissions-policy' in v for v in vt)
        assert any('cross-origin-opener-policy' in v for v in vt)

    def test_misconfigured_real_world_response(self):
        """
        Simulates a response with headers present but badly configured.
        Before Phase 2: all headers would PASS (presence-only check).
        After Phase 2: the bad values are detected.
        """
        headers = {
            'content-security-policy': "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
            'strict-transport-security': 'max-age=0',
            'x-frame-options': 'ALLOWALL',
            'x-content-type-options': 'sniff',
            'referrer-policy': 'unsafe-url',
            'x-xss-protection': '1; mode=block',
        }
        findings = check_security_headers(headers)
        vt = [f['vuln_type'] for f in findings]

        # Wildcard in default-src (script-src is set separately so * lives in default-src)
        assert any('wildcard' in v.lower() for v in vt), f"Expected wildcard finding in {vt}"
        # unsafe-inline
        assert any('unsafe-inline' in v.lower() for v in vt), f"Expected unsafe-inline in {vt}"
        # unsafe-eval
        assert any('unsafe-eval' in v.lower() for v in vt), f"Expected unsafe-eval in {vt}"
        # HSTS max-age=0
        assert any('max-age=0' in v.lower() for v in vt), f"Expected max-age=0 finding in {vt}"
        # Bad XFO
        assert any('invalid value' in v.lower() for v in vt), f"Expected XFO invalid value in {vt}"
        # Wrong xcto
        assert any('invalid value' in v.lower() for v in vt)
        # unsafe-url referrer
        assert any('unsafe-url' in v.lower() for v in vt), f"Expected unsafe-url in {vt}"
        # Deprecated x-xss-protection
        assert any('x-xss-protection' in v.lower() for v in vt), f"Expected deprecated header finding in {vt}"


# ---------------------------------------------------------------------------
# Eval() pattern precision tests (Phase 2 fix)
# ---------------------------------------------------------------------------

class TestEvalSinkPattern:
    def test_eval_with_variable_argument_flagged(self):
        findings = check_xss_sinks(["var cmd = getParam(); eval(cmd);"])
        assert any("eval" in f['vuln_type'].lower() for f in findings)

    def test_eval_with_concatenation_flagged(self):
        """eval("a" + x) is concatenation with variable data — must be flagged."""
        findings = check_xss_sinks(['eval("doSomething(" + payload + ")")'])
        assert any("eval" in f['vuln_type'].lower() for f in findings)

    def test_eval_with_concatenation_var_first_flagged(self):
        findings = check_xss_sinks(['eval(payload + "; finish();")'])
        assert any("eval" in f['vuln_type'].lower() for f in findings)

    def test_eval_with_template_literal_variable_flagged(self):
        """eval(`do(${payload})`) with template variables must be flagged."""
        findings = check_xss_sinks(['eval(`console.log(${payload})`)'])
        assert any("eval" in f['vuln_type'].lower() for f in findings)

    def test_eval_plain_double_quote_string_not_flagged(self):
        """Webpack / bundler module runtime eval("plain string;") should NOT be flagged."""
        findings = check_xss_sinks(['eval("console.log(\'bundled module\');");'])
        assert not any("eval" in f['vuln_type'].lower() for f in findings)

    def test_eval_plain_single_quote_string_not_flagged(self):
        findings = check_xss_sinks(["eval('var x = 1; var y = 2;');"])
        assert not any("eval" in f['vuln_type'].lower() for f in findings)

    def test_eval_plain_template_literal_without_vars_not_flagged(self):
        findings = check_xss_sinks(["eval(`console.log('static template');`);"])
        assert not any("eval" in f['vuln_type'].lower() for f in findings)


# ---------------------------------------------------------------------------
# HTTP probe validation and timeout tests (Phase 2 fix)
# ---------------------------------------------------------------------------

class TestHttpProbeValidation:
    def test_invalid_url_returns_empty_dict(self):
        assert _probe_http_headers("") == {}
        assert _probe_http_headers("   ") == {}
        assert _probe_http_headers("://invalid") == {}
        assert _probe_http_headers("not a url at all") == {}
        assert _probe_http_headers(None) == {}

    def test_unreachable_target_returns_empty_dict(self):
        # 192.0.2.1 is TEST-NET-1 (RFC 5737, guaranteed non-routable)
        assert _probe_http_headers("http://192.0.2.1:1") == {}


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
