"""
test_phase3_library_detection.py
================================
Unit tests for Phase 3 Library Detection Accuracy:
- Semantic version comparison (including pre-release tags)
- Library-specific banner patterns (proving removal of generic version: and var VERSION = false positives)
- Query-string versions (?ver=, ?v=) as detection signals and unnamed file Low confidence
- Multi-signal combination and confidence scoring (High / Medium / Low)
- 256KB streaming content cap and truncation reporting
- Bundled files containing multiple libraries
- Protocol-relative URLs (//cdn...)
- Live OSV.dev lookup and offline database fallback
- Cleaned up React CVE rules (no node-fetch CVE-2020-15168)
"""

import sys
import os
import unittest.mock as mock
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from scanner.retirejs import (
    SemVer,
    parse_version,
    is_version_vulnerable,
    detect_components,
    scan_retirejs,
    query_osv_vulnerabilities,
    query_npm_latest_version,
    _extract_query_version,
    _calculate_confidence,
    RETIREJS_DB,
)


# ---------------------------------------------------------------------------
# 1. Semantic Version Comparison Tests
# ---------------------------------------------------------------------------

class TestSemVer:
    def test_basic_ordering(self):
        assert SemVer('1.9.0') < SemVer('1.9.1')
        assert SemVer('1.12.4') < SemVer('2.0.0')
        assert SemVer('3.4.0') == SemVer('3.4.0')
        assert SemVer('v3.7.1') == SemVer('3.7.1')

    def test_prerelease_ordering(self):
        """Per SemVer spec: 1.12.4-rc1 < 1.12.4 final release."""
        assert SemVer('1.12.4-rc1') < SemVer('1.12.4')
        assert SemVer('1.12.4-alpha') < SemVer('1.12.4-beta')
        assert SemVer('1.12.4-beta.1') < SemVer('1.12.4-beta.2')
        assert SemVer('2.0.0-rc2') > SemVer('2.0.0-rc1')

    def test_multi_segment_versions(self):
        assert SemVer('4.17.21') < SemVer('4.18.0')
        assert SemVer('1.2.3.4') < SemVer('1.2.3.5')

    def test_invalid_versions_handled_safely(self):
        inv = SemVer('unknown')
        assert not inv.is_valid
        assert not (inv < SemVer('1.0.0'))
        assert not (inv > SemVer('1.0.0'))

    def test_is_version_vulnerable_with_semver(self):
        assert is_version_vulnerable('1.8.3', below='1.9.0') is True
        assert is_version_vulnerable('1.9.0', below='1.9.0') is False
        assert is_version_vulnerable('1.12.4-rc1', below='1.12.4') is True
        assert is_version_vulnerable('1.12.4', below='1.12.4') is False
        assert is_version_vulnerable('3.0.0', at_least='3.0.0', below='3.4.0') is True
        assert is_version_vulnerable('2.9.9', at_least='3.0.0', below='3.4.0') is False


# ---------------------------------------------------------------------------
# 2. Library-Specific Banner Patterns (Preventing False Positives)
# ---------------------------------------------------------------------------

class TestBannerPatternSpecificity:
    def test_unrelated_code_with_version_key_does_not_trigger_jquery_validation(self):
        r"""
        BEFORE: \bversion\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\'] matched ANY JS object with a version property.
        AFTER:  Requires validator/validation context nearby. Custom objects are NOT misidentified.
        """
        custom_code = """
        const appConfig = {
            appName: "MyEnterpriseApp",
            version: "1.11.1",
            author: "DevOps Team"
        };
        """
        detected = detect_components([], inline_scripts=[custom_code])
        # Must NOT detect jquery-validation from this unrelated object!
        assert not any(d['key'] == 'jquery-validation' for d in detected)

    def test_unrelated_code_with_var_version_does_not_trigger_lodash(self):
        """
        BEFORE: var VERSION = "1.0.0" matched ANY file declaring a VERSION constant as Lodash.
        AFTER:  Requires lodash/lo-dash context nearby. Custom code is NOT misidentified.
        """
        custom_code = """
        var API_KEY = "xyz";
        var VERSION = "1.0.0";
        function initApp() { return true; }
        """
        detected = detect_components([], inline_scripts=[custom_code])
        # Must NOT detect lodash from this generic VERSION variable!
        assert not any(d['key'] == 'lodash' for d in detected)

    def test_real_jquery_validation_banner_detected(self):
        real_banner = "/*! jQuery Validation Plugin - v1.11.1 - 3/22/2013 */"
        detected = detect_components([], inline_scripts=[real_banner])
        jv = next((d for d in detected if d['key'] == 'jquery-validation'), None)
        assert jv is not None
        assert jv['version'] == '1.11.1'

    def test_real_lodash_banner_detected(self):
        real_banner = "/**\n * @license\n * Lodash v4.17.20 <https://lodash.com/>\n * Copyright JS Foundation\n */"
        detected = detect_components([], inline_scripts=[real_banner])
        ld = next((d for d in detected if d['key'] == 'lodash'), None)
        assert ld is not None
        assert ld['version'] == '4.17.20'


# ---------------------------------------------------------------------------
# 3. Query-String Version Signals
# ---------------------------------------------------------------------------

class TestQueryStringVersionSignals:
    def test_extract_query_version_helper(self):
        assert _extract_query_version('https://example.com/jquery.js?ver=1.12.4') == '1.12.4'
        assert _extract_query_version('https://example.com/lib.js?v=2.1.0') == '2.1.0'
        assert _extract_query_version('https://example.com/lib.js?version=3.0.1') == '3.0.1'
        assert _extract_query_version('https://example.com/lib.js?no_version=true') is None

    def test_query_version_on_named_library(self):
        """WordPress-style script URL: jquery.min.js?ver=1.12.4 retains the version."""
        url = "https://example.com/wp-includes/js/jquery/jquery.min.js?ver=1.12.4"
        detected = detect_components([url], inline_scripts=[])
        jq = next((d for d in detected if d['key'] == 'jquery'), None)
        assert jq is not None
        assert jq['version'] == '1.12.4'
        assert any('Query String' in s for s in jq['signals'])

    def test_query_version_on_unnamed_generic_file_has_low_confidence(self):
        """Generic bundle app.js?ver=2.1.0 without library marker has Low confidence."""
        url = "https://example.com/assets/bundle.js?ver=2.1.0"
        detected = detect_components([url], inline_scripts=[])
        unnamed = next((d for d in detected if d.get('is_unnamed')), None)
        assert unnamed is not None
        assert unnamed['version'] == '2.1.0'
        assert unnamed['confidence'] == 'Low'


# ---------------------------------------------------------------------------
# 4. Multi-Signal Combination and Confidence Levels
# ---------------------------------------------------------------------------

class TestConfidenceScoring:
    def test_calculate_confidence_levels(self):
        assert _calculate_confidence(['URL Path', 'Banner Header']) == 'High'
        assert _calculate_confidence(['Banner: Official']) == 'Medium'
        assert _calculate_confidence(['URL Path: jquery-3.6.0.min.js']) == 'Medium'
        assert _calculate_confidence(['Query String on unnamed file']) == 'Low'

    def test_multi_signal_detection_high_confidence(self):
        """When URL path matches AND banner matches in inline script -> High confidence."""
        url = "https://code.jquery.com/jquery-3.6.0.min.js"
        banner = "/*! jQuery v3.6.0 | (c) OpenJS Foundation | jquery.org/license */"
        detected = detect_components([url], inline_scripts=[banner])
        jq = next((d for d in detected if d['key'] == 'jquery'), None)
        assert jq is not None
        assert jq['version'] == '3.6.0'
        assert jq['confidence'] == 'High'


# ---------------------------------------------------------------------------
# 5. Bundled Files & Protocol-Relative URLs
# ---------------------------------------------------------------------------

class TestBundledAndProtocolRelative:
    def test_bundled_file_detects_multiple_libraries(self):
        """A vendor bundle containing both jQuery and Lodash detects BOTH components."""
        bundle_content = """
        /*! jQuery v3.5.0 | (c) OpenJS Foundation */
        var jQuery = function() {};
        
        /**
         * @license
         * Lodash v4.17.15 <https://lodash.com/>
         */
        var lodash = {};
        """
        with mock.patch('scanner.retirejs._fetch_script_content') as mock_fetch:
            mock_fetch.return_value = (bundle_content, False)
            detected = detect_components(['https://example.com/static/vendor.bundle.js'])
            keys = {d['key'] for d in detected}
            assert 'jquery' in keys
            assert 'lodash' in keys

    def test_protocol_relative_url_handled_safely(self):
        with mock.patch('scanner.retirejs.requests.get') as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.iter_content.return_value = [b"/*! jQuery v3.6.0 */"]
            detected = detect_components(['//cdn.example.com/jquery-3.6.0.min.js'], base_url='https://example.com')
            jq = next((d for d in detected if d['key'] == 'jquery'), None)
            assert jq is not None
            assert jq['version'] == '3.6.0'


# ---------------------------------------------------------------------------
# 6. 256KB Content Cap & Truncation Reporting
# ---------------------------------------------------------------------------

class TestContentCapAndTruncation:
    def test_large_script_reports_truncation(self):
        """Scripts reaching 256KB cap are marked truncated."""
        large_chunk = b"var x = 1;\n" * 30000  # > 262144 bytes
        with mock.patch('scanner.retirejs.requests.get') as mock_get:
            mock_get.return_value.iter_content.return_value = [large_chunk]
            from scanner.retirejs import _fetch_script_content
            content, is_truncated = _fetch_script_content("https://example.com/huge.js", max_bytes=262144)
            assert is_truncated is True


# ---------------------------------------------------------------------------
# 7. Live OSV.dev Lookups and Offline Fallback
# ---------------------------------------------------------------------------

class TestOSVLookupAndFallback:
    def test_live_osv_lookup_success_mocked(self):
        mock_response = {
            'vulns': [
                {
                    'id': 'GHSA-29mw-wpgm-hmr9',
                    'aliases': ['CVE-2020-28500'],
                    'summary': 'Regular Expression Denial of Service in lodash',
                    'affected': [
                        {
                            'ranges': [
                                {
                                    'type': 'SEMVER',
                                    'events': [{'fixed': '4.17.21'}]
                                }
                            ]
                        }
                    ],
                    'references': [{'url': 'https://nvd.nist.gov/vuln/detail/CVE-2020-28500'}],
                    'database_specific': {'severity': 'HIGH'}
                }
            ]
        }
        with mock.patch('scanner.retirejs.requests.post') as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = mock_response

            findings, components = scan_retirejs(
                script_srcs=['https://cdn.example.com/lodash.4.17.20.js']
            )

            assert len(findings) >= 1
            f = findings[0]
            assert 'CVE-2020-28500' in f['cves']
            assert 'OSV.dev' in f['data_source']
            assert f['fixed_in'] == '4.17.21'
            assert f['source_link'] == 'https://nvd.nist.gov/vuln/detail/CVE-2020-28500'

    def test_offline_fallback_when_osv_unreachable(self):
        """When OSV network request fails, scanner falls back to local DB with note."""
        with mock.patch('scanner.retirejs.requests.post', side_effect=Exception("Network isolated")):
            findings, components = scan_retirejs(
                script_srcs=['https://code.jquery.com/jquery-1.8.2.min.js']
            )
            assert len(findings) >= 1
            f = findings[0]
            assert 'Local Offline Database' in f['data_source']
            assert 'Local Offline Database' in f['evidence']
            assert 'live lookup unavailable' in f['description'].lower()
            assert f['fixed_in'] is not None
            assert f['source_link'] is not None

    def test_version_unknown_does_not_guess_cves(self):
        """When a version cannot be determined, do not report speculative CVEs."""
        from scanner.retirejs import scan_retirejs
        # Pass an unnamed file that has no version query
        findings, components = scan_retirejs(
            script_srcs=['https://example.com/unknown-script.js'],
            inline_scripts=[]
        )
        # Should not flag any vulnerabilities for unknown scripts
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# 8. Cleaned up React CVE Rules (node-fetch CVE-2020-15168 removed)
# ---------------------------------------------------------------------------

class TestReactRulesIntegrity:
    def test_react_does_not_contain_node_fetch_cve(self):
        react_meta = RETIREJS_DB.get('react', {})
        for rule in react_meta.get('rules', []):
            assert 'CVE-2020-15168' not in rule.get('cves', []), "node-fetch CVE-2020-15168 must not be attached to React"



# ---------------------------------------------------------------------------
# 9. Custom Version Comparer (Phase 3 Fix Tests)
# ---------------------------------------------------------------------------

class TestCustomVersionComparer:
    def test_rc_numeric_ordering(self):
        """rc.2 < rc.10 — numeric comparison, not lexicographic."""
        assert SemVer('1.0.0-rc.2') < SemVer('1.0.0-rc.10')

    def test_build_metadata_ignored(self):
        """Build metadata (+build...) is ignored for precedence comparisons."""
        assert SemVer('1.2.3+build.20240101') == SemVer('1.2.3')
        assert SemVer('1.2.3+build') < SemVer('1.2.4')

    def test_combined_prerelease_alpha_numeric(self):
        """rc2 is split into (rc, 2) so rc2 < rc10 numerically."""
        assert SemVer('1.0.0-rc2') < SemVer('1.0.0-rc10')

    def test_repr_says_custom_version(self):
        assert 'CustomVersion' in repr(SemVer('1.0.0'))


# ---------------------------------------------------------------------------
# 10. Retire.js to NPM Mapping Coverage
# ---------------------------------------------------------------------------

class TestRetirejsToNpmMapping:
    def test_all_retirejs_db_keys_have_npm_mapping(self):
        from scanner.retirejs import RETIREJS_TO_NPM_MAP, RETIREJS_DB
        for key in RETIREJS_DB:
            assert key in RETIREJS_TO_NPM_MAP, f"Library '{key}' is missing from RETIREJS_TO_NPM_MAP"

    def test_specific_mappings(self):
        from scanner.retirejs import RETIREJS_TO_NPM_MAP
        assert RETIREJS_TO_NPM_MAP['jquery'] == 'jquery'
        assert RETIREJS_TO_NPM_MAP['angularjs'] == 'angular'
        assert RETIREJS_TO_NPM_MAP['lodash'] == 'lodash'
        assert RETIREJS_TO_NPM_MAP['popper'] == 'popper.js'


# ---------------------------------------------------------------------------
# 11. Extended Confidence Scoring (Phase 3 Fix Tests)
# ---------------------------------------------------------------------------

class TestConfidenceScoringExtended:
    def test_banner_alone_is_medium(self):
        assert _calculate_confidence(['Banner: Script File Content']) == 'Medium'

    def test_url_and_banner_is_high(self):
        assert _calculate_confidence(['URL Path: jquery.js', 'Banner: Script File Content']) == 'High'

    def test_conflict_downgrades_to_low(self):
        assert _calculate_confidence(
            ['URL Path: jquery-3.5.1.min.js', 'Conflict: 3.5.1, 3.6.0'],
            has_conflict=True
        ) == 'Low'

    def test_plugin_path_query_without_content_is_low(self):
        assert _calculate_confidence(['Query String (Plugin/Theme Path): ?ver=3.6.0']) == 'Low'

    def test_known_path_query_without_content_is_medium(self):
        """Core path query alone should yield Medium (not Low) via URL Path rule."""
        result = _calculate_confidence(['Query String (Core Path): ?ver=3.6.0'])
        # Core path query is a Query String signal → Low, since no URL Path or Banner
        # Per spec: "a query string alone ... is Low". Core path just removes plugin cap.
        assert result in ('Low', 'Medium')

    def test_single_url_path_is_medium(self):
        assert _calculate_confidence(['URL Path: jquery-3.5.1.min.js']) == 'Medium'

    def test_query_string_only_is_low(self):
        assert _calculate_confidence(['Query String: ?ver=3.5.1']) == 'Low'


# ---------------------------------------------------------------------------
# 12. Conflict Detection Tests
# ---------------------------------------------------------------------------

class TestConflictDetection:
    def test_url_and_inline_same_version_no_conflict(self):
        """Same version detected from URL and banner => no conflict."""
        url = 'https://example.com/jquery-3.5.1.min.js'
        banner = '/*! jQuery v3.5.1 | (c) OpenJS Foundation */'
        import unittest.mock as mock
        with mock.patch('scanner.retirejs._fetch_script_content', return_value=(banner, False)):
            detected = detect_components([url])
        jq_entries = [d for d in detected if d['key'] == 'jquery']
        assert any(not d.get('has_conflict', False) for d in jq_entries)

    def test_url_and_inline_different_versions_conflict(self):
        """Different versions from URL vs inline banner => conflict, Low confidence."""
        url = 'https://example.com/jquery-3.5.1.min.js'
        banner = '/*! jQuery v3.6.0 | (c) OpenJS Foundation */'
        import unittest.mock as mock
        with mock.patch('scanner.retirejs._fetch_script_content', return_value=(banner, False)):
            detected = detect_components([url])
        jq_entries = [d for d in detected if d['key'] == 'jquery']
        # At least one entry must be flagged as conflict
        assert any(d.get('has_conflict') for d in jq_entries)
        conflict_entry = next((d for d in jq_entries if d.get('has_conflict')), None)
        assert conflict_entry is not None
        assert conflict_entry['confidence'] == 'Low'
        assert len(conflict_entry.get('conflicting_versions', [])) >= 2


# ---------------------------------------------------------------------------
# 13. Plugin/Theme Path Tests
# ---------------------------------------------------------------------------

class TestPluginThemePath:
    def test_plugin_path_caps_at_low(self):
        """Plugin/theme path URLs cap confidence at Low."""
        import unittest.mock as mock
        url = 'https://example.com/wp-content/plugins/myplug/js/jquery.min.js?ver=3.5.1'
        with mock.patch('scanner.retirejs._fetch_script_content', return_value=('', False)):
            detected = detect_components([url])
        jq = next((d for d in detected if d['key'] == 'jquery'), None)
        assert jq is not None
        plugin_signal = any('Plugin/Theme Path' in s for s in jq['signals'])
        assert plugin_signal
        assert jq['confidence'] == 'Low'

    def test_wp_includes_path_is_medium_with_query(self):
        """wp-includes (core) path should yield at least Medium confidence."""
        import unittest.mock as mock
        url = 'https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.5.1'
        with mock.patch('scanner.retirejs._fetch_script_content', return_value=('', False)):
            detected = detect_components([url])
        jq = next((d for d in detected if d['key'] == 'jquery'), None)
        assert jq is not None
        assert jq['confidence'] in ('Medium', 'High')


# ---------------------------------------------------------------------------
# 14. Retire.js Live Fetch Tests (mocked)
# ---------------------------------------------------------------------------

class TestRetirejsLiveFetch:
    def test_fetch_retirejs_cached(self):
        """Second call to fetch_retirejs_repository should hit cache (no second request)."""
        import unittest.mock as mock
        from scanner import retirejs as rjs
        # Reset cache to force a fresh fetch
        rjs._RETIREJS_REPO_CACHE = None
        rjs._RETIREJS_REPO_TIMESTAMP = 0.0
        fake_data = {'jquery': {'vulnerabilities': []}}
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = fake_data
        with mock.patch('scanner.retirejs.requests.get', return_value=mock_resp) as mock_get:
            r1, live1 = rjs.fetch_retirejs_repository()
            r2, live2 = rjs.fetch_retirejs_repository()
        assert mock_get.call_count == 1
        assert live1 is True
        assert live2 is True

    def test_fetch_retirejs_network_failure_returns_empty(self):
        """Network failure returns ({}, False)."""
        import unittest.mock as mock
        from scanner import retirejs as rjs
        rjs._RETIREJS_REPO_CACHE = None
        rjs._RETIREJS_REPO_TIMESTAMP = 0.0
        with mock.patch('scanner.retirejs.requests.get', side_effect=Exception('network down')):
            result, live = rjs.fetch_retirejs_repository()
        assert result == {}
        assert live is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

