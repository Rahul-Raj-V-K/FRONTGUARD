# Testing Guide & Audit Verification

## Test Execution

Run the complete test suite from the repository root:

```powershell
python -m pytest web_vuln_scanner --tb=short -q
```

All **160 unit tests** execute in under 1 second with 100% pass rate.

---

## Test Results Table

| Test Suite File | Focus Area | Test Count | Pass Rate | Status |
|-----------------|------------|------------|-----------|--------|
| `test_phase2_headers.py` | HTTP Security Header Validation (CSP directives, HSTS, XFO, XCTO, Referrer-Policy, COOP, CORP, COEP, Deprecated headers, HTTP/HTTPS redirect diff) | 84 tests | 100% | ✅ Passing |
| `test_phase3_library_detection.py` | Client-Side Library Detection Accuracy (Custom 4-part version comparator, numeric pre-releases, +build metadata, banner specificity, query-string signals, confidence scoring, Retire.js mapping, conflict detection) | 49 tests | 100% | ✅ Passing |
| `test_phase4_reliability.py` | Reliability, Hardening & Benchmarks (WAF/Challenge detection, bounded retry with Retry-After, scan budget, thread-safe bounded TTL cache, SSRF private IP protection, real-world pinned fixtures, local test pages) | 27 tests | 100% | ✅ Passing |
| **Total** | **Full End-to-End Suite** | **160 tests** | **100%** | **✅ All Passing** |

---

## Detailed Test Coverage Summary

### 1. HTTP Security Headers (`test_phase2_headers.py` — 84 Tests)
- **CSP Directive Parsing**: Validates `default-src`, `script-src`, `object-src`, `base-uri`, and `frame-ancestors`.
- **Script Context Rules**: Evaluates `default-src` governing scripts only when `script-src` is absent; ignores `'unsafe-inline'` when a cryptographic nonce, sha hash, or `'strict-dynamic'` is supplied.
- **HSTS Enforcement**: Enforces `max-age >= 31536000`, validates `includeSubDomains`, flags `max-age=0` as disabling HSTS, and validates preload criteria.
- **Clickjacking & UI Layering**: Validates `X-Frame-Options` (`DENY`, `SAMEORIGIN`), treats CSP `frame-ancestors` as an equivalent modern control, and suppresses missing `frame-ancestors` when valid `X-Frame-Options` is set.
- **MIME Sniffing**: Validates `X-Content-Type-Options: nosniff`.
- **Referrer Privacy**: Flags `unsafe-url` as Medium severity; requires modern strict referrer policies.
- **Cross-Origin Isolation**: Validates COOP (`same-origin`), CORP (`same-origin`, `same-site`), and COEP (`require-corp`).
- **Information Disclosure**: Detects `X-Powered-By` presence; flags `Server` header only when version numbers are leaked.
- **Header Conflicts & Duplicates**: Detects duplicate headers with differing values.
- **HTTP vs HTTPS Redirect Probe**: Flags HSTS set on cleartext HTTP redirect responses.

### 2. Client-Side JavaScript Library Detection (`test_phase3_library_detection.py` — 49 Tests)
- **Custom Version Comparer**: Supports up to 4-part numeric components (`1.2.3.4`), numeric pre-release precedence (`1.0.0-rc.2 < 1.0.0-rc.10`, `rc2 < rc10`), and ignores `+build` metadata (`1.2.3+2024 == 1.2.3`).
- **Banner Specificity**: Replaced generic false-positive patterns (`version:`, `var VERSION =`) with library-anchored context matches, verified against custom objects.
- **Query-String Signals**: Captures `?ver=`, `?v=`, `?version=` on recognized library files; labels generic files (`app.js?ver=2.1.0`) with Low confidence.
- **Path-Based Trust**: Core library paths (`/wp-includes/`, `/libs/`, `/vendor/`, `/cdn/`) are trusted (Medium confidence); plugin/theme paths (`/plugins/`, `/themes/`) are capped at Low confidence.
- **Multi-Signal Confidence Scoring**:
  - **High**: Agreement between independent sources (Location/URL + File Content Banner).
  - **Medium**: Single independent source (URL path alone, content banner alone, or core path query).
  - **Low**: Generic query string alone, plugin/theme path query, or unverified script.
- **Conflict Handling**: Detects conflicting versions across signals (e.g., URL indicates v1.12.4 but banner indicates v3.5.1), lowers confidence to Low, and lists all observed versions.
- **Package Name Mapping**: Validates `RETIREJS_TO_NPM_MAP` coverage across every supported library; reports `LOOKUP_FAILED` when a library cannot be resolved.
- **Live Lookups & Offline Fallback**: Queries OSV.dev and Retire.js `jsrepository.json` live; falls back to `RETIREJS_DB` with explicit offline labeling.

### 3. Reliability, Hardening & Benchmarks (`test_phase4_reliability.py` — 27 Tests)
- **WAF & Challenge Page Detection**: Identifies 403, 429, 503 status codes, `cf-mitigated` and WAF headers, Cloudflare "Just a moment..." challenges, reCAPTCHA tags, and suspiciously small HTML responses (< 2KB with no scripts).
- **Retry with Exponential Backoff & Jitter**: Bounded retries for idempotent GET requests; parses and honors `Retry-After` headers on 429 and 503 responses; terminates retries when scan budget expires.
- **Global Scan Budget**: `ScanBudget` tracks overall scan wall-clock time and halts further requests once deadline is reached, returning partial results rather than hanging.
- **Bounded TTL Cache**: Thread-safe in-memory cache (`BoundedTTLCache`) with LRU eviction at `maxsize` and timestamp-based TTL expiry for OSV, npm, and scan history findings.
- **SSRF Prevention**: Validates target and redirect IP addresses against private and loopback ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`); aborts requests to internal targets.
- **Pinned Real-World Fixtures**: Verifies accurate detection against real-world pinned snippets (`jquery-3.5.1.min.js`, `bootstrap-4.6.0.js`, `lodash-4.17.20.js`).
- **Local Test Benchmarks**: Evaluates scanner execution against `weak_csp.html`, `old_jquery.html`, and `hardened_page.html`.

---

## Known Limitations

1. **Network Connectivity for Live Lookups**: OSV.dev, the npm registry, and the raw GitHub Retire.js repository require outbound HTTPS egress. In air-gapped or sandboxed offline environments, the scanner seamlessly falls back to the local `RETIREJS_DB` with an explicit note in findings.
2. **Aggressive WAF / Bot-Protection**: Targets protected by advanced Cloudflare Managed Challenges or Akamai Bot Manager will present a challenge page instead of origin HTML. The scanner identifies these challenge pages, sets scan status to `blocked`, and avoids diagnosing the challenge page as the origin application.
3. **Heavy Bundlers / Webpack Code Splitting**: Heavily minified or obfuscated bundles where banner comments and version identifiers are stripped by minifiers may result in "Version Unknown" or Low confidence detections, preventing speculative false-positive alerts.
4. **Passive Scanner Scope**: The scanner performs purely non-intrusive, read-only GET requests. It does not actively inject payloads, fuzz parameters, or spider beyond the initial target landing page.

---

## AI Assistance Disclosure

In accordance with academic and project requirements:
This project was developed and refined with pair-programming assistance from **Google Deepmind Antigravity (Advanced Agentic Coding)**. AI capabilities were utilized for:
- Auditing the existing codebase for false positives, false negatives, and architectural edge cases.
- Implementing value-based HTTP security header parsing and compliance rules.
- Refactoring library detection logic to support multi-signal confidence scoring and semantic version comparison.
- Implementing network reliability patterns (bounded exponential backoff, thread-safe TTL caching, WAF challenge diagnostics, and SSRF prevention).
- Authoring unit test suites with mocked network responses and maintaining 100% test pass fidelity across all phases.

