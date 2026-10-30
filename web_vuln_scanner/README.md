# Web Vulnerability Scanner (Passive Security Audit Framework)

A deterministic, passive web application security scanner built with Python, Flask, and ReportLab. It performs automated HTTP response header validation, client-side JavaScript software composition analysis (SCA), and generates enterprise-grade PDF audit reports.

---

## Key Features

- **HTTP Security Header Audit**: Directive-level parsing for CSP, HSTS compliance validation (including preload & subdomains), modern frame protection (`X-Frame-Options` & `frame-ancestors`), MIME-type restriction (`X-Content-Type-Options: nosniff`), Referrer Policy, Permissions Policy, and cross-origin isolation headers (COOP, CORP, COEP).
- **Client-Side Library SCA**: Identifies third-party JavaScript libraries using multi-signal corroboration (URL paths, header comment banners, query strings `?ver=`, and in-content global variables).
- **Custom 4-Part Version Comparator**: Evaluates multi-part software versions (`1.2.3.4`), handles numeric pre-release precedence (`1.0.0-rc.2 < 1.0.0-rc.10`), and ignores build metadata (`1.2.3+build == 1.2.3`).
- **Live Advisory Feeds & Offline Fallback**: Queries OSV.dev and Retire.js `jsrepository.json` live; falls back gracefully to a curated local database when offline or sandboxed.
- **Reliability & Defense-in-Depth**:
  - WAF and challenge page detection (Cloudflare, AWS WAF, Akamai, Imperva).
  - Bounded exponential backoff with jitter and `Retry-After` header honoring.
  - Global scan time budget (`ScanBudget`) preventing hung scans.
  - SSRF protection rejecting targets resolving to private, loopback, or link-local IP addresses.
  - Thread-safe bounded TTL caching (`BoundedTTLCache`).
  - 512 KB streaming cap on HTML fetches and 256 KB streaming cap on external scripts.
- **Enterprise PDF Reporting**: Two-pass ReportLab engine generating typographic audit reports with CVSS v3.1 scores, CWE/CVE links, and actionable technical remediation.

---

## Setup & Quickstart

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.14)
- pip

### 2. Installation
```powershell
# Clone or open repository
cd "c:\Users\rahu0\Downloads\MCA Project\web_vuln_scanner"

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Web Application
```powershell
python main.py
```
Open your browser to `http://127.0.0.1:5000` to access the interactive web interface.

### 4. Run the Test Suite
```powershell
python -m pytest --tb=short -q
```

---

## Architecture

```
web_vuln_scanner/
│
├── main.py                  # Flask web application & scan orchestration pipeline
├── requirements.txt         # Pinned production dependencies
├── scanner.db               # SQLite database storing scan history & vulnerability rules
│
├── scanner/
│   ├── extractor.py         # HTTP fetching, streaming HTML cap, TLS fallback, SSRF prevention
│   ├── matcher.py           # Security header evaluation, secrets detection, XSS sink audits
│   ├── retirejs.py          # JS component detection, custom version comparer, OSV/Retire.js lookups
│   └── reliability.py       # WAF detection, retry_get, ScanBudget, BoundedTTLCache, SSRF validation
│
├── database/
│   ├── db_handler.py        # Database operations, startup migration (cve_id -> ref_id)
│   └── schema.sql           # SQLite table definitions
│
├── reporting/
│   └── pdf_builder.py       # Two-pass ReportLab PDF generation with visual risk hierarchy
│
├── fixtures/                # Pinned real-world JavaScript files for test verification
│   ├── jquery-3.5.1.min.js
│   ├── bootstrap-4.6.0.js
│   └── lodash-4.17.20.js
│
├── test_pages/              # Reference test targets for benchmark testing
│   ├── weak_csp.html
│   ├── old_jquery.html
│   └── hardened_page.html
│
└── test_*.py                # 160 unit tests across 3 phases (100% passing)
```

---

## Data Sources

| Data Source | Type | Endpoint / Path | Purpose |
|-------------|------|-----------------|---------|
| **OSV.dev** | Live API | `https://api.osv.dev/v1/query` | Authoritative open source vulnerability database for npm packages |
| **npm Registry** | Live API | `https://registry.npmjs.org/<pkg>/latest` | Official package versions and safe upgrade targets |
| **Retire.js** | Live JSON | `https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json` | JavaScript-specific security advisory catalog |
| **Local Offline DB** | Fallback | `scanner/retirejs.py (RETIREJS_DB)` | Offline component signatures and validated vulnerability rules |
| **CWE / MITRE** | Static Ref | `https://cwe.mitre.org/data/definitions/` | Weakness classification for missing architectural controls |

---

## Limitations

- **Non-Intrusive Scope**: The scanner performs purely passive analysis. It does not fuzz parameters or execute active exploits.
- **Single-Page Depth**: Scans inspect the target landing page and its directly loaded script dependencies.
- **Air-Gapped Environments**: When executed without internet access, live OSV/npm queries fall back to the local database, with findings explicitly marked as offline data.
- **Aggressive WAF Challenges**: Targets requiring interactive JavaScript challenges (Cloudflare Turnstile, reCAPTCHA) are flagged as `BLOCKED` rather than evaluating the challenge page as origin code.
