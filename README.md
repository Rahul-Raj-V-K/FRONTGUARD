# FRONTGUARD: AUTOMATED PASSIVE WEB SECURITY VULNERABILITY SCANNER

A production-grade, passive web application security scanner built with Python, Flask, and ReportLab. FRONTGUARD performs automated HTTP response security header validation, client-side JavaScript software composition analysis (SCA) against live CVE feeds, credential exposure auditing, and generates enterprise PDF audit reports.

> 📖 **Evaluator & Installation Manual:** See [INSTALLATION_AND_USER_GUIDE.md](INSTALLATION_AND_USER_GUIDE.md) for a complete step-by-step installation, user operations, and test verification guide.

---

## Key Capabilities

- **HTTP Security Header Audit**:
  - Directive-level AST tokenizer & parser for `Content-Security-Policy` (checks for `unsafe-inline`, `unsafe-eval`, wildcards `*`, `data:` URI sinks, and missing `object-src`/`base-uri`/`frame-ancestors`/`default-src`).
  - Strict Transport Security (`Strict-Transport-Security` / HSTS) verification (`max-age >= 31536000`, `includeSubDomains`, `preload` eligibility, and detection of `max-age=0` bypass).
  - Modern clickjacking prevention (`X-Frame-Options` and CSP `frame-ancestors` equivalence).
  - MIME-sniffing protection (`X-Content-Type-Options: nosniff`).
  - Privacy controls (`Referrer-Policy`, `Permissions-Policy`).
  - Cross-origin isolation (`Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `Cross-Origin-Embedder-Policy`).
  - Server banner & framework disclosure detection (`X-Powered-By`, version-disclosing `Server` headers).
  - HTTP-to-HTTPS redirect header difference analysis (detects HSTS erroneously placed only on plain-HTTP redirect responses).

- **Client-Side Component SCA (Software Composition Analysis)**:
  - Multi-signal corroboration for third-party JavaScript libraries (URL paths, comment banners, query parameters `?ver=`, and in-content global variables).
  - Specialized 4-part version comparator (`SemVer` / `CustomVersion`) supporting pre-release tags (`1.12.4-rc.1 < 1.12.4-rc.10 < 1.12.4`) and build metadata (`1.2.3+build == 1.2.3`).
  - Live advisory synchronization with **OSV.dev** and official **Retire.js** repository (`jsrepository.json`).
  - Curated offline fallback database with exact CVE and CVSS v3.1 mappings when internet access is restricted.

- **Defensive Engineering & Reliability**:
  - **SSRF Prevention**: Pre-flight DNS resolution using `socket.gethostbyname_ex()`; strictly blocks private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local, multicast, and reserved IP ranges.
  - **WAF & Challenge Detection**: Recognizes Cloudflare, AWS WAF, Akamai, and Imperva block pages and CAPTCHAs, preventing distorted audit findings.
  - **Bounded Exponential Backoff**: Retries idempotent requests with jitter and honors remote `Retry-After` headers.
  - **Global Scan Budget**: 45-second wall-clock deadline prevents resource exhaustion on slow or unresponsive targets.
  - **Memory Protection**: 512 KB streaming cap on HTML bodies; 256 KB streaming cap on external scripts.
  - **Thread-Safe Bounded TTL Cache**: LRU in-memory eviction prevents memory leaks over long runtime periods.

- **Enterprise PDF Audit Reports**:
  - Two-pass ReportLab engine generating visual risk hierarchies, executive summary scorecards, CVSS v3.1 severity matrices, affected URL locations, and actionable remediation steps.

---

## Project Structure

```
FRONTGUARD/
├── .env.example                     # Environment configuration template
├── .gitignore                       # Git exclusions (ignores .env, *.db, reports/)
├── README.md                        # Project documentation
├── TESTING.md                       # Comprehensive testing guide & results
├── requirements.txt                 # Python dependencies
├── main.py                          # Flask web application & scan orchestration pipeline
│
├── scanner/
│   ├── extractor.py                 # HTTP fetching, HTML streaming cap, TLS fallback, SSRF prevention
│   ├── matcher.py                   # Security header analysis, secret token detection, XSS sink checks
│   ├── retirejs.py                  # Component inventory, custom version comparer, OSV/Retire.js feeds
│   └── reliability.py               # WAF detection, retry_get, ScanBudget, BoundedTTLCache, SSRF logic
│
├── database/
│   ├── db_handler.py                # SQLite persistence, scan history, audit ledger management
│   └── schema.sql                   # Relational schema (scan_history, vulnerability_rules)
│
├── reporting/
│   └── pdf_builder.py               # Enterprise PDF audit report generator (ReportLab)
│
├── templates/
│   ├── index.html                   # Dashboard, scan launch form, target history ledger
│   └── result.html                  # Interactive audit telemetry & vulnerability breakdown
│
├── static/
│   └── style.css                    # Clean, utilitarian dark-mode cybersecurity theme
│
├── fixtures/                        # Pinned real-world JavaScript libraries for test validation
│   ├── jquery-3.5.1.min.js
│   ├── bootstrap-4.6.0.js
│   └── lodash-4.17.20.js
│
├── test_pages/                      # Local HTML benchmark targets
│   ├── hardened_page.html
│   ├── old_jquery.html
│   └── weak_csp.html
│
├── test_phase2_headers.py           # Unit tests: HTTP security header rules (84 tests)
├── test_phase3_library_detection.py # Unit tests: Library detection & version comparator (49 tests)
└── test_phase4_reliability.py       # Unit tests: SSRF, WAF, cache, budget, ledger (29 tests)
```

---

## Getting Started

### 1. Prerequisites
- Python 3.10 or newer (tested on Python 3.14)
- Git

### 2. Installation & Setup

```powershell
# Clone the repository
git clone https://github.com/Rahul-Raj-V-K/FRONTGUARD.git
cd FRONTGUARD

# Install required dependencies
pip install -r requirements.txt
```

> **Note on Configuration:** FRONTGUARD works **100% out of the box with zero manual configuration**. If no `.env` file is present, the app automatically generates a cryptographically secure 32-byte secret key in memory (`os.urandom(32).hex()`).
> 
> *(Optional: To use a fixed custom key, copy `.env.example` to `.env` and paste a generated key from `python -c "import secrets; print(secrets.token_hex(32))"`).*

### 3. Launching the Web Interface

```powershell
python main.py
```

Open your browser to:
```
http://127.0.0.1:5000
```

### 4. Running the Verification Suite

Run all 162 unit tests:

```powershell
python -m pytest --tb=short -q
```

All 162 tests execute in under 1 second with a 100% pass rate.

---

## Data Sources & Compliance References

| Source | Role | Endpoint / Standard |
|---|---|---|
| **OSV.dev** | Live Advisory API | `https://api.osv.dev/v1/query` |
| **npm Registry** | Package Metadata | `https://registry.npmjs.org/<pkg>/latest` |
| **Retire.js** | Vulnerability Catalog | `https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json` |
| **OWASP Top 10** | Security Standard | A05:2021 (Security Misconfiguration), A06:2021 (Vulnerable and Outdated Components) |
| **CWE / MITRE** | Weakness Classification | CWE-693, CWE-319, CWE-1021, CWE-798, CWE-918, CWE-200 |

---

## Operational Scope & Ethical Guidelines

- **Strictly Passive Assessment**: FRONTGUARD conducts non-destructive, read-only HTTP inspections. It does not perform active fuzzing, parameter injection, denial of service, or exploit delivery.
- **Authorization**: Only scan domain names and IP addresses you own or have explicit authorization to assess.
