# FRONTGUARD: AUTOMATED PASSIVE WEB SECURITY VULNERABILITY SCANNER
## Comprehensive Project Technical Dossier for MCA Capstone Report

**Project Title:** FRONTGUARD: Automated Passive Web Security Vulnerability Scanner  
**Document Purpose:** Exhaustive Technical Specification, Architecture, Design, and Implementation Data for 60–80 Page Academic Project Report  
**Degree:** Master of Computer Applications (MCA)  
**Subject Area:** Web Technologies / Information Security / Python Engineering  

---

## 1. INTRODUCTION

### 1.1 Project Background
Modern web applications are increasingly composed of client-heavy architectures, single-page frameworks, third-party Content Delivery Networks (CDNs), and complex reverse-proxy infrastructure. While dynamic application security testing (DAST) tools traditionally focus on active exploitation (e.g., fuzzing input parameters with SQL injection or command injection payloads), significant classes of critical web vulnerabilities exist in the structural and architectural perimeter. These perimeter weaknesses include:
1. Missing, defective, or conflicting HTTP security response headers.
2. Unpatched, outdated third-party JavaScript libraries containing published Common Vulnerabilities and Exposures (CVEs).
3. Inadvertently exposed administrative secrets, API keys, or private tokens embedded within client-side script code and DOM structures.
4. Dangerous Document Object Model (DOM) Cross-Site Scripting (XSS) sinks capable of executing arbitrary attacker-controlled code.

### 1.2 The Problem Domain & Limitations of Conventional Scanners
Active penetration testing and enterprise DAST suites (such as OWASP ZAP, Burp Suite Professional, or Nessus) have fundamental operational limitations in modern enterprise environments:
- **Intrusive Overhead & Service Disruption:** Active scanners send thousands of malformed HTTP requests, triggering alert fatigue in Web Application Firewalls (WAFs), polluting production databases, and risking unintended denial of service.
- **Prohibitive Licensing & Complexity:** Enterprise vulnerability scanners require substantial compute resources, dedicated orchestration, and costly commercial licensing.
- **Surface-Level Header Audits:** Conventional scanners perform trivial boolean checks (e.g., verifying whether a `Content-Security-Policy` header exists). They fail to perform syntactic tokenization or semantic evaluation—passing defective configurations such as `Content-Security-Policy: default-src * 'unsafe-inline'` or `Strict-Transport-Security: max-age=0` without warning.
- **Static vs. Live SCA Disconnect:** Local component scanners frequently rely on stale, offline JSON dumps that fail to recognize zero-day advisories or require proprietary software composition agents.

### 1.3 The FrontGuard Solution
**FRONTGUARD** addresses these limitations by providing an automated, purely **passive** web vulnerability scanner engineered in Python, Flask, and SQLite. It conducts comprehensive security audits strictly through read-only HTTP/HTTPS inspections, ensuring zero business disruption. FrontGuard parses and evaluates HTTP security headers using a custom directive-level tokenizer, performs multi-signal software composition analysis (SCA) corroborated across live feeds (OSV.dev, official Retire.js repository) and local offline fallbacks, prevents Server-Side Request Forgery (SSRF) through pre-flight DNS interrogation, enforces strict execution budgets (45-second wall clock deadline), and outputs publication-grade PDF audit dossiers via ReportLab.

---

## 2. OBJECTIVES

### 2.1 Primary Objectives
1. **Passive Perimeter Inspection:** Develop a non-intrusive, read-only scanning engine capable of auditing target web endpoints without injecting active attack payloads, altering remote data, or inducing service degradation.
2. **Directive-Level Header Evaluation:** Implement an Abstract Syntax Tokenizer and validator for HTTP security headers (CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP) that flags structural misconfigurations, conflicting directives, and weak fallback policies.
3. **Multi-Signal Client-Side SCA:** Design a Software Composition Analysis module capable of discovering third-party JavaScript libraries using multi-signal corroboration (URL regexes, comment banners, query strings, and in-code global variables) with an integrated confidence-scoring engine.
4. **Custom 4-Part Semantic Version Comparison:** Implement a dedicated version parsing and comparison engine (`SemVer` / `CustomVersion`) supporting up to 4 numeric parts (`1.2.3.4`), numeric pre-release precedence (`1.12.4-rc.1 < 1.12.4-rc.10 < 1.12.4`), and build metadata exclusion (`1.2.3+build == 1.2.3`).
5. **Live & Resilient Vulnerability Enrichment:** Synchronize component findings against Google's Open Source Vulnerabilities (OSV.dev) API and official Retire.js repositories, with automatic fallback to a local, curated database when operating in air-gapped environments.

### 2.2 Secondary / Measurable Objectives
- **Execution Budget:** Enforce a strict **45.0-second wall-clock deadline (`ScanBudget`)** per scan to prevent hung scans on unresponsive target servers.
- **Anti-DoS Memory Caps:** Implement a **512 KB streaming cap** on HTML body downloads and a **256 KB cap** on external script retrieval.
- **SSRF Immunity:** Interrogate target hostnames via `socket.gethostbyname_ex()` and unconditionally block any target resolving to RFC-1918 private, loopback (`127.0.0.0/8`), link-local, multicast, or reserved IP ranges.
- **Automated Two-Pass PDF Reporting:** Generate high-contrast, typographic PDF audit reports utilizing ReportLab's two-pass canvas renderer with dynamic "Page X of Y" pagination, executive scorecards, CVSS v3.1 severity metrics, and technical remediation guides.
- **Deterministic Verification:** Maintain a 100% automated test suite consisting of **162 unit tests** executing in under 1 second.

---

## 3. SYSTEM ANALYSIS

### 3.1 Identification of Need
Enterprise IT ecosystems, university networks, and DevOps environments require continuous baseline security monitoring. However, conducting active penetration testing requires formal authorization, rules of engagement, and maintenance windows. Without lightweight, passive tooling, system administrators frequently deploy web applications with severe perimeter vulnerabilities:
- Inline scripts vulnerable to Cross-Site Scripting due to missing CSP nonces.
- SSL stripping vulnerabilities resulting from omitted or improperly formatted HSTS headers.
- Clickjacking vulnerabilities resulting from missing `X-Frame-Options` or `frame-ancestors`.
- Third-party JavaScript dependencies with well-known CVEs (e.g., Prototype Pollution in jQuery `<3.4.0` or Lodash `<4.17.12`).

There is an acute need for a deterministic, zero-configuration utility that automates these checks instantaneously and produces executive-ready evidence dossiers without requiring commercial agents or heavy infrastructure.

### 3.2 Preliminary Investigation
An investigation was conducted comparing existing open-source and commercial approaches:
- **cURL / Manual Scripts:** Fast, but require manual inspection of header values; cannot evaluate CSP syntax, cannot resolve script dependencies, and cannot query CVE databases.
- **Lighthouse (Google Chrome):** Evaluates web performance and basic best practices; however, security checks are limited to surface-level indicators, without CVE correlation or multi-signal library extraction.
- **OWASP ZAP (Passive Mode):** Highly capable, but requires a heavy Java runtime, complex local proxy configuration, high RAM consumption (1GB+), and lacks focused, standalone client-side JavaScript SCA with live OSV.dev querying.
- **Proposed FrontGuard System:** Combines a zero-dependency Python/Flask lightweight core, instant DNS/SSRF validation, directive-level tokenization, live OSV.dev querying, and automatic ReportLab PDF synthesis into a package requiring less than 50MB of RAM.

### 3.3 Feasibility Study

#### 3.3.1 Technical Feasibility
The chosen technology stack is mature, standards-compliant, and platform-agnostic:
- **Python 3.10–3.14:** Provides robust networking, built-in SQLite bindings, strong string manipulation, and comprehensive standard libraries (`urllib.parse`, `ipaddress`, `socket`, `threading`).
- **Flask (v3.0.3):** A lightweight WSGI web application framework offering rapid route registration, Jinja2 templating, and low memory overhead without the monolithic complexity of Django.
- **Requests (v2.32.3) & BeautifulSoup4 (v4.12.3):** High-level HTTP client enabling streaming downloads, custom timeouts, and HTML DOM traversal for tag/script/comment extraction.
- **ReportLab (v4.2.2):** Industry-standard PDF generation library allowing exact millimeter-level canvas positioning, custom flowables, dynamic table styling, and two-pass page counting.
- **OSV.dev API:** A high-availability, machine-readable REST interface for open-source vulnerability intelligence supported by Google and the OpenSSF.

#### 3.3.2 Operational Feasibility
FrontGuard requires zero operational onboarding:
- Evaluators and analysts access the dashboard via standard browsers on port 5000.
- Single-input audit initiation: Analysts enter a domain or URL and receive full diagnostic telemetry within seconds.
- The interface is structured with a utilitarian dark-mode theme, utilizing high-contrast severity color tokens (Red: Critical/High, Orange: Medium, Blue: Low, Gray: Info) and avoiding ambiguous visual clutter.
- Generated PDFs can be directly forwarded to engineering teams as technical remediation tickets.

#### 3.3.3 Economic Feasibility
- **Commercial Tooling Comparison:** Commercial DAST/SCA solutions (e.g., Snyk, Veracode, Rapid7) cost thousands of dollars annually per agent or per target URL.
- **FrontGuard Costs:** 100% open-source software stack. Zero licensing fees. Can run on existing commodity hardware, local laptops, or minimal cloud VMs (such as Oracle Cloud Always Free compute instances or AWS t3.micro).

### 3.4 Project Planning & Effort Distribution
The development effort followed an iterative, agile security engineering lifecycle totaling **170 person-hours** across 6 distinct phases:

| Phase | Milestone Description | Allocated Hours | Percentage |
|---|---|---|---|
| **Phase 1** | Requirement Analysis, Literature Review, and Threat Modeling | 22 Hours | 12.9% |
| **Phase 2** | Architecture Design, Network Extractor & Security Header Parser | 38 Hours | 22.4% |
| **Phase 3** | Client-Side SCA Engine, SemVer Comparator & OSV.dev Integration | 36 Hours | 21.2% |
| **Phase 4** | Reliability Engineering (SSRF, WAF Detection, ScanBudget, Cache) | 30 Hours | 17.6% |
| **Phase 5** | Database Persistence, Dark-Mode Web UI & ReportLab PDF Engine | 26 Hours | 15.3% |
| **Phase 6** | Test Suite Construction (162 Tests), Code Audit & Documentation | 18 Hours | 10.6% |
| **Total** | **End-to-End System Delivery** | **170 Hours** | **100.0%** |

### 3.5 Project Scheduling

#### 3.5.1 Gantt Chart Schedule
```
---------------------------------------------------------------------------------------
Phase / Activity                  W01 W02 W03 W04 W05 W06 W07 W08 W09 W10 W11 W12 W13 W14
---------------------------------------------------------------------------------------
P1: Requirement Analysis & Spec   [=====]
P2: Extractor & Header Parser           [===========]
P3: SCA Engine & SemVer Logic                 [===========]
P4: Reliability & SSRF Guard                        [=======]
P5: Web UI & PDF Reporting                                [=======]
P6: Verification, Tests & Docs                                  [=====]
---------------------------------------------------------------------------------------
```

#### 3.5.2 PERT Chart & Critical Path Analysis
- **Activity A (P1):** Requirements & Architecture ($t_e = 12$ days)
- **Activity B (P2):** Core Network Extractor & Header Tokenizer ($t_e = 18$ days, Depends on A)
- **Activity C (P3):** SCA & Version Comparator ($t_e = 16$ days, Depends on B)
- **Activity D (P4):** Defensive Reliability & Cache ($t_e = 14$ days, Depends on C)
- **Activity E (P5):** Database, Web Interface & PDF Generation ($t_e = 12$ days, Depends on D)
- **Activity F (P6):** Comprehensive Testing & Submission Prep ($t_e = 10$ days, Depends on E)

**Critical Path:** `A → B → C → D → E → F`  
Total Expected Duration ($T_E$): $12 + 18 + 16 + 14 + 12 + 10 = 82\text{ working days}$.  
Formula applied per task: 
$$t_e = \frac{O + 4M + P}{6}$$
*(where $O$ = Optimistic time, $M$ = Most likely time, $P$ = Pessimistic time).*

### 3.6 Software Requirement Specification (SRS)

#### 3.6.1 Functional Requirements (FR)
- **FR-01 (URL Ingress & Normalization):** Accepts raw target URLs or domain names; automatically enforces valid HTTP/HTTPS schemes and sanitizes hostname strings.
- **FR-02 (Pre-flight DNS & SSRF Validation):** Resolves all public A-records using `socket.gethostbyname_ex()`; checks resolved addresses against RFC-1918/loopback ranges and aborts with a high-severity alert if an internal IP is detected.
- **FR-03 (HTTP/HTTPS Redirect Divergence Analysis):** Probes plain-HTTP endpoints without following redirects to capture redirect headers, comparing them against the final HTTPS response to flag HSTS-on-HTTP misconfigurations.
- **FR-04 (TLS Handshake & Defensive Fallback):** Validates remote TLS certificates; if invalid, records a high-severity finding (`CWE-295`) and seamlessly falls back to unverified TLS to evaluate subsequent headers.
- **FR-05 (CSP AST Parsing):** Tokenizes `Content-Security-Policy` into structured directive-to-source mappings; flags `'unsafe-inline'`, `'unsafe-eval'`, wildcards (`*`), `data:` schemes, and missing directives (`default-src`, `object-src`, `base-uri`, `frame-ancestors`).
- **FR-06 (HSTS Compliance Validation):** Verifies `Strict-Transport-Security` directives, checking for `max-age >= 31536000`, `includeSubDomains`, `preload`, and flags `max-age=0` as an active security revocation.
- **FR-07 (Modern Clickjacking Equivalence):** Validates `X-Frame-Options` (`DENY`, `SAMEORIGIN`), but recognizes CSP `frame-ancestors` as an equivalent modern control to eliminate false positives.
- **FR-08 (Client-Side Component Discovery):** Traverses HTML script elements to extract external script URLs and inline script blocks; identifies component signatures via multi-signal regex corroboration.
- **FR-09 (Semantic Version Evaluation):** Parses extracted version strings into 4-part numeric tuples with alphanumeric pre-release tokens; performs interval checks against known vulnerable ranges.
- **FR-10 (Live Advisory Querying):** Queries OSV.dev REST API and Retire.js live repository; extracts CVE aliases, summary descriptions, CVSS ratings, and safe remediation targets.
- **FR-11 (In-Memory Bounded Caching):** Maintains an LRU cache with time-to-live expiration to store external API query results and avoid duplicate network overhead.
- **FR-12 (Audit Persistence & Reset):** Logs all scan telemetry and risk scores into an SQLite relational database; provides a dedicated `/clear-history` endpoint to purge the ledger securely.
- **FR-13 (Automated PDF Report Generation):** Renders a structured, publication-grade PDF report containing executive scorecards, finding summaries, code evidence, and technical remediation recommendations.

#### 3.6.2 Non-Functional Requirements (NFR)
- **NFR-01 (Performance & Wall-Clock Budget):** A single scan must terminate within **45.0 seconds** (`ScanBudget`).
- **NFR-02 (Memory Safety & Stream Caps):** HTML streaming must abort upon reading **512 KB**; individual script streaming must abort upon reading **256 KB**.
- **NFR-03 (Concurrency & Thread-Safety):** The in-memory cache and script retrieval pool must use explicit mutex locks (`threading.Lock()`) and bounded thread worker pools (`max_workers=5`).
- **NFR-04 (Determinism & Zero Exploitation):** All audit operations must be 100% passive, read-only, and repeatable across equivalent network conditions.
- **NFR-05 (Availability & Fault Tolerance):** Network failures, connection timeouts, or missing remote APIs must degrade gracefully to local offline databases without crashing the WSGI server.

### 3.7 System Specifications

#### 3.7.1 Hardware Specifications
- **Host CPU:** Any modern 64-bit multi-core processor (Intel Core i3/i5/i7, AMD Ryzen, or ARM64 Ampere/Apple Silicon).
- **Host RAM:** 2 GB Minimum (4 GB Recommended).
- **Disk Space:** 150 MB (Application code, dependencies, and local PDF reports).

#### 3.7.2 Software Specifications
- **Operating System:** Windows 10/11, macOS Monterey+, or Linux (Ubuntu 20.04/22.04 LTS).
- **Core Platform:** Python 3.10.x through 3.14.x.
- **WSGI Application Framework:** Flask 3.0.3.
- **HTTP Client:** Requests 2.32.3 with urllib3.
- **HTML DOM Parser:** BeautifulSoup4 4.12.3.
- **PDF Generation Engine:** ReportLab 4.2.2.
- **Environment Management:** python-dotenv 1.0.1.
- **Automated Test Harness:** Pytest 9.2.0.
- **Database Engine:** SQLite 3 (Standard Python Library).

### 3.8 Data Models & Diagrammatic Specifications

#### 3.8.1 Class Diagram Specifications
```
+-------------------------------------------------------------------+
|                            TargetData                             |
+-------------------------------------------------------------------+
| - dict_store: dict                                                |
+-------------------------------------------------------------------+
| + __iter__(): tuple (headers, script_srcs)                        |
| + get(key, default): Any                                          |
| + keys(): list                                                    |
+-------------------------------------------------------------------+
                                 ^
                                 | uses
+--------------------------------+----------------------------------+
|                            ScanBudget                             |
+-------------------------------------------------------------------+
| - _deadline: float                                                |
| - _total: float                                                   |
+-------------------------------------------------------------------+
| + is_expired(): bool                                              |
| + remaining(): float                                              |
| + can_sleep(seconds: float): bool                                 |
| + clamp_timeout(connect: float, read: float): tuple[float, float] |
+-------------------------------------------------------------------+

+-------------------------------------------------------------------+
|                         BoundedTTLCache                           |
+-------------------------------------------------------------------+
| - _store: OrderedDict                                             |
| - _maxsize: int                                                   |
| - _ttl: float                                                     |
| - _lock: threading.Lock                                           |
+-------------------------------------------------------------------+
| + get(key: str): tuple[bool, Any]                                 |
| + set(key: str, value: Any): void                                 |
| + __len__(): int                                                  |
+-------------------------------------------------------------------+

+-------------------------------------------------------------------+
|                             SemVer                                |
+-------------------------------------------------------------------+
| + raw: str                                                        |
| + parts: tuple[int, ...]                                          |
| + prerelease: tuple[tuple[int, Any], ...] | None                  |
| + build: str | None                                               |
| + is_valid: bool                                                  |
+-------------------------------------------------------------------+
| + __lt__(other: SemVer): bool                                     |
| + __eq__(other: SemVer): bool                                     |
| + __gt__(other: SemVer): bool                                     |
| + __le__(other: SemVer): bool                                     |
| + __ge__(other: SemVer): bool                                     |
+-------------------------------------------------------------------+
```

#### 3.8.2 Activity Diagram (Sequential Logic Flow)
1. **User Action:** Submits target endpoint (e.g., `https://example.com`) via Web Dashboard.
2. **Controller:** Normalizes URL scheme and invokes `dummy_scan(url)`.
3. **DNS Pre-flight:** Executes `resolve_target_ip()`.
   - *Decision:* Does resolved IP belong to a private, loopback, or multicast subnet?
   - *If Yes:* Abort scan immediately; generate high-severity SSRF alert finding; render failed result view.
   - *If No:* Proceed to connection.
4. **Network Probe:** Sends non-redirecting GET request to plain-HTTP endpoint to capture redirect headers.
5. **TLS Evaluation:** Initiates HTTPS GET with strict certificate validation.
   - *Decision:* Does TLS handshake succeed?
   - *If No (SSLError):* Record High-Severity `TLS Certificate Validation Failed` finding; retry with unverified TLS fallback.
   - *If Yes:* Proceed.
6. **Streaming Ingestion:** Downloads HTML stream up to 512 KB cap; parses DOM using BeautifulSoup.
7. **Rule Matching:**
   - Tokenizes and evaluates security headers (`matcher.py`).
   - Discovers inline secrets, API keys, passwords, and DOM XSS sinks.
   - Compares HTTP redirect headers with HTTPS headers.
8. **SCA Engine:**
   - Discovers scripts; resolves versions using `SemVer`.
   - Interrogates `BoundedTTLCache`. If cache miss, queries live OSV.dev and Retire.js APIs (falls back to local `RETIREJS_DB` on network timeout).
9. **Report Generation:** Compiles findings matrix and synthesizes PDF via `NumberedCanvas`.
10. **Persistence:** Inserts audit summary into `scan_history` in `scanner.db` and writes findings JSON to `reports/`.
11. **Presentation:** Renders interactive result view to the browser.

#### 3.8.3 Sequence Diagram Specifications
```
User            Dashboard (Flask)       Extractor           Matcher/SCA           OSV.dev API        SQLite DB
 |                     |                     |                   |                     |                 |
 |--- POST /scan ----->|                     |                   |                     |                 |
 |                     |--- extract_data --->|                   |                     |                 |
 |                     |                     |-- DNS / SSRF Check|                     |                 |
 |                     |                     |-- HTTP & HTTPS GET|                     |                 |
 |                     |<-- TargetData ------|                   |                     |                 |
 |                     |                                         |                     |                 |
 |                     |------- run_matcher(headers, scripts) -->|                     |                 |
 |                     |                                         |--- query OSV ------>|                 |
 |                     |                                         |<-- CVE Payload -----|                 |
 |                     |<------ vulnerabilities list ------------|                     |                 |
 |                     |                                                                                 |
 |                     |------- insert_scan_record() --------------------------------------------------->|
 |                     |                                                                                 |
 |                     |------- generate_audit_report(pdf)                                               |
 |<-- 302 /result/id --|                                                                                 |
 |--- GET /result/id ->|                                                                                 |
 |<-- Rendered HTML ---|                                                                                 |
```

#### 3.8.4 Entity Relationship Diagram (ERD)
The database schema (`schema.sql`) implements relational persistence using SQLite:

```
+-----------------------------------+             +-----------------------------------+
|           scan_history            |             |        vulnerability_rules        |
+-----------------------------------+             +-----------------------------------+
| PK  id             INTEGER        |             | PK  id                INTEGER     |
|     target_url     TEXT (NOT NULL)|             | UQ  rule_key          VARCHAR(100)|
|     target_ip      TEXT           |             |     name              VARCHAR(255)|
|     scan_date      TEXT (NOT NULL)|    1 : N    |     severity          VARCHAR(50) |
|     findings_count INTEGER        | < - - - - > |     description       TEXT        |
|     risk_level     TEXT           |  (Logical)  |     ref_id            VARCHAR(50) |
|     pdf_path       TEXT           |             |     cve_id            VARCHAR(50) |
+-----------------------------------+             |     cvss_score        FLOAT       |
                                                  |     reference_link    VARCHAR(500)|
                                                  |     remediation_steps TEXT        |
                                                  +-----------------------------------+
```
- **`scan_history` Table:** Stores one record per executed scan execution, capturing the target URL, all resolved public IP addresses, the exact timestamp (UTC), the total count of identified findings, the calculated overall risk rating, and the local filepath to the generated PDF.
- **`vulnerability_rules` Table:** Serves as the authoritative knowledge base for misconfiguration types, linking each rule key to standardized CWE classifications, default CVSS v3.1 base scores, OWASP documentation links, and actionable remediation steps.
- **Logical Cardinality:** One scan run correlates with multiple identified findings ($1:N$ relationship), each referencing a standardized rule definition in `vulnerability_rules`.

#### 3.8.5 Use Case Diagram Specifications
- **Primary Actor:** Security Analyst / Auditor / Developer
  - *Use Cases:*
    1. Enter target URL and trigger passive audit.
    2. View live scan telemetry (resolved IPs, overall risk level).
    3. Inspect categorized vulnerability findings (Headers vs. Component CVEs).
    4. Download formal PDF audit dossier.
    5. Review past audit logs in Audit Ledger.
    6. Purge historical records via Audit Ledger reset.
- **Secondary Actor:** Target Web Server
  - *Use Cases:*
    1. Receives non-intrusive HTTP/HTTPS GET requests.
    2. Returns response headers and streamed HTML payload.
- **External System Actor:** OSV.dev / Retire.js Repositories
  - *Use Cases:*
    1. Ingests package name and version query payload.
    2. Returns JSON array of published CVE records and remediation versions.

---

## 4. SYSTEM DESIGN

### 4.1 Modularization Details

#### 4.1.1 Network Extractor Module (`scanner/extractor.py`)
- **Input:** Target URL string (e.g., `https://example.com`).
- **Processing Logic:**
  1. Resolves all public A-records using `socket.gethostbyname_ex()`; sorts IP list alphabetically for deterministic output.
  2. Applies `is_private_ip()` validation; if private/loopback, terminates with SSRF prevention alert.
  3. Executes a non-redirecting GET request to `http://<target>` using `TARGET_TIMEOUT = (4.0, 8.0)` to record redirect-stage headers.
  4. Initiates HTTPS GET with strict certificate verification (`verify=True`). Catches `requests.exceptions.SSLError`; records high-severity finding and falls back to `verify=False` with `urllib3.disable_warnings(InsecureRequestWarning)`.
  5. Reads response body via `resp.iter_content(chunk_size=8192)`; enforces `MAX_HTML_BYTES = 512 * 1024` streaming cap.
  6. Evaluates WAF challenge signatures via `detect_waf_or_block()`.
  7. Parses HTML DOM with BeautifulSoup to extract `<script src="...">`, inline scripts, HTML comments, and `<form>` inputs.
- **Output:** Structured `TargetData` dictionary container.

#### 4.1.2 Security Header Matcher Module (`scanner/matcher.py`)
- **Input:** Raw response headers dictionary, inline script list, comments, and form structures.
- **Processing Logic:**
  1. **CSP Evaluation:** Parses directives into `{directive: [sources]}` map. Checks for:
     - Header absence.
     - Report-Only present but not enforced.
     - `'unsafe-inline'` without nonces/hashes/strict-dynamic.
     - `'unsafe-eval'`.
     - Wildcards (`*`) in `script-src` (High) vs `default-src` (Medium).
     - Missing `object-src`, `base-uri`, `frame-ancestors`, `default-src`.
  2. **HSTS Evaluation:** Extracts `max-age` integer. Flags `max-age=0` (disabling HSTS), `max-age < 86400` (too short), `max-age < 31536000` (preload non-compliant), missing `includeSubDomains`, and missing `preload`.
  3. **X-Frame-Options Evaluation:** Validates `DENY` or `SAMEORIGIN`; suppresses missing alert if CSP `frame-ancestors` is actively enforced.
  4. **X-Content-Type-Options:** Requires exact value `'nosniff'`.
  5. **Referrer-Policy:** Flags `'unsafe-url'` as Medium severity (worse than absent).
  6. **Cross-Origin Policies:** Audits COOP, CORP, and COEP headers.
  7. **Information Disclosure:** Flags `X-Powered-By` presence and checks if `Server` header contains numeric version strings (`_server_discloses_version()`).
  8. **DOM XSS & Secrets:** Runs regex matching across inline scripts for API keys (`api_key`, `bearer`, AWS access keys) and dangerous execution sinks (`eval(dynamic)`, `document.write()`, `.innerHTML`).
- **Output:** Categorized list of vulnerability findings dictionaries.

#### 4.1.3 RetireJS & SCA Engine Module (`scanner/retirejs.py`)
- **Input:** Discovered script URLs, inline script contents, and target URL.
- **Processing Logic:**
  1. Compares script paths and header comments against component regex signatures for jQuery, Bootstrap, Lodash, Moment.js, Vue, Axios, Handlebars, etc.
  2. Parses candidate versions using `SemVer`.
  3. Checks `BoundedTTLCache` for cached advisories.
  4. If cache miss, queries `https://api.osv.dev/v1/query` with `{package: {name, ecosystem: 'npm'}, version}`.
  5. If OSV succeeds, parses CVE aliases, fixed version ranges, and severity scores.
  6. If live network fails, falls back seamlessly to `RETIREJS_DB` in memory.
  7. Formats component inventory items with confidence scores (High/Medium/Low).
- **Output:** Tuple of `(retirejs_findings_list, components_inventory_list)`.

#### 4.1.4 Reliability & Defense Module (`scanner/reliability.py`)
- **Input:** Network responses, IP strings, elapsed execution times.
- **Processing Logic:**
  1. `ScanBudget`: Tracks monotonic deadline ($T_{\text{start}} + 45.0$). Clamps connect/read timeouts dynamically.
  2. `BoundedTTLCache`: Thread-safe LRU dictionary with TTL validation; evicts oldest items when capacity (256) is exceeded.
  3. `detect_waf_or_block`: Evaluates status codes (403, 406, 429, 503), header markers (`cf-mitigated`, `x-amzn-waf-action`), and body markers ('just a moment', '_cf_chl_').
  4. `retry_get`: Implements bounded exponential backoff with jitter and honors `Retry-After` headers.
  5. `is_private_ip`: Evaluates IP against standard private network blocks.
- **Output:** Enforced time limits, safe caching, and WAF classification tags.

#### 4.1.5 Database Handler Module (`database/db_handler.py`)
- **Input:** Scan metadata, target IP, findings counts, vulnerability rule identifiers.
- **Processing Logic:**
  1. `init_db()`: Executes `schema.sql` on startup; checks PRAGMA table info and applies dynamic schema migrations.
  2. Populates `vulnerability_rules` with default CWE and OWASP mappings using `ON CONFLICT(rule_key) DO UPDATE`.
  3. `insert_scan_record()`: Persists scan events with parameterized SQL statements.
  4. `clear_scan_history()`: Deletes records from `scan_history` and resets the SQLite autoincrement sequence counter.
- **Output:** Integer primary keys, record dictionaries, and rule definitions.

#### 4.1.6 PDF Builder Module (`reporting/pdf_builder.py`)
- **Input:** Consolidated `scan_data` dictionary and output filesystem path.
- **Processing Logic:**
  1. Initializes ReportLab `SimpleDocTemplate` on A4 paper with 13 mm margins.
  2. Constructs custom Flowables: Title Header, Telemetry Key-Value Table, Severity Distribution Scorecard, and Finding Tables.
  3. Applies utilitarian high-contrast color palette: Dark Navy (`#0f172a`), Slate Border (`#cbd5e1`), Row Alt (`#f8fafc`).
  4. Maps findings to severity badge colors (Critical: `#991b1b`, High: `#c2410c`, Medium: `#854d0e`, Low: `#0369a1`).
  5. Uses `NumberedCanvas` to calculate total pages dynamically and prints footer text ("CONFIDENTIAL // TECHNICAL SECURITY AUDIT", "Page X of Y").
- **Output:** Finalized binary PDF document written to `reports/`.

#### 4.1.7 Flask Web Controller (`main.py`)
- **Input:** User HTTP requests on routes `/`, `/scan`, `/result/<id>`, `/report/<id>/pdf`, `/clear-history`.
- **Processing Logic:**
  1. Manages environment variables and secret key initialization (`os.environ.get('FLASK_SECRET_KEY') or os.urandom(32).hex()`).
  2. Orchestrates end-to-end pipeline: extraction → matching → SCA → report synthesis → DB logging.
  3. Handles caching in `_findings_cache` and serves responses using Jinja2 templates.
- **Output:** HTML views, JSON findings files, and streamed PDF downloads.

### 4.2 Data Integrity and Constraints
- **SQL Injection Prevention:** 100% of database interactions in `db_handler.py` utilize parameterized query syntax (`?` placeholders). Zero string concatenation is used.
- **Thread Safety:** The in-memory cache (`BoundedTTLCache`) wraps every read, write, and eviction inside an explicit `threading.Lock()` mutex context.
- **Streaming Resource Caps:** To protect server memory from zip-bombs or multi-gigabyte responses, network streams terminate immediately upon reaching 512 KB (HTML) or 256 KB (JavaScript).
- **Graceful Zero-Configuration Fallback:** The session secret key automatically falls back to cryptographically secure random bytes (`os.urandom(32).hex()`) if no `.env` file exists, preventing unhandled startup exceptions.

---

## 5. TESTING SPECIFICATIONS

The test suite consists of **162 unit tests** achieving 100% pass rate in **0.75 seconds**. Below is a representative matrix of 12 critical test scenarios implemented across the test suites:

| Test ID | Test Suite | Scenario Description | Test Input / Mock Condition | Expected Result |
|---|---|---|---|---|
| **TC-01** | `test_phase4` | SSRF Private IP Prevention | Target URL resolving to `192.168.1.1` | Scan blocked; `is_ssrf_blocked=True`; finding `CWE-918` emitted. |
| **TC-02** | `test_phase4` | SSRF Loopback Range Check | Target hostname resolving to `127.0.0.1` | Target access blocked; zero outbound HTTP requests issued. |
| **TC-03** | `test_phase4` | Streaming HTML Cap (Anti-DoS) | Mock HTTP stream emitting 1.2 MB of payload | Stream terminates at exactly 512 KB; `html_truncated=True`. |
| **TC-04** | `test_phase2` | TLS Certificate Failure Fallback | Host triggering `requests.exceptions.SSLError` | Emits High-Severity `CWE-295`; successfully retries with unverified TLS. |
| **TC-05** | `test_phase2` | CSP `unsafe-inline` Detection | `Content-Security-Policy: default-src 'self' 'unsafe-inline'` | Flags High-Severity finding for un-hashed inline execution. |
| **TC-06** | `test_phase2` | CSP Nonce Exemption | `script-src 'unsafe-inline' 'nonce-r4nd0m'` | Ignores `'unsafe-inline'` per CSP3 spec (compliant behavior). |
| **TC-07** | `test_phase2` | HSTS Revocation Detection | `Strict-Transport-Security: max-age=0` | Flags High-Severity finding for active policy disabling. |
| **TC-08** | `test_phase2` | Frame Protection Equivalence | Header has no `X-Frame-Options`, but CSP has `frame-ancestors 'none'` | Suppresses missing XFO alert; recognizes modern CSP compliance. |
| **TC-09** | `test_phase3` | 4-Part SemVer Numeric Precedence | Version comparison: `1.12.4` vs `1.9.0` | `SemVer('1.12.4') > SemVer('1.9.0')` returns `True`. |
| **TC-10** | `test_phase3` | SemVer Pre-release Hierarchy | Pre-release check: `1.0.0-rc.2` vs `1.0.0-rc.10` | `SemVer('1.0.0-rc.2') < SemVer('1.0.0-rc.10')` returns `True`. |
| **TC-11** | `test_phase3` | SemVer Build Metadata Exclusion | Build metadata equality: `1.2.3+2024` vs `1.2.3` | `SemVer('1.2.3+2024') == SemVer('1.2.3')` returns `True`. |
| **TC-12** | `test_phase4` | WAF Challenge Page Detection | Response with Cloudflare marker `_cf_chl_` | Scan status marked `BLOCKED`; diagnostic emitted. |

---

## 6. SYSTEM SECURITY & SELF-DEFENSE MEASURES

FrontGuard implements rigorous defense-in-depth controls to protect both the scanning host and target infrastructure:

1. **Pre-Flight SSRF Defenses (`is_private_ip`):**
   Before initiating any socket connection, FrontGuard parses the target hostname, queries DNS via `socket.gethostbyname_ex()`, and converts all returned addresses to `ipaddress.ip_address` objects. It validates against `is_private`, `is_loopback`, `is_link_local`, `is_reserved`, and `is_multicast`. This ensures attackers cannot weaponize FrontGuard to pivot into AWS instance metadata (`169.254.169.254`), Kubernetes API services (`10.96.0.1`), or local intranet databases.
2. **Anti-DoS Streaming Caps:**
   Malicious targets could attempt to exhaust scanner memory by returning infinite HTTP chunked data or multi-gigabyte files. FrontGuard consumes raw sockets using `resp.iter_content(chunk_size=8192)` and breaks execution if total received bytes exceed 512 KB (HTML) or 256 KB (external scripts).
3. **Execution Wall-Clock Budget (`ScanBudget`):**
   Targets utilizing tarpitting techniques (sending bytes at extreme slow rates) are neutralized by FrontGuard's monotonic deadline timer. If the 45.0-second total budget expires, remaining checks are bypassed and partial results are synthesized cleanly.
4. **WAF & Challenge Page Quarantine:**
   When targets present Cloudflare Turnstile, AWS WAF, or Imperva challenge screens, standard scanners evaluate the challenge HTML as if it were the application itself (producing dozens of false vulnerabilities). FrontGuard detects these signatures and quarantines the result with an explicit `BLOCKED` status.
5. **Memory Leak Mitigation via Bounded TTLs:**
   The internal cache utilizes an `OrderedDict` bounded at 256 elements with a 3600-second TTL. Every insertion checks capacity and evicts the oldest items, ensuring memory footprint never exceeds 50 MB regardless of uptime.

---

## 7. COST ESTIMATION

### 7.1 Development Effort Valuation (Theoretical Academic Valuation)
Applying the industry standard COCOMO-II / Software Engineering Hourly Model:
- **Total Engineering Hours:** 170 Hours
- **Standard Industry Rate (Junior Security Analyst / Python Engineer):** \$35.00 / hour
- **Total Development Labor Value:** $170 \times 35 = \mathbf{\$5,950.00\text{ USD}}$ (Approx. ₹4,95,000 INR).

### 7.2 Infrastructure & Operational Costs
- **Software Licenses:** \$0.00 (Python, Flask, SQLite, BeautifulSoup4, ReportLab Community Edition, Pytest are all open-source under MIT/BSD/LGPL/Apache licenses).
- **API Costs:** \$0.00 (Google OSV.dev API and Retire.js GitHub raw endpoints are free public services).
- **Deployment Costs:**
  - *Academic / Local Evaluation:* \$0.00 (Executed on commodity student hardware).
  - *Cloud Hosting (Optional):* \$0.00 / month utilizing Oracle Cloud Infrastructure (OCI) Always Free Tier (4 OCPUs, 24 GB RAM Ampere instance) or \$5.00 / month on DigitalOcean/Render.

---

## 8. REPORTING & VISUALIZATION

### 8.1 Interactive Web Dashboard Metrics
The web frontend presents findings through an intuitive, dark-mode cybersecurity cockpit:
- **Telemetry Bar:** Displays Target URL, Public IP, Scan Status (`COMPLETE`, `BLOCKED`, `FAILED`), and Risk Rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Interactive Risk Breakdown:** Separates issues into distinct cards for Security Headers, Client-Side JavaScript Components, and Secret/XSS Exposures.
- **Audit Ledger:** Displays complete historical scan records stored in SQLite, allowing instant re-inspection or PDF export.

### 8.2 Enterprise PDF Audit Report Architecture
The generated PDF audit dossier is rendered using ReportLab's Flowable architecture:
- **Geometry:** A4 Paper Dimensions ($210 \times 297\text{ mm}$) with $13\text{ mm}$ side margins.
- **Cover Header:** Displays "TECHNICAL SECURITY AUDIT REPORT", Target FQDN, Target IP, and Generation Timestamp.
- **Executive Summary Matrix:** High-contrast scorecard visualizing finding distribution across Critical, High, Medium, Low, and Informational severity tiers.
- **Detailed Finding Tables:** For each issue, the PDF renders a bounded table specifying:
  - Vulnerability Title & Type
  - Severity Rating with Color-Coded Indicators
  - CVSS v3.1 Base Score & Standardized CWE Reference ID (e.g., `CWE-693`, `CWE-798`, `CWE-319`)
  - Attack Prevented Technical Rationale
  - Observed Raw Evidence Snippet
  - Actionable Step-by-Step Remediation Recommendations
- **Two-Pass Dynamic Pagination:** Implements `NumberedCanvas` to calculate total pages in memory, printing exact footers: `"Page X of Y // CONFIDENTIAL // FRONTGUARD AUDIT ENGINE"`.

---

## 9. FUTURE SCOPE

While FrontGuard provides a complete, robust passive auditing solution, several architectural enhancements are planned for future iterations:
1. **Authenticated Session Auditing:** Support for cookie injection, HTTP Bearer token headers, and automated login scripting to allow passive scanning behind enterprise authentication portals.
2. **Headless Browser / SPA Execution (Puppeteer / Playwright Integration):** Integration with headless Chromium to evaluate Single Page Applications (React, Angular, Vue) where scripts, DOM nodes, and headers are constructed dynamically via client-side JavaScript.
3. **CI/CD Pipeline Security Gate (GitHub Actions / GitLab CI):** Packaging FrontGuard as a Docker container and CLI tool capable of failing pull requests if high-severity CVEs or missing security headers are detected.
4. **Automated Subdomain Discovery:** Integrating passive DNS enumeration (crt.sh, Certificate Transparency logs) to scan entire organization domains automatically.
5. **Continuous Cron-Based Monitoring:** Scheduling automated recurring scans to alert system administrators when new CVEs are published for their detected library versions.

---

## 10. APPENDICES

### 10.1 Core Python Code Snippets

#### Snippet 1: Pre-Flight DNS Interrogation & SSRF Guard (`scanner/reliability.py`)
```python
import ipaddress

def is_private_ip(ip_str: str) -> bool:
    """Evaluates whether an IP address belongs to private or loopback ranges."""
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
```

#### Snippet 2: Wall-Clock Scan Budget Manager (`scanner/reliability.py`)
```python
import time

class ScanBudget:
    """Enforces strict wall-clock timeout deadlines across all scan operations."""
    def __init__(self, total_seconds=45.0):
        self._deadline = time.monotonic() + total_seconds
        self._total = total_seconds

    def is_expired(self) -> bool:
        return time.monotonic() >= self._deadline

    def remaining(self) -> float:
        return max(0.0, self._deadline - time.monotonic())

    def can_sleep(self, seconds: float) -> bool:
        return (time.monotonic() + seconds) < self._deadline

    def clamp_timeout(self, connect: float, read: float) -> tuple[float, float]:
        rem = self.remaining()
        return (min(connect, rem * 0.4), min(read, rem * 0.6))
```

#### Snippet 3: Custom 4-Part SemVer Comparator (`scanner/retirejs.py`)
```python
import re

class SemVer:
    """Custom 4-part semantic version parser with numeric pre-release support."""
    def __init__(self, v_str):
        self.raw = str(v_str or '').strip()
        cleaned = self.raw.lstrip('v').lstrip('V')
        version_no_build, _, build_part = cleaned.partition('+')
        self.build = build_part if build_part else None

        main_part, _, pre_part = version_no_build.partition('-')
        nums = [int(x) for x in re.findall(r'\d+', main_part)]
        while len(nums) < 3:
            nums.append(0)
        self.parts = tuple(nums)

        if pre_part:
            pre_tokens = []
            for token in re.split(r'[.-]', pre_part):
                for sp in re.findall(r'[a-zA-Z]+|\d+', token):
                    pre_tokens.append((0, int(sp)) if sp.isdigit() else (1, sp.lower()))
            self.prerelease = tuple(pre_tokens) if pre_tokens else None
        else:
            self.prerelease = None
        self.is_valid = bool(nums)

    def __lt__(self, other):
        if not isinstance(other, SemVer):
            other = SemVer(other)
        if self.parts != other.parts:
            return self.parts < other.parts
        if self.prerelease is None and other.prerelease is None:
            return False
        if self.prerelease is not None and other.prerelease is None:
            return True
        if self.prerelease is None and other.prerelease is not None:
            return False
        return self.prerelease < other.prerelease
```

#### Snippet 4: CSP Directive Tokenizer (`scanner/matcher.py`)
```python
def _parse_csp_directives(csp_value: str) -> dict[str, list[str]]:
    """Tokenizes CSP header into a directive-to-source-list dictionary."""
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
```

#### Snippet 5: Thread-Safe Bounded TTL Cache (`scanner/reliability.py`)
```python
import time
import threading
from collections import OrderedDict

class BoundedTTLCache:
    """Thread-safe LRU cache with monotonic TTL eviction."""
    def __init__(self, maxsize=256, ttl=3600.0):
        self._store = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            if key not in self._store:
                return False, None
            ts, val = self._store[key]
            if time.monotonic() - ts > self._ttl:
                del self._store[key]
                return False, None
            self._store.move_to_end(key)
            return True, val

    def set(self, key: str, value):
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (time.monotonic(), value)
            while len(self._store) > self._maxsize:
                self._store.popitem(last=False)
```

#### Snippet 6: Dynamic Two-Pass Page Numbering (`reporting/pdf_builder.py`)
```python
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and draw total page count."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColorHex("#64748b")
        text = f"Page {self._pageNumber} of {page_count}  //  CONFIDENTIAL  //  FRONTGUARD AUDIT ENGINE"
        self.drawRightString(210 * 2.83465 - 13 * 2.83465, 10 * 2.83465, text)
        self.restoreState()
```

### 10.2 Bibliography & Technical Standards
1. **RFC 6797:** Hodges, J., et al. *"HTTP Strict Transport Security (HSTS)"*, Internet Engineering Task Force (IETF), 2012. URL: https://datatracker.ietf.org/doc/html/rfc6797
2. **RFC 7034:** Ross, D., et al. *"HTTP Header Field X-Frame-Options"*, Internet Engineering Task Force (IETF), 2013. URL: https://datatracker.ietf.org/doc/html/rfc7034
3. **W3C Content Security Policy Level 3:** West, M., et al. *"Content Security Policy Level 3 Specification"*, W3C Working Draft, 2023. URL: https://www.w3.org/TR/CSP3/
4. **OWASP Top 10 (2021):** Open Web Application Security Project. *"A05:2021 – Security Misconfiguration"*, OWASP Foundation, 2021. URL: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
5. **OWASP Top 10 (2021):** Open Web Application Security Project. *"A06:2021 – Vulnerable and Outdated Components"*, OWASP Foundation, 2021. URL: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
6. **MITRE Common Weakness Enumeration (CWE):** The MITRE Corporation. *"CWE-693: Protection Mechanism Failure"*, 2024. URL: https://cwe.mitre.org/data/definitions/693.html
7. **MITRE Common Weakness Enumeration (CWE):** The MITRE Corporation. *"CWE-918: Server-Side Request Forgery (SSRF)"*, 2024. URL: https://cwe.mitre.org/data/definitions/918.html
8. **MITRE Common Weakness Enumeration (CWE):** The MITRE Corporation. *"CWE-798: Use of Hard-coded Credentials"*, 2024. URL: https://cwe.mitre.org/data/definitions/798.html
9. **Google Open Source Vulnerabilities (OSV):** OpenSSF / Google. *"OSV Schema and API Specification v1.5"*, 2024. URL: https://osv.dev/docs/
10. **Retire.js:** Erlend Oftedal. *"Retire.js JavaScript Vulnerability Repository"*, 2024. URL: https://github.com/RetireJS/retire.js
11. **ReportLab Documentation:** ReportLab Europe Ltd. *"ReportLab PDF Generation User Guide"*, Version 4.2, 2024. URL: https://www.reportlab.com/docs/reportlab-userguide.pdf
12. **Flask Documentation:** Pallets Projects. *"Flask Web Development Framework Documentation (v3.0.x)"*, 2024. URL: https://flask.palletsprojects.com/
