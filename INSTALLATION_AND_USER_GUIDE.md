# FRONTGUARD: AUTOMATED PASSIVE WEB SECURITY VULNERABILITY SCANNER
## Project Installation & User Manual

**Academic Degree:** Master of Computer Applications (MCA)  
**Project Title:** FRONTGUARD: Automated Passive Web Security Vulnerability Scanner  
**Document Version:** 1.0 (Production Submission)

---

## Table of Contents
1. [Overview](#1-overview)
2. [Hardware & Software Prerequisites](#2-hardware--software-prerequisites)
3. [Unpacking the Submission Archive](#3-unpacking-the-submission-archive)
4. [Step-by-Step Installation](#4-step-by-step-installation)
   - [Method 1: Virtual Environment (Recommended)](#method-1-virtual-environment-recommended)
   - [Method 2: Direct System Installation](#method-2-direct-system-installation)
   - [Method 3: Flask Secret Key & Environment Configuration](#method-3-flask-secret-key--environment-configuration)
5. [Starting the Application](#5-starting-the-application)
6. [User Guide: Operating the Scanner](#6-user-guide-operating-the-scanner)
   - [6.1 Launching a Target Vulnerability Audit](#61-launching-a-target-vulnerability-audit)
   - [6.2 Reading the Telemetry Dossier & Risk Matrix](#62-reading-the-telemetry-dossier--risk-matrix)
   - [6.3 Inspecting HTTP Security Header Audits](#63-inspecting-http-security-header-audits)
   - [6.4 Reviewing Client-Side SCA & CVE Advisories](#64-reviewing-client-side-sca--cve-advisories)
   - [6.5 Generating & Downloading the PDF Audit Report](#65-generating--downloading-the-pdf-audit-report)
   - [6.6 Managing the Target History & Audit Ledger](#66-managing-the-target-history--audit-ledger)
7. [Running the Automated Verification Test Suite (162 Tests)](#7-running-the-automated-verification-test-suite-162-tests)
8. [Demonstration Test Targets](#8-demonstration-test-targets)
9. [Troubleshooting & Common Questions](#9-troubleshooting--common-questions)

---

## 1. Overview

**FRONTGUARD** is an automated, passive web application security assessment tool engineered for security officers, system administrators, and university auditors. It provides deterministic, non-intrusive evaluation of:

- **HTTP Security Response Headers** (CSP directive-level AST parsing, HSTS max-age & preload validation, X-Frame-Options clickjacking defense, MIME-sniffing, Referrer Policy, Permissions Policy, COOP/CORP/COEP cross-origin isolation).
- **Client-Side Component Vulnerabilities (SCA)** (corroborates third-party JavaScript libraries, evaluates 4-part semantic versions against OSV.dev and official Retire.js CVE databases).
- **Client-Side Credential & Data Exposure** (detects exposed API keys, bearer tokens, passwords in script blocks, and DOM XSS sinks).
- **Target Network Telemetry** (multi-record public IPv4 resolution, private IP / SSRF defense, WAF challenge page detection).
- **Automated Publication of PDF Reports** (two-pass ReportLab engine generating formal audit documents with CVSS v3.1 scores and technical remediation steps).

---

## 2. Hardware & Software Prerequisites

### Minimum Hardware Requirements
- **Processor:** Dual-Core 1.8 GHz or faster (x86_64 or ARM64)
- **RAM:** 2 GB minimum (4 GB recommended)
- **Storage:** 150 MB free disk space (application + dependencies + PDF storage)

### Software Requirements
- **Operating System:**
  - Windows 10 / 11
  - macOS (Monterey 12 or newer)
  - Linux (Ubuntu 20.04+, Debian 11+, Fedora, etc.)
- **Python Runtime:**
  - Python **3.10, 3.11, 3.12, 3.13, or 3.14** installed.
  - Check your Python installation by running in your terminal:
    ```bash
    python --version
    ```
    *(Or `python3 --version` on macOS/Linux).*
- **Web Browser:** Any modern browser (Google Chrome, Mozilla Firefox, Microsoft Edge, or Safari).
- **Network Access:** An active internet connection is recommended for real-time CVE and npm package queries. If run offline, FRONTGUARD automatically falls back to its built-in local vulnerability catalog.

---

## 3. Unpacking the Submission Archive

1. Save the received `FRONTGUARD.zip` file to your preferred directory (for example: `Downloads` or `Desktop`).
2. Extract / Unzip the archive:
   - **Windows:** Right-click `FRONTGUARD.zip` → select **Extract All...** → click **Extract**.
   - **macOS:** Double-click `FRONTGUARD.zip`.
   - **Linux:** Run `unzip FRONTGUARD.zip -d FRONTGUARD`.
3. Open your terminal or command prompt inside the extracted folder:
   - **Windows:** Hold `Shift`, right-click inside the extracted folder window, and select **Open PowerShell window here** (or open Windows Terminal).
   - **macOS / Linux:** Open Terminal and navigate to the directory:
     ```bash
     cd path/to/FRONTGUARD
     ```

Verify that the folder contains `main.py`, `requirements.txt`, `README.md`, and the subdirectories `scanner/`, `database/`, `reporting/`, `templates/`, and `static/`.

---

## 4. Step-by-Step Installation

### Method 1: Virtual Environment (Recommended)

Using an isolated Python virtual environment prevents conflicts with existing libraries on your computer.

#### On Windows (PowerShell):
```powershell
# 1. Create a virtual environment named 'venv'
python -m venv venv

# 2. Allow script execution in current PowerShell session (if prompted)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Activate the virtual environment
.\venv\Scripts\Activate.ps1

# 4. Upgrade pip and install all required dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### On Windows (Command Prompt - cmd.exe):
```cmd
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
```

#### On macOS / Linux:
```bash
# 1. Create a virtual environment
python3 -m venv venv

# 2. Activate the virtual environment
source venv/bin/activate

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

### Method 2: Direct System Installation

If you prefer not to use a virtual environment, simply install the requirements directly into your current Python environment:

```bash
# Windows
pip install -r requirements.txt

# macOS / Linux
pip3 install -r requirements.txt
```

---

### 4.3 Flask Secret Key: Is It Needed?

#### What is the Flask Secret Key?
In Flask, a secret key is required internally to cryptographically sign client-side session cookies and power UI notification messages (such as `flash('Target endpoint required')` or `flash('Audit Ledger cleared')`).

#### Do you or the examiner need to configure it manually?
**NO. Manual configuration is completely optional.** 

FRONTGUARD implements an **intelligent dual-mode configuration** in `main.py`:

```python
# main.py (Lines 22-25)
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32).hex()
```

This design provides two operational modes:

1. **Default Academic / Evaluator Mode (Zero-Configuration — Recommended):**
   - When the university examiner unzips the project and runs `python main.py`, **no `.env` file is required**.
   - The application automatically generates a random, cryptographically secure 32-byte hexadecimal key on startup using Python's built-in `os.urandom(32).hex()`.
   - The application starts immediately without prompts, missing key errors, or manual file edits.

2. **Custom / Production Mode (Optional):**
   - If you wish to set a fixed, persistent secret key, copy `.env.example` to `.env`:
     ```bash
     # Optional: Create custom .env
     cp .env.example .env
     ```
   - Generate and paste a 32-byte secret key:
     ```bash
     python -c "import secrets; print(secrets.token_hex(32))"
     ```
   - Add it to `.env` as `FLASK_SECRET_KEY=<your-key>`. If present, FRONTGUARD will prioritize your custom key over the automatic fallback.

---

## 5. Starting the Application

Once dependencies are installed, launch the FRONTGUARD web application by running:

```bash
# Windows
python main.py

# macOS / Linux
python3 main.py
```

### Expected Startup Output
```text
 * Serving Flask app 'main'
 * Debug mode: off
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
```

Open your web browser and navigate to:
```
http://127.0.0.1:5000
```
You will be greeted by the **FRONTGUARD: AUTOMATED PASSIVE WEB SECURITY VULNERABILITY SCANNER** dashboard.

---

## 6. User Guide: Operating the Scanner

### 6.1 Launching a Target Vulnerability Audit
1. On the home dashboard, locate the **Target Endpoint Input Field**.
2. Enter any fully-qualified domain name (FQDN) or URL. Examples:
   - `https://example.com`
   - `https://github.com`
   - `https://react.dev`
   *(If you omit the protocol, e.g. `example.com`, FRONTGUARD automatically prefixes `https://`).*
3. Click the blue **Initiate Scan** button.
4. The scanner initiates a passive inspection pipeline:
   - Resolves target IP addresses via DNS.
   - Verifies TLS certificates (with defensive fallback if invalid).
   - Fetches response headers and probes for HTTP-to-HTTPS redirect misconfigurations.
   - Streams the HTML (capped at 512 KB to prevent memory exhaustion).
   - Discovers all script references and extracts inline code blocks.
   - Evaluates security header directives against OWASP and CWE standards.
   - Cross-references discovered JavaScript components against live CVE databases.
   - Compiles a cryptographic audit report into PDF format.
5. You will automatically be redirected to the **Technical Audit Result** page once complete.

---

### 6.2 Reading the Telemetry Dossier & Risk Matrix
At the top of the scan result page, the **Target Evaluation Telemetry** card displays:
- **Target Host / FQDN**: The canonical URL inspected.
- **Target Public IP(s)**: All resolved public IPv4 addresses sorted deterministically.
- **Timestamp**: Audit execution time in UTC.
- **Overall Risk Level**: Evaluated as **CRITICAL**, **HIGH**, **MEDIUM**, **LOW**, or **INFO** based on the highest-severity vulnerability identified.

---

### 6.3 Inspecting HTTP Security Header Audits
The **Security Header Architecture Findings** table evaluates each response header:
- **Content-Security-Policy (CSP)**: Reports missing directives (`object-src`, `base-uri`, `frame-ancestors`), unsafe execution flags (`'unsafe-inline'`, `'unsafe-eval'`), and wildcard sinks.
- **Strict-Transport-Security (HSTS)**: Checks whether HTTPS enforcement is active, checks minimum duration (`max-age >= 31536000`), verifies subdomain coverage, and confirms preload eligibility.
- **X-Frame-Options**: Confirms clickjacking defense. (If modern CSP `frame-ancestors` is active, FRONTGUARD recognizes it as compliant).
- **X-Content-Type-Options**: Flags missing `nosniff` directives preventing MIME-confusion attacks.
- **Referrer-Policy & Permissions-Policy**: Identifies parameter leakage and unrestricted browser sensor permissions.
- **Information Disclosure**: Flags `X-Powered-By` headers and server version strings that facilitate targeted exploitation.

---

### 6.4 Reviewing Client-Side SCA & CVE Advisories
The **Client-Side Component Inventory** card shows:
- **Detected Library**: The component name (e.g., jQuery, Bootstrap, Lodash, Moment.js, Vue, Axios).
- **Installed Version**: Detected through multi-signal corroboration (URL paths, comment banners, and query parameters).
- **Vulnerability Status**: Marked as **VULNERABLE** (with CVE identifiers and CVSS score) or **SECURE / UPDATED**.
- **Actionable Remediation**: Specific package versions required to patch the weakness.

---

### 6.5 Generating & Downloading the PDF Audit Report
1. On the top navigation bar of any scan result, click the **Export Official PDF Report** button.
2. The browser will download an audit document named:
   ```
   scan_<domain>_<timestamp>.pdf
   ```
3. Open the downloaded PDF in any PDF reader (Adobe Acrobat, Chrome, Preview). The report includes:
   - Formal cover header with audit reference numbers.
   - High-contrast Executive Summary scorecard with severity distribution.
   - Full tabular vulnerability inventory with CVSS v3.1 scores and CWE mappings.
   - Exact code evidence snippets and step-by-step technical remediation guidelines.

---

### 6.6 Managing the Target History & Audit Ledger
1. Click **Dashboard** to return to the home screen.
2. The **Audit Ledger & Target History** table records every executed scan with its target URL, IP address, timestamp, findings count, risk rating, and quick links to review or download reports.
3. To reset the database and clear all previous audit logs, click the red **Clear History** button at the top-right of the table.

---

## 7. Running the Automated Verification Test Suite (162 Tests)

FRONTGUARD includes a comprehensive, automated test suite covering 100% of the scanner's security validation logic, version comparison algorithms, SSRF controls, and reliability mechanisms.

To execute the test suite, open your terminal in the project directory and run:

```bash
# Windows
python -m pytest --tb=short -q

# macOS / Linux
python3 -m pytest --tb=short -q
```

### Expected Test Execution Output
```text
........................................................................ [ 44%]
........................................................................ [ 88%]
..................                                                       [100%]
162 passed in 0.75s
```

### Breakdown of Verification Suites
| Test Suite File | Tested Security Logic | Tests |
|---|---|---|
| `test_phase2_headers.py` | CSP tokenization, HSTS directives, XFO/clickjacking, MIME protection, Referrer/Permissions policies, COOP/CORP/COEP isolation, information disclosure, duplicate header conflict handling. | **84 tests** |
| `test_phase3_library_detection.py` | 4-part semantic version comparator, numeric pre-releases (`1.0.0-rc.2 < 1.0.0-rc.10`), build metadata handling, multi-signal confidence scoring, Retire.js mapping, conflict resolution. | **49 tests** |
| `test_phase4_reliability.py` | SSRF prevention (private & loopback IP blocking), WAF/challenge page detection, bounded exponential retry, scan budget timeouts, bounded TTL cache, audit ledger clearing, and real-world pinned fixtures (jQuery, Bootstrap, Lodash). | **29 tests** |
| **Total** | **End-to-End Test Suite** | **162 Passing Tests** |

---

## 8. Demonstration Test Targets

For examination and demonstration purposes, FRONTGUARD includes three offline test benchmarks in the `test_pages/` folder:

1. **`test_pages/hardened_page.html`**:
   - Represents a production-grade, hardened website with comprehensive CSP, HSTS, no-sniff, and modern libraries.
   - Demonstrates that FRONTGUARD accurately identifies clean, compliant endpoints without false positives.
2. **`test_pages/weak_csp.html`**:
   - Contains intentionally permissive CSP (`unsafe-inline`, `unsafe-eval`, wildcards `*`, missing `object-src`).
   - Demonstrates directive-level CSP tokenization and high-severity XSS risk detection.
3. **`test_pages/old_jquery.html`**:
   - Incorporates legacy, vulnerable libraries (e.g. jQuery 1.12.4 with prototype pollution and cross-domain script execution risks).
   - Demonstrates client-side SCA, version extraction, and CVE lookup.

To scan external live sites during a viva, safe public demonstration targets include:
- `https://example.com` (Clean baseline endpoint)
- `https://owasp.org` (Hardened cybersecurity portal)

---

## 9. Troubleshooting & Common Questions

### Q1: `python: command not found` or `'python' is not recognized`
- **Cause:** Python is not added to your system `PATH` environment variable.
- **Solution:** 
  - On Windows, re-run the Python installer, select **Modify**, and check the box **"Add Python to PATH"**.
  - Alternatively, try running `py main.py` or `python3 main.py`.

### Q2: Port 5000 is already in use (`Address already in use`)
- **Cause:** Another local service (e.g., AirPlay on macOS, or another Flask instance) is occupying port 5000.
- **Solution:** Edit the last line of `main.py`:
  ```python
  app.run(debug=debug_mode, port=5001)
  ```
  Then access the application at `http://127.0.0.1:5001`.

### Q3: PowerShell script execution error (`Execution_Policies`)
- **Cause:** Windows PowerShell disables running unverified activation scripts by default.
- **Solution:** Run this single command in PowerShell before activating:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```

### Q4: Target scan status returns "BLOCKED"
- **Cause:** The target website is protected by an active Web Application Firewall (WAF) or bot challenge (such as Cloudflare Turnstile, AWS WAF, or reCAPTCHA).
- **Behavior:** This is an intentional security design feature of FRONTGUARD. Rather than mistakenly analyzing a CAPTCHA interstitial page as application code, FRONTGUARD flags the scan as `BLOCKED (WAF Challenge Detected)`.

### Q5: "Target blocked for SSRF prevention"
- **Cause:** You attempted to scan an internal or loopback IP address (such as `http://127.0.0.1`, `http://localhost`, or `http://192.168.1.1`).
- **Behavior:** This demonstrates FRONTGUARD's built-in **Server-Side Request Forgery (SSRF) Defense**. The scanner actively rejects targets resolving to private, loopback, or link-local network segments to safeguard internal infrastructure.

### Q6: Do I need to create a `.env` file or configure `FLASK_SECRET_KEY`?
- **Answer:** **No.** You do not need to create or edit any configuration file. If no `.env` file is present, FRONTGUARD automatically generates a cryptographically secure 32-byte key in memory on the fly (`os.urandom(32).hex()`). You can simply unzip the project and run `python main.py` directly.

---

## 10. Summary Checklist for Submitting Project ZIP

Before creating the final ZIP file to submit to the university, verify:
- [x] All 162 automated tests pass (`python -m pytest --tb=short -q`).
- [x] `main.py` starts properly without errors (`python main.py`).
- [x] `INSTALLATION_AND_USER_GUIDE.md` is placed at the top level of the archive.
- [x] `requirements.txt` is present and up-to-date.
- [x] Temporary cache folders (`__pycache__/`, `.pytest_cache/`) and sensitive `.env` files are excluded from the zip archive.

---
*FRONTGUARD: Automated Passive Web Security Vulnerability Scanner — MCA Capstone Submission.*

