# FRONTGUARD: AUTOMATED PASSIVE WEB SECURITY VULNERABILITY SCANNER

---

### A CAPSTONE PROJECT REPORT

*Submitted to the Uttaranchal University in partial fulfilment of the requirements for the award of the Degree of*

#### **MASTER OF COMPUTER APPLICATIONS**

---

**Submitted By:**  
**Rahul Raj V K**  
(Learner ID: `2426010073`)  

**Under the Guidance of:**  
**Maneesha Devadas**  
IT Team Lead  

---

```
                       [UTTARANCHAL UNIVERSITY LOGO]
```

### **DEPARTMENT OF COMPUTER APPLICATIONS**  
### **UTTARANCHAL UNIVERSITY, DEHRADUN**  
**Academic Year: 2025 – 2026**

---
\newpage

## CANDIDATE DECLARATION

I, **Rahul Raj V K** (Learner ID: `2426010073`), hereby declare that the capstone project report entitled **"FRONTGUARD: AUTOMATED PASSIVE WEB SECURITY VULNERABILITY SCANNER"**, submitted to the Department of Computer Applications, Uttaranchal University, Dehradun, in partial fulfilment of the requirements for the award of the degree of **Master of Computer Applications (MCA)**, is an authentic record of original research and engineering work carried out by me under the supervision and guidance of **Maneesha Devadas**, IT Team Lead.

The matter embodied in this report has not been submitted by me or any other person for the award of any other degree, diploma, or title in this or any other university or educational institution. Every theoretical formulation, algorithmic model, code implementation, and dataset cited from external sources has been duly acknowledged with proper references and citations.

---

**Date:** 05 November 2026  
**Place:** Dehradun  

\
\
__________________________________  
**Rahul Raj V K**  
Learner ID: `2426010073`  
Master of Computer Applications  
Uttaranchal University, Dehradun  

---
\newpage

## BONAFIDE CERTIFICATE

This is to certify that the project report entitled **"FRONTGUARD: AUTOMATED PASSIVE WEB SECURITY VULNERABILITY SCANNER"**, submitted by **Rahul Raj V K** (Learner ID: `2426010073`) in partial fulfilment of the requirements for the award of the degree of **Master of Computer Applications (MCA)** to Uttaranchal University, Dehradun, is a bonafide record of work carried out by him under my direct guidance and technical supervision.

To the best of my knowledge, the matter presented in this report represents genuine research, sound system design, and rigorous software verification. It has reached the requisite academic and technical standard prescribed by the university guidelines.

---

**Date:** 05 November 2026  
**Place:** Dehradun  

\
\
__________________________________  
**Maneesha Devadas**  
IT Team Lead  
(Technical Project Guide)  

\
\
__________________________________  
**Head of Department**  
Department of Computer Applications  
Uttaranchal University, Dehradun  

---
\newpage

## ACKNOWLEDGEMENT

I wish to express my profound gratitude and sincere appreciation to my esteemed project guide, **Maneesha Devadas**, IT Team Lead, for her invaluable guidance, perceptive technical insights, and continuous encouragement throughout the conceptualization, development, and architectural verification of **FrontGuard**. Her rigorous professional standards in software engineering and web application security have been instrumental in elevating this capstone project to enterprise-grade quality.

I also extend my heartfelt appreciation to the faculty members and administrative leadership of the **Department of Computer Applications, Uttaranchal University, Dehradun**, for providing the requisite academic environment, laboratory facilities, and computational infrastructure essential for conducting this research.

Finally, I express my deepest gratitude to my family, colleagues, and peers for their unfailing encouragement, understanding, and patience during the demanding milestones of this research and software engineering endeavor.

---

**Rahul Raj V K**  
Learner ID: `2426010073`  

---
\newpage

## ABSTRACT

Modern web applications represent the foundational operational layer connecting global consumer bases with enterprise backend databases and microservice clusters. In contemporary software delivery lifecycles, frontend architectures have evolved into decoupled single-page applications (SPAs) and micro-frontends heavily dependent on Content Delivery Networks (CDNs), reverse proxies, and third-party JavaScript libraries. However, this architectural complexity has introduced critical, systemic vulnerabilities at the application perimeter—predominantly categorized under **OWASP Top 10:2021 A05 (Security Misconfiguration)** and **A06 (Vulnerable and Outdated Components)**.

Traditional Dynamic Application Security Testing (DAST) methodologies rely on active fuzzing, intrusive parameter mutation, and exploit delivery. While effective in isolated staging environments, active scanners pose severe operational hazards in production: they disrupt business continuity, trigger account lockouts, pollute production transactional databases, and demand significant computational overhead. Conversely, lightweight perimeter utilities frequently perform superficial key-existence checks that yield dangerous false negatives by failing to evaluate directive syntax.

To resolve this engineering trade-off, this capstone project presents **FRONTGUARD: Automated Passive Web Security Vulnerability Scanner**. Built upon Python 3.14+, Flask 3.0.3, SQLite3, and ReportLab 4.2.2, FrontGuard establishes a non-intrusive, read-only security assessment framework. The system implements:
1. **Pre-flight DNS Interrogation and SSRF Defense:** Deterministic multi-A-record resolution via `socket.gethostbyname_ex()` with strict rejection of RFC 1918 private, loopback, link-local, and multicast IP ranges (`CWE-918`).
2. **Directive-Level Header AST Parsing:** Tokenization and semantic evaluation of `Content-Security-Policy` (CSP Level 3), `Strict-Transport-Security` (HSTS, RFC 6797), `X-Frame-Options` (RFC 7034), `X-Content-Type-Options`, `Referrer-Policy`, and modern cross-origin isolation headers (COOP, CORP, COEP).
3. **Multi-Signal Client-Side Software Composition Analysis (SCA):** Corroboration of third-party JavaScript libraries across URL regex signatures, comment banners, and query parameters, powered by a custom 4-part `SemVer` engine supporting numeric pre-releases (`1.0.0-rc.2 < 1.0.0-rc.10`) and build metadata exclusion.
4. **Resilient Vulnerability Synchronization:** Real-time query integration with Google's OSV.dev REST API and Retire.js catalog, fortified by a local, curated fallback database (`RETIREJS_DB`) for air-gapped resilience.
5. **Defensive Self-Protection:** Enforces a monotonic 45.0-second execution deadline (`ScanBudget`), 512 KB HTML streaming caps, thread-safe LRU-TTL caching (`BoundedTTLCache`), and WAF challenge quarantine.
6. **Enterprise Reporting:** Synthesizes two-pass typographic PDF audit dossiers featuring executive scorecards, CVSS v3.1 base scoring matrices, and actionable technical remediation guidelines.

The complete FrontGuard system is validated by an automated test suite comprising **162 unit tests** executing with a 100% pass rate in **0.75 seconds**, delivering an enterprise-ready, zero-cost, and non-destructive perimeter security audit solution.

---
\newpage

## TABLE OF CONTENTS

| Chapter No. | Topic Title | Page Range |
|:---:|:---|:---:|
| | **CANDIDATE DECLARATION** | ii |
| | **BONAFIDE CERTIFICATE** | iii |
| | **ACKNOWLEDGEMENT** | iv |
| | **ABSTRACT** | v |
| | **LIST OF FIGURES** | viii |
| | **LIST OF TABLES** | ix |
| **1** | **INTRODUCTION** | **1 – 8** |
| | 1.1 Project Overview & Context | 1 |
| | 1.2 The Problem Domain & Threat Landscape | 2 |
| | 1.3 Critical Limitations of Conventional Vulnerability Scanners | 4 |
| | 1.4 The FrontGuard Passive Auditing Paradigm | 6 |
| | 1.5 Scope and Delimitations of the Project | 7 |
| **2** | **PROJECT OBJECTIVES** | **9 – 12** |
| | 2.1 Primary Engineering Objectives | 9 |
| | 2.2 Measurable & Quantitative Technical Targets | 10 |
| | 2.3 Operational & Defensive Reliability Benchmarks | 11 |
| **3** | **SYSTEM ANALYSIS** | **13 – 38** |
| | 3.1 Identification of Need | 13 |
| | 3.2 Preliminary Investigation & Literature Review | 15 |
| | 3.3 Feasibility Study | 18 |
| | 3.3.1 Technical Feasibility | 18 |
| | 3.3.2 Operational Feasibility | 20 |
| | 3.3.3 Economic Feasibility | 21 |
| | 3.4 Project Planning & Work Breakdown Structure (WBS) | 22 |
| | 3.5 Project Scheduling | 24 |
| | 3.5.1 Gantt Chart Milestone Scheduling | 24 |
| | 3.5.2 PERT Network Scheduling & Critical Path Method (CPM) | 26 |
| | 3.6 Software Requirement Specification (SRS) | 29 |
| | 3.6.1 Functional Requirements (FR-01 to FR-15) | 29 |
| | 3.6.2 Non-Functional Requirements (NFR-01 to NFR-10) | 33 |
| | 3.7 System Specifications (Hardware & Software) | 35 |
| | 3.8 Detailed System Data Models | 36 |
| | 3.8.1 Object-Oriented Class Model | 36 |
| | 3.8.2 Activity Model & Operational Process Logic | 39 |
| | 3.8.3 Chronological Sequence Model | 42 |
| | 3.8.4 Entity-Relationship Model & 3NF Schema Analysis | 44 |
| | 3.8.5 Use Case Behavioral Model | 46 |
| **4** | **SYSTEM DESIGN & ARCHITECTURE** | **39 – 54** |
| | 4.1 Architectural Pattern & Pipeline Decomposition | 39 |
| | 4.2 Comprehensive Modularization Specifications | 41 |
| | 4.2.1 Network Extractor Module (`scanner/extractor.py`) | 41 |
| | 4.2.2 Security Header Matcher Module (`scanner/matcher.py`) | 43 |
| | 4.2.3 RetireJS & SCA Engine Module (`scanner/retirejs.py`) | 46 |
| | 4.2.4 Reliability Subsystem Module (`scanner/reliability.py`) | 48 |
| | 4.2.5 Database Persistence Engine (`database/db_handler.py`) | 50 |
| | 4.2.6 Typographic PDF Builder (`reporting/pdf_builder.py`) | 52 |
| | 4.2.7 Web Presentation Controller (`main.py`) | 53 |
| | 4.3 Data Integrity, Concurrency & Security Constraints | 54 |
| **5** | **TESTING & QUALITY ASSURANCE** | **55 – 64** |
| | 5.1 Quality Assurance Strategy & Test Harness | 55 |
| | 5.2 Exhaustive Test Suite Matrix (20+ Representative Scenarios) | 56 |
| | 5.3 Regression Analysis & Statement Coverage Metrics | 63 |
| **6** | **SYSTEM SECURITY & DEFENSE-IN-DEPTH** | **65 – 70** |
| | 6.1 Scanner Threat Modeling & Adversarial Surface | 65 |
| | 6.2 Pre-Flight SSRF Protection Architecture | 66 |
| | 6.3 Anti-DoS & Streaming Memory Bounds | 67 |
| | 6.4 Monotonic Wall-Clock Scan Budget Enforcement | 68 |
| | 6.5 WAF & Bot Challenge Detection Engine | 69 |
| | 6.6 Thread-Safe LRU-TTL Cache Management | 70 |
| **7** | **COST ESTIMATION & ECONOMIC ANALYSIS** | **71 – 74** |
| | 7.1 Software Engineering Effort Valuation (COCOMO II Model) | 71 |
| | 7.2 Total Cost of Ownership (TCO) vs. Commercial Alternatives | 73 |
| **8** | **REPORTING & TELEMETRY ARCHITECTURE** | **75 – 78** |
| | 8.1 Web Presentation & UI Design System | 75 |
| | 8.2 Typographic Two-Pass ReportLab PDF Engine | 76 |
| **9** | **FUTURE SCOPE & RESEARCH ROADMAP** | **79 – 82** |
| | 9.1 Headless Browser & Client-Side SPA Execution | 79 |
| | 9.2 Authenticated State & Contextual Ingress | 80 |
| | 9.3 CI/CD DevSecOps Automation | 80 |
| | 9.4 Passive Subdomain Discovery & Certificate Transparency | 81 |
| | 9.5 Enterprise SIEM Integration | 82 |
| **10** | **APPENDICES** | **83 – 92** |
| | 10.1 Core Python Implementation Code Listings | 83 |
| | 10.2 Academic & Industry Bibliography | 90 |

---
\newpage

## LIST OF FIGURES

- **Figure 1.1:** Conceptual Architecture of the FrontGuard Passive Auditing Pipeline (Page 7)
- **Figure 3.1:** Work Breakdown Structure (WBS) Tree across 6 Work Packages (Page 23)
- **Figure 3.2:** Gantt Chart Depicting the 14-Week Development Lifecycle (Page 25)
- **Figure 3.3:** PERT Network Activity Diagram and Critical Path Sequence (Page 28)
- **Figure 3.4:** Object-Oriented Class Hierarchy and Structural Associations (Page 38)
- **Figure 3.5:** High-Level Activity Flowchart of the Inspection and Decision Gates (Page 41)
- **Figure 3.6:** System Sequence Diagram Illustrating Chronological Message Passing (Page 43)
- **Figure 3.7:** Entity-Relationship (ER) Diagram of the SQLite Relational Schema (Page 45)
- **Figure 3.8:** Use Case Diagram Illustrating Analyst and System Interactions (Page 47)
- **Figure 4.1:** Multi-Tier Pipeline Decomposition Architecture (Page 40)
- **Figure 8.1:** Utilitarian Dark-Mode Web Cockpit Layout (Page 76)
- **Figure 8.2:** ReportLab Flowable Two-Pass Rendering Architecture (Page 78)

---
\newpage

## LIST OF TABLES

- **Table 1.1:** Comprehensive Taxonomy of Front-End and Header Vulnerabilities (Page 3)
- **Table 1.2:** Comparison Matrix: Active DAST Fuzzers vs. FrontGuard Passive Engine (Page 5)
- **Table 3.1:** Comparative Feature Matrix: FrontGuard vs. Contemporary Open-Source Tools (Page 16)
- **Table 3.2:** Work Breakdown Structure (WBS) and Effort Allocation Table (Page 22)
- **Table 3.3:** PERT Three-Point Duration Estimates and Task Variance Table (Page 27)
- **Table 3.4:** Hardware Specification Matrix (Development, Testing, and Production) (Page 35)
- **Table 3.5:** Production Software Dependencies and Toolchain Specification (Page 36)
- **Table 3.6:** Data Dictionary for `scan_history` Entity (Page 44)
- **Table 3.7:** Data Dictionary for `vulnerability_rules` Entity (Page 45)
- **Table 4.1:** Supported Security Headers and Corresponding Verification Directives (Page 44)
- **Table 4.2:** Supported Client-Side Libraries and Corroboration Detection Signals (Page 47)
- **Table 5.1:** Exhaustive Unit Test Verification Suite (Representative Test Cases) (Page 57)
- **Table 5.2:** Test Execution Metrics and Code Statement Coverage by Module (Page 64)
- **Table 7.1:** COCOMO II Cost Estimation Modeling Parameters and Calculations (Page 72)
- **Table 7.2:** 3-Year Total Cost of Ownership (TCO) Comparison (Page 74)

---
\newpage

# CHAPTER 1: INTRODUCTION

### 1.1 Project Overview & Context
In the contemporary era of enterprise cloud computing, the World Wide Web constitutes the primary operational fabric connecting distributed consumer bases with mission-critical corporate databases, transactional payment gateways, and software-as-a-service (SaaS) platforms. Over the preceding decade, web application architectures have undergone a profound paradigm shift: monolithic, server-side rendered application frameworks (such as traditional ASP, PHP, and early Java Servlets) have been systematically replaced by decoupled, client-heavy single-page applications (SPAs) and micro-frontends. Modern web interfaces rely extensively on client-side JavaScript execution, leveraging sophisticated frameworks such as React, Angular, Vue.js, and auxiliary utility packages to deliver dynamic, desktop-grade user experiences.

However, this rapid architectural evolution has introduced critical security vulnerabilities at the application perimeter. In traditional monolithic environments, security defenses were largely focused on backend server hardening, database isolation, and perimeter network firewalls. In modern distributed architectures, the front-end perimeter—comprising HTTP transmission response headers, browser security policies, external Content Delivery Network (CDN) dependencies, and client-side scripts—has become an attractive attack surface for adversaries. 

A substantial percentage of live web deployments inadvertently omit foundational HTTP security headers or host outdated third-party JavaScript libraries containing known Common Vulnerabilities and Exposures (CVEs). When an enterprise application imports an unpatched library or misconfigures its Content Security Policy, the strongest backend firewalls and database access controls cannot prevent an adversary from executing Cross-Site Scripting (XSS), launching clickjacking campaigns, or performing SSL-stripping attacks.

**FRONTGUARD: Automated Passive Web Security Vulnerability Scanner** is an engineering response to this architectural challenge. Developed as an MCA capstone project in Python, Flask, SQLite, and ReportLab, FrontGuard is designed to automate the non-intrusive discovery, parsing, corroboration, and reporting of front-end security misconfigurations and vulnerable client-side dependencies. Operating under a strictly passive inspection paradigm, FrontGuard executes comprehensive audits without transmitting a single destructive payload, modifying remote application state, or inducing operational disruption.

---

### 1.2 The Problem Domain & Threat Landscape
To establish the technical necessity of FrontGuard, the vulnerability classes it identifies must be examined against authoritative industry taxonomies: the **OWASP Top 10:2021** and the **MITRE Common Weakness Enumeration (CWE)**.

```
+-------------------------------------------------------------------------------------------------------+
|                                    APPLICATION PERIMETER ATTACK SURFACE                              |
+-------------------------------------------------------------------------------------------------------+
|  [HTTP Response Headers]             [Client-Side JavaScript Dependencies]     [DOM & Script Ingress]  |
|  - Missing / Permissive CSP          - Outdated jQuery / Prototype Pollution    - Hardcoded API Keys    |
|  - Absent / Short HSTS               - Vulnerable Bootstrap Modal Sinks         - Exposed Bearer Tokens |
|  - Missing X-Frame-Options           - Unpatched Lodash Object Merging          - Dangerous eval() Sinks|
|  - Omitted X-Content-Type-Options    - Deprecated AngularJS Sandbox Escapes     - Sensitive HTML Comments|
+-------------------------------------------------------------------------------------------------------+
```

#### 1. OWASP A05:2021 – Security Misconfiguration
Security misconfiguration represents one of the most prevalent vulnerabilities across modern web architectures. It arises when system administrators, DevOps engineers, or developers fail to implement secure default configurations or actively define conflicting HTTP headers:
- **CWE-693 (Protection Mechanism Failure):** Browsers are engineered with powerful defensive subsystems designed to restrict script execution, isolate cross-origin frames, and enforce MIME typing. However, these mechanisms remain entirely inactive unless explicitly commanded by the server via HTTP headers. When a server omits `Content-Security-Policy` (CSP) or `X-Content-Type-Options`, the browser operates in a permissive legacy mode, leaving users vulnerable to Cross-Site Scripting and MIME-sniffing drive-by downloads.
- **CWE-319 (Cleartext Transmission of Sensitive Information):** While modern web platforms predominantly employ Transport Layer Security (TLS), omitting the `Strict-Transport-Security` (HSTS) header allows active network adversaries to execute SSL-stripping attacks. In an SSL-stripping scenario, an adversary intercepts initial unencrypted HTTP requests, downgrading communication between the client and proxy to cleartext and exposing session tokens and credentials.
- **CWE-1021 (Improper Restriction of Rendered UI Layers):** Omitting `X-Frame-Options` or modern CSP `frame-ancestors` permits an adversary to load the vulnerable application inside an invisible, transparent `<iframe>` element on an attacker-controlled portal. Known as Clickjacking, this allows the attacker to deceive authenticated users into executing unintended transactions, deleting account data, or modifying security permissions by clicking seemingly innocuous buttons overlaid on the concealed frame.

#### 2. OWASP A06:2021 – Vulnerable and Outdated Components
In modern web development, speed-to-market is frequently prioritized over software dependency maintenance. Software Composition Analysis (SCA) reports consistently indicate that over 80% of enterprise web applications import JavaScript libraries with known security vulnerabilities:
- **Prototype Pollution (CVE-2019-11358, CVE-2019-10744):** Libraries such as jQuery (`<3.4.0`) and Lodash (`<4.17.12`) contain recursive object-merging utilities (`$.extend(true, {}, ...)` or `_.merge()`) that improperly process properties such as `__proto__`. An adversary can inject malicious payload objects that modify the root Object prototype across the JavaScript runtime, altering application logic or escalating to client-side code execution.
- **Cross-Site Scripting via Selectors (CVE-2012-6708, CVE-2015-9251, CVE-2020-11022):** Legacy jQuery versions contain flawed regular expression checks in DOM manipulation methods, allowing HTML tags containing executable script vectors to bypass pre-filters when parsing external input.
- **Client-Side Cross-Site Scripting in UI Toolkits (CVE-2018-14040, CVE-2019-8331):** Versions of Twitter Bootstrap (`<3.4.1` and `<4.3.1`) allow malicious script execution via client-side attributes such as `data-target` in collapse plugins and unescaped HTML content in tooltip and popover options.

#### 3. CWE-798: Hardcoded Credentials & Client-Side Secrets
During rapid feature delivery, developers frequently embed internal testing credentials, staging API keys, Firebase access tokens, and AWS Secret Access Keys directly into client-side JavaScript files or HTML comments. Because these scripts are delivered to every web visitor in cleartext, automated inspection easily harvests these credentials, leading to downstream cloud database compromise.

*Table 1.1: Comprehensive Taxonomy of Front-End and Header Vulnerabilities Audited by FrontGuard.*

| Vulnerability Classification | CWE Identifier | OWASP Category | Primary Exploitation Vector | Real-World Impact |
|---|:---:|:---:|---|---|
| **Missing / Weak CSP** | `CWE-693` | `A05:2021` | Reflected / Stored Cross-Site Scripting (XSS) | Full session hijacking, DOM manipulation, credential theft |
| **Missing / Invalid HSTS** | `CWE-319` | `A05:2021` | Man-in-the-Middle SSL Stripping / Downgrade | Cleartext traffic interception, session cookie exfiltration |
| **Missing Clickjacking Defense**| `CWE-1021` | `A05:2021` | Invisible `<iframe>` UI Layer Redressing | Unauthorized state-changing actions, password resets |
| **Missing MIME Protection** | `CWE-693` | `A05:2021` | MIME Confusion (e.g. executing `.txt` as JS) | Drive-by malware download, persistent client execution |
| **Outdated Client Libraries** | `CWE-1104` | `A06:2021` | Prototype Pollution, known CVE exploitation | Denial of service, client-side RCE, DOM XSS |
| **Hardcoded API Keys / Secrets** | `CWE-798` | `A07:2021` | Credential extraction from inline scripts | Unauthorized backend database access, cloud account takeover |
| **Information Disclosure** | `CWE-200` | `A05:2021` | Banner grabbing (`Server`, `X-Powered-By`) | Precise attack-surface mapping, targeted CVE exploitation |

---

### 1.3 Critical Limitations of Conventional Vulnerability Scanners
Automated security testing has traditionally been dominated by heavy Dynamic Application Security Testing (DAST) frameworks, such as OWASP ZAP, Burp Suite Professional, Qualys, and Acunetix. While these platforms serve as the gold standard for dedicated penetration testing teams, they present fundamental operational liabilities when applied to continuous perimeter monitoring, lightweight administrative verification, and continuous integration environments:

1. **Intrusive Overhead and Service Degradation:** Active scanners operate by generating millions of permutations of attack payloads (fuzzing), injecting SQL strings (`' OR 1=1--`), cross-site scripting tags (`<script>alert(1)</script>`), and directory traversal sequences (`../../etc/passwd`). In live production environments, these payloads:
   - Pollute transactional databases with junk records.
   - Trigger account lockouts through invalid authentication attempts.
   - Overwhelm application servers, exhausting connection pools and causing denial-of-service outages.
   - Trigger security operations center (SOC) alerts, causing alert fatigue.
2. **Surface-Level Header Checking (Boolean Existence Fallacy):** When existing scanners evaluate security headers, they frequently implement naive key-presence heuristics:
   $$\text{Header Key Exists} \implies \text{Verification: Passed}$$
   In practice, this creates a false sense of security. A web application deploying:
   ```http
   Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'
   Strict-Transport-Security: max-age=0
   X-Content-Type-Options: allow-sniffing
   ```
   will successfully pass checks in many automated scanners because the header keys exist, despite the header values actively disabling browser protection mechanisms.
3. **The Static-Live Disconnect in Client SCA:** Traditional client-side vulnerability assessment tools rely on static, frozen vulnerability signature files bundled during installation. They fail to reflect newly disclosed CVEs published in global repositories. Conversely, cloud-native tools require transmitting proprietary application code to third-party SaaS vendors, raising regulatory and data sovereignty concerns.
4. **Heavy Resource Consumption & Complex Setup:** Enterprise DAST frameworks require dedicated multi-gigabyte virtual machines, Java runtimes, browser driver dependencies (Selenium/Chromium), and intricate network proxy configurations.

*Table 1.2: Comparison Matrix: Active DAST Fuzzers vs. FrontGuard Passive Engine.*

| Evaluation Metric | Active DAST Fuzzers (OWASP ZAP, Burp Suite) | FrontGuard Passive Engine |
|---|---|---|
| **Inspection Methodology** | Invasive payload fuzzing & state mutation | 100% Passive, read-only HTTP GET interrogation |
| **Production Risk** | High (risk of data pollution, table drops, DoS) | Zero (indistinguishable from standard browser visits) |
| **Resource Footprint** | Massive (1.5 GB – 4.0 GB RAM, Java runtime) | Minimal (< 50 MB RAM, native Python runtime) |
| **Scan Execution Duration**| 15 Minutes to several hours per target | **Under 15 Seconds** (hard 45.0s budget ceiling) |
| **CSP Audit Methodology** | Surface existence or simple string presence | **Directive AST Tokenizer & Semantic Policy Engine** |
| **Dependency Analysis** | Limited or reliant on secondary plugins | **Multi-Signal Corroboration (Regex, Path, Banners)** |
| **Vulnerability Feeds** | Proprietary static databases / manual updates | **Live Google OSV.dev REST API + Offline Curated DB** |
| **Licensing Cost** | Commercial (\$4,000–\$25,000/yr) or Complex OSS | **100% Open Source / Free Academic Distribution** |

---

### 1.4 The FrontGuard Passive Auditing Paradigm
FrontGuard bridges the divide between lightweight manual inspection and heavy enterprise DAST tooling by establishing an automated, non-destructive, and deterministic security auditing pipeline. 

```
+--------------------------------------------------------------------------------------------------------+
|                                  FRONTGUARD SYSTEM ARCHITECTURAL PIPELINE                              |
+--------------------------------------------------------------------------------------------------------+
|                                                                                                        |
|   [Target Ingress] ──► [DNS Pre-flight] ──► [SSRF Screening] ──► [HTTP/HTTPS Diff]                    |
|                                                                        │                               |
|   [PDF Synthesis]  ◄── [SQLite Ledger] ◄── [Risk Scoring] ◄── [SCA & Header Audits]                    |
|          │                                                             │                               |
|          ▼                                                             ▼                               |
|   Formal PDF Audit Report                                 Google OSV.dev & Retire.js                   |
|                                                                                                        |
+--------------------------------------------------------------------------------------------------------+
```

The system is founded upon four architectural pillars:
1. **Zero-Exploit Principle:** Network communication is restricted strictly to standard HTTP/HTTPS GET requests matching modern browser User-Agent fingerprints. FrontGuard never executes parameter fuzzing, never submits state-altering POST requests to foreign targets, and never injects exploit strings.
2. **Directive-Level Tokenization:** FrontGuard implements an Abstract Syntax Tokenizer that decomposes complex security headers into directive arrays. Each directive is validated against established W3C and RFC standards, auditing fallback inheritance rules (e.g., how `default-src` governs `script-src` only in the absence of explicit directives).
3. **Multi-Signal Dependency Corroboration:** Software Composition Analysis does not rely on single, easily manipulated indicators. FrontGuard corroborates versions by evaluating URL paths, script header comment banners, query parameters (`?ver=`), and in-content global variables, calculating confidence ratings (High, Medium, Low) and flagging contradictory signals.
4. **Self-Defensive Architecture:** FrontGuard assumes that target web servers may be hostile, misconfigured, or protected by Web Application Firewalls. The scanner incorporates self-defensive mechanisms: pre-flight SSRF IP validation, monotonic execution timeout budgets, memory-capped streaming ingestion, and WAF challenge quarantine.

---

### 1.5 Scope and Delimitations of the Project

#### Project Inclusions:
- Automated interrogation of public FQDNs and IPv4 endpoints over standard HTTP and HTTPS ports (80, 443).
- Pre-flight DNS interrogation resolving all A-records via `socket.gethostbyname_ex()`.
- Unconditional rejection of targets resolving to private, loopback, link-local, and multicast IP blocks (`CWE-918`).
- Deep syntactic evaluation of 12+ HTTP response headers, including CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP, CORP, and COEP.
- Comparison of plain-HTTP redirect headers against HTTPS origin headers to surface SSL-stripping gaps.
- Detection, parsing, and semantic version comparison across 15+ major client-side JavaScript frameworks.
- Real-time advisory synchronization with Google's OSV.dev API and official Retire.js repository.
- Extraction of client-side credentials, hardcoded API keys, bearer tokens, and dangerous DOM XSS sinks via compiled regular expressions.
- Automated generation of publication-grade, two-pass PDF audit dossiers via ReportLab.
- Persistence of historical audit telemetry within an embedded SQLite relational database.

#### Project Delimitations:
- **No Active Exploitation:** The system intentionally avoids active fuzzing, authenticated session tampering, and brute-force testing.
- **Single-Page Perimeter Scope:** FrontGuard inspects the target landing page and its directly linked script dependencies; it does not execute deep recursive multi-tier web crawling.
- **No CAPTCHA / WAF Bypass:** In strict compliance with security engineering ethics, FrontGuard does not attempt to solve CAPTCHAs, bypass anti-bot mechanisms, or defeat Web Application Firewall challenge screens. Targets presenting Cloudflare Turnstile, AWS WAF, or Imperva challenge screens are safely quarantined with an explicit `BLOCKED` status.

---
\newpage

# CHAPTER 2: PROJECT OBJECTIVES

### 2.1 Primary Engineering Objectives
The engineering objectives of the FrontGuard project are structured across six key domains:

1. **Engineering an Automated Non-Destructive Ingress Pipeline:** Construct a multi-threaded, robust network client in Python capable of resolving DNS records, probing protocol redirections, handling unverified TLS certificates gracefully, and safely extracting response headers and HTML payloads.
2. **Developing an Abstract Syntax Tokenizer for Security Headers:** Implement an advanced parsing engine in `scanner/matcher.py` that dissects raw header strings into directive-to-source maps, verifying syntactic compliance, identifying deprecations, and flagging weak configurations against W3C, RFC 6797, and RFC 7034 specifications.
3. **Designing a Multi-Signal Client-Side Software Composition Engine:** Construct an SCA discovery module in `scanner/retirejs.py` that discovers third-party JavaScript dependencies via multi-signal corroboration across URL patterns, comment banners, and query strings.
4. **Constructing a 4-Part Semantic Version Engine:** Develop a version comparator (`SemVer`) supporting up to 4 numeric segments (`1.2.3.4`), numeric pre-release precedence (`1.0.0-rc.2 < 1.0.0-rc.10`), and build metadata exclusion (`1.2.3+2024 == 1.2.3`) to evaluate library vulnerability ranges.
5. **Integrating Live & Offline Vulnerability Threat Intelligence:** Construct a hybrid advisory lookup subsystem communicating with Google’s OSV.dev REST API and Retire.js catalog in real-time, while providing an embedded offline database (`RETIREJS_DB`) for air-gapped resilience.
6. **Architecting an Automated Typographic PDF Synthesis Pipeline:** Develop an automated document synthesis engine using ReportLab that computes two-pass page numbers, formats visual risk scorecards, and provides concrete remediation code snippets.

---

### 2.2 Measurable & Quantitative Targets
To maintain software quality and engineering rigor, the following performance metrics were established:

- **Strict Wall-Clock Execution Budget:** The entire inspection pipeline must execute within a **45.0-second total deadline (`ScanBudget`)**. Any scan exceeding this threshold must terminate gracefully and return partial findings without locking worker threads.
- **Strict Ingestion Memory Ceilings:** Network streams must enforce a hard **512 KB ceiling** on HTML body downloads and a **256 KB ceiling** on external JavaScript file retrieval, neutralizing memory exhaustion and decompression bomb attacks.
- **SSRF Immunity:** The system must achieve a **100% rejection rate** against hostnames resolving to RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and multicast networks.
- **Automated Test Coverage:** The core scanning engine must maintain a **100% pass rate** across **162 automated unit tests** executing within a cumulative runtime of **$\le 1.0$ second**.
- **Report Generation Throughput:** The ReportLab PDF generation engine must render a comprehensive, multi-page, two-pass PDF document in **$< 1.5$ seconds** from raw scan findings.

---

### 2.3 Operational & Defensive Benchmarks
- **Zero-Configuration Execution:** The application must start out-of-the-box without requiring complex setup scripts, environment variables, or pre-existing databases. If no `.env` file exists, the application must automatically generate a cryptographically secure 256-bit session secret in memory.
- **WAF Challenge Resilience:** When encountering Cloudflare Turnstile, AWS WAF, or Imperva challenge screens, FrontGuard must identify the challenge screen and quarantine the scan status as `BLOCKED`, preventing false vulnerability alerts.
- **Deterministic Reproducibility:** Repeated scans against identical target server configurations must yield 100% identical vulnerability finding counts, CVSS base scores, and risk classifications.
- **Air-Gapped Autonomous Operation:** If remote network connectivity fails during scanning, all components must fall back to the built-in offline database without throwing unhandled exceptions.

---
\newpage

# CHAPTER 3: SYSTEM ANALYSIS

### 3.1 Identification of Need
The deployment of enterprise web applications has outpaced the administrative ability to continuously verify perimeter security. In modern agile and continuous deployment (CI/CD) environments, web systems are subject to continuous updates: reverse proxies (Nginx, Traefik, HAProxy, Cloudflare) are reconfigured, dependencies are imported via dynamic package managers (npm, yarn), and CDN endpoints are modified.

This dynamic operating environment leads to common perimeter security failures:
1. **Accidental Header Stripping:** During reverse proxy migrations or CDN configuration changes, headers such as `Content-Security-Policy` or `Strict-Transport-Security` are frequently dropped or overridden by default proxy configurations.
2. **Silent Dependency Obsolescence:** Developers frequently vendor JavaScript libraries (copying `jquery.min.js` directly into static assets) to bypass build tool complexities. These libraries remain frozen in time, quietly accumulating known CVEs while the backend application is continuously patched.
3. **The Penalty of False Positives:** Existing command-line security tools often rely on naive string matching, producing high rates of false positives (such as flagging an application for missing `X-Frame-Options` when CSP `frame-ancestors` is already enforcing clickjacking protection). This erodes trust in automated security tooling.

There is a distinct need for an **intelligent, non-destructive, zero-cost auditing utility** that security analysts, academic researchers, and system administrators can execute on-demand without impacting production environments.

---

### 3.2 Preliminary Investigation & Literature Review
An extensive literature review and comparative benchmarking analysis was undertaken across existing open-source and commercial solutions.

*Table 3.1: Comparative Feature Matrix: FrontGuard vs. Contemporary Solutions.*

| Architectural Capability | FrontGuard | OWASP ZAP (Passive) | Google Lighthouse | Nikto | Mozilla Observatory |
|---|:---:|:---:|:---:|:---:|:---:|
| **Operating Model** | Standalone Web / PDF Engine | Intercepting Proxy / Java | Headless Browser Suite | Command-Line Perl Script | Cloud SaaS Service |
| **Active Fuzzing Risk** | **Zero (Strictly Passive)** | Low in passive mode | Zero | High (Emits 6000+ noisy GETs) | Zero |
| **CSP Directive AST Parsing** | **Yes (Full Tokenization)** | Primitive string presence | Basic scoring | Primitive string matching | Yes (Online only) |
| **Client JavaScript SCA** | **Yes (Multi-Signal)** | Limited plugin | None | Primitive filename checks | None |
| **Live OSV.dev CVE Querying** | **Yes (Real-Time REST)** | No | No | No | No |
| **Offline Air-Gapped Fallback**| **Yes (Curated DB)** | Yes | Yes (Local rules) | Yes (Static DB) | No (Requires Internet) |
| **SSRF Self-Defense** | **Yes (Pre-flight DNS)** | Manual exclusion | None | None | Handled by cloud infrastructure|
| **Two-Pass PDF Dossier** | **Yes (ReportLab)** | Generic HTML/XML | JSON / DevTools | Plain text dump | None |
| **System Memory Footprint** | **< 50 MB RAM** | 1.5 GB – 4.0 GB RAM | 600 MB – 1.2 GB RAM | < 30 MB RAM | N/A (Cloud Hosted) |

Key findings from the preliminary investigation:
- **OWASP ZAP:** Highly capable but designed primarily as an intercepting proxy for interactive penetration testing. Its passive scanning capabilities require routing browser traffic through its internal proxy engine, which is unnecessarily complex for quick perimeter assessments.
- **Google Lighthouse:** An excellent developer tool focused heavily on front-end performance, Progressive Web App (PWA) compliance, and SEO. Its security category is limited to a handful of basic best-practice checks, lacking component CVE correlation and PDF export capabilities.
- **Nikto:** An established open-source web server scanner written in Perl. However, Nikto is unmaintained, relies on outdated vulnerability databases, emits thousands of noisy requests that trigger WAF rate-limits, and produces high false-positive rates on modern SPAs.
- **Mozilla Observatory:** An excellent web-based scanner for HTTP security headers, but operated strictly as an external SaaS platform. It cannot be deployed within private intranet networks or air-gapped staging environments, and provides zero client-side JavaScript SCA.

FrontGuard incorporates the architectural strengths of these utilities—combining the speed of cURL, the header precision of Mozilla Observatory, and the SCA intelligence of Retire.js—into an integrated, self-contained Python architecture.

---

### 3.3 Feasibility Study

#### 3.3.1 Technical Feasibility
The technical feasibility of FrontGuard was evaluated across its core software dependencies:
- **Language Selection (Python 3.14+):** Python was selected due to its mature networking primitives, built-in memory safety, cross-platform socket implementations, and rich ecosystem of security analysis libraries. The built-in `ipaddress` and `socket` modules provide high-speed, thread-safe network interrogation without external C-extension dependencies.
- **WSGI Framework (Flask 3.0.3):** Flask provides a minimalist, robust WSGI web controller. Unlike monolithic frameworks like Django, Flask does not require heavyweight object-relational mappers (ORMs), administrative subsystems, or background message brokers, keeping the application footprint under 50 MB RAM.
- **HTTP Client (Requests 2.32.3):** Requests provides high-level session management, clean streaming interfaces (`iter_content`), fine-grained socket timeout tuple configuration `(connect_timeout, read_timeout)`, and flexible SSL context overrides.
- **HTML Parsing Engine (BeautifulSoup4 4.12.3):** BeautifulSoup provides fault-tolerant parsing of real-world, syntactically malformed HTML documents. Its clean search API allows rapid discovery of `<script>`, `<form>`, and HTML comment nodes.
- **Document Engine (ReportLab 4.2.2):** ReportLab is the industry standard for programmatic PDF synthesis in Python. Its Flowable architecture allows building complex document flows that automatically reflow across pages, while its `Canvas` API permits low-level drawing of branding and pagination footers.

#### 3.3.2 Operational Feasibility
FrontGuard requires zero administrative configuration or onboarding:
- **Deployment Simplicity:** The application requires only cloning the repository, installing `requirements.txt`, and executing `python main.py`.
- **Intuitive Web Cockpit:** Users interact with a clean, utilitarian dark-mode interface. The single input field accepts any valid domain name or URL, automatically enforcing scheme sanitization.
- **Actionable Reporting:** Findings are presented with explicit CVSS v3.1 severity scores, CWE weakness links, raw observed evidence snippets, and step-by-step remediation commands. System administrators can immediately copy and paste remediation directives directly into their server configuration files (such as Nginx or Apache).

#### 3.3.3 Economic Feasibility
The economic viability of FrontGuard was analyzed by comparing its development and operational costs against commercial enterprise alternatives:
- **Direct Software Licensing Costs:** **\$0.00**. All underlying frameworks, runtimes, and libraries are licensed under open-source licenses (MIT, BSD, Apache 2.0, or LGPL).
- **Threat Intelligence Costs:** **\$0.00**. Both Google OSV.dev and Retire.js provide free, high-availability public API endpoints and repositories without subscription requirements.
- **Infrastructure Overhead:** **\$0.00 to \$5.00/month**. FrontGuard can be executed locally on commodity student hardware or hosted on free cloud tiers (such as the Oracle Cloud Infrastructure Always Free tier).
- **Cost Avoidance:** Eliminates commercial dynamic security scanning subscriptions (such as Snyk or Veracode), saving organizations between \$5,000 and \$25,000 annually.

---

### 3.4 Project Planning & Work Breakdown Structure (WBS)
The project lifecycle followed a structured, agile engineering plan encompassing **170 logged development hours** distributed across six work packages:

*Table 3.2: Work Breakdown Structure (WBS) and Effort Allocation Table.*

| Work Package ID | Work Package Title & Detailed Scope | Logged Effort | Percentage |
|:---:|:---|:---:|:---:|
| **WP-1** | **Architecture Design & Threat Modeling**<br>• Protocol specification review (RFC 6797, RFC 7034, W3C CSP3)<br>• Threat modeling scanner attack surface (SSRF, DoS, tarpitting)<br>• Definition of passive inspection boundaries | 22 Hours | 12.9% |
| **WP-2** | **Network Ingress & Header AST Tokenizer**<br>• Multi-threaded extraction engine with streaming memory caps<br>• Pre-flight DNS interrogation and deterministic A-record sorting<br>• CSP directive tokenizer and semantic header evaluation rules | 38 Hours | 22.4% |
| **WP-3** | **Client-Side SCA & SemVer Logic**<br>• Multi-signal component signature regex development<br>• 4-part SemVer version parser with alphanumeric pre-releases<br>• Real-time OSV.dev REST API client and Retire.js sync engine | 36 Hours | 21.2% |
| **WP-4** | **Defensive Engineering & Reliability Subsystems**<br>• Pre-flight DNS interrogation & SSRF private IP screening<br>• WAF challenge page signature detection and quarantine<br>• Monotonic wall-clock ScanBudget and BoundedTTLCache | 30 Hours | 17.6% |
| **WP-5** | **Database Persistence, Web Cockpit & PDF Generator**<br>• SQLite relational schema design, indexing, and migration script<br>• Utilitarian dark-mode web cockpit (HTML5, Bootstrap, CSS3)<br>• ReportLab two-pass typographic PDF generation engine | 26 Hours | 15.3% |
| **WP-6** | **Automated Testing, Verification & Code Audit**<br>• Construction of 162 unit tests across three testing suites<br>• Security audit, secret purging, and .gitignore hardening<br>• Technical documentation and comprehensive project dossier | 18 Hours | 10.6% |
| **TOTAL** | **Comprehensive End-to-End System Delivery** | **170 Hours** | **100.0%** |

---

### 3.5 Project Scheduling

#### 3.5.1 Gantt Chart Milestone Scheduling
The project was executed over a 14-week timeline:

```
---------------------------------------------------------------------------------------
Work Package / Milestone          W01 W02 W03 W04 W05 W06 W07 W08 W09 W10 W11 W12 W13 W14
---------------------------------------------------------------------------------------
WP-1: Spec & Threat Modeling      [=====]
WP-2: Extractor & Header Parser         [===========]
WP-3: Client SCA & SemVer Logic               [===========]
WP-4: Defensive Reliability                         [=======]
WP-5: Web Cockpit & PDF Engine                            [=======]
WP-6: Test Suite (162 Tests) & QA                               [=====]
---------------------------------------------------------------------------------------
```

#### 3.5.2 PERT Network Scheduling & Critical Path Method (CPM)
The Program Evaluation and Review Technique (PERT) was applied using three-point time estimates:
$$t_e = \frac{O + 4M + P}{6}, \quad \sigma^2 = \left(\frac{P - O}{6}\right)^2$$

*Table 3.3: PERT Three-Point Duration Estimates and Task Variance Table.*

| Task ID | Task Scope Description | Optimistic ($O$) | Most Likely ($M$) | Pessimistic ($P$) | Expected ($t_e$) | Variance ($\sigma^2$) |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|
| **Task A** | Threat Modeling & Spec Definition | 8 Days | 12 Days | 16 Days | **12.0 Days** | 1.78 |
| **Task B** | Ingress Client & Header Parser | 14 Days | 18 Days | 24 Days | **18.3 Days** | 2.78 |
| **Task C** | SCA Engine & SemVer Logic | 12 Days | 16 Days | 22 Days | **16.3 Days** | 2.78 |
| **Task D** | Defensive Reliability & SSRF Guard | 10 Days | 14 Days | 18 Days | **14.0 Days** | 1.78 |
| **Task E** | Persistence, Web Cockpit & PDF Engine | 9 Days | 12 Days | 15 Days | **12.0 Days** | 1.00 |
| **Task F** | Test Automation (162 Tests) & Review | 7 Days | 10 Days | 13 Days | **10.0 Days** | 1.00 |

```
                       PERT CRITICAL PATH NETWORK DIAGRAM
                       
   [Node 1] ─── Task A (12.0d) ───► [Node 2] ─── Task B (18.3d) ───► [Node 3]
                                                                        │
   [Node 6] ◄─── Task F (10.0d) ◄─── [Node 5] ◄─── Task D (14.0d) ◄─── Task C (16.3d)
                    │                    ▲
                    └──── Task E (12.0d) ┘
```

- **Critical Path:** `Task A → Task B → Task C → Task D → Task E → Task F`
- **Total Project Expected Duration ($T_E$):**
  $$T_E = 12.0 + 18.3 + 16.3 + 14.0 + 12.0 + 10.0 = \mathbf{82.6\text{ Working Days}}\quad (\approx 14\text{ Calendar Weeks})$$
- **Total Project Variance ($\sigma^2_{\text{total}}$):**
  $$\sigma^2_{\text{total}} = 1.78 + 2.78 + 2.78 + 1.78 + 1.00 + 1.00 = \mathbf{11.12}$$
- **Project Standard Deviation ($\sigma_{\text{project}}$):**
  $$\sigma_{\text{project}} = \sqrt{11.12} \approx \mathbf{3.33\text{ Days}}$$

---

### 3.6 Software Requirement Specification (SRS)

#### 3.6.1 Detailed Functional Requirements (FR)
- **FR-01: Ingress Normalization & Validation:** The system shall accept a target domain name or URL string, trim leading/trailing whitespace, and prepend `https://` if no scheme is specified.
- **FR-02: Pre-Flight Multi-A-Record DNS Interrogation:** The system shall invoke `socket.gethostbyname_ex()` to resolve all IPv4 A-records associated with the target domain. The resulting IP address array shall be sorted alphabetically to guarantee consistent, deterministic output across round-robin DNS configurations.
- **FR-03: Pre-Flight SSRF Screening:** The system shall convert all resolved IP addresses into `ipaddress.ip_address` objects. If any IP falls within RFC 1918 private space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback space (`127.0.0.0/8`), link-local space (`169.254.0.0/16`), or multicast space, the system shall abort execution immediately, record a High-Severity finding (`CWE-918`), and emit zero downstream HTTP requests.
- **FR-04: Plain-HTTP Redirect Header Divergence Probe:** The system shall issue a non-redirecting GET request to `http://<target>` to capture intermediate redirect response headers. It shall evaluate whether `Strict-Transport-Security` is erroneously emitted on the HTTP response rather than the HTTPS origin, surfacing this divergence as a configuration finding.
- **FR-05: Resilient TLS Handshake & Fallback:** The system shall execute HTTPS GET requests with strict certificate verification (`verify=True`). Upon encountering a `requests.exceptions.SSLError`, the system shall record a High-Severity finding (`CWE-295`) and seamlessly re-execute with `verify=False` to audit underlying headers, suppressing repetitive `InsecureRequestWarning` output.
- **FR-06: Anti-DoS Streaming Ingestion:** The system shall read incoming HTML response streams in 8192-byte chunks, enforcing a strict 512 KB hard ceiling (`MAX_HTML_BYTES`). If total bytes read exceed 512 KB, the stream shall terminate immediately, setting the diagnostic flag `html_truncated=True`.
- **FR-07: WAF Challenge Page Detection & Quarantine:** The system shall evaluate HTTP response codes (403, 406, 429, 503), headers (`cf-mitigated`, `x-amzn-waf-action`), and body markers ('just a moment', '_cf_chl_', 'g-recaptcha') to identify Cloudflare, AWS WAF, and Imperva challenge screens. When detected, the audit status shall be marked `BLOCKED`, preventing false-positive findings against challenge pages.
- **FR-08: Directive-Level CSP AST Tokenizer:** The system shall parse `Content-Security-Policy` strings into structured directive maps. It shall audit for:
  - Header absence or Report-Only without enforced policy.
  - `'unsafe-inline'` in script contexts (suppressed when cryptographic nonces or hashes are present).
  - `'unsafe-eval'`.
  - Wildcard (`*`) sources in `script-src` and `default-src`.
  - `data:` URI schemes in script sources.
  - Missing structural directives (`object-src`, `base-uri`, `frame-ancestors`, `default-src`).
- **FR-09: Modern Clickjacking Equivalence:** The system shall validate `X-Frame-Options` (`DENY` or `SAMEORIGIN`), but shall treat CSP `frame-ancestors` as an equivalent modern control, suppressing missing XFO alerts when valid `frame-ancestors` directives are active.
- **FR-10: Multi-Signal Client-Side Component SCA:** The system shall discover third-party JavaScript libraries across external `<script src="...">` tags and inline script blocks by evaluating URL paths, comment banners, and query strings (`?ver=`).
- **FR-11: 4-Part SemVer Version Comparison:** The system shall parse extracted version strings into 4-part numeric tuples with alphanumeric pre-release tokens, evaluating whether the version falls within known vulnerable ranges $[V_{\text{min}}, V_{\text{fixed}})$.
- **FR-12: Live Advisory Synchronization:** The system shall query Google's OSV.dev REST API (`https://api.osv.dev/v1/query`) and the Retire.js repository in real-time, extracting CVE aliases, CVSS ratings, and safe remediation targets.
- **FR-13: Monotonic Wall-Clock Budget Enforcement:** The system shall enforce a strict 45.0-second total deadline (`ScanBudget`), clamping internal socket timeouts dynamically to prevent application lockup.
- **FR-14: Relational Persistence & Audit Ledger Management:** The system shall persist scan metadata into SQLite `scan_history` and provide a dedicated `/clear-history` endpoint to purge historical logs securely.
- **FR-15: Two-Pass Typographic PDF Generation:** The system shall synthesize a formal, multi-page PDF report using ReportLab, calculating dynamic page totals ("Page X of Y") via `NumberedCanvas` and structuring findings by CVSS severity.

#### 3.6.2 Non-Functional Requirements (NFR)
- **NFR-01: Performance & Execution Ceiling:** A complete scan pipeline execution across any responsive web target shall complete within $\le 45.0$ seconds.
- **NFR-02: Low Memory Footprint:** The resident set size (RSS) memory consumption of the Python process shall not exceed 100 MB under standard operating conditions.
- **NFR-03: Thread-Safe Concurrency:** All in-memory caches and script retrieval worker pools must enforce mutex synchronization (`threading.Lock()`), preventing race conditions in multi-threaded WSGI servers.
- **NFR-04: Deterministic Audit Reproducibility:** Repeated scans against identical static server configurations shall produce 100% identical finding counts and risk scores.
- **NFR-05: Non-Destructive Operation:** The scanner shall emit zero form mutations, zero parameter fuzzing strings, and zero exploit payloads under any circumstances.
- **NFR-06: Zero-Config Startup Fault Tolerance:** The application shall start without throwing unhandled exceptions if the `.env` secret key configuration file is missing, automatically generating high-entropy cryptographic keys in memory.
- **NFR-07: Portability:** The application code shall run without modification across Windows, Linux (Ubuntu/Debian), and macOS environments on Python 3.10 through 3.14.
- **NFR-08: Standardized Weakness Categorization:** Every discovered misconfiguration and vulnerable component shall correlate with an authoritative CWE identifier and OWASP category.
- **NFR-09: Automated Test Coverage:** The core engine shall maintain $\ge 90\%$ statement coverage verified by automated pytest harnesses.
- **NFR-10: Graceful Network Degradation:** External API outages (OSV.dev or GitHub raw) shall degrade silently to local curated data without interrupting the end-user report generation.

---

### 3.7 System Specifications

#### 3.7.1 Hardware Environment Matrix

*Table 3.4: Hardware Specification Matrix (Development, Testing, and Production).*

| Hardware Component | Development Workstation | Minimal Staging / Test Node | Cloud Production VM (OCI / VPS) |
|---|---|---|---|
| **CPU Architecture** | x86_64 (Intel Core i7-12700H) | x86_64 Dual-Core @ 2.0 GHz | ARM64 Ampere A1 (1 to 4 OCPUs) |
| **System RAM** | 16 GB DDR4 @ 3200 MHz | 2 GB DDR3 / DDR4 | 6 GB to 24 GB RAM |
| **Storage Allocation**| 512 GB NVMe SSD | 20 GB Disk Space | 50 GB Boot Volume |
| **Network Interface** | 1 Gbps Ethernet / Wi-Fi 6 | 100 Mbps Virtual NIC | 1 Gbps to 4 Gbps Virtual NIC |

#### 3.7.2 Software Dependencies & Toolchain

*Table 3.5: Production Software Dependencies and Toolchain Specification.*

| Dependency Package | Pinned Version | License Type | Architectural Role & Justification |
|---|:---:|:---:|---|
| **Python** | `3.14.6` | PSF License | Core system runtime; native socket, typing, and regex engines |
| **Flask** | `3.0.3` | BSD-3-Clause | Lightweight WSGI web framework, template routing, error handling |
| **requests** | `2.32.3` | Apache 2.0 | Synchronous HTTP networking, connection pooling, chunk streaming |
| **beautifulsoup4**| `4.12.3` | MIT License | Fault-tolerant HTML DOM traversal, tag discovery, comment extraction |
| **reportlab** | `4.2.2` | BSD License | PDF rendering engine, flowables architecture, canvas drawing |
| **python-dotenv** | `1.0.1` | BSD-3-Clause | Runtime `.env` configuration loading and fallback protection |
| **pytest** | `9.2.0` | MIT License | Unit test automation harness, fixture mocking, regression verification |
| **SQLite3** | Embedded (3.x)| Public Domain | ACID-compliant relational persistence engine, serverless database |

---

### 3.8 Detailed System Data Models

#### 3.8.1 Object-Oriented Class Model
The object-oriented architecture is composed of decoupled domain entities:

```
+-----------------------------------------------------------------------------------+
|                                    TargetData                                     |
+-----------------------------------------------------------------------------------+
| - _dict: dict                                                                     |
+-----------------------------------------------------------------------------------+
| + __init__(data: dict)                                                            |
| + __iter__(): tuple (headers: dict, script_srcs: list) [Backward Compatibility]   |
| + __getitem__(key: str): Any                                                      |
| + get(key: str, default: Any): Any                                                |
+-----------------------------------------------------------------------------------+
                                         ^
                                         | returns
+----------------------------------------+------------------------------------------+
|                                    ScanBudget                                     |
+-----------------------------------------------------------------------------------+
| - _total: float                                                                   |
| - _deadline: float                                                                |
+-----------------------------------------------------------------------------------+
| + __init__(total_seconds: float = 45.0)                                           |
| + is_expired(): bool                                                              |
| + remaining(): float                                                              |
| + can_sleep(seconds: float): bool                                                 |
| + clamp_timeout(connect: float, read: float): tuple[float, float]                 |
+-----------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------+
|                                 BoundedTTLCache                                   |
+-----------------------------------------------------------------------------------+
| - _store: OrderedDict[str, tuple[float, Any]]                                     |
| - _maxsize: int                                                                   |
| - _ttl: float                                                                     |
| - _lock: threading.Lock                                                           |
+-----------------------------------------------------------------------------------+
| + __init__(maxsize: int = 256, ttl: float = 3600.0)                               |
| + get(key: str): tuple[bool, Any | None]                                          |
| + set(key: str, value: Any): void                                                 |
| + __len__(): int                                                                  |
| + __contains__(key: str): bool                                                    |
+-----------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------+
|                                      SemVer                                       |
+-----------------------------------------------------------------------------------+
| + raw: str                                                                        |
| + parts: tuple[int, ...]                                                          |
| + prerelease: tuple[tuple[int, Any], ...] | None                                  |
| + build: str | None                                                               |
| + is_valid: bool                                                                  |
+-----------------------------------------------------------------------------------+
| + __init__(v_str: str)                                                            |
| + __lt__(other: SemVer): bool                                                     |
| + __le__(other: SemVer): bool                                                     |
| + __eq__(other: SemVer): bool                                                     |
| + __gt__(other: SemVer): bool                                                     |
| + __ge__(other: SemVer): bool                                                     |
+-----------------------------------------------------------------------------------+
```

#### 3.8.2 Activity Model & Operational Process Logic
The activity model defines the sequential execution and decision gates from target ingress to PDF rendering:

```mermaid
flowchart TD
    Start([User Initiates Scan]) --> Ingress[URL Normalization & Scheme Validation]
    Ingress --> DNS[Execute socket.gethostbyname_ex]
    DNS --> SSRFCheck{Is IP in Private/Loopback/Link-Local Range?}
    SSRFCheck -- Yes --> SSRFBlock[Abort Scan: Emit High-Severity CWE-918 Finding]
    SSRFBlock --> Persist[Persist Error & Render Failed Dashboard]
    SSRFCheck -- No --> HTTPProbe[Probe Plain-HTTP Endpoint for Redirect Headers]
    HTTPProbe --> TLSHandshake[Execute HTTPS GET with verify=True]
    TLSHandshake --> TLSError{SSLError Triggered?}
    TLSError -- Yes --> TLSFallback[Emit CWE-295 Finding & Fallback to verify=False]
    TLSError -- No --> HTMLStream[Stream HTML Body capped at 512 KB]
    TLSFallback --> HTMLStream
    HTMLStream --> WAFDetect{WAF / Challenge Page Markers Detected?}
    WAFDetect -- Yes --> Quarantine[Mark Status as BLOCKED; Quarantine Origin Checks]
    WAFDetect -- No --> DOMParse[Parse DOM: Extract Script Tags & Comments]
    Quarantine --> PDFGen
    DOMParse --> HeaderMatch[Execute Header Matcher: CSP, HSTS, XFO, MIME]
    HeaderMatch --> SCAScan[Corroborate JavaScript Components & SemVer]
    SCAScan --> CacheCheck{OSV Data in BoundedTTLCache?}
    CacheCheck -- Yes --> CacheHit[Load Advisory from Cache]
    CacheCheck -- No --> OSVQuery[Query OSV.dev REST API]
    OSVQuery -- Fails/Timeout --> OfflineDB[Fallback to Curated RETIREJS_DB]
    OSVQuery -- Succeeds --> CacheSet[Store in BoundedTTLCache]
    CacheHit --> PDFGen[Synthesize ReportLab PDF via NumberedCanvas]
    OfflineDB --> PDFGen
    CacheSet --> PDFGen
    PDFGen --> DBPersist[Insert Audit Record into SQLite scan_history]
    DBPersist --> End([Render Interactive Results Dashboard])
```

#### 3.8.3 Chronological Sequence Model
The chronological interactions between system actors are defined below:

```
User          Web Controller      Extractor         Matcher/SCA       OSV.dev API     SQLite DB
 |                  |                 |                  |                 |              |
 |--- POST /scan -->|                 |                  |                 |              |
 |                  |-- extract_data >|                  |                 |              |
 |                  |                 |-- DNS Query ---->|                 |              |
 |                  |                 |-- SSRF Filter -->|                 |              |
 |                  |                 |-- HTTPS Stream ->|                 |              |
 |                  |<- TargetData ---|                  |                 |              |
 |                  |                                    |                 |              |
 |                  |------ run_matcher(headers) ------->|                 |              |
 |                  |------ scan_retirejs(scripts) ----->|                 |              |
 |                  |                                    |-- POST /query ->|              |
 |                  |                                    |<- CVE JSON -----|              |
 |                  |<----- Findings & Components List --|                 |              |
 |                  |                                                                     |
 |                  |------ insert_scan_record() ---------------------------------------->|
 |                  |                                                                     |
 |                  |------ generate_audit_report(PDF)                                    |
 |<-- 302 Redirect -|                                                                     |
 |--- GET /result ->|                                                                     |
 |<-- Rendered HTML-|                                                                     |
```

#### 3.8.4 Entity-Relationship Model & 3NF Schema Analysis

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

*Table 3.6: Data Dictionary for `scan_history` Entity.*

| Column Name | Physical Data Type | Constraints | Nullable | Default Value | Description / Business Meaning |
|---|:---:|:---:|:---:|:---:|---|
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | No | Auto | Unique sequential scan event identifier |
| `target_url` | `TEXT` | `NOT NULL` | No | None | Normalized target URL / FQDN |
| `target_ip` | `TEXT` | None | Yes | `'N/A'` | Sorted comma-separated public IPv4 addresses |
| `scan_date` | `TEXT` | `NOT NULL` | No | None | ISO UTC timestamp string (`YYYY-MM-DD HH:MM:SS`)|
| `findings_count` | `INTEGER` | None | Yes | `0` | Total count of identified vulnerabilities |
| `risk_level` | `TEXT` | None | Yes | `'info'` | Overall risk rating (`critical`, `high`, `medium`, `low`)|
| `pdf_path` | `TEXT` | None | Yes | None | Absolute path to generated ReportLab PDF |

*Table 3.7: Data Dictionary for `vulnerability_rules` Entity.*

| Column Name | Physical Data Type | Constraints | Nullable | Default Value | Description / Business Meaning |
|---|:---:|:---:|:---:|:---:|---|
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | No | Auto | Unique rule knowledge base identifier |
| `rule_key` | `VARCHAR(100)` | `UNIQUE` | No | None | Normalized lookup token (e.g. `content-security-policy`)|
| `name` | `VARCHAR(255)` | `NOT NULL` | No | None | Human-readable vulnerability title |
| `severity` | `VARCHAR(50)` | `NOT NULL` | No | None | Base severity level (`critical`, `high`, `medium`, etc.)|
| `description` | `TEXT` | None | Yes | None | Technical narrative explaining the vulnerability |
| `ref_id` | `VARCHAR(50)` | None | Yes | None | Standardized CWE reference identifier (e.g. `CWE-693`)|
| `cve_id` | `VARCHAR(50)` | None | Yes | None | Legacy CVE identifier (if applicable) |
| `cvss_score` | `FLOAT` | None | Yes | `None` | Standardized CVSS v3.1 base score (0.0 to 10.0)|
| `reference_link` | `VARCHAR(500)`| None | Yes | None | Authoritative documentation link (OWASP / MDN)|
| `remediation_steps`| `TEXT` | None | Yes | None | Concrete technical remediation instructions |

##### Third Normal Form (3NF) Normalization Proof:
1. **1NF Compliance:** All attributes contain atomic scalar values. Repeating groups (findings arrays and component inventories) are persisted as independent JSON documents in the `reports/` directory with file paths cross-referenced in the database.
2. **2NF Compliance:** Both tables utilize single-attribute primary keys (`id`). Therefore, no partial functional dependencies on composite keys can exist:
   $$\forall X \to Y, \quad X = \{\text{id}\}$$
3. **3NF Compliance:** In `scan_history`, all non-key attributes (`target_url`, `target_ip`, `scan_date`, `findings_count`, `risk_level`, `pdf_path`) are directly dependent on `id`. There are no transitive dependencies between non-key attributes:
   $$\text{id} \to \text{target\_url}, \quad \text{target\_url} \not\to \text{risk\_level}$$
   Similarly, in `vulnerability_rules`, all metadata depends directly on the unique `rule_key` and `id`, fully decoupling static rule definitions from dynamic scan events.

#### 3.8.5 Use Case Behavioral Model

```
                               USE CASE DIAGRAM
                               
      (External APIs)                            (Security Analyst)
             |                                           |
             |                                           +--- [UC-01: Initiate Perimeter Scan]
             |                                           |
   [UC-07: Deliver Advisory Data]                        +--- [UC-02: Review Live Telemetry]
             ^                                           |
             |                                           +--- [UC-03: Inspect Vulnerability Findings]
             |                                           |
      <<queries>>                                        +--- [UC-04: Export Official PDF Dossier]
             |                                           |
    [FrontGuard Engine]                                  +--- [UC-05: Reset Audit Ledger]
             |                                           
             +--- [UC-06: Interrogate Target Perimeters] 
             |
      (Target Server)
```

- **Use Case UC-01: Initiate Perimeter Scan**
  - *Actor:* Security Analyst.
  - *Pre-conditions:* Web browser navigated to `http://127.0.0.1:5000`.
  - *Main Success Scenario:* Analyst inputs target domain, submits form. System validates FQDN, conducts pre-flight DNS interrogation, executes passive checks, compiles findings, logs record in SQLite, and redirects user to results view.
  - *Alternative Flow:* If target resolves to private IP, system aborts scan, logs `CWE-918` SSRF alert, and presents error card.
- **Use Case UC-04: Export Official PDF Dossier**
  - *Actor:* Security Analyst.
  - *Pre-conditions:* Scan completed; result view active.
  - *Main Success Scenario:* Analyst clicks "Export Official PDF Report". Controller calls ReportLab builder, executes two-pass `NumberedCanvas` rendering, and streams binary PDF to client with attachment headers.
- **Use Case UC-05: Reset Audit Ledger**
  - *Actor:* Security Analyst.
  - *Pre-conditions:* Dashboard active with historical scan records.
  - *Main Success Scenario:* Analyst clicks "Clear History". Controller invokes `clear_scan_history()`, executes `DELETE FROM scan_history`, resets autoincrement sequence, and returns flash confirmation.

---
\newpage

# CHAPTER 4: SYSTEM DESIGN & ARCHITECTURE

### 4.1 Architectural Pattern & Pipeline Decomposition
FrontGuard is designed following a **Layered Pipeline Architecture**. Control flow progresses linearly through discrete processing stages, with state encapsulated inside standardized data transfer containers:

```
+─────────────────────────────────────────────────────────────────────────────────+
|                               PRESENTATION TIER                                 |
|  Jinja2 Dark-Mode Templates (index.html, result.html) & CSS System (style.css)  |
+─────────────────────────────────────────────────────────────────────────────────+
                                       ▲ │
                         HTTP Requests │ │ JSON / HTML
                                       │ ▼
+─────────────────────────────────────────────────────────────────────────────────+
|                              ORCHESTRATION TIER                                 |
|          Flask Controller & WSGI Pipeline Manager: dummy_scan() in main.py      |
+─────────────────────────────────────────────────────────────────────────────────+
                                       ▲ │
                          Target URL   │ │ TargetData
                                       │ ▼
+─────────────────────────────────────────────────────────────────────────────────+
|                              EXTRACTION LAYER                                   |
|      DNS Interrogation, SSRF Screening & Stream Ingestion (scanner/extractor.py)|
+─────────────────────────────────────────────────────────────────────────────────+
                                       ▲ │
                          Raw Headers  │ │ Scripts / DOM
                                       │ ▼
+─────────────────────────────────────────────────────────────────────────────────+
|                           AUDIT & EVALUATION LAYER                              |
|    Security Header Matcher (matcher.py) & Client-Side SCA Engine (retirejs.py)  |
+─────────────────────────────────────────────────────────────────────────────────+
                                       ▲ │
                          Advisory Qs  │ │ Vulnerability Payloads
                                       │ ▼
+─────────────────────────────────────────────────────────────────────────────────+
|                           DEFENSE & RELIABILITY LAYER                           |
|        ScanBudget, BoundedTTLCache & WAF Quarantine (scanner/reliability.py)    |
+─────────────────────────────────────────────────────────────────────────────────+
                                       ▲ │
                         Findings Data │ │ PDF Filesystem
                                       │ ▼
+─────────────────────────────────────────────────────────────────────────────────+
|                           PERSISTENCE & REPORTING                               |
|        SQLite Relational Engine (db_handler.py) & PDF Builder (pdf_builder.py)  |
+─────────────────────────────────────────────────────────────────────────────────+
```

---

### 4.2 Comprehensive Modularization Specifications (7 Core Modules)

#### 4.2.1 Network Extractor Module (`scanner/extractor.py`)
- **Module Purpose:** Handles low-level network ingress, DNS resolution, streaming byte caps, and HTML node parsing.
- **Input Contract:** `url: str` (e.g., `https://example.com`).
- **Processing Logic:**
  1. Calls `resolve_target_ip(url)`, utilizing `socket.gethostbyname_ex()` to query system DNS.
  2. Applies `is_private_ip()` validation to every resolved address. If an internal address is detected, returns `TargetData` with `is_ssrf_blocked=True`.
  3. Dispatches a non-redirecting GET request to `http://<target>` using `TARGET_TIMEOUT = (4.0, 8.0)` to record redirect-stage headers.
  4. Dispatches an HTTPS GET request with `verify=True`. Catches `requests.exceptions.SSLError`, logs `CWE-295`, and re-executes with `verify=False` and suppressed warnings.
  5. Reads response body via `resp.iter_content(chunk_size=8192)`. Increments `total_len`; if $\text{total\_len} \ge \text{MAX\_HTML\_BYTES}$ (512 KB), truncates stream and sets `html_truncated=True`.
  6. Evaluates WAF signatures via `detect_waf_or_block(resp)`.
  7. Parses HTML DOM using BeautifulSoup to extract `<script src="...">` URLs, inline `<script>` blocks, HTML comments, and `<form>` attributes.
- **Output Contract:** Structured `TargetData` object containing `headers`, `http_headers`, `script_srcs`, `inline_scripts`, `comments`, `forms`, `target_ip`, and `scan_coverage`.

#### 4.2.2 Security Header Matcher Module (`scanner/matcher.py`)
- **Module Purpose:** Deconstructs HTTP headers into syntax directives, evaluating compliance against RFC and W3C security standards.
- **Input Contract:** `headers: dict`, `scripts: list`, `inline_scripts: list`, `target_url: str`.
- **Processing Logic:**
  1. **CSP Evaluation (`_check_csp`):** Tokenizes CSP into `{directive: [sources]}` map. Checks for absence, Report-Only status, `'unsafe-inline'` without nonces/hashes, `'unsafe-eval'`, wildcards (`*`), `data:` schemes, and missing directives (`object-src`, `base-uri`, `frame-ancestors`, `default-src`).
  2. **HSTS Evaluation (`_check_hsts`):** Extracts `max-age` integer. Flags `max-age=0` (disabling HSTS), `max-age < 86400` (too short), `max-age < 31536000` (preload non-compliant), missing `includeSubDomains`, and missing `preload`.
  3. **Frame Protection (`_check_xfo`):** Validates `DENY` or `SAMEORIGIN`; suppresses missing alert if CSP `frame-ancestors` is actively enforced.
  4. **MIME Protection (`_check_xcto`):** Requires exact value `'nosniff'`.
  5. **Referrer-Policy (`_check_referrer_policy`):** Flags `'unsafe-url'` as Medium severity (worse than absent).
  6. **Cross-Origin Policies:** Audits COOP, CORP, and COEP headers.
  7. **Information Disclosure (`_check_dangerous_headers`):** Flags `X-Powered-By` and evaluates `Server` headers for numeric version strings using `_server_discloses_version()`.
  8. **DOM XSS & Secrets:** Runs regex matching across inline scripts for API keys (`api_key`, `bearer`, AWS access keys) and dangerous execution sinks (`eval(dynamic)`, `document.write()`, `.innerHTML`).
- **Output Contract:** Ordered list of vulnerability findings dictionaries with standardized attributes: `vuln_type`, `severity`, `description`, `evidence`, `attack_prevented`, `recommended_value`, `reference`, `ref_id`, and `cvss_score`.

*Table 4.1: Supported Security Headers and Corresponding Verification Directives.*

| Security Header | Standard Reference | Evaluated Directive Constraints | Minimum Compliant Value |
|---|:---:|---|---|
| **Content-Security-Policy** | W3C CSP3 | Check for `'unsafe-inline'`, `'unsafe-eval'`, `*`, missing fallbacks | `default-src 'self'; object-src 'none'; frame-ancestors 'none'` |
| **Strict-Transport-Security**| RFC 6797 | Enforce `max-age >= 31536000`, `includeSubDomains`, `preload` | `max-age=31536000; includeSubDomains; preload` |
| **X-Frame-Options** | RFC 7034 | Enforce `DENY` or `SAMEORIGIN`; evaluate CSP `frame-ancestors` | `DENY` or `SAMEORIGIN` |
| **X-Content-Type-Options** | Fetch Spec | Enforce literal string `nosniff` | `nosniff` |
| **Referrer-Policy** | W3C Referrer | Prohibit `unsafe-url`; require strict origin controls | `strict-origin-when-cross-origin` |
| **Permissions-Policy** | W3C Permissions | Restrict camera, microphone, geolocation access | `geolocation=(), camera=(), microphone=()` |
| **Cross-Origin-Opener-Policy**| HTML Spec | Enforce process isolation against Spectre attacks | `same-origin` |
| **Cross-Origin-Resource-Policy**| Fetch Spec | Prevent cross-origin no-cors resource reads | `same-origin` |
| **Cross-Origin-Embedder-Policy**| HTML Spec | Enforce cross-origin isolation | `require-corp` |

#### 4.2.3 RetireJS & SCA Engine Module (`scanner/retirejs.py`)
- **Module Purpose:** Detects client-side JavaScript packages, compares semantic versions, and correlates CVE intelligence.
- **Input Contract:** `script_srcs: list[str]`, `inline_scripts: list[str]`, `base_url: str`.
- **Processing Logic:**
  1. Iterates through discovered scripts, matching URL path regexes and comment banners against known component signatures.
  2. Extracts candidate version strings and parses them into `SemVer` objects.
  3. Queries in-memory `BoundedTTLCache` using cache key `<package>::<version>`.
  4. On cache miss, issues POST request to OSV.dev REST API (`https://api.osv.dev/v1/query`) with JSON payload:
     ```json
     {"package": {"name": "jquery", "ecosystem": "npm"}, "version": "1.12.4"}
     ```
  5. Parses returned advisory array, extracting primary CVE aliases, fixed version boundaries, and CVSS severity ratings.
  6. If OSV.dev lookup fails or times out, seamlessly evaluates `RETIREJS_DB` in memory.
- **Output Contract:** Tuple of `(retirejs_findings_list, components_inventory_list)`.

*Table 4.2: Supported Client-Side Libraries and Corroboration Detection Signals.*

| Library Identifier | URL Pattern Signature | Banner Regex Context Signature | Fallback Rules Version Ceiling |
|---|---|---|:---:|
| **jQuery** | `/jquery[.-]([0-9]+(?:\.[0-9]+)+)` | `/\*!*?\s*jQuery\s+v([0-9]+(?:\.[0-9]+)+)` | `< 3.5.0` (CVE-2020-11022) |
| **Bootstrap** | `/bootstrap[.-]([0-9]+(?:\.[0-9]+)+)` | `Bootstrap\s+v([0-9]+(?:\.[0-9]+)+)` | `< 4.3.1` (CVE-2019-8331) |
| **Lodash** | `/lodash[.-]([0-9]+(?:\.[0-9]+)+)` | `Lo-Dash\s+v?([0-9]+(?:\.[0-9]+)+)` | `< 4.17.21` (CVE-2020-8203) |
| **Moment.js** | `/moment[.-]([0-9]+(?:\.[0-9]+)+)` | `Moment\.js\s+([0-9]+(?:\.[0-9]+)+)` | `< 2.29.4` (CVE-2022-31129) |
| **Vue.js** | `/vue[.-]([0-9]+(?:\.[0-9]+)+)` | `Vue\.js\s+v([0-9]+(?:\.[0-9]+)+)` | `< 2.6.14` (CVE-2024-6783) |
| **Axios** | `/axios[.-]([0-9]+(?:\.[0-9]+)+)` | `axios\s+v([0-9]+(?:\.[0-9]+)+)` | `< 1.6.0` (CVE-2023-45857) |
| **Handlebars** | `/handlebars[.-]([0-9]+(?:\.[0-9]+)+)` | `Handlebars\.js\s+v([0-9]+(?:\.[0-9]+)+)` | `< 4.7.7` (CVE-2021-23369) |

#### 4.2.4 Reliability Subsystem Module (`scanner/reliability.py`)
- **Module Purpose:** Enforces execution time limits, stream byte ceilings, and thread-safe caching.
- **Core Abstractions:**
  - `ScanBudget`: Tracks monotonic deadline ($T_{\text{start}} + 45.0$). Clamps connect/read timeouts dynamically.
  - `BoundedTTLCache`: Thread-safe LRU dictionary with TTL validation; evicts oldest items when capacity (256) is exceeded.
  - `detect_waf_or_block`: Evaluates status codes (403, 406, 429, 503), WAF headers, and challenge page text markers.
  - `retry_get`: Implements bounded exponential backoff with jitter and honors `Retry-After` headers.
  - `is_private_ip`: Evaluates IP against standard private network blocks.

#### 4.2.5 Database Persistence Engine (`database/db_handler.py`)
- **Module Purpose:** Manages SQLite connection lifecycle, schema initialization, and audit logging.
- **Key Functions:**
  - `init_db()`: Executes `schema.sql`, performs dynamic schema alterations (`ALTER TABLE ADD COLUMN`), and populates default CWE/OWASP rules.
  - `insert_scan_record(...) -> int`: Inserts new audit event into `scan_history` using parameterized SQL, returning `lastrowid`.
  - `get_scan_history() -> list[dict]`: Retrieves all historical audit records sorted chronologically descending.
  - `clear_scan_history() -> int`: Executes `DELETE FROM scan_history` and resets `sqlite_sequence`.
  - `get_vulnerability_rule(identifier: str) -> dict | None`: Queries vulnerability knowledge base for CWE, CVSS, and remediation data.

#### 4.2.6 Typographic PDF Builder (`reporting/pdf_builder.py`)
- **Module Purpose:** Generates publication-grade, multi-page PDF audit reports.
- **Key Functions:**
  - `NumberedCanvas(canvas.Canvas)`: Two-pass canvas renderer that tracks total pages dynamically, printing `"Page X of Y // CONFIDENTIAL // FRONTGUARD AUDIT ENGINE"`.
  - `generate_audit_report(scan_data, output_path)`: Builds Document Flowables: Executive Summary Scorecard, Severity Matrix Table, and Detailed Findings Tables.
  - Implements high-contrast utilitarian palette: Dark Navy (`#0f172a`), Slate Border (`#cbd5e1`), Row Alt (`#f8fafc`).

#### 4.2.7 Web Presentation Controller (`main.py`)
- **Module Purpose:** Serves Flask WSGI routes and orchestrates pipeline execution.
- **Key Routes:**
  - `GET /`: Renders `index.html` displaying scan launch input and historical Audit Ledger.
  - `POST /scan`: Ingress point for scan execution; invokes `dummy_scan()`.
  - `GET /result/<scan_id>`: Renders interactive `result.html` showing categorized telemetry, headers, and CVE cards.
  - `GET /report/<scan_id>/pdf`: Streams binary PDF report to client with `attachment` disposition header.
  - `POST /clear-history`: Purges historical ledger and redirects with flash notification.

---

### 4.3 Data Integrity, Concurrency & Security Constraints
1. **SQL Injection Parameterization:** 100% of SQL statements executed within `db_handler.py` strictly utilize parameterized `?` placeholders. Zero string concatenation or formatting (`f"SELECT ... {input}"`) is permitted.
2. **Mutex-Locked In-Memory Caching:** Concurrent threads accessing `BoundedTTLCache` are synchronized using `threading.Lock()` contexts:
   ```python
   with self._lock:
       # Thread-safe read / write / evict operations
   ```
3. **Defensive Cryptographic Key Fallback:** If no `.env` file is present, `main.py` generates a cryptographically secure 256-bit random key in memory on startup:
   ```python
   app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32).hex()
   ```
   This ensures the application starts seamlessly out-of-the-box for evaluators without compromising session signing security.

---
\newpage

# CHAPTER 5: TESTING & QUALITY ASSURANCE

### 5.1 Quality Assurance Strategy & Test Harness
To guarantee deterministic execution, zero false positives, and software reliability, FrontGuard was developed under a rigorous test-driven quality assurance methodology. The primary testing harness is implemented using **Pytest (v9.2.0)**, augmented by Python's built-in `unittest.mock` framework to isolate network sockets and simulate adversarial responses.

The testing strategy is partitioned into four validation tiers:
1. **Unit Testing:** Validates isolated methods and algorithms, including regular expression compilation, version tokenization in `SemVer`, and individual header verification rules.
2. **Boundary & Stress Testing:** Evaluates system behavior under boundary conditions, such as streaming HTML payloads exceeding 512 KB, socket timeouts approaching the 45.0-second limit, and extreme multi-part version strings (e.g., `1.2.3.4.5-beta.10+build2024`).
3. **Adversarial & Fault Injection Testing:** Simulates malicious server behaviors, including target hostnames resolving to internal AWS metadata IP addresses (`169.254.169.254`), self-signed and expired TLS certificates, infinite chunked HTTP streams, and Cloudflare WAF interstitial challenge blocks.
4. **Integration & Route Testing:** Tests the Flask WSGI controller using `app.test_client()`, confirming HTTP status codes, flash session alerts, database row insertion, and binary PDF streaming headers.

---

### 5.2 Exhaustive Test Suite Matrix (25 Representative Scenarios)

The automated test suite comprises **162 unit tests** distributed across three primary test modules:
- `test_phase2_headers.py` (84 tests): Comprehensive HTTP response header compliance and syntactic validation.
- `test_phase3_library_detection.py` (49 tests): Component discovery, regex precision, and version comparator logic.
- `test_phase4_reliability.py` (29 tests): Reliability subsystems, SSRF defenses, WAF quarantine, cache, and database lifecycle.

*Table 5.1: Exhaustive Unit Test Verification Suite (25 Critical Scenarios).*

| Test ID | Test Suite | Component Under Test | Scenario & Description | Input / Mock Fixture | Expected Assertion & Result | Status |
|:---:|:---:|---|---|---|---|:---:|
| **TC-01** | `phase4` | `reliability.py` | SSRF Private IP RFC 1918 Block | Hostname resolves to `192.168.1.1` | `is_ssrf_blocked == True`, `CWE-918` logged, 0 outbound requests | **PASS** |
| **TC-02** | `phase4` | `reliability.py` | SSRF Loopback Subnet Block | Hostname resolves to `127.0.0.1` | Scan aborted; SSRF error finding emitted | **PASS** |
| **TC-03** | `phase4` | `reliability.py` | SSRF Cloud Metadata Block | Hostname resolves to `169.254.169.254` | Immediate termination; AWS instance metadata protected | **PASS** |
| **TC-04** | `phase4` | `reliability.py` | Anti-DoS Streaming Body Cap | Response stream emitting 1.5 MB data | Stream breaks at 512 KB; `html_truncated == True` | **PASS** |
| **TC-05** | `phase4` | `reliability.py` | ScanBudget Deadline Expiry | Mock execution elapsed $\ge 45.0\text{s}$ | `budget.is_expired() == True`, socket timeouts clamped to 0 | **PASS** |
| **TC-06** | `phase4` | `reliability.py` | BoundedTTLCache Capacity Eviction | Insert 257 items into 256-cap cache | Oldest item evicted via LRU; length clamped at 256 | **PASS** |
| **TC-07** | `phase4` | `reliability.py` | BoundedTTLCache Monotonic Expiry | Retrieve entry after TTL duration | Returns `(False, None)`; expired entry purged | **PASS** |
| **TC-08** | `phase4` | `reliability.py` | Cloudflare Challenge Page Quarantine| HTTP 403 with `_cf_chl_` body marker | `is_waf_blocked == True`, status `BLOCKED`, origin quarantined | **PASS** |
| **TC-09** | `phase4` | `reliability.py` | AWS WAF Header Marker Detection | Header `x-amzn-waf-action: block` | `is_waf_blocked == True`, diagnostic emitted | **PASS** |
| **TC-10** | `phase2` | `extractor.py` | TLS Certificate Failure Fallback | Host triggers `SSLError` (expired cert) | Logs High-Severity `CWE-295`; retries with `verify=False` | **PASS** |
| **TC-11** | `phase2` | `extractor.py` | Plain-HTTP vs HTTPS HSTS Probe | HSTS on HTTP redirect, absent on HTTPS | Flags Medium-Severity HSTS misconfiguration finding | **PASS** |
| **TC-12** | `phase2` | `matcher.py` | CSP Absence Detection | Raw headers dictionary omitting CSP | High-Severity `CWE-693` missing header finding logged | **PASS** |
| **TC-13** | `phase2` | `matcher.py` | CSP Report-Only Disenactment | `Content-Security-Policy-Report-Only` set | Flags Medium-Severity finding: policy logged but not enforced | **PASS** |
| **TC-14** | `phase2` | `matcher.py` | CSP `unsafe-inline` Detection | `script-src 'self' 'unsafe-inline'` | Flags High-Severity unhashed script execution | **PASS** |
| **TC-15** | `phase2` | `matcher.py` | CSP Nonce Exemption Handling | `script-src 'unsafe-inline' 'nonce-xyz'` | `'unsafe-inline'` ignored per CSP Level 3 specification | **PASS** |
| **TC-16** | `phase2` | `matcher.py` | CSP Wildcard in `script-src` | `Content-Security-Policy: script-src *` | High-Severity arbitrary origin script execution finding | **PASS** |
| **TC-17** | `phase2` | `matcher.py` | CSP Wildcard in `default-src` | `default-src *; script-src 'self'` | Medium-Severity finding (scripts constrained, media open) | **PASS** |
| **TC-18** | `phase2` | `matcher.py` | HSTS Revocation Detection | `Strict-Transport-Security: max-age=0` | Flags High-Severity active policy revocation | **PASS** |
| **TC-19** | `phase2` | `matcher.py` | HSTS Preload Compliance Audit | `max-age=15552000` (6 Months) | Flags Low-Severity: below 1-year preload requirement | **PASS** |
| **TC-20** | `phase2` | `matcher.py` | Modern Clickjacking Equivalence | No XFO, but CSP has `frame-ancestors 'none'` | Suppresses missing XFO alert; recognizes modern compliance | **PASS** |
| **TC-21** | `phase2` | `matcher.py` | Referrer Policy `unsafe-url` Audit | `referrer-policy: unsafe-url` | Flags Medium-Severity finding (worse than header absence) | **PASS** |
| **TC-22** | `phase3` | `retirejs.py` | SemVer 4-Part Version Ordering | Compare `1.12.4` vs `1.9.0` | `SemVer('1.12.4') > SemVer('1.9.0') == True` | **PASS** |
| **TC-23** | `phase3` | `retirejs.py` | SemVer Pre-Release Tag Ordering | Compare `1.0.0-rc.2` vs `1.0.0-rc.10` | `SemVer('1.0.0-rc.2') < SemVer('1.0.0-rc.10') == True` | **PASS** |
| **TC-24** | `phase3` | `retirejs.py` | SemVer Build Metadata Exclusion | Compare `1.2.3+build` vs `1.2.3` | `SemVer('1.2.3+build') == SemVer('1.2.3') == True` | **PASS** |
| **TC-25** | `phase4` | `db_handler.py`| Audit Ledger Purge Execution | Dispatch POST to `/clear-history` | Deletes all rows; resets sequence; flash message returned | **PASS** |

---

### 5.3 Regression Analysis & Statement Coverage Metrics
Automated code coverage was evaluated using `pytest-cov`. The test suite achieved an aggregate statement coverage of **92.4%** across all production modules:

*Table 5.2: Test Execution Metrics and Code Statement Coverage by Module.*

| Module Filename | Total Statements | Missed Statements | Branch Coverage | Statement Coverage | Test Execution Time |
|---|:---:|:---:|:---:|:---:|:---:|
| `main.py` | 240 | 28 | 84.2% | **88.3%** | 0.22s |
| `scanner/extractor.py` | 215 | 14 | 89.1% | **93.5%** | 0.18s |
| `scanner/matcher.py` | 385 | 22 | 92.4% | **94.3%** | 0.12s |
| `scanner/retirejs.py` | 310 | 26 | 87.5% | **91.6%** | 0.11s |
| `scanner/reliability.py` | 165 | 9 | 94.0% | **94.5%** | 0.05s |
| `database/db_handler.py` | 115 | 8 | 90.0% | **93.0%** | 0.04s |
| `reporting/pdf_builder.py` | 50 | 5 | 82.0% | **90.0%** | 0.03s |
| **Cumulative Total** | **1,480** | **112** | **88.6%** | **92.4%** | **0.75s** |

---
\newpage

# CHAPTER 6: SYSTEM SECURITY & DEFENSE-IN-DEPTH

### 6.1 Scanner Threat Modeling & Adversarial Surface
Unlike standard web applications where input arrives from end-user HTTP parameters, a security scanner consumes input from **remote, potentially hostile third-party web servers**. When an analyst commands FrontGuard to scan `https://adversarial-target.com`, the remote server controls the response status codes, header names, header values, redirect locations, and HTML body contents.

Without defensive engineering, an adversary could weaponize the scanner using four attack vectors:
1. **Server-Side Request Forgery (SSRF):** Providing URLs that resolve to internal infrastructure (e.g. `http://169.254.169.254/latest/meta-data/` or `http://192.168.1.1:8080/admin`), tricking the scanner host into exfiltrating cloud credentials or mapping internal networks.
2. **Denial of Service via Decompression & Buffer Floods:** Returning infinite chunked HTTP streams or highly compressed gzip payloads ("zip bombs") that expand into gigabytes of data in scanner memory.
3. **Slowloris / Resource Tarpitting:** Emitting single response bytes at 5-second intervals, holding socket connections open indefinitely and exhausting the scanner's worker threads.
4. **Memory Leaks via Cache Poisoning:** Returning thousands of randomized script URLs with distinct version strings to exhaust system RAM through unbounded caching.

---

### 6.2 Pre-Flight SSRF Protection Architecture
FrontGuard implements a strict pre-flight DNS screening model. The network client never connects to a remote hostname without first interrogating DNS and validating the resulting IP address against private address blocks.

```python
import socket
import ipaddress

def is_private_ip(ip_str: str) -> bool:
    """
    Evaluates whether an IPv4 address belongs to non-routable, private,
    loopback, or cloud-infrastructure network blocks.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private or       # RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            ip.is_loopback or      # 127.0.0.0/8 (Localhost loopback interface)
            ip.is_link_local or    # 169.254.0.0/16 (AWS / GCP / Azure Instance Metadata)
            ip.is_reserved or      # IETF Special Purpose Reserved Space
            ip.is_multicast or     # 224.0.0.0/4 (Multicast network traffic)
            ip.is_unspecified      # 0.0.0.0
        )
    except ValueError:
        return False
```

#### Operational Workflow:
1. User supplies target string `http://169.254.169.254` or domain `internal.corp`.
2. `extractor.py` extracts the hostname and executes `socket.gethostbyname_ex(hostname)`.
3. If any resolved IP satisfies `is_private_ip(ip) == True`:
   - The scan terminates immediately.
   - Zero outbound TCP handshakes are dispatched.
   - High-severity finding `CWE-918: Server-Side Request Forgery (SSRF)` is recorded.
   - Diagnostic message returned: *"Target blocked for SSRF prevention (Resolved IP: X.X.X.X in private range)."*

---

### 6.3 Anti-DoS & Streaming Memory Bounds
To prevent decompression bombs and memory exhaustion, FrontGuard prohibits monolithic reads (such as `requests.get().text`). Instead, all network reads are streamed in fixed 8192-byte chunks with an unyielding counter:

```python
MAX_HTML_BYTES = 512 * 1024  # 512 KB hard streaming ceiling
html_chunks = []
total_len = 0
html_truncated = False

try:
    for chunk in resp.iter_content(chunk_size=8192):
        if chunk:
            html_chunks.append(chunk)
            total_len += len(chunk)
            if total_len >= MAX_HTML_BYTES:
                html_truncated = True
                break  # Hard termination: closes raw socket connection immediately
    raw_bytes = b''.join(html_chunks)
    html_text = raw_bytes.decode('utf-8', errors='ignore')
except Exception:
    html_text = getattr(resp, 'text', '')
```
Similarly, external JavaScript files fetched during Software Composition Analysis are capped at **256 KB** per file, ensuring that multi-megabyte minified bundles cannot exhaust memory.

---

### 6.4 Monotonic Wall-Clock Scan Budget Enforcement
Adversarial servers may implement "tarpitting" (transmitting HTTP headers or body bytes at fractional rates, such as 1 byte every 4 seconds) to keep connections alive while exhausting scanner execution threads.

FrontGuard neutralizes this using the `ScanBudget` class. Unlike `time.time()` (which is vulnerable to NTP clock updates or system time manipulation), `ScanBudget` relies exclusively on `time.monotonic()`:

```python
import time

class ScanBudget:
    """Enforces a strict 45.0-second monotonic wall-clock deadline."""
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
        """Dynamically scales socket timeouts to never exceed the deadline."""
        rem = self.remaining()
        return (min(connect, rem * 0.4), min(read, rem * 0.6))
```

---

### 6.5 WAF & Bot Challenge Detection Engine
When a scanned web endpoint is fronted by a Web Application Firewall (WAF) or anti-bot challenge (such as Cloudflare Turnstile, AWS WAF, or Imperva Incapsula), the server returns an interstitial challenge screen rather than the actual web application.

If analyzed naively, a scanner will audit Cloudflare's challenge page, attributing Cloudflare's headers and inline scripts to the target organization and generating false alerts.

FrontGuard solves this via the `detect_waf_or_block()` subsystem:
1. **HTTP Status Code Inspection:** Checks for 403 (Forbidden), 406 (Not Acceptable), 429 (Rate Limited), and 503 (Service Unavailable).
2. **WAF Header Markers:** Inspects for `cf-mitigated`, `x-amzn-waf-action`, `x-akamai-edgescape`, and `x-cdn: imperva`.
3. **Challenge Body Signatures:** Searches the first 8192 bytes for markers: `'just a moment'`, `'please wait while we verify'`, `'_cf_chl_'`, `'g-recaptcha'`, and `'ddos-guard'`.

When detected, the scan status is marked `BLOCKED`. Origin checks are quarantined, and an informational diagnostic finding is emitted: *"Target Access Blocked or WAF Challenge Detected."*

---

### 6.6 Thread-Safe LRU-TTL Cache Management
To prevent memory leaks across long running periods, FrontGuard's `BoundedTTLCache` pairs capacity bounds with time-to-live eviction:
- **Maximum Size:** 256 entries (evicts oldest item via `popitem(last=False)` upon overflow).
- **Time-to-Live (TTL):** 3600.0 seconds (1 hour).
- **Concurrency Protection:** Wraps all dictionary mutations within a `threading.Lock()` mutex context.
- **Result:** Memory consumption remains flat ($< 50\text{ MB}$ RAM) indefinitely, even across thousands of continuous scans.

---
\newpage

# CHAPTER 7: COST ESTIMATION & ECONOMIC ANALYSIS

### 7.1 Software Engineering Effort Valuation (COCOMO II Model)
To establish the formal academic and commercial valuation of the FrontGuard system, the **Constructive Cost Model (COCOMO II)** was applied. COCOMO II is an industry-standard algorithmic software cost estimation model developed by Dr. Barry Boehm.

#### 1. Codebase Sizing
The codebase size was measured across production Python modules, templates, and database schemas:
- `main.py`: 435 SLOC
- `scanner/extractor.py`: 413 SLOC
- `scanner/matcher.py`: 1,055 SLOC
- `scanner/retirejs.py`: 1,541 SLOC
- `scanner/reliability.py`: 297 SLOC
- `database/db_handler.py`: 287 SLOC
- `reporting/pdf_builder.py`: 639 SLOC
- **Total Production Codebase:** **4,667 Source Lines of Code (SLOC)**
- **Effective Size ($KSLOC$):** **$4.67\text{ KSLOC}$**

#### 2. COCOMO II Effort Equation
The effort equation for an organic software project is expressed as:
$$\text{Effort (Person-Months)} = A \times (\text{KSLOC})^B \times \prod_{i=1}^{17} \text{EM}_i$$

Where:
- Baseline constant $A = 2.94$
- Scaling exponent $B = 1.05$ (Organic development mode)
- Effort Multiplier Product ($\prod \text{EM} = 1.12$, accounting for high reliability constraints `RELY = 1.10`, execution time constraints `TIME = 1.11`, and tool use `TOOL = 0.92`).

$$\text{Effort} = 2.94 \times (4.67)^{1.05} \times 1.12$$
$$(4.67)^{1.05} \approx 5.03$$
$$\text{Effort} = 2.94 \times 5.03 \times 1.12 \approx \mathbf{16.56\text{ Person-Months (PM)}}$$

#### 3. Development Schedule ($TDEV$) Equation
The nominal development time in calendar months is calculated using:
$$TDEV = C \times (\text{Effort})^D$$
Where $C = 2.5$ and $D = 0.38$:
$$TDEV = 2.5 \times (16.56)^{0.38}$$
$$(16.56)^{0.38} \approx 2.91$$
$$TDEV = 2.5 \times 2.91 \approx \mathbf{7.28\text{ Calendar Months}}$$

#### 4. Commercial Engineering Labor Valuation
Applying the prevailing market rate for specialized cybersecurity Python software engineers:
- **Standard Industry Rate:** \$35.00 / Hour (₹2,900 INR / Hour).
- **Logged Engineering Hours:** 170 Development Hours.
- **Direct Labor Valuation:**
  $$\text{Direct Labor Cost} = 170\text{ Hours} \times \$35.00 = \mathbf{\$5,950.00\text{ USD}}\quad (\approx \mathbf{\text{₹}4,95,000\text{ INR}})$$

*Table 7.1: COCOMO II Cost Estimation Modeling Parameters and Calculations.*

| Model Parameter | Parameter Description | Assigned Value | Technical Justification |
|---|---|:---:|---|
| **$KSLOC$** | Thousands of Source Lines of Code | `4.67` | Physical lines of code across all production modules |
| **$A$** | Base Effort Multiplier Constant | `2.94` | Standard COCOMO II calibrated constant |
| **$B$** | Scale Factor Exponent | `1.05` | Organic project mode (small team, familiar domain) |
| **$\text{EM}_{\text{RELY}}$** | Required Software Reliability | `1.10` | High consequence of false negatives in security auditing |
| **$\text{EM}_{\text{TIME}}$** | Execution Time Constraint | `1.11` | Strict 45.0s budget ceiling and sub-second tests |
| **$\text{EM}_{\text{TOOL}}$** | Modern Software Tool Usage | `0.92` | Advanced IDEs, Pytest automation, Git version control |
| **$\text{Effort}$**| Cumulative Engineering Effort | **`16.56 PM`**| Total estimated professional person-months |
| **$TDEV$** | Estimated Development Schedule | **`7.28 Mos`**| Nominal calendar delivery schedule |
| **Valuation** | Total Economic Labor Value | **`$5,950.00`**| Direct equivalent engineering market valuation |

---

### 7.2 Total Cost of Ownership (TCO) vs. Commercial Alternatives
To demonstrate the economic advantage of deploying FrontGuard, a 3-Year Total Cost of Ownership (TCO) model was constructed comparing FrontGuard against leading commercial enterprise scanning solutions:

*Table 7.2: 3-Year Total Cost of Ownership (TCO) Comparison.*

| Cost Category | FrontGuard (Self-Hosted / Cloud Free-Tier) | Commercial SaaS DAST (Snyk / Veracode / Burp) |
|---|:---:|:---:|
| **Initial Software Licensing** | **\$0.00** (Open Source) | \$5,000 – \$15,000 upfront |
| **Annual Subscription (Years 1–3)** | **\$0.00** | \$15,000 – \$45,000 cumulative |
| **Compute / Hosting Infrastructure** | **\$0.00** (Oracle Cloud Always Free Tier) | Bundled or \$1,200/yr for scanner runners |
| **Maintenance & Support Contracts** | **\$0.00** (Community Maintained) | \$2,500/year premium support |
| **Per-Scan / Per-Target Overage Fees**| **\$0.00** (Unlimited scans) | \$500 per additional target domain |
| **3-Year Cumulative TCO** | **\$0.00** | **\$22,500 – \$62,500 USD** |
| **Net Institutional Savings** | — | **\$22,500+ Saved** |

---
\newpage

# CHAPTER 8: REPORTING & TELEMETRY ARCHITECTURE

### 8.1 Web Presentation & UI Design System
The FrontGuard web interface (`templates/index.html`, `templates/result.html`, `static/style.css`) is engineered following an **Utilitarian Security Cockpit** philosophy. It rejects decorative animations, heavy graphics, and ambiguous gradients, prioritizing high information density, clear visual hierarchies, and instantaneous cognitive recognition.

#### Design Tokens & Architecture:
- **Color Palette:**
  - Base Canvas: `--bs-body-bg: #090a0d` (Deep Charcoal)
  - Card Surfaces: `--bs-card-bg: #111318` (Neutral Slate)
  - Layout Borders: `--bs-border-color: #232733` (Subtle Gridlines)
  - Accent Color: `#3b82f6` (Single reserved primary blue utilized exclusively for the "Initiate Scan" action button)
- **High-Contrast Severity Badges:**
  - Critical / High: `#dc2626` (Pure Red) — reserved strictly for exploitable vulnerabilities.
  - Medium: `#ea580c` (Pure Orange) — applied to significant misconfigurations.
  - Low / Info: `#0284c7` / `#1e2330` (Muted Blue / Slate) — informational telemetry.
- **Component Hierarchy:**
  1. **Top Header:** Clean branding bar displaying the uppercase title `FRONTGUARD`.
  2. **Telemetry Dossier:** High-visibility tabular card displaying Target Host, Resolved Public IPv4 addresses, UTC execution timestamp, and overall computed Risk Badge.
  3. **Categorized Findings Cards:** Distinct collapsible cards separating HTTP Security Headers, Client-Side JavaScript Components, and Inline Credentials.
  4. **Audit Ledger:** Chronological historical table rendered from SQLite with instantaneous "View Report" and "Clear History" controls.

---

### 8.2 Typographic Two-Pass ReportLab PDF Engine
The automated PDF synthesis module (`reporting/pdf_builder.py`) builds enterprise-grade, printable security audit reports using ReportLab's low-level Flowable architecture.

#### Technical Specifications:
- **Page Geometry:** ISO standard A4 paper dimensions ($210 \times 297\text{ mm}$) with $13\text{ mm}$ side margins, yielding an exact printable width of $184\text{ mm}$.
- **Two-Pass NumberedCanvas:** ReportLab's standard canvas renders pages sequentially. Because total page counts cannot be determined until document completion, FrontGuard implements `NumberedCanvas`, intercepting `showPage()` and `save()` to compute total pages in memory and draw dynamic footers on the second pass:
  ```python
  class NumberedCanvas(canvas.Canvas):
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

#### PDF Document Structure:
1. **Title Header Banner:** Formatted in Dark Navy (`#0f172a`), presenting the formal title "TECHNICAL SECURITY AUDIT REPORT", Target URL, Resolved IP, and Timestamp.
2. **Executive Summary Scorecard:** High-contrast summary table tabulating total findings across Critical, High, Medium, Low, and Info severity tiers.
3. **Structured Finding Blocks:** Each identified issue is enclosed within a bordered flowable table containing:
   - Vulnerability Title & Type
   - Severity Badge with Hex-matched background tint
   - CVSS v3.1 Base Score & Standardized CWE Reference ID (e.g., `CWE-693`, `CWE-798`, `CWE-319`)
   - Attack Prevented Technical Rationale
   - Observed Raw Evidence Snippet
   - Step-by-Step Technical Remediation Directive

---
\newpage

# CHAPTER 9: FUTURE SCOPE & RESEARCH ROADMAP

While FrontGuard delivers a comprehensive, production-ready passive auditing solution, several architectural enhancements are planned for future research and engineering releases:

### 9.1 Headless Browser & Client-Side SPA Execution
- **Current Limitation:** FrontGuard parses raw HTML returned from initial HTTP GET requests. Single Page Applications (SPAs) built with React, Angular, or Vue often deliver empty `<div id="root"></div>` shells, loading components and script tags dynamically during client-side hydration.
- **Future Architecture:** Integrate a headless browser automation engine (such as Microsoft Playwright or Puppeteer). The scanner will instantiate a lightweight headless Chromium container, execute initial JavaScript bundles, wait for DOM network idle state, and inspect the hydrated DOM tree to discover dynamically injected scripts and iframe sinks.

### 9.2 Authenticated State & Contextual Ingress
- **Current Limitation:** Audits are restricted to public, unauthenticated landing perimeters.
- **Future Architecture:** Implement an authenticated session ingestion subsystem. Auditors will be able to supply session cookies, HTTP Bearer tokens, or configure automated login macro scripts (form authentication or OAuth2 flows). This will allow FrontGuard to passively audit authenticated enterprise dashboards, administrative panels, and internal portals.

### 9.3 CI/CD DevSecOps Automation
- **Current Limitation:** Invoked manually via web dashboard or standalone CLI.
- **Future Architecture:** Package FrontGuard into an official **GitHub Action** and containerized GitLab CI runner. Software engineering teams will be able to embed FrontGuard directly into deployment pipelines:
  ```yaml
  - name: FrontGuard Security Quality Gate
    uses: Rahul-Raj-V-K/frontguard-action@v1
    with:
      target-url: 'https://staging.internal.corp'
      fail-on-severity: 'high'
  ```
  The pipeline will automatically fail pull requests if high-severity CVEs or missing security headers are detected.

### 9.4 Passive Subdomain Discovery & Certificate Transparency
- **Current Limitation:** Audits single hostnames supplied at runtime.
- **Future Architecture:** Integrate passive Certificate Transparency (CT) log stream interrogation (via `crt.sh`). When an analyst inputs an apex domain (e.g., `example.com`), FrontGuard will passively enumerate all valid subdomains (`api.example.com`, `admin.example.com`, `mail.example.com`) and audit the entire organizational perimeter concurrently.

### 9.5 Enterprise SIEM Integration
- **Current Limitation:** Findings are logged to local SQLite and PDF reports.
- **Future Architecture:** Develop automated output emitters for Common Event Format (CEF), Syslog, and JSON webhooks. This will permit direct streaming of discovered vulnerabilities into enterprise Security Information and Event Management (SIEM) systems including Splunk, Elastic Security, and Microsoft Sentinel.

---
\newpage

# CHAPTER 10: APPENDICES

### 10.1 Core Python Implementation Code Listings

#### Listing 1: 4-Part Semantic Version Engine (`scanner/retirejs.py`)
```python
import re

class SemVer:
    """
    Custom 4-part semantic version parser with numeric pre-release support.
    Precedence rules:
      1. Numeric segments compare numerically (1.9.0 < 1.12.0).
      2. Pre-release tags have lower precedence than final release (1.12.4-rc.1 < 1.12.4).
      3. Pre-release numeric segments compare numerically (rc.2 < rc.10).
      4. Build metadata (+build) is ignored for precedence comparisons.
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
            for token in re.split(r'[.-]', pre_part):
                if not token:
                    continue
                for sp in re.findall(r'[a-zA-Z]+|\d+', token):
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
        if self.prerelease is None and other.prerelease is None:
            return False
        if self.prerelease is not None and other.prerelease is None:
            return True
        if self.prerelease is None and other.prerelease is not None:
            return False
        return self.prerelease < other.prerelease

    def __eq__(self, other):
        if not isinstance(other, SemVer):
            other = SemVer(other)
        if not self.is_valid or not other.is_valid:
            return False
        return self.parts == other.parts and self.prerelease == other.prerelease
```

#### Listing 2: CSP Directive Tokenizer (`scanner/matcher.py`)
```python
def _parse_csp_directives(csp_value: str) -> dict[str, list[str]]:
    """
    Tokenizes raw Content-Security-Policy strings into structured directive maps.
    Example: "default-src 'self'; script-src 'unsafe-inline' cdn.com"
      -> {'default-src': ["'self'"], 'script-src': ["'unsafe-inline'", 'cdn.com']}
    """
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

#### Listing 3: Pre-Flight SSRF Guard (`scanner/reliability.py`)
```python
import ipaddress

def is_private_ip(ip_str: str) -> bool:
    """Evaluates whether an IP address belongs to non-routable private ranges."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private or       # RFC 1918 (10/8, 172.16/12, 192.168/16)
            ip.is_loopback or      # 127.0.0.0/8
            ip.is_link_local or    # 169.254.0.0/16
            ip.is_reserved or      # IETF reserved
            ip.is_multicast or     # 224.0.0.0/4
            ip.is_unspecified      # 0.0.0.0
        )
    except ValueError:
        return False
```

#### Listing 4: Monotonic ScanBudget Enforcer (`scanner/reliability.py`)
```python
import time

class ScanBudget:
    """Enforces strict monotonic wall-clock deadlines across all scan actions."""
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

#### Listing 5: Thread-Safe Bounded TTL Cache (`scanner/reliability.py`)
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

---

### 10.2 Academic & Industry Bibliography
1. **Hodges, J., Jackson, C., and Barth, A.:** *"HTTP Strict Transport Security (HSTS)"*, Internet Engineering Task Force (IETF), Standards Track RFC 6797, November 2012. URL: https://datatracker.ietf.org/doc/html/rfc6797
2. **Ross, D. and Gondwana, B.:** *"HTTP Header Field X-Frame-Options"*, Internet Engineering Task Force (IETF), Informational RFC 7034, October 2013. URL: https://datatracker.ietf.org/doc/html/rfc7034
3. **West, M., Barth, A., and Veditz, D.:** *"Content Security Policy Level 3 Specification"*, World Wide Web Consortium (W3C) Working Draft, September 2023. URL: https://www.w3.org/TR/CSP3/
4. **OWASP Foundation:** *"OWASP Top 10:2021 – The Ten Most Critical Web Application Security Risks: A05:2021 Security Misconfiguration"*, Open Web Application Security Project, 2021. URL: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
5. **OWASP Foundation:** *"OWASP Top 10:2021 – The Ten Most Critical Web Application Security Risks: A06:2021 Vulnerable and Outdated Components"*, Open Web Application Security Project, 2021. URL: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
6. **MITRE Corporation:** *"Common Weakness Enumeration: CWE-693 Protection Mechanism Failure"*, National Vulnerability Database, 2024. URL: https://cwe.mitre.org/data/definitions/693.html
7. **MITRE Corporation:** *"Common Weakness Enumeration: CWE-918 Server-Side Request Forgery (SSRF)"*, National Vulnerability Database, 2024. URL: https://cwe.mitre.org/data/definitions/918.html
8. **MITRE Corporation:** *"Common Weakness Enumeration: CWE-798 Use of Hard-coded Credentials"*, National Vulnerability Database, 2024. URL: https://cwe.mitre.org/data/definitions/798.html
9. **MITRE Corporation:** *"Common Weakness Enumeration: CWE-1021 Improper Restriction of Rendered UI Layers"*, National Vulnerability Database, 2024. URL: https://cwe.mitre.org/data/definitions/1021.html
10. **Google Open Source Security Team:** *"Open Source Vulnerabilities (OSV) Schema and Query API Specification v1.5"*, Open Source Security Foundation (OpenSSF), 2024. URL: https://osv.dev/docs/
11. **Oftedal, E.:** *"Retire.js: What you require you must also retire – Detecting JavaScript libraries with known vulnerabilities"*, 2024. URL: https://github.com/RetireJS/retire.js
12. **ReportLab Europe Ltd.:** *"ReportLab PDF Generation User Guide (Version 4.2)"*, ReportLab Europe, London, UK, 2024. URL: https://www.reportlab.com/docs/reportlab-userguide.pdf
13. **Pallets Projects:** *"Flask Web Framework Documentation (Release 3.0.x)"*, Pallets Community, 2024. URL: https://flask.palletsprojects.com/
14. **Boehm, B., Abts, C., Brown, A. W., Chulani, S., Clark, B. K., Horowitz, E., Madachy, R., Reifer, D., and Steece, B.:** *"Software Cost Estimation with COCOMO II"*, Prentice Hall PTR, Upper Saddle River, NJ, 2000.
15. **FIRST (Forum of Incident Response and Security Teams):** *"Common Vulnerability Scoring System v3.1: Specification Document"*, FIRST.Org, Inc., 2019. URL: https://www.first.org/cvss/v3.1/specification-document
16. **Mozilla Developer Network (MDN):** *"HTTP Headers: Content-Security-Policy Directives and Source Expressions"*, MDN Web Docs, 2026. URL: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
