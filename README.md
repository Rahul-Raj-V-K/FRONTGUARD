# MCA Web Vulnerability Scanner Project

A passive web application security scanner implementing:
- HTTP Security Header Auditing (CSP, HSTS, XFO, XCTO, Referrer-Policy, COOP, CORP, COEP)
- Client-Side JavaScript Software Composition Analysis (Retire.js & OSV.dev)
- Enterprise PDF Audit Report Generation

## Quickstart

```powershell
cd web_vuln_scanner
pip install -r requirements.txt
python main.py
```

## Running Tests

```powershell
python -m pytest web_vuln_scanner --tb=short -q
```
All **160 tests pass** across Phase 2, Phase 3, and Phase 4.

See detailed documentation in [web_vuln_scanner/README.md](web_vuln_scanner/README.md) and [web_vuln_scanner/TESTING.md](web_vuln_scanner/TESTING.md).
