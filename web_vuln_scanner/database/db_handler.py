import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'scanner.db')
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'schema.sql')

DEFAULT_RULES = [
    # WHY: Missing security headers are misconfigurations, not CVEs.
    # We now reference CWE IDs and OWASP A05:2021 (Security Misconfiguration)
    # instead of unrelated CVE numbers that confused enrichment lookups.
    (
        'content-security-policy',
        'Missing Content-Security-Policy',
        'high',
        'Content-Security-Policy header is missing, exposing the application to cross-site scripting (XSS) and data injection attacks.',
        'CWE-693',          # Protection Mechanism Failure
        7.5,
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
        "Define and enforce a restrictive Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'."
    ),
    (
        'strict-transport-security',
        'Missing Strict-Transport-Security (HSTS)',
        'high',
        'HSTS header is missing, allowing SSL-stripping and man-in-the-middle downgrade attacks.',
        'CWE-319',          # Cleartext Transmission of Sensitive Information
        7.4,
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
        'Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
    ),
    (
        'x-frame-options',
        'Missing X-Frame-Options',
        'medium',
        'X-Frame-Options header is absent and CSP frame-ancestors is not set; page can be embedded in iframes for clickjacking.',
        'CWE-1021',         # Improper Restriction of Rendered UI Layers
        5.4,
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
        "Set X-Frame-Options: DENY, or add frame-ancestors 'none' to your CSP (preferred)."
    ),
    (
        'x-content-type-options',
        'Missing X-Content-Type-Options',
        'low',
        'Without nosniff, browsers may MIME-sniff responses and execute scripts served as text/plain.',
        'CWE-693',
        4.3,
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
        'Set X-Content-Type-Options: nosniff on all HTTP responses.'
    ),
    (
        'referrer-policy',
        'Missing Referrer-Policy',
        'low',
        'Referrer-Policy header is missing. Sensitive URL parameters may leak to third-party domains via HTTP Referer.',
        'CWE-200',          # Exposure of Sensitive Information
        4.0,
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
        'Set Referrer-Policy: strict-origin-when-cross-origin'
    ),
    (
        'permissions-policy',
        'Missing Permissions-Policy',
        'low',
        'Permissions-Policy header is missing; sensitive browser features (camera, mic, geolocation) are unrestricted.',
        'CWE-693',
        3.5,
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
        'Set Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()'
    ),
    (
        'x-powered-by',
        'Information Disclosure: X-Powered-By',
        'medium',
        'X-Powered-By header discloses underlying framework and version, aiding fingerprinting.',
        'CWE-200',
        5.3,
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Server',
        'Remove X-Powered-By in your framework or reverse proxy config.'
    ),
    (
        'server',
        'Information Disclosure: Server Version',
        'low',
        'Server header discloses web server software and version, aiding targeted exploitation.',
        'CWE-200',
        4.0,
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
        'Suppress or sanitize the Server header; at minimum, strip version numbers.'
    ),
    (
        'exposed_api_key',
        'Exposed API Key',
        'critical',
        'Potential API key found embedded in client-side code or scripts.',
        'CWE-798',          # Use of Hard-coded Credentials
        8.5,
        'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
        'Revoke the exposed key immediately, regenerate credentials, and store secrets server-side in environment variables.'
    ),
    (
        'hardcoded_secret',
        'Hardcoded Secret or Password',
        'critical',
        'Hardcoded password or secret string detected in scripts or comments.',
        'CWE-798',
        9.8,
        'https://cwe.mitre.org/data/definitions/798.html',
        'Remove credential from codebase, rotate affected secrets, and adopt a secret manager (e.g., Vault, AWS Secrets Manager).'
    )
]


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
        schema_sql = f.read()

    conn = _connect()
    conn.executescript(schema_sql)

    cur = conn.cursor()
    cur.execute("PRAGMA table_info(scan_history)")
    scan_cols = [row['name'] for row in cur.fetchall()]
    if 'target_ip' not in scan_cols:
        conn.execute("ALTER TABLE scan_history ADD COLUMN target_ip TEXT DEFAULT 'N/A'")

    cur.execute("PRAGMA table_info(vulnerability_rules)")
    rule_cols = [row['name'] for row in cur.fetchall()]
    needed_cols = [
        ('ref_id', 'VARCHAR(50)'),
        ('cve_id', 'VARCHAR(50)'),
        ('cvss_score', 'FLOAT'),
        ('reference_link', 'VARCHAR(500)'),
        ('remediation_steps', 'TEXT')
    ]
    for col_name, col_type in needed_cols:
        if col_name not in rule_cols:
            conn.execute(f"ALTER TABLE vulnerability_rules ADD COLUMN {col_name} {col_type}")

    # Data Migration: synchronize ref_id and ensure CWE values are never stored in cve_id.
    conn.execute("UPDATE vulnerability_rules SET ref_id = cve_id WHERE ref_id IS NULL AND cve_id IS NOT NULL")
    conn.execute("UPDATE vulnerability_rules SET cve_id = NULL WHERE cve_id LIKE 'CWE-%'")

    for r in DEFAULT_RULES:
        rule_key = r[0]
        name = r[1]
        severity = r[2]
        description = r[3]
        ref_id = r[4]
        cve_id = None if str(r[4]).startswith('CWE-') else r[4]
        cvss_score = r[5]
        reference_link = r[6]
        remediation_steps = r[7]
        conn.execute(
            """
            INSERT INTO vulnerability_rules
            (rule_key, name, severity, description, ref_id, cve_id, cvss_score, reference_link, remediation_steps)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rule_key) DO UPDATE SET
                name = excluded.name,
                severity = excluded.severity,
                description = excluded.description,
                ref_id = excluded.ref_id,
                cve_id = excluded.cve_id,
                cvss_score = excluded.cvss_score,
                reference_link = excluded.reference_link,
                remediation_steps = excluded.remediation_steps
            """,
            (rule_key, name, severity, description, ref_id, cve_id, cvss_score, reference_link, remediation_steps)
        )

    conn.commit()
    conn.close()


def insert_scan_record(target_url: str, findings_count: int,
                       risk_level: str, pdf_path: str, target_ip: str = 'N/A') -> int:
    scan_date = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    conn = _connect()
    cur = conn.execute(
        """
        INSERT INTO scan_history (target_url, target_ip, scan_date, findings_count, risk_level, pdf_path)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (target_url, target_ip or 'N/A', scan_date, findings_count, risk_level, pdf_path)
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def get_scan_history() -> list[dict]:
    conn = _connect()
    rows = conn.execute("SELECT * FROM scan_history ORDER BY scan_date DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_vulnerability_rule(identifier: str) -> dict | None:
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM vulnerability_rules WHERE rule_key = ? OR name = ? LIMIT 1",
        (identifier, identifier)
    )
    row = cur.fetchone()
    if not row:
        cur.execute(
            """
            SELECT * FROM vulnerability_rules
            WHERE ? LIKE '%' || rule_key || '%' OR ? LIKE '%' || name || '%'
            LIMIT 1
            """,
            (identifier, identifier)
        )
        row = cur.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if not d.get('ref_id') and d.get('cve_id'):
        d['ref_id'] = d['cve_id']
    if d.get('cve_id') and str(d['cve_id']).startswith('CWE-'):
        if not d.get('ref_id'):
            d['ref_id'] = d['cve_id']
        d['cve_id'] = None
    return d


def upsert_vulnerability_rule(rule_key: str, name: str, severity: str,
                              description: str = '', cve_id: str = None,
                              cvss_score: float = None, reference_link: str = None,
                              remediation_steps: str = None) -> int:
    conn = _connect()
    cur = conn.execute(
        """
        INSERT INTO vulnerability_rules
        (rule_key, name, severity, description, cve_id, cvss_score, reference_link, remediation_steps)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(rule_key) DO UPDATE SET
            name = excluded.name,
            severity = excluded.severity,
            description = excluded.description,
            cve_id = excluded.cve_id,
            cvss_score = excluded.cvss_score,
            reference_link = excluded.reference_link,
            remediation_steps = excluded.remediation_steps
        """,
        (rule_key, name, severity, description, cve_id, cvss_score, reference_link, remediation_steps)
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def get_all_vulnerability_rules() -> list[dict]:
    conn = _connect()
    rows = conn.execute("SELECT * FROM vulnerability_rules ORDER BY id ASC").fetchall()
    conn.close()
    return [dict(row) for row in rows]
