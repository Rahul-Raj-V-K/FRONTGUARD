CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url      TEXT    NOT NULL,
    target_ip       TEXT    DEFAULT 'N/A',
    scan_date       TEXT    NOT NULL,
    findings_count  INTEGER NOT NULL DEFAULT 0,
    risk_level      TEXT    NOT NULL DEFAULT 'unknown',
    pdf_path        TEXT
);

CREATE TABLE IF NOT EXISTS vulnerability_rules (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_key           VARCHAR(100) UNIQUE NOT NULL,
    name               VARCHAR(200) NOT NULL,
    severity           VARCHAR(20)  NOT NULL DEFAULT 'info',
    description        TEXT,
    ref_id             VARCHAR(50),
    cve_id             VARCHAR(50),
    cvss_score         FLOAT,
    reference_link     VARCHAR(500),
    remediation_steps  TEXT
);
