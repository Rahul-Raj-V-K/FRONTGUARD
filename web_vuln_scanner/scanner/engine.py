import urllib3
from scanner.extractor import extract_target_data
from scanner.matcher import run_all_checks

# Suppress SSL warnings for targets with self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEVERITY_WEIGHTS = {
    'critical': 40,
    'high': 20,
    'medium': 10,
    'low': 5,
    'info': 1,
}

# Ordered high-to-low — first match wins
RISK_LABELS = [
    (60, 'critical'),
    (30, 'high'),
    (10, 'medium'),
    (1,  'low'),
    (0,  'info'),
]


def calculate_risk_score(findings: list[dict]) -> int:
    score = sum(SEVERITY_WEIGHTS.get(f['severity'], 0) for f in findings)
    return min(score, 100)


def score_to_level(score: int) -> str:
    for threshold, label in RISK_LABELS:
        if score >= threshold:
            return label
    return 'info'


def run_scan(target_url: str) -> dict:
    """
    Pure orchestration — fetch, extract, match, score.
    Returns a result dict with status, findings list, risk_score, and risk_level.
    """
    data = extract_target_data(target_url)

    # Treat empty headers as connection failure
    if not data.get('headers'):
        return {
            'status': 'failed',
            'error': 'Could not reach target (timeout or connection error)',
            'target_url': target_url,
            'target_ip': data.get('target_ip', 'N/A')
        }

    findings = run_all_checks(
        raw_headers=data['headers'],
        script_srcs=data.get('script_srcs', []),
        inline_scripts=data.get('inline_scripts', []),
        base_url=target_url,
        comments=data.get('comments', []),
        forms=data.get('forms', [])
    )

    risk_score = calculate_risk_score(findings)

    return {
        'status': 'complete',
        'target_url': target_url,
        'target_ip': data.get('target_ip', 'N/A'),
        'findings': findings,
        'total_findings': len(findings),
        'risk_score': risk_score,
        'risk_level': score_to_level(risk_score),
    }
