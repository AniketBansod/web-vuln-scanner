# scanner/analyzer.py
from scanner import signatures
from difflib import SequenceMatcher

def analyze_security_headers(url: str, response) -> list:
    """Check basic security headers on a response. Returns list of findings dicts.
    This is informational to help assess baseline security posture.
    """
    findings = []
    if response is None:
        return findings
    headers = {k.lower(): v for k, v in (response.headers or {}).items()}

    def missing(name: str) -> bool:
        return name.lower() not in headers or not headers.get(name.lower())

    # Content Security Policy
    if missing("Content-Security-Policy"):
        findings.append({
            "type": "Header-Missing",
            "header": "Content-Security-Policy",
            "url": url,
            "evidence": "No Content-Security-Policy header present"
        })
    # X-Frame-Options
    if missing("X-Frame-Options"):
        findings.append({
            "type": "Header-Missing",
            "header": "X-Frame-Options",
            "url": url,
            "evidence": "No X-Frame-Options header present"
        })
    # X-Content-Type-Options
    if missing("X-Content-Type-Options"):
        findings.append({
            "type": "Header-Missing",
            "header": "X-Content-Type-Options",
            "url": url,
            "evidence": "No X-Content-Type-Options header present"
        })
    # Referrer-Policy
    if missing("Referrer-Policy"):
        findings.append({
            "type": "Header-Missing",
            "header": "Referrer-Policy",
            "url": url,
            "evidence": "No Referrer-Policy header present"
        })
    # Permissions-Policy
    if missing("Permissions-Policy"):
        findings.append({
            "type": "Header-Missing",
            "header": "Permissions-Policy",
            "url": url,
            "evidence": "No Permissions-Policy header present"
        })
    # Strict-Transport-Security (only meaningful over https)
    try:
        scheme = getattr(response.request, 'url', url)
        if isinstance(scheme, str) and scheme.lower().startswith('https'):
            if missing("Strict-Transport-Security"):
                findings.append({
                    "type": "Header-Missing",
                    "header": "Strict-Transport-Security",
                    "url": url,
                    "evidence": "No HSTS header present on HTTPS response"
                })
    except Exception:
        pass
    return findings

def detect_sql_error(text: str):
    """Return (bool, match_str)"""
    if not text:
        return False, None
    m = signatures.SQL_ERRORS_RE.search(text)
    if m:
        return True, m.group(0)
    return False, None

def detect_reflected_payload(response_text: str, payload: str) -> bool:
    """Simple reflection check: payload appears verbatim in response body."""
    if not response_text or not payload:
        return False
    return payload in response_text

def response_similarity(a: str, b: str) -> float:
    """Return ratio 0..1 of similarity (higher=more similar)."""
    if a is None or b is None:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()
