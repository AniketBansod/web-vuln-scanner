# scanner/form_tester.py
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode
from scanner import signatures
from scanner.analyzer import detect_reflected_payload, detect_sql_error
import requests

HEADERS = {"User-Agent": "VulnScanner/0.1 (+https://example.com)"}

def extract_forms(html: str, base_url: str):
    """Return a list of forms with resolved actions and inputs."""
    soup = BeautifulSoup(html or "", "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "get").lower()
        inputs = {}
        # gather inputs, textareas and selects
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            # default values or empty
            value = inp.get("value") or ""
            inputs[name] = value
        forms.append({"action": urljoin(base_url, action), "method": method, "inputs": inputs})
    return forms

def test_single_form(session, form: dict, timeout: int = 10):
    """Test one form and return list of findings discovered."""
    findings = []
    for param in list(form["inputs"].keys()):
        orig = form["inputs"].get(param, "")
        # SQL payloads
        for payload in signatures.SQL_PAYLOADS:
            data = form["inputs"].copy()
            data[param] = orig + payload
            try:
                if form["method"] == "post":
                    resp = session.post(form["action"], data=data, timeout=timeout)
                else:
                    qs = urlencode(data)
                    resp = session.get(form["action"] + "?" + qs, timeout=timeout)
            except Exception:
                resp = None
            body = resp.text if resp else ""
            found, evidence = detect_sql_error(body)
            if found:
                findings.append({
                    "type": "SQLi-form",
                    "action": form["action"],
                    "param": param,
                    "payload": payload,
                    "evidence": evidence
                })
        # XSS payloads
        for payload in signatures.XSS_PAYLOADS:
            data = form["inputs"].copy()
            data[param] = orig + payload
            try:
                if form["method"] == "post":
                    resp = session.post(form["action"], data=data, timeout=timeout)
                else:
                    qs = urlencode(data)
                    resp = session.get(form["action"] + "?" + qs, timeout=timeout)
            except Exception:
                resp = None
            body = resp.text if resp else ""
            if detect_reflected_payload(body, payload):
                findings.append({
                    "type": "XSS-form",
                    "action": form["action"],
                    "param": param,
                    "payload": payload,
                    "evidence": "payload reflected in response"
                })
    return findings

def test_forms_on_page(session, page_url: str, timeout: int = 10):
    """Fetch page_url, parse forms, test them and return findings list."""
    findings = []
    try:
        r = session.get(page_url, headers=HEADERS, timeout=timeout)
        html = r.text if r else ""
    except Exception:
        return findings
    forms = extract_forms(html, page_url)
    for f in forms:
        findings.extend(test_single_form(session, f, timeout=timeout))
    return findings
