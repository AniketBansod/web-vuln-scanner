"""scanner/main.py
High-level scan orchestration: crawl pages, test forms and GET params, and report findings.
"""

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner import __version__
from scanner.input_handler import validate_url, parse_url_params, build_url_with_params
from scanner.requester import create_session, send_get
from scanner.injector import generate_all_tests
from scanner.analyzer import (
    detect_sql_error,
    detect_reflected_payload,
    response_similarity,
    analyze_security_headers,
)
from scanner.reporter import write_json_report, pretty_print_findings
from scanner.form_tester import test_forms_on_page
from scanner.crawler import crawl


def baseline_response(session, parsed, params):
    base_url = build_url_with_params(parsed, params)
    r = send_get(session, base_url)
    text = r.text if r else ""
    return base_url, r, text


def _scan_single_page(session, page: str):
    findings = []
    parsed, params = parse_url_params(page)
    base_url, base_resp, base_body = baseline_response(session, parsed, params)
    base_len = len(base_body or "")

    # 0) Security headers
    findings.extend(analyze_security_headers(base_url, base_resp))

    # 1) Forms
    print("[*] Testing forms on page:", base_url)
    findings.extend(test_forms_on_page(session, base_url))

    # 2) GET params or synthetic fuzzing if no params exist
    if not params:
        print("[!] No query parameters detected (GET) on:", base_url)
        from scanner import signatures

        synth_param = "q"
        # SQLi
        for payload in signatures.SQL_PAYLOADS:
            url = build_url_with_params(parsed, {synth_param: payload})
            r = send_get(session, url)
            body = r.text or "" if r else ""
            found, evidence = detect_sql_error(body)
            if found:
                findings.append({
                    "type": "SQLi",
                    "param": synth_param,
                    "payload": payload,
                    "url": url,
                    "evidence": evidence,
                })
            elif abs(len(body) - base_len) > 200:
                findings.append({
                    "type": "SQLi-suspected",
                    "param": synth_param,
                    "payload": payload,
                    "url": url,
                    "evidence": f"response length changed from {base_len} to {len(body)}",
                })
        # XSS
        for payload in signatures.XSS_PAYLOADS:
            url = build_url_with_params(parsed, {synth_param: payload})
            r = send_get(session, url)
            body = r.text or "" if r else ""
            if detect_reflected_payload(body, payload):
                findings.append({
                    "type": "XSS-reflected",
                    "param": synth_param,
                    "payload": payload,
                    "url": url,
                    "evidence": "payload reflected in response body",
                })
    else:
        for test in generate_all_tests(parsed, params):
            r = send_get(session, test["url"])
            if not r:
                continue
            body = r.text or ""
            if test["type"] == "sqli":
                found, evidence = detect_sql_error(body)
                if found:
                    findings.append({
                        "type": "SQLi",
                        "param": test["param"],
                        "payload": test["payload"],
                        "url": test["url"],
                        "evidence": evidence,
                    })
                    print("[!] SQLi signature detected:", evidence)
                elif abs(len(body) - base_len) > 200:
                    findings.append({
                        "type": "SQLi-suspected",
                        "param": test["param"],
                        "payload": test["payload"],
                        "url": test["url"],
                        "evidence": f"response length changed from {base_len} to {len(body)}",
                    })
                    print("[!] SQLi suspected (length change).")
            elif test["type"] == "xss":
                if detect_reflected_payload(body, test["payload"]):
                    findings.append({
                        "type": "XSS-reflected",
                        "param": test["param"],
                        "payload": test["payload"],
                        "url": test["url"],
                        "evidence": "payload reflected in response body",
                    })
                    print("[!] Reflected XSS detected.")
    return findings


def scan_target(target_url: str, crawl_depth: int = 0, max_pages: int = 50, workers: int = 8):
    if not validate_url(target_url):
        print("[ERROR] Invalid URL. Example: http://example.com/page?param=value")
        return

    session = create_session()

    # Auto depth if not specified or <= 0
    eff_depth = crawl_depth if (crawl_depth and crawl_depth > 0) else 2

    # Determine pages to scan
    pages = [target_url]
    if eff_depth > 0:
        try:
            pages = crawl(session, target_url, max_depth=eff_depth, max_pages=max_pages)
            if not pages:
                pages = [target_url]
            print(f"[*] Crawling enabled (depth={eff_depth}, max_pages={max_pages}). Discovered {len(pages)} page(s).")
        except Exception:
            pages = [target_url]

    findings = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_scan_single_page, session, p) for p in pages]
        for fut in as_completed(futures):
            try:
                findings.extend(fut.result())
            except Exception:
                # ignore single-page failures
                pass

    pretty_print_findings(findings)
    out = write_json_report(target_url, findings)
    print(f"[+] Report saved to {out}")


def main():
    if len(sys.argv) < 2:
        print(f"vuln_scanner {__version__} - Usage: python -m scanner.main \"http://target/path?param=value\" [depth] [max_pages]")
        sys.exit(1)
    target = sys.argv[1]
    try:
        depth = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    except Exception:
        depth = 0
    try:
        max_pages = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    except Exception:
        max_pages = 50
    scan_target(target, crawl_depth=depth, max_pages=max_pages)


if __name__ == "__main__":
    main()
