# scanner/reporter.py
import json
import time
from typing import List, Dict

def write_json_report(target: str, findings: List[Dict], outpath: str = "report.json"):
    report = {
        "target": target,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": findings
    }
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return outpath

def pretty_print_findings(findings: List[Dict]):
    if not findings:
        print("[+] No findings.")
        return
    print(f"[+] {len(findings)} finding(s):")
    for i, f in enumerate(findings, 1):
        print(f"  {i}. [{f.get('type')}] param={f.get('param')} payload={f.get('payload')}")
        print(f"     evidence: {f.get('evidence')}")
        print(f"     url: {f.get('url')}")
