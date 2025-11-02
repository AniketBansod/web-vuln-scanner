# webapp/app.py
from flask import Flask, render_template, request, redirect, url_for, send_file, flash
import os
import sys
import threading
import uuid
import json

# Ensure package imports work when running as a script: `python webapp/app.py`
if __package__ is None or __package__ == "":
    # Add the parent directory (project root: <repo>/vuln_scanner) to sys.path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.requester import create_session
from scanner.input_handler import validate_url
from scanner.main import scan_target  # performs scan and writes report.json
from scanner.reporter import write_json_report

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(APP_ROOT, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "change-this-secret-to-something-safe"

# We will run scan in a background thread to keep UI responsive (simple approach)
# scan tasks map: task_id -> {"status": "queued|running|done", "report": path}
TASKS = {}

def _run_scan_sync(target_url, outpath):
    """Helper to run the existing scanner and dump report to outpath."""
    # Use the scanner functions but capture findings to outpath
    # We will call scanner.main.scan_target which writes 'report.json' currently.
    # To avoid clobbering global report, we call scan_target then move report.json -> outpath
    try:
        scan_target(target_url)
        # move produced report.json to outpath (reporter writes report.json by default)
        default_report = os.path.join(os.getcwd(), "report.json")
        if os.path.exists(default_report):
            os.replace(default_report, outpath)
            return True
        else:
            # nothing created - create an empty report
            with open(outpath, "w", encoding="utf-8") as f:
                json.dump({"target": target_url, "findings": []}, f)
            return True
    except Exception as e:
        return False

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("target_url", "").strip()
        if not validate_url(url):
            flash("Invalid URL. Use http:// or https:// and include domain.", "danger")
            return redirect(url_for("index"))
        # Auto crawl depth; tune here if needed
        depth = 2
        task_id = str(uuid.uuid4())[:8]
        outpath = os.path.join(REPORTS_DIR, f"report_{task_id}.json")
        TASKS[task_id] = {"status": "queued", "report": outpath, "target": url, "depth": depth}
        # launch background thread
        def worker(tid, target, out, crawl_depth):
            TASKS[tid]["status"] = "running"
            ok = _run_scan_sync_advanced(target, out, crawl_depth)
            TASKS[tid]["status"] = "done" if ok else "error"
        t = threading.Thread(target=worker, args=(task_id, url, outpath, depth), daemon=True)
        t.start()
        return redirect(url_for("task", task_id=task_id))
    return render_template("index.html")

@app.route("/task/<task_id>")
def task(task_id):
    info = TASKS.get(task_id)
    if not info:
        flash("Task not found.", "warning")
        return redirect(url_for("index"))
    status = info["status"]
    return render_template("task.html", task_id=task_id, status=status, info=info)

@app.route("/report/<task_id>/download")
def download_report(task_id):
    info = TASKS.get(task_id)
    if not info or not os.path.exists(info["report"]):
        flash("Report not available yet.", "warning")
        return redirect(url_for("task", task_id=task_id))
    return send_file(info["report"], as_attachment=True, download_name=os.path.basename(info["report"]))

@app.route("/report/<task_id>/view")
def view_report(task_id):
    info = TASKS.get(task_id)
    if not info or not os.path.exists(info["report"]):
        flash("Report not available yet.", "warning")
        return redirect(url_for("task", task_id=task_id))
    with open(info["report"], "r", encoding="utf-8") as f:
        data = json.load(f)

    # Enrich findings with severity and normalize fields for UI
    def classify_severity(f: dict) -> str:
        t = (f.get("type") or "").lower()
        if t in {"sqli"}:
            return "High"
        if t in {"xss-reflected", "sqli-suspected"}:
            return "Medium"
        if t in {"header-missing"}:
            return "Low"
        return "Info"

    findings = data.get("findings", []) or []
    for f in findings:
        f.setdefault("param", "-")
        f.setdefault("payload", "-")
        f.setdefault("evidence", "-")
        f.setdefault("url", data.get("target", ""))
        f["severity"] = classify_severity(f)

    # Aggregates
    total = len(findings)
    severities = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    types = {}
    pages = set()
    for f in findings:
        severities[f["severity"]] = severities.get(f["severity"], 0) + 1
        t = f.get("type", "Unknown")
        types[t] = types.get(t, 0) + 1
        if f.get("url"):
            pages.add(f["url"])

    aggregates = {
        "total": total,
        "severities": severities,
        "types": types,
        "affected_pages": len(pages),
    }

    return render_template(
        "report.html",
        report=data,
        task_id=task_id,
        findings=findings,
        aggregates=aggregates,
    )

def _run_scan_sync_advanced(target_url, outpath, crawl_depth: int = 0):
    """Run scanner with optional crawl depth and write report to target outpath."""
    try:
        scan_target(target_url, crawl_depth=crawl_depth)
        default_report = os.path.join(os.getcwd(), "report.json")
        if os.path.exists(default_report):
            os.replace(default_report, outpath)
            return True
        else:
            with open(outpath, "w", encoding="utf-8") as f:
                json.dump({"target": target_url, "findings": []}, f)
            return True
    except Exception:
        return False
if __name__ == "__main__":
    app.run(debug=True, port=5001)
