import json
import os
import shutil
import subprocess
import threading
import uuid
from datetime import datetime

import requests as http_requests
from flask import Flask, jsonify, render_template, request, send_file

app = Flask(__name__)

CONFIG_FILE  = "/app/project/config.json"
OUTPUT_DIR   = "/app/output"
LOG_FILE     = "/app/output/scan.log"
COMPOSE_FILE = "/app/project/docker-compose.yml"
PROJECT_NAME = "dast-platform"
ES_URL       = os.environ.get("ES_URL", "http://elasticsearch:9200")
KIBANA_URL   = os.environ.get("KIBANA_URL", "http://kibana:5601")
KIBANA_URL_EXTERNAL = os.environ.get("KIBANA_URL_EXTERNAL", "http://localhost:5601")

DEFAULT_CONFIG = {
    "target_url": "http://dvwa:80",
    "app_type": "dvwa",
    "credentials": {"username": "admin", "password": "password"},
}

# ---------------------------------------------------------------------------
# Scan state (in-memory, single-scan-at-a-time)
# ---------------------------------------------------------------------------
scan_state = {
    "running": False,
    "current_module": None,
    "started_at": None,
    "error": None,
    "stages": ["crawler", "passive-scanner", "active-scanner", "ai-module"],
}
state_lock = threading.Lock()


def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")


def ensure_config_file():
    if os.path.isdir(CONFIG_FILE):
        shutil.rmtree(CONFIG_FILE)
    if not os.path.exists(CONFIG_FILE):
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)


def read_config():
    ensure_config_file()
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG.copy()


def write_config(data):
    ensure_config_file()
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)


def get_kibana_dashboard_link():
    try:
        r = http_requests.get(
            f"{KIBANA_URL}/api/saved_objects/_find",
            params={"type": "dashboard", "search": "DAST", "search_fields": "title"},
            timeout=3,
        )
        objs = r.json().get("saved_objects", [])
        if objs:
            return f"{KIBANA_URL_EXTERNAL}/app/dashboards#/view/{objs[0]['id']}"
    except Exception:
        pass
    return f"{KIBANA_URL_EXTERNAL}/app/dashboards#/list"



def get_es_stats():
    """Aggregate finding counts and severity from the dast-* indices."""
    stats = {"total": 0, "severity": {}, "es_available": False}
    try:
        r = http_requests.get(
            f"{ES_URL}/dast-*/_search",
            params={"size": 0},
            json={"aggs": {"sev": {"terms": {"field": "severity", "size": 10}}}},
            timeout=4,
        )
        d = r.json()
        stats["total"] = d.get("hits", {}).get("total", {}).get("value", 0)
        for b in d.get("aggregations", {}).get("sev", {}).get("buckets", []):
            stats["severity"][b["key"]] = b["doc_count"]
        stats["es_available"] = True
    except Exception:
        pass
    return stats


def run_module(module_name):
    with state_lock:
        scan_state["current_module"] = module_name
    cmd = ["docker", "compose", "-p", PROJECT_NAME, "-f", COMPOSE_FILE,
           "run", "--rm", "--no-deps", module_name]
    log(f"--- Running {module_name} ---")
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, cwd="/app/project",
    )
    scan_state["process"] = process
    with open(LOG_FILE, "a") as f:
        for line in process.stdout:
            f.write(line)
            f.flush()
    process.wait()
    log(f"{module_name} finished (exit code {process.returncode})")
    return process.returncode


def pipeline(run_ai):
    modules = ["crawler", "passive-scanner", "active-scanner"]
    if run_ai:
        modules.append("ai-module")
    modules.append("reporter")
    try:
        for module in modules:
            with state_lock:
                if not scan_state["running"]:      # stopped by user
                    log("Scan stopped by user.")
                    return
            if run_module(module) != 0:
                with state_lock:
                    scan_state["error"] = f"{module} failed"
                log(f"ERROR: {module} exited non-zero. Aborting pipeline.")
                return
        log("Scan complete.")
    except Exception as e:
        with state_lock:
            scan_state["error"] = str(e)
        log(f"Pipeline error: {e}")
    finally:
        with state_lock:
            scan_state["running"] = False
            scan_state["current_module"] = None
            scan_state["process"] = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template(
        "index.html",
        config=read_config(),
        kibana_link=get_kibana_dashboard_link(),
        report_exists=os.path.exists(os.path.join(OUTPUT_DIR, "report.pdf")),
    )


@app.route("/start_scan", methods=["POST"])
def start_scan():
    with state_lock:
        if scan_state["running"]:
            return jsonify({"status": "error", "message": "A scan is already running"}), 409

    config = read_config()
    config["target_url"] = request.form.get("target_url", config["target_url"])

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    target = config["target_url"].lower()

    # Route to the right login flow by target, when creds are given
    if username or password:
        if "bwapp" in target:
            config["app_type"] = "bwapp"
        elif "dvwa" in target:
            config["app_type"] = "dvwa"
        else:
            config["app_type"] = "generic"
    else:
        config["app_type"] = "generic"

    config.setdefault("credentials", {})
    config["credentials"]["username"] = username
    config["credentials"]["password"] = password
    config["scan_id"] = str(uuid.uuid4())
    write_config(config)

    run_ai = request.form.get("run_ai", "on") == "on"

    # Reset previous results
    for fname in ["crawl_results.json", "passive_results.json",
                  "active_results.json", "ai_summary.json"]:
        try:
            with open(os.path.join(OUTPUT_DIR, fname), "w") as fp:
                fp.write("[]" if "ai_summary" not in fname else "{}")
        except Exception:
            pass

    with open(LOG_FILE, "w") as f:
        f.write("")

    log(f"Scan started — target: {config['target_url']} ({config['app_type']})")

    with state_lock:
        scan_state.update({
            "running": True,
            "current_module": None,
            "started_at": datetime.now().isoformat(),
            "error": None,
        })

    threading.Thread(target=pipeline, args=(run_ai,), daemon=True).start()
    return jsonify({"status": "ok", "message": "Scan started", "scan_id": config["scan_id"]})


@app.route("/stop_scan", methods=["POST"])
def stop_scan():
    with state_lock:
        proc = scan_state.get("process")
        scan_state["running"] = False
    if proc and proc.poll() is None:
        proc.terminate()
    log("Stop requested by user.")
    return jsonify({"status": "ok"})


@app.route("/scan_status")
def scan_status():
    with state_lock:
        s = dict(scan_state)
        s.pop("process", None)
    if s.get("started_at"):
        s["elapsed"] = (datetime.now() - datetime.fromisoformat(s["started_at"])).seconds
    return jsonify(s)


@app.route("/stats")
def stats():
    return jsonify(get_es_stats())


@app.route("/logs")
def logs():
    try:
        tail = int(request.args.get("tail", 0))
        with open(LOG_FILE) as f:
            content = f.read()
        if tail and len(content) > tail:
            content = content[-tail:]
        return jsonify({"logs": content})
    except Exception:
        return jsonify({"logs": "No scan log available."})


@app.route("/kibana_link")
def kibana_link():
    return jsonify({"url": get_kibana_dashboard_link()})


@app.route("/report_status")
def report_status():
    return jsonify({"exists": os.path.exists(os.path.join(OUTPUT_DIR, "report.pdf"))})


@app.route("/download/report")
def download_report():
    path = os.path.join(OUTPUT_DIR, "report.pdf")
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name="dast_report.pdf")
    return jsonify({"error": "Report not generated yet."}), 404


@app.route("/ai_summary")
def ai_summary():
    path = os.path.join(OUTPUT_DIR, "ai_summary.json")
    if os.path.exists(path):
        try:
            with open(path) as f:
                data = json.load(f)
            if data and data != {} and data != []:
                return jsonify({"available": True, "data": data})
        except Exception as e:
            return jsonify({"available": False, "message": f"Could not parse AI summary: {e}"})
    return jsonify({"available": False, "message": "No AI analysis yet. Enable 'Run AI Analysis' when starting a scan."})


@app.route("/download/ai_summary")
def download_ai_summary():
    path = os.path.join(OUTPUT_DIR, "ai_summary.json")
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name="ai_summary.json")
    return jsonify({"error": "No AI summary available."}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=False)

