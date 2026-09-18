import json
import os
import uuid
import time
import requests
import re
import urllib3
from datetime import datetime
from urllib.parse import urlencode
from elasticsearch import Elasticsearch
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ES_HOST  = os.environ.get("ES_HOST", "elasticsearch")
ES_PORT  = os.environ.get("ES_PORT", "9200")
INPUT    = os.environ.get("INPUT_FILE", "/app/input/crawl_results.json")
OUTPUT   = os.environ.get("OUTPUT_FILE", "/app/output/active_results.json")
ES_INDEX = "dast-active"
TIMEOUT  = 7
_thread_local = threading.local()
MAX_WORKERS = int(os.environ.get("SCAN_WORKERS", "8"))

es = Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")

def load_config():
    config_path = "/app/config.json"
    if os.path.exists(config_path) and os.path.isfile(config_path):
        with open(config_path) as f:
            return json.load(f)
    return {
        "target_url": os.environ.get("TARGET_URL", "http://dvwa:80"),
        "app_type": "dvwa",
        "credentials": {"username": "admin", "password": "password"}
    }

def ensure_index():
    if not es.indices.exists(index=ES_INDEX):
        es.indices.create(index=ES_INDEX, body={
            "mappings": {
                "properties": {
                    "attack_id":  {"type": "keyword"},
                    "url":        {"type": "keyword"},
                    "parameter":  {"type": "keyword"},
                    "payload":    {"type": "text"},
                    "vuln_type":  {"type": "keyword"},
                    "severity":   {"type": "keyword"},
                    "evidence":   {"type": "text"},
                    "vulnerable": {"type": "boolean"},
                    "timestamp":  {"type": "date"},
                }
            }
        })

# NOTE: cheap error-based payloads first, slow time-based payload LAST
SQLI_PAYLOADS = [
    ("'", "error-based"),
    ("1' OR '1'='1", "error-based"),
    ("' OR 1=1--", "error-based"),
    ("' OR 'x'='x", "error-based"),
    ("1' AND 1=2 UNION SELECT 1,2,3--", "error-based"),
    ("1' AND SLEEP(3)--", "time-based"),
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax", "mysql_fetch", "mysql_num_rows",
    "supplied argument is not a valid mysql",
    "column count doesn't match", "division by zero",
]

SQLI_SUCCESS = ["first name:", "surname:", "user id:", "password:", "email:"]

def create_finding(url, parameter, payload, vuln_type,
                   severity, evidence, vulnerable, method="GET"):
    return {
        "attack_id":  str(uuid.uuid4()),
        "url":        url,
        "parameter":  parameter,
        "payload":    payload,
        "vuln_type":  vuln_type,
        "severity":   severity,
        "evidence":   evidence[:500] if evidence else "",
        "vulnerable": vulnerable,
        "method":     method,
        "timestamp":  datetime.utcnow().isoformat(),
        "module":     "active-scanner"
    }

def get_token(text):
    match = re.search(r"name='user_token' value='([a-f0-9]+)'", text)
    return match.group(1) if match else ""

def reset_dvwa_db(config):
    """Reset the DVWA database ONCE before scanning (not per thread)."""
    if config.get("app_type") != "dvwa":
        return
    target_url = config["target_url"].rstrip("/")
    s = requests.Session()
    try:
        setup = s.get(f"{target_url}/setup.php", timeout=TIMEOUT, verify=False)
        setup_token = get_token(setup.text)
        s.post(f"{target_url}/setup.php",
            data={"create_db": "Create / Reset Database", "user_token": setup_token},
            timeout=TIMEOUT, verify=False, allow_redirects=True)
        print("[*] DVWA database reset")
    except Exception as e:
        print(f"[WARN] DVWA DB reset failed: {e}")

def get_session(config):
    session = requests.Session()
    app_type   = config.get("app_type", "generic")
    target_url = config["target_url"].rstrip("/")
    username   = config["credentials"].get("username", "")
    password   = config["credentials"].get("password", "")

    try:
        if app_type == "dvwa":
            login = session.get(f"{target_url}/login.php", timeout=TIMEOUT, verify=False)
            login_token = get_token(login.text)
            session.post(f"{target_url}/login.php",
                data={"username": username, "password": password,
                      "Login": "Login", "user_token": login_token},
                timeout=TIMEOUT, verify=False, allow_redirects=True)

            sec = session.get(f"{target_url}/security.php", timeout=TIMEOUT, verify=False)
            sec_token = get_token(sec.text)
            session.post(f"{target_url}/security.php",
                data={"security": "low", "seclev_submit": "Submit", "user_token": sec_token},
                timeout=TIMEOUT, verify=False, allow_redirects=True)

        elif app_type == "juiceshop":
            r = session.post(f"{target_url}/rest/user/login",
                json={"email": username, "password": password},
                timeout=TIMEOUT, verify=False)
            token = r.json().get("authentication", {}).get("token", "")
            session.headers.update({"Authorization": f"Bearer {token}"})

    except Exception as e:
        print(f"[ERROR] Session setup failed: {e}")

    return session

def get_thread_session(config):
    """One session per thread (requests.Session is NOT thread-safe)."""
    if not hasattr(_thread_local, "session"):
        _thread_local.session = get_session(config)
    return _thread_local.session

def send_request(session, url, parameter, payload, method, form_inputs=None):
    data = {}
    if form_inputs:
        for inp in form_inputs:
            name = inp.get("name", "")
            if name and name not in ["user_token"]:
                data[name] = inp.get("value", "")
    data[parameter] = payload

    if method == "GET":
        data["Submit"] = "Submit"
        attack_url = url.split("?")[0] + "?" + urlencode(data)
        return session.get(attack_url, timeout=TIMEOUT, verify=False)
    else:
        return session.post(url, data=data, timeout=TIMEOUT, verify=False)

def get_baseline(session, url, parameter, method, form_inputs=None):
    try:
        r = send_request(session, url, parameter, "1", method, form_inputs)
        return len(r.text), r.text
    except Exception:
        return 0, ""

def test_sqli(session, url, parameter, method="GET", form_inputs=None):
    findings = []
    baseline_len, baseline_text = get_baseline(session, url, parameter, method, form_inputs)
    baseline_count = sum(baseline_text.lower().count(s) for s in SQLI_SUCCESS)

    for payload, technique in SQLI_PAYLOADS:
        try:
            start_time = time.time()
            response = send_request(session, url, parameter, payload, method, form_inputs)
            elapsed = time.time() - start_time
            response_lower = response.text.lower()
            response_len = len(response.text)

            if technique == "error-based":
                found_error = False
                for error in SQLI_ERRORS:
                    if error in response_lower:
                        f = create_finding(url, parameter, payload, "SQL Injection", "Critical",
                            f"SQL error: '{error}'", True, method)
                        f["technique"] = "error-based"
                        findings.append(f)
                        found_error = True
                        break

                if found_error:
                    break  # EARLY EXIT: confirmed SQLi, stop testing this parameter

                success_count = sum(response_lower.count(s) for s in SQLI_SUCCESS)
                if success_count > baseline_count + 2:
                    f = create_finding(url, parameter, payload, "SQL Injection", "Critical",
                        f"Data leak: {success_count} records vs {baseline_count} baseline",
                        True, method)
                    f["technique"] = "success-based"
                    findings.append(f)
                    break  # EARLY EXIT

                if baseline_len > 0 and response_len > baseline_len * 1.3:
                    f = create_finding(url, parameter, payload, "SQL Injection", "High",
                        f"Size anomaly: {response_len} vs {baseline_len}", True, method)
                    f["technique"] = "size-based"
                    findings.append(f)
                    break  # EARLY EXIT

            elif technique == "time-based" and elapsed >= 2.5:
                f = create_finding(url, parameter, payload, "SQL Injection (Blind)", "Critical",
                    f"Time-based SQLi: response took {elapsed:.2f}s",
                    True, method)
                f["technique"] = "time-based"
                findings.append(f)
                break  # EARLY EXIT

        except requests.exceptions.Timeout:
            if technique == "time-based":
                f = create_finding(url, parameter, payload, "SQL Injection (Blind)", "Critical",
                    "Request timed out — possible blind SQLi",
                    True, method)
                f["technique"] = "time-based"
                findings.append(f)
                break  # EARLY EXIT
        except Exception:
            pass  # silently skip transient errors during parallel execution

    return findings

def test_xss(session, url, parameter, method="GET", form_inputs=None):
    findings = []
    for payload in XSS_PAYLOADS:
        try:
            response = send_request(session, url, parameter, payload, method, form_inputs)
            if payload.lower() in response.text.lower():
                f = create_finding(url, parameter, payload,
                    "Cross-Site Scripting (XSS)", "High",
                    f"Payload reflected: {payload}", True, method)
                f["technique"] = "reflected"
                findings.append(f)
                break  # EARLY EXIT
        except Exception:
            pass
    return findings

def test_parameter(config, url, parameter, method, form_inputs):
    """Run both SQLi and XSS tests on one parameter. Each thread gets its own session."""
    session = get_thread_session(config)
    findings = []
    findings += test_sqli(session, url, parameter, method, form_inputs)
    findings += test_xss(session, url, parameter, method, form_inputs)
    return parameter, url, findings

def main():
    config = load_config()
    print(f"[*] Starting active scanner (parallel mode, {MAX_WORKERS} workers)")
    print(f"[*] Target: {config['target_url']} ({config['app_type']})")
    ensure_index()

    with open(INPUT) as f:
        crawl_results = json.load(f)
    print(f"[*] Found {len(crawl_results)} URLs to scan")

    # Reset DVWA DB once, before spawning threads
    reset_dvwa_db(config)

    all_findings = []

    # Build task list
    tasks = []
    seen = set()
    for item in crawl_results:
        url    = item["url"]
        forms  = item.get("forms", [])
        params = item.get("params", {})

        if not forms and not params:
            continue

        for param_name in params.keys():
            if param_name in ["user_token", "Submit"]:
                continue
            key = (url, param_name, "GET")
            if key not in seen:
                seen.add(key)
                tasks.append((url, param_name, "GET", None))

        for form in forms:
            form_url = form.get("action", url)
            method   = form.get("method", "GET").upper()
            inputs   = form.get("inputs", [])
            for inp in inputs:
                param_name = inp.get("name", "")
                if not param_name or param_name in [
                    "user_token", "Submit", "Login",
                    "MAX_FILE_SIZE", "uploaded", "Upload", "seclev_submit"
                ]:
                    continue
                key = (form_url, param_name, method)
                if key not in seen:
                    seen.add(key)
                    tasks.append((form_url, param_name, method, inputs))

    print(f"[*] Total parameters to test: {len(tasks)}")
    print(f"[*] Running with {MAX_WORKERS} concurrent workers...\n")

    completed = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(test_parameter, config, url, param, method, inputs): (url, param)
            for url, param, method, inputs in tasks
        }

        for future in as_completed(futures):
            url, param = futures[future]
            completed += 1
            try:
                parameter, result_url, findings = future.result()
                if findings:
                    all_findings.extend(findings)
                    vuln_summary = ", ".join(set(f["vuln_type"] for f in findings))
                    print(f"[{completed}/{len(tasks)}] [!] {result_url} :: {parameter} -> {vuln_summary}")
                else:
                    print(f"[{completed}/{len(tasks)}] {url} :: {param} - clean")
            except Exception as e:
                print(f"[{completed}/{len(tasks)}] {url} :: {param} - error: {e}")

    print(f"\n[*] Indexing {len(all_findings)} findings...")
    for finding in all_findings:
        try:
            es.index(index=ES_INDEX, document=finding)
        except Exception as e:
            print(f"[ERROR] ES index failed: {e}")

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(all_findings, f, indent=2, default=str)

    print(f"\n[+] Active scan complete!")
    print(f"[+] Total findings: {len(all_findings)}")
    vulnerable = [f for f in all_findings if f["vulnerable"]]
    print(f"[+] Confirmed vulnerabilities: {len(vulnerable)}")
    for vtype, count in Counter(f["vuln_type"] for f in vulnerable).items():
        print(f"    {vtype}: {count}")
    print(f"[+] Results saved to {OUTPUT}")
    print(f"[+] Results indexed in Elasticsearch: {ES_INDEX}")

if __name__ == "__main__":
    main()

