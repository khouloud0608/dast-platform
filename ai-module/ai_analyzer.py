import os
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from elasticsearch import Elasticsearch

# --- Config (all tunable via env) ---
ES_URL         = os.getenv("ES_URL", "http://elasticsearch:9200")
LLM_URL        = os.getenv("LLM_URL", "http://192.168.1.12:1234/v1/chat/completions")
MODEL          = os.getenv("MODEL", "qwen2.5-3b-instruct")
AI_WORKERS     = int(os.getenv("WORKERS", "1"))
LLM_TIMEOUT    = int(os.getenv("LLM_TIMEOUT", "300"))
LLM_SEVERITIES = set(s.strip().lower() for s in
                     os.getenv("LLM_SEVERITIES", "high,critical").split(","))
OUTPUT_FILE    = "/app/output/ai_summary.json"
RESULT_INDEX   = "dast-ai"

es = Elasticsearch(ES_URL)

TEMPLATES = {
    "medium": ("Medium-risk finding. Review the affected endpoint, validate input "
               "handling and ensure security headers and patches are up to date."),
    "low": ("Low-risk informational finding. Apply standard hardening practices "
            "and monitor for changes."),
    "info":  ("Informational finding. No immediate action required."),
    "informational": ("Informational finding. No immediate action required."),
}

def infer_name(url: str) -> str:
    mapping = {
        "xss_r": "Reflected XSS", "xss_s": "Stored XSS", "xss_d": "DOM XSS",
        "sqli_blind": "Blind SQL Injection", "sqli": "SQL Injection",
        "csrf": "CSRF", "exec": "Command Injection", "brute": "Brute Force",
        "upload": "File Upload Vulnerability", "fi/": "File Inclusion",
        "open_redirect": "Open Redirect", "csp": "Weak CSP",
        "weak_id": "Insecure Session ID", "authbypass": "Auth Bypass",
        "bac": "Broken Access Control", "captcha": "CAPTCHA Issue",
        "cryptography": "Weak Cryptography", "phpinfo": "Info Disclosure",
    }
    low = url.lower()
    for key, val in mapping.items():
        if key in low:
            return val
    return "Web Security Finding"

def fetch_findings():
    findings = []
    for index in ("dast-active", "dast-passive"):
        try:
            resp = es.search(index=index, size=1000, query={"match_all": {}})
            for hit in resp["hits"]["hits"]:
                src = hit.get("_source")
                if isinstance(src, dict):
                    findings.append(src)
        except Exception as e:
            print(f"[WARN] Could not read {index}: {e}")
    return findings

def deduplicate(findings):
    seen = {}
    for f in findings:
        name = f.get("name") or f.get("alert") or infer_name(f.get("url", ""))
        url  = (f.get("url") or "").split("?")[0]
        key  = (name, url)
        if key not in seen:
            seen[key] = f
    return list(seen.values())

def get_severity(f):
    sev = (f.get("risk") or f.get("severity") or "info")
    return str(sev).lower()

def ask_llm(name: str, url: str, severity: str) -> str:
    prompt = f"""You are drafting a security documentation report for the developer of a
private training application (DVWA).

Finding: {name}
Endpoint: {url}
Severity: {severity}

Provide a 3-sentence summary for the developer: explain what the configuration or
code weakness is, the impact on application integrity, and the recommended
remediation step."""

    resp = requests.post(LLM_URL, json={
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 200
    }, timeout=LLM_TIMEOUT)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()

def analyze(f):
    sev = get_severity(f)
    name = f.get("name") or f.get("alert") or infer_name(f.get("url", ""))
    if name.lower() in ("unknown", ""):
        name = infer_name(f.get("url", ""))
    if sev in LLM_SEVERITIES:
        try:
            explanation = ask_llm(name, f.get("url", ""), sev)
            source = "llm"
        except Exception as e:
            print(f"[WARN] LLM failed for {name}: {e}")
            explanation = TEMPLATES.get(sev, TEMPLATES["info"])
            source = "template-fallback"
    else:
        explanation = TEMPLATES.get(sev, TEMPLATES["info"])
        source = "template"
    return {
        "name": name,
        "url": f.get("url", ""),
        "severity": sev,
        "analysis_source": source,
        "explanation": explanation,
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

def main():
    print(f"[INFO] Model={MODEL} workers={AI_WORKERS} "
          f"llm_severities={sorted(LLM_SEVERITIES)}")
    findings = deduplicate(fetch_findings())
    total = len(findings)
    llm_count = sum(1 for f in findings if get_severity(f) in LLM_SEVERITIES)
    print(f"[INFO] {total} unique findings, {llm_count} going to LLM, "
          f"{total - llm_count} using templates")

    with open(OUTPUT_FILE, "w") as fh:
        json.dump({"status": "running", "results": []}, fh)

    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=AI_WORKERS) as pool:
        futures = {pool.submit(analyze, f): f for f in findings}
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            done += 1
            try:
                es.index(index=RESULT_INDEX, document=res)
            except Exception as e:
                print(f"[WARN] ES index failed: {e}")
            with open(OUTPUT_FILE, "w") as fh:
                json.dump({"status": "running",
                           "progress": f"{done}/{total}",
                           "results": results}, fh, indent=2)
            print(f"[{done}/{total}] {res['severity']:>8} "
                  f"({res['analysis_source']}) {res['name'][:60]}")

    with open(OUTPUT_FILE, "w") as fh:
        json.dump({"status": "complete", "total": total,
                   "results": results}, fh, indent=2)
    print(f"[DONE] {total} findings processed. Report: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

