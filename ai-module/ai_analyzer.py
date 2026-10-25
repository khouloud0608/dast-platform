#!/usr/bin/env python3
"""
AI Module - direct local LLM (Ollama) client
=============================================
Reads the CURRENT scan's findings from the per-scan JSON files, aggregates
them into compact statistics, and asks a LOCAL Ollama model (running on the
Windows host CPU) for an executive summary + prioritized remediation plan.

No proxy. No external API. The only outbound call is to the Ollama server on
the Windows host, reachable from inside the VM at the VMware NAT address.
"""

import os
import re
import json
import time
import requests
from collections import Counter

try:
    from elasticsearch import Elasticsearch
except Exception:
    Elasticsearch = None

# --- Config ---
ES_URL         = os.getenv("ES_URL", "http://elasticsearch:9200")
OLLAMA_URL     = os.getenv("OLLAMA_URL", "http://192.168.159.1:11434").rstrip("/")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "qwen3:4b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "300"))
CONFIG_PATH    = "/app/config.json"
OUTPUT_DIR     = "/app/output"
OUTPUT_FILE    = os.path.join(OUTPUT_DIR, "ai_summary.json")
LOG_FILE       = os.path.join(OUTPUT_DIR, "scan.log")
RESULT_INDEX   = "dast-ai"


def log(msg):
    line = f"[AI] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as lf:
            lf.write(line + "\n")
    except Exception:
        pass


def load_config():
    try:
        if os.path.isfile(CONFIG_PATH):
            with open(CONFIG_PATH) as f:
                return json.load(f)
    except Exception as e:
        log(f"WARN could not read config.json: {e}")
    return {}


def fetch_findings():
    """Per-scan JSON files, NOT Elasticsearch (ES accumulates across scans)."""
    findings = []
    for fname in ("active_results.json", "passive_results.json"):
        path = os.path.join(OUTPUT_DIR, fname)
        try:
            with open(path) as f:
                data = json.load(f)
                if isinstance(data, list):
                    findings.extend(data)
                elif isinstance(data, dict) and isinstance(data.get("results"), list):
                    findings.extend(data["results"])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log(f"WARN could not read {fname}: {e}")
    return findings


def f_get(d, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v:
            return v
    return default


def aggregate(findings):
    sev, typ, urls = Counter(), Counter(), Counter()
    type_sev = {}  # type -> Counter(severity -> count)
    for f in findings:
        if not isinstance(f, dict):
            continue
        s = str(f_get(f, "severity", "risk", "level", default="info")).lower()
        t = str(f_get(f, "type", "vuln_type", "name", "check", "issue",
                      "category", default="other"))
        sev[s] += 1
        typ[t] += 1
        type_sev.setdefault(t, Counter())[s] += 1
        u = f_get(f, "url", "target", "endpoint", default="")
        if u:
            urls[str(u)] += 1

    # Pair each issue type with the severity the scanner assigned it, so the
    # model respects those labels instead of guessing a severity per type.
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_by_type = []
    for t, counts in type_sev.items():
        label = min(counts, key=lambda x: sev_rank.get(x, 9))
        findings_by_type.append(
            {"type": t, "severity": label, "count": sum(counts.values())}
        )
    findings_by_type.sort(key=lambda d: (sev_rank.get(d["severity"], 9), -d["count"]))

    return {
        "total": len(findings),
        "by_severity": dict(sev),
        "findings_by_type": findings_by_type[:20],
        "top_urls": dict(urls.most_common(10)),
    }


def build_prompt(stats, app_type):
    return (
        "/no_think\n"
        "You are a senior application security analyst writing the summary "
        "section of a DAST (Dynamic Application Security Testing) report for a "
        f"{app_type}. Below are the AGGREGATED scan results as JSON.\n\n"
        f"{json.dumps(stats, indent=2)}\n\n"
        "SEVERITY RULES (follow exactly):\n"
        "- 'by_severity' gives the exact count of findings at each level. Use "
        "these numbers as-is; do not recompute or invent totals.\n"
        "- 'findings_by_type' lists each issue type with the severity the "
        "scanner assigned it. That label is authoritative.\n"
        "- Never describe an issue at a higher or lower severity than its "
        "label. If a missing header is labeled medium, do not call it "
        "high-severity or group it with the high-severity findings.\n"
        "- When naming the most serious issues, choose only from the Critical "
        "and High entries of 'findings_by_type'.\n\n"
        "- When naming the most serious issues, choose only from the Critical "
        "and High entries of 'findings_by_type'.\n"
        "- Mention every Critical and High issue type by name.\n"
        "- 'top_urls' only counts findings per URL. Do not speculate about "
        "traffic, usage, popularity or why findings concentrate on a page.\n\n"
        "Respond with ONLY a JSON object with exactly these two fields:\n"
        '  "executive_summary": a 120-200 word plain-text overview of the '
        "overall security posture, the most serious issues, and the business "
        "risk. No markdown.\n"
        '  "remediations": an array of 5-10 short strings, each a concrete, '
        "prioritized remediation action, most critical first. No numbering "
        "inside the strings.\n"
        "Base everything strictly on the data above. Do not invent findings."
    )


def clean_json_text(text):
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text).strip()
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    return m.group(0) if m else text


def call_ollama(prompt):
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.3, "num_predict": 1500},
    }
    url = f"{OLLAMA_URL}/api/generate"
    log(f"sending aggregated findings to local model ({OLLAMA_MODEL})")
    r = requests.post(url, json=payload, timeout=OLLAMA_TIMEOUT)
    r.raise_for_status()
    raw = r.json().get("response", "")
    return json.loads(clean_json_text(raw))


def write_output(data):
    with open(OUTPUT_FILE, "w") as fh:
        json.dump(data, fh, indent=2)


def write_txt(summary, remediations, generated_at):
    try:
        with open(os.path.join(OUTPUT_DIR, "ai_summary.txt"), "w") as tf:
            tf.write("DAST PLATFORM - AI SECURITY SUMMARY\n" + "=" * 50 + "\n\n")
            tf.write("EXECUTIVE OVERVIEW\n" + "-" * 50 + "\n")
            tf.write((summary or "No overview generated.") + "\n\n")
            tf.write("RECOMMENDED REMEDIATIONS\n" + "-" * 50 + "\n")
            if remediations:
                for i, rem in enumerate(remediations, 1):
                    tf.write(f"{i}. {rem}\n")
            else:
                tf.write("No remediations generated.\n")
            tf.write("\n" + "=" * 50 + "\n")
            tf.write(f"Generated: {generated_at}  |  Model: {OLLAMA_MODEL}\n")
    except Exception as e:
        log(f"WARN could not write .txt summary: {e}")


def index_es(doc):
    if Elasticsearch is None:
        return
    try:
        Elasticsearch(ES_URL).index(index=RESULT_INDEX, document=doc)
    except Exception as e:
        log(f"WARN ES index failed: {e}")


def main():
    app_type = load_config().get("app_type", "web application")
    write_output({"status": "running", "results": []})

    findings = fetch_findings()
    total = len(findings)
    log(f"{total} findings read from scan output")

    if total == 0:
        log("WARN no findings to summarize")
        write_output({"status": "complete",
                      "executive_summary": "No findings were available to summarize.",
                      "remediations": [], "results": []})
        return

    stats = aggregate(findings)
    log(f"aggregated severities: {stats['by_severity']}")

    try:
        data = call_ollama(build_prompt(stats, app_type))
    except Exception as e:
        log(f"ERROR Ollama call failed: {e}")
        write_output({"status": "error", "executive_summary": "", "remediations": [],
                      "message": f"Local AI model unavailable: {e}", "results": []})
        return

    summary = (data.get("executive_summary") or "").strip()
    remediations = data.get("remediations") or []
    if isinstance(remediations, str):
        remediations = [remediations]
    remediations = [str(x).strip() for x in remediations if str(x).strip()]

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    result_doc = {
        "status": "complete",
        "executive_summary": summary,
        "remediations": remediations,
        "stats": stats,
        "model": OLLAMA_MODEL,
        "generated_at": generated_at,
        "results": [
            {"name": f"Remediation {i}", "severity": "info", "explanation": rem}
            for i, rem in enumerate(remediations, 1)
        ],
    }
    write_output(result_doc)
    write_txt(summary, remediations, generated_at)
    index_es({"type": "summary", "executive_summary": summary,
              "remediations": remediations, "stats": stats,
              "model": OLLAMA_MODEL, "timestamp": generated_at})

    log(f"DONE - overview: {summary[:100]}...")
    log(f"remediations: {len(remediations)} items")


if __name__ == "__main__":
    main()
