#!/usr/bin/env python3
"""
AI Module (proxy client)
========================
Reads findings from Elasticsearch, sends them to the internal AI PROXY
(which holds the key and sanitizes the data), and writes the returned
overview + remediation list to ai_summary.json.

This module holds NO API key and never calls any external service directly.
Its only outbound call is to http://ai-proxy:5000 inside dast-net.
"""

import os
import json
import time
import requests
from elasticsearch import Elasticsearch

# --- Config ---
ES_URL       = os.getenv("ES_URL", "http://elasticsearch:9200")
PROXY_URL    = os.getenv("PROXY_URL", "http://ai-proxy:5000/summarize")
PROXY_TIMEOUT = int(os.getenv("PROXY_TIMEOUT", "90"))
CONFIG_PATH  = "/app/config.json"
OUTPUT_FILE  = "/app/output/ai_summary.json"
RESULT_INDEX = "dast-ai"

es = Elasticsearch(ES_URL)


def load_app_type():
    """Read app_type from config so the summary knows the target category."""
    try:
        if os.path.isfile(CONFIG_PATH):
            with open(CONFIG_PATH) as f:
                return json.load(f).get("app_type", "web application")
    except Exception:
        pass
    return "web application"


def fetch_findings():
    """
    Read the CURRENT scan's findings from the JSON files the scanners produce,
    NOT from Elasticsearch. ES indices accumulate across every scan, which would
    inflate the summary with data from previous/other-target scans. The JSON
    files are per-scan (the crawler truncates them at the start of each run), so
    the AI summary matches exactly what the reporter shows.
    """
    findings = []
    for fname in ("active_results.json", "passive_results.json"):
        path = os.path.join("/app/output", fname)
        try:
            with open(path) as f:
                data = json.load(f)
                if isinstance(data, list):
                    findings.extend(data)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[WARN] Could not read {fname}: {e}")
    return findings


def write_output(data):
    with open(OUTPUT_FILE, "w") as fh:
        json.dump(data, fh, indent=2)


def main():
    app_type = load_app_type()
    findings = fetch_findings()
    total = len(findings)
    print(f"[INFO] {total} findings read from Elasticsearch")

    # Show 'running' state immediately (GUI polls this file).
    write_output({"status": "running", "results": []})

    if total == 0:
        print("[WARN] No findings to summarize.")
        write_output({
            "status": "complete",
            "executive_summary": "No findings were available to summarize.",
            "results": [],
        })
        return

    # Send RAW findings to the proxy. The proxy sanitizes to aggregate stats
    # before anything leaves the platform boundary. This module has no key.
    try:
        print(f"[INFO] Sending {total} findings to proxy at {PROXY_URL}")
        r = requests.post(
            PROXY_URL,
            json={"findings": findings, "app_type": app_type},
            timeout=PROXY_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Proxy call failed: {e}")
        # Graceful degradation: reporter/GUI fall back to their generated summary.
        write_output({
            "status": "error",
            "executive_summary": "",
            "message": f"AI proxy unavailable: {e}",
            "results": [],
        })
        return

    executive_summary = data.get("executive_summary", "")
    remediations = data.get("remediations", [])
    stats = data.get("stats", {})

    # Shape the output to what the reporter reads (executive_summary) and what
    # the GUI's AI panel renders (executive_summary + optional results list).
    result_doc = {
        "status": "complete",
        "executive_summary": executive_summary,
        "remediations": remediations,
        "stats": stats,
        "model": data.get("model", ""),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # 'results' kept for GUI compatibility; each remediation as an item.
        "results": [
            {"name": "Remediation", "severity": "info", "explanation": rem}
            for rem in remediations
        ],
    }
    write_output(result_doc)

    # Also write a human-readable .txt for easy download (not raw JSON).
    try:
        txt_path = "/app/output/ai_summary.txt"
        with open(txt_path, "w") as tf:
            tf.write("DAST PLATFORM - AI SECURITY SUMMARY\n")
            tf.write("=" * 50 + "\n\n")
            tf.write("EXECUTIVE OVERVIEW\n")
            tf.write("-" * 50 + "\n")
            tf.write((executive_summary or "No overview generated.") + "\n\n")
            tf.write("RECOMMENDED REMEDIATIONS\n")
            tf.write("-" * 50 + "\n")
            if remediations:
                for i, rem in enumerate(remediations, 1):
                    tf.write(f"{i}. {rem}\n")
            else:
                tf.write("No remediations generated.\n")
            tf.write("\n" + "=" * 50 + "\n")
            tf.write(f"Generated: {result_doc['generated_at']}  |  Model: {data.get('model','')}\n")
        print(f"[INFO] Readable summary written to {txt_path}")
    except Exception as e:
        print(f"[WARN] Could not write .txt summary: {e}")

    # Index the summary into ES for Kibana, non-fatal if it fails.
    try:
        es.index(index=RESULT_INDEX, document={
            "type": "summary",
            "executive_summary": executive_summary,
            "remediations": remediations,
            "stats": stats,
            "timestamp": result_doc["generated_at"],
        })
    except Exception as e:
        print(f"[WARN] ES index failed: {e}")

    print(f"[DONE] Summary written to {OUTPUT_FILE}")
    print(f"       Overview: {executive_summary[:100]}...")
    print(f"       Remediations: {len(remediations)} items")


if __name__ == "__main__":
    main()
