#!/usr/bin/env python3
"""
AI Proxy / Broker
=================
Single, network-internal chokepoint between the DAST platform and the external
LLM (Groq). Three security controls enforced in ONE place:

  1. KEY ISOLATION      - the Groq API key lives ONLY here (from env). No
                          scanner, crawler, ai-module, or GUI holds it.
  2. DATA MINIMIZATION  - incoming findings are reduced to aggregate statistics
                          (severity counts + vulnerability TYPES). URLs,
                          payloads, evidence, parameters are DROPPED and never
                          leave the platform boundary.
  3. NETWORK SEGMENTATION - publishes NO host ports (see compose); reachable
                          only from inside dast-net. The only outbound call is
                          proxy -> Groq over HTTPS.

Contract: ai-module POSTs {"findings":[...], "app_type":"..."} to /summarize.
"""

import os
import sys
import json
from collections import Counter

import requests
from flask import Flask, request, jsonify

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL   = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"
GROQ_TIMEOUT = int(os.getenv("GROQ_TIMEOUT", "60"))
PORT         = int(os.getenv("PROXY_PORT", "5000"))

app = Flask(__name__)


def sanitize(findings):
    """
    SECURITY CONTROL #2 - reduce raw findings to aggregate stats ONLY.
    Drops url, payload, evidence, parameter, detail. Keeps counts + type names.
    """
    severity_counts = Counter()
    active_types = Counter()
    passive_types = Counter()

    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or f.get("risk") or "info").capitalize()
        severity_counts[sev] += 1
        vtype = f.get("vuln_type")
        check = f.get("check")
        if vtype:
            active_types[str(vtype)] += 1
        elif check:
            passive_types[str(check)] += 1

    return {
        "total_findings": sum(severity_counts.values()),
        "severity_counts": dict(severity_counts),
        "active_vulnerability_types": dict(active_types),
        "passive_issue_types": dict(passive_types),
    }


def build_prompt(app_type, stats):
    return f"""You are a senior application security consultant writing the executive \
summary of an automated DAST (Dynamic Application Security Testing) report.

You are given ONLY aggregate statistics about the findings (no URLs, no payloads, \
no sensitive data). Application category: {app_type}.

Findings summary (JSON):
{json.dumps(stats, indent=2)}

Write your response in TWO clearly labelled sections:

OVERVIEW:
A concise 4-6 sentence executive overview of the application's security posture, \
referencing the severity distribution and the main classes of vulnerability found. \
Write for a technical manager. Do not invent specific URLs or data you were not given.

REMEDIATIONS:
A prioritized, consolidated list of remediation actions (one per line, each starting \
with "- "), ordered most critical first, addressing the vulnerability classes present. \
Keep each item to one actionable sentence."""


def call_groq(prompt):
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 900,
    }
    r = requests.post(GROQ_URL, headers=headers, json=body, timeout=GROQ_TIMEOUT)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


def split_sections(text):
    overview, remediations = text, []
    up = text.upper()
    if "REMEDIATION" in up:
        idx = up.index("REMEDIATION")
        overview_part = text[:idx]
        rem_part = text[idx:]
        rem_lines = rem_part.split("\n", 1)
        rem_body = rem_lines[1] if len(rem_lines) > 1 else ""
        remediations = [ln.strip(" -\t").strip()
                        for ln in rem_body.splitlines()
                        if ln.strip(" -\t").strip()]
        overview = overview_part
    for label in ("OVERVIEW:", "OVERVIEW"):
        if overview.strip().upper().startswith(label):
            overview = overview.strip()[len(label):].strip()
            break
    return overview.strip(), remediations


@app.route("/health")
def health():
    return jsonify({"status": "ok", "model": GROQ_MODEL,
                    "key_present": bool(GROQ_API_KEY)})


@app.route("/summarize", methods=["POST"])
def summarize():
    payload = request.get_json(silent=True) or {}
    findings = payload.get("findings", [])
    app_type = payload.get("app_type", "web application")

    if not findings:
        return jsonify({"error": "no findings provided"}), 400

    stats = sanitize(findings)               # sanitize BEFORE anything leaves
    print(f"[proxy] sanitized -> {json.dumps(stats)}", flush=True)

    try:
        text = call_groq(build_prompt(app_type, stats))
        overview, remediations = split_sections(text)
        return jsonify({
            "executive_summary": overview,
            "remediations": remediations,
            "stats": stats,
            "model": GROQ_MODEL,
        })
    except requests.exceptions.RequestException as e:
        print(f"[proxy] Groq call failed: {e}", flush=True)
        return jsonify({"error": "LLM upstream failed", "detail": str(e)[:200]}), 502


if __name__ == "__main__":
    if not GROQ_API_KEY:
        print("[proxy] FATAL: GROQ_API_KEY is not set. Refusing to start.",
              file=sys.stderr)
        sys.exit(1)
    print(f"[proxy] starting on :{PORT} model={GROQ_MODEL}", flush=True)
    app.run(host="0.0.0.0", port=PORT)
