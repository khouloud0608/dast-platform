import json
import os
import uuid
import requests
from datetime import datetime
from elasticsearch import Elasticsearch

# ── Configuration ────────────────────────────────────────────
ES_HOST   = os.environ.get("ES_HOST", "elasticsearch")
ES_PORT   = os.environ.get("ES_PORT", "9200")
INPUT     = os.environ.get("INPUT_FILE", "/app/input/crawl_results.json")
OUTPUT    = os.environ.get("OUTPUT_FILE", "/app/output/passive_results.json")
ES_INDEX  = "dast-passive"

# ── Elasticsearch setup ───────────────────────────────────────
es = Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")

def ensure_index():
    if not es.indices.exists(index=ES_INDEX):
        es.indices.create(index=ES_INDEX, body={
            "mappings": {
                "properties": {
                    "url":       {"type": "keyword"},
                    "check":     {"type": "keyword"},
                    "severity":  {"type": "keyword"},
                    "detail":    {"type": "text"},
                    "evidence":  {"type": "text"},
                    "timestamp": {"type": "date"},
                }
            }
        })

# ── Security headers to check ─────────────────────────────────
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "detail": "Content-Security-Policy header is missing. This allows XSS attacks to execute malicious scripts.",
        "recommendation": "Add 'Content-Security-Policy: default-src self' header."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "detail": "X-Frame-Options header is missing. The page can be embedded in an iframe (Clickjacking risk).",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "detail": "HSTS header is missing. Browsers may access this site over HTTP instead of HTTPS.",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "detail": "X-Content-Type-Options header is missing. Browser may misinterpret file types (MIME sniffing).",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "detail": "Referrer-Policy header is missing. Sensitive URLs may be leaked to third parties.",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header."
    },
    "Permissions-Policy": {
        "severity": "Info",
        "detail": "Permissions-Policy header is missing. Browser features are not restricted.",
        "recommendation": "Add Permissions-Policy header to restrict access to browser features."
    },
}

# ── Cookie checks ─────────────────────────────────────────────
def check_cookies(url, response_headers):
    findings = []
    set_cookie = response_headers.get("Set-Cookie", "")
    if not set_cookie:
        return findings

    if "httponly" not in set_cookie.lower():
        findings.append(create_finding(
            url=url,
            check="Insecure Cookie — Missing HttpOnly",
            severity="High",
            detail="Cookie is missing the HttpOnly flag. JavaScript can access and steal it (XSS risk).",
            evidence=set_cookie[:200],
            recommendation="Add 'HttpOnly' flag to all session cookies."
        ))

    if "secure" not in set_cookie.lower():
        findings.append(create_finding(
            url=url,
            check="Insecure Cookie — Missing Secure",
            severity="Medium",
            detail="Cookie is missing the Secure flag. It may be transmitted over unencrypted HTTP.",
            evidence=set_cookie[:200],
            recommendation="Add 'Secure' flag to all cookies."
        ))

    if "samesite" not in set_cookie.lower():
        findings.append(create_finding(
            url=url,
            check="Insecure Cookie — Missing SameSite",
            severity="Medium",
            detail="Cookie is missing the SameSite attribute. Vulnerable to CSRF attacks.",
            evidence=set_cookie[:200],
            recommendation="Add 'SameSite=Strict' or 'SameSite=Lax' to all cookies."
        ))

    return findings

# ── HTML content checks ───────────────────────────────────────
def check_html_content(url, html):
    findings = []
    html_lower = html.lower()

    # Stack traces
    if any(kw in html_lower for kw in ["traceback", "stack trace", "exception in", "fatal error"]):
        findings.append(create_finding(
            url=url,
            check="Sensitive Data — Stack Trace Exposed",
            severity="High",
            detail="A stack trace or error message is exposed in the HTML response. Server internals may be leaked.",
            evidence="Stack trace detected in response body.",
            recommendation="Disable detailed error messages in production. Use custom error pages."
        ))

    # PHP errors
    if any(kw in html_lower for kw in ["php warning", "php notice", "php fatal", "php parse error"]):
        findings.append(create_finding(
            url=url,
            check="Sensitive Data — PHP Error Exposed",
            severity="Medium",
            detail="PHP error or warning message is visible in the response.",
            evidence="PHP error detected in response body.",
            recommendation="Set 'display_errors = Off' in php.ini for production."
        ))

    # Version disclosure in HTML comments
    import re
    version_patterns = [
        r'version\s*[:\=]\s*[\d\.]+',
        r'v\d+\.\d+\.\d+',
        r'powered by .{1,30}\d+\.\d+',
    ]
    for pattern in version_patterns:
        matches = re.findall(pattern, html_lower)
        if matches:
            findings.append(create_finding(
                url=url,
                check="Information Disclosure — Version Number",
                severity="Low",
                detail="Version information is exposed in the page content.",
                evidence=str(matches[:3]),
                recommendation="Remove version numbers from HTML content and HTTP headers."
            ))
            break

    return findings

# ── Server header check ───────────────────────────────────────
def check_server_header(url, response_headers):
    findings = []
    server = response_headers.get("Server", "")
    x_powered = response_headers.get("X-Powered-By", "")

    if server:
        findings.append(create_finding(
            url=url,
            check="Information Disclosure — Server Header",
            severity="Low",
            detail=f"Server header reveals technology information: '{server}'",
            evidence=server,
            recommendation="Remove or obscure the Server header in web server configuration."
        ))

    if x_powered:
        findings.append(create_finding(
            url=url,
            check="Information Disclosure — X-Powered-By Header",
            severity="Low",
            detail=f"X-Powered-By header reveals technology: '{x_powered}'",
            evidence=x_powered,
            recommendation="Remove X-Powered-By header from responses."
        ))

    return findings

# ── Finding factory ───────────────────────────────────────────
def create_finding(url, check, severity, detail, evidence="", recommendation=""):
    return {
        "finding_id": str(uuid.uuid4()),
        "url": url,
        "check": check,
        "severity": severity,
        "detail": detail,
        "evidence": evidence,
        "recommendation": recommendation,
        "timestamp": datetime.utcnow().isoformat(),
        "module": "passive-scanner"
    }

# ── Main scan function ────────────────────────────────────────
def scan_url(url):
    findings = []
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        headers = dict(response.headers)
        html = response.text

        # 1. Check security headers
        for header, info in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(create_finding(
                    url=url,
                    check=f"Missing Header — {header}",
                    severity=info["severity"],
                    detail=info["detail"],
                    evidence=f"Header '{header}' not present in response.",
                    recommendation=info["recommendation"]
                ))

        # 2. Check cookies
        findings.extend(check_cookies(url, headers))

        # 3. Check HTML content
        findings.extend(check_html_content(url, html))

        # 4. Check server header
        findings.extend(check_server_header(url, headers))

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to scan {url}: {e}")

    return findings

# ── Main ──────────────────────────────────────────────────────
def main():
    print(f"[*] Starting passive scanner")
    print(f"[*] Reading crawl results from {INPUT}")

    ensure_index()

    with open(INPUT, "r") as f:
        crawl_results = json.load(f)

    print(f"[*] Found {len(crawl_results)} URLs to scan")

    all_findings = []
    seen_urls = set()

    for item in crawl_results:
        url = item["url"]

        # Replace dvwa hostname with localhost for scanning from inside container
        scan_url_addr = url.replace("http://dvwa:80", "http://dvwa:80")

        if url in seen_urls:
            continue
        seen_urls.add(url)

        print(f"[*] Scanning: {url}")
        findings = scan_url(scan_url_addr)
        print(f"    → {len(findings)} findings")

        for finding in findings:
            all_findings.append(finding)
            try:
                es.index(index=ES_INDEX, document=finding)
            except Exception as e:
                print(f"[ERROR] ES index failed: {e}")

    # Save to JSON
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(all_findings, f, indent=2, default=str)

    print(f"\n[+] Passive scan complete!")
    print(f"[+] Total findings: {len(all_findings)}")

    # Summary by severity
    from collections import Counter
    severity_count = Counter(f["severity"] for f in all_findings)
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev in severity_count:
            print(f"    {sev}: {severity_count[sev]}")

    print(f"[+] Results saved to {OUTPUT}")
    print(f"[+] Results indexed in Elasticsearch: {ES_INDEX}")

if __name__ == "__main__":
    main()
