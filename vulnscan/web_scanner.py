"""
web_scanner.py
--------------
Lightweight web application checks:
"""

import requests
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

TIMEOUT = 6

SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS and data injection attacks.",
    "Strict-Transport-Security": "Forces HTTPS, prevents downgrade attacks.",
    "X-Frame-Options": "Prevents clickjacking via iframes.",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks.",
    "Referrer-Policy": "Controls how much referrer info is leaked.",
    "Permissions-Policy": "Restricts access to browser features/APIs.",
}

# Marker used to detect reflected XSS without ever executing a real script.
XSS_MARKER = "vulnscan_xss_test_12345"
XSS_PAYLOAD = f"<script>{XSS_MARKER}</script>"

# Payloads that commonly trigger SQL errors if input isn't sanitized.
SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' ORDER BY 1--"]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "pg_query()",
    "odbc sql server driver",
    "ora-01756",
]


def check_security_headers(url):
    """Fetch the URL and report which recommended security headers are missing."""
    try:
        resp = requests.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        return {"error": str(e)}

    present = {}
    missing = []
    for header, why in SECURITY_HEADERS.items():
        if header in resp.headers:
            present[header] = resp.headers[header]
        else:
            missing.append({"header": header, "why_it_matters": why})

    return {
        "status_code": resp.status_code,
        "headers_present": present,
        "headers_missing": missing,
    }


def _inject_param(url, param, value):
    """Return a copy of url with `param` set to `value` in the query string."""
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query))
    query[param] = value
    new_query = urlencode(query)
    return urlunparse(parts._replace(query=new_query))


def test_reflected_xss(url, param="q"):
    """
    Send a harmless marker payload as a query parameter and check whether
    it comes back unescaped in the response (a sign of reflected XSS).
    """
    test_url = _inject_param(url, param, XSS_PAYLOAD)
    try:
        resp = requests.get(test_url, timeout=TIMEOUT)
    except requests.RequestException as e:
        return {"tested_url": test_url, "error": str(e)}

    reflected_raw = XSS_PAYLOAD in resp.text
    return {
        "tested_url": test_url,
        "vulnerable": reflected_raw,
        "note": (
            "Payload reflected without encoding — likely vulnerable to XSS."
            if reflected_raw
            else "Payload not found unescaped in response."
        ),
    }


def test_sql_injection(url, param="id"):
    """
    Send common SQLi trigger characters and look for database error
    signatures in the response. This is error-based detection only —
    it does not attempt to extract data.
    """
    findings = []
    for payload in SQLI_PAYLOADS:
        test_url = _inject_param(url, param, payload)
        try:
            resp = requests.get(test_url, timeout=TIMEOUT)
        except requests.RequestException as e:
            findings.append({"payload": payload, "error": str(e)})
            continue

        text_lower = resp.text.lower()
        matched = [sig for sig in SQL_ERROR_SIGNATURES if sig in text_lower]
        if matched:
            findings.append({
                "payload": payload,
                "tested_url": test_url,
                "vulnerable": True,
                "matched_signatures": matched,
            })

    return {
        "param_tested": param,
        "possible_sqli": len(findings) > 0,
        "findings": findings,
    }


def scan_web(url, xss_param="q", sqli_param="id"):
    """Run all web checks and return a combined report."""
    return {
        "url": url,
        "security_headers": check_security_headers(url),
        "reflected_xss": test_reflected_xss(url, xss_param),
        "sql_injection": test_sql_injection(url, sqli_param),
    }
