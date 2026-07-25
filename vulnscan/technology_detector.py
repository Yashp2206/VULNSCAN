"""
technology_detector.py
Detects server/technology hints from HTTP response headers.
"""

import requests

TECH_HEADERS = [
    "Server",
    "X-Powered-By",
    "Via",
    "CF-Cache-Status",
    "CF-RAY",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]


def detect_technology(url):
    """
    Fetches the URL and returns a dict describing which technology-revealing
    headers were present. Returns: {status_code, detected, error}
    """
    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=10)
    except requests.RequestException as e:
        return {"url": url, "error": str(e)}

    detected = []
    for header in TECH_HEADERS:
        if header in response.headers:
            detected.append({"header": header, "value": response.headers[header]})

    return {
        "url": url,
        "status_code": response.status_code,
        "detected": detected,
        "found": len(detected) > 0,
    }
