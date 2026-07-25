"""
report.py
---------
Turns raw scan results into a readable text report and/or JSON file.
"""

import json
from datetime import datetime

from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet


def build_text_report(network_result=None, network_risks=None, web_result=None):
    lines = []
    lines.append("=" * 60)
    lines.append("VulnScan Report")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("=" * 60)

    if network_result:
        lines.append("\n[ Network Scan ]")
        lines.append(f"Host: {network_result['host']}")
        lines.append(f"Ports scanned: {network_result['ports_scanned']}")
        lines.append(f"Duration: {network_result['duration_seconds']}s")

        if network_result["open_ports"]:
            lines.append("Open ports:")

            for p in network_result["open_ports"]:
                banner = f" | banner: {p['banner']}" if p["banner"] else ""
                lines.append(f"  - {p['port']}/tcp  {p['service']}{banner}")

        else:
            lines.append("No open ports found among scanned ports.")

        if network_risks:
            lines.append("Risk notes:")

            for r in network_risks:
                lines.append(f"  - Port {r['port']}: {r['risk']}")

    if web_result:
        lines.append("\n[ Web Application Scan ]")
        lines.append(f"URL: {web_result['url']}")

        headers = web_result.get("security_headers", {})

        if "error" in headers:
            lines.append(f"  Could not fetch URL: {headers['error']}")

        else:
            lines.append(f"  Status code: {headers.get('status_code')}")

            missing = headers.get("headers_missing", [])

            if missing:
                lines.append("  Missing security headers:")

                for m in missing:
                    lines.append(
                        f"    - {m['header']}: {m['why_it_matters']}"
                    )

            else:
                lines.append("  All checked security headers present.")

        xss = web_result.get("reflected_xss", {})

        if xss.get("vulnerable"):
            lines.append(
                f"  [!] Possible reflected XSS at: {xss['tested_url']}"
            )

        elif "error" not in xss:
            lines.append(
                "  No reflected XSS detected with test payload."
            )

        sqli = web_result.get("sql_injection", {})

        if sqli.get("possible_sqli"):

            lines.append(
                f"  [!] Possible SQL injection on param '{sqli['param_tested']}'"
            )

            for f in sqli["findings"]:

                if f.get("vulnerable"):

                    lines.append(
                        f"      payload={f['payload']!r} matched={f['matched_signatures']}"
                    )

        else:
            lines.append(
                "  No SQL error signatures detected with test payloads."
            )

    lines.append("\n" + "=" * 60)

    return "\n".join(lines)


def save_json_report(path, network_result=None, network_risks=None, web_result=None):

    data = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "network": network_result,
        "network_risks": network_risks,
        "web": web_result,
    }

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    return path


# ============================================================
# PDF REPORT GENERATOR (Added)
# ============================================================

styles = getSampleStyleSheet()


def generate_pdf(path, report_text):
    """
    Generates a PDF report from the text report.
    """

    doc = SimpleDocTemplate(path)

    story = []

    for line in report_text.split("\n"):

        story.append(
            Paragraph(
                line.replace(" ", "&nbsp;"),
                styles["BodyText"]
            )
        )

    doc.build(story)

    return path