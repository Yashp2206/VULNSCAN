"""
report.py
---------
Turns raw scan results into a readable text report and/or JSON file.
"""

import json
from datetime import datetime


def build_text_report(network_result=None, network_risks=None, web_result=None,
                       ssl_result=None, tech_result=None):
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
                    lines.append(f"    - {m['header']}: {m['why_it_matters']}")
            else:
                lines.append("  All checked security headers present.")

        xss = web_result.get("reflected_xss", {})
        if xss.get("vulnerable"):
            lines.append(f"  [!] Possible reflected XSS at: {xss['tested_url']}")
        elif "error" not in xss:
            lines.append("  No reflected XSS detected with test payload.")

        sqli = web_result.get("sql_injection", {})
        if sqli.get("possible_sqli"):
            lines.append(f"  [!] Possible SQL injection on param '{sqli['param_tested']}'")
            for f in sqli["findings"]:
                if f.get("vulnerable"):
                    lines.append(f"      payload={f['payload']!r} matched={f['matched_signatures']}")
        else:
            lines.append("  No SQL error signatures detected with test payloads.")

    if ssl_result:
        lines.append("\n[ SSL/TLS Certificate Check ]")
        if ssl_result.get("valid"):
            lines.append(f"  Issuer: {ssl_result.get('issuer')}")
            lines.append(f"  Subject: {ssl_result.get('subject')}")
            lines.append(f"  Expires: {ssl_result.get('expires')} ({ssl_result.get('days_left')} days left)")
            if ssl_result.get("warning"):
                lines.append(f"  [!] {ssl_result['warning']}")
        else:
            lines.append(f"  [!] {ssl_result.get('error')}")

    if tech_result:
        lines.append("\n[ Technology Detection ]")
        if tech_result.get("error"):
            lines.append(f"  Could not fetch URL: {tech_result['error']}")
        elif tech_result.get("found"):
            for d in tech_result["detected"]:
                lines.append(f"  - {d['header']}: {d['value']}")
        else:
            lines.append("  No technology-revealing headers found.")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def save_json_report(path, network_result=None, network_risks=None, web_result=None,
                      ssl_result=None, tech_result=None):
    data = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "network": network_result,
        "network_risks": network_risks,
        "web": web_result,
        "ssl": ssl_result,
        "technology": tech_result,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def save_pdf_report(path, network_result=None, network_risks=None, web_result=None,
                     ssl_result=None, tech_result=None):
    """Renders the same content as build_text_report() into a simple PDF."""
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("T", parent=styles["Title"], fontSize=18)
    h_style = ParagraphStyle("H", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1B998B"),
                              spaceBefore=14, spaceAfter=6)
    body_style = ParagraphStyle("B", parent=styles["Normal"], fontSize=9.5, fontName="Courier",
                                 leading=13, spaceAfter=3)
    alert_style = ParagraphStyle("A", parent=body_style, textColor=colors.HexColor("#E8763C"))

    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=0.7 * inch, bottomMargin=0.7 * inch,
                             leftMargin=0.7 * inch, rightMargin=0.7 * inch)
    story = [Paragraph("VulnScan Report", title_style),
             Paragraph(f"Generated: {datetime.now().isoformat(timespec='seconds')}", body_style),
             Spacer(1, 10)]

    if network_result:
        story.append(Paragraph("Network Scan", h_style))
        story.append(Paragraph(f"Host: {network_result['host']}", body_style))
        story.append(Paragraph(
            f"Ports scanned: {network_result['ports_scanned']} | Duration: {network_result['duration_seconds']}s",
            body_style))
        if network_result["open_ports"]:
            for p in network_result["open_ports"]:
                banner = f" | banner: {p['banner']}" if p["banner"] else ""
                story.append(Paragraph(f"- {p['port']}/tcp {p['service']}{banner}", body_style))
        else:
            story.append(Paragraph("No open ports found.", body_style))
        if network_risks:
            for r in network_risks:
                story.append(Paragraph(f"[!] Port {r['port']}: {r['risk']}", alert_style))

    if web_result:
        story.append(Paragraph("Web Application Scan", h_style))
        story.append(Paragraph(f"URL: {web_result['url']}", body_style))
        headers = web_result.get("security_headers", {})
        if "error" in headers:
            story.append(Paragraph(f"Could not fetch URL: {headers['error']}", alert_style))
        else:
            story.append(Paragraph(f"Status code: {headers.get('status_code')}", body_style))
            for m in headers.get("headers_missing", []):
                story.append(Paragraph(f"Missing: {m['header']} — {m['why_it_matters']}", body_style))
        xss = web_result.get("reflected_xss", {})
        if xss.get("vulnerable"):
            story.append(Paragraph(f"[!] Possible reflected XSS at: {xss['tested_url']}", alert_style))
        sqli = web_result.get("sql_injection", {})
        if sqli.get("possible_sqli"):
            story.append(Paragraph(f"[!] Possible SQL injection on param '{sqli['param_tested']}'", alert_style))

    if ssl_result:
        story.append(Paragraph("SSL/TLS Certificate Check", h_style))
        if ssl_result.get("valid"):
            story.append(Paragraph(f"Issuer: {ssl_result.get('issuer')}", body_style))
            story.append(Paragraph(f"Subject: {ssl_result.get('subject')}", body_style))
            story.append(Paragraph(
                f"Expires: {ssl_result.get('expires')} ({ssl_result.get('days_left')} days left)", body_style))
            if ssl_result.get("warning"):
                story.append(Paragraph(f"[!] {ssl_result['warning']}", alert_style))
        else:
            story.append(Paragraph(f"[!] {ssl_result.get('error')}", alert_style))

    if tech_result:
        story.append(Paragraph("Technology Detection", h_style))
        if tech_result.get("error"):
            story.append(Paragraph(f"Could not fetch URL: {tech_result['error']}", alert_style))
        elif tech_result.get("found"):
            for d in tech_result["detected"]:
                story.append(Paragraph(f"{d['header']}: {d['value']}", body_style))
        else:
            story.append(Paragraph("No technology-revealing headers found.", body_style))

    doc.build(story)
    return path