"""
app.py
A simple web front-end for VulnScan: enter a target, choose which scans
to run, and view the report in the browser.

Run with:
    python3 app.py
Then open http://127.0.0.1:5000 in your browser.
"""

from flask import Flask, render_template, request, send_file

from vulnscan import network_scanner, web_scanner, report
from vulnscan.llama_ai import generate_ai

try:
    from vulnscan import ssl_checker
except ImportError:
    ssl_checker = None

try:
    from vulnscan import technology_detector
except ImportError:
    technology_detector = None

app = Flask(__name__)

# Store latest scan
LAST_RESULTS = {}
LAST_TARGET = ""


def normalize_url(target):
    """Ensure a target has an http(s):// prefix for web-based checks."""
    if not target.startswith("http://") and not target.startswith("https://"):
        return "http://" + target
    return target


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    global LAST_RESULTS, LAST_TARGET

    target = request.form.get("target", "").strip()
    scans = request.form.getlist("scans")
    error = None
    results = {}

    if not target:
        error = "Please enter a host or URL."
        return render_template(
            "results.html",
            target=target,
            results=results,
            error=error
        )

    if "network" in scans:
        try:
            host_only = target.replace("http://", "").replace("https://", "").split("/")[0]

            network_result = network_scanner.scan_host(host_only)

            results["network"] = network_result

            results["network_risks"] = network_scanner.analyze_risks(network_result)

        except ValueError as e:
            results["network_error"] = str(e)

    if "web" in scans:
        url = normalize_url(target)
        results["web"] = web_scanner.scan_web(url)

    if "ssl" in scans:
        if ssl_checker:
            host_only = target.replace("http://", "").replace("https://", "").split("/")[0]
            results["ssl"] = ssl_checker.check_ssl(host_only)
        else:
            results["ssl_error"] = "ssl_checker module not found."

    if "tech" in scans:
        if technology_detector:
            url = normalize_url(target)
            results["tech"] = technology_detector.detect_technology(url)
        else:
            results["tech_error"] = "technology_detector module not found."

    # Save latest scan
    LAST_RESULTS = results
    LAST_TARGET = target

    return render_template(
        "results.html",
        target=target,
        results=results,
        error=error
    )


@app.route("/download")
@app.route("/download")
def download():

    report_text = report.build_text_report(
        network_result=LAST_RESULTS.get("network"),
        network_risks=LAST_RESULTS.get("network_risks"),
        web_result=LAST_RESULTS.get("web")
    )

    filename = "VulnScan_Report.pdf"

    report.generate_pdf(
        filename,
        report_text
    )

    return send_file(
        filename,
        as_attachment=True
    )


@app.route("/ai")
def ai():

    report_text = report.build_text_report(
        network_result=LAST_RESULTS.get("network"),
        network_risks=LAST_RESULTS.get("network_risks"),
        web_result=LAST_RESULTS.get("web")
    )

    recommendation = generate_ai(report_text)

    return render_template(
        "ai.html",
        recommendation=recommendation,
        target=LAST_TARGET
    )


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)