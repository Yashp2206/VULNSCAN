#!/usr/bin/env python3
"""
VulnScan - a lightweight vulnerability scanning prototype.


"""

import argparse
import sys

from vulnscan import network_scanner, web_scanner, report


def main():
    parser = argparse.ArgumentParser(description="VulnScan - network + web vulnerability scanner prototype")
    parser.add_argument("--network", metavar="HOST", help="Host/IP to port-scan")
    parser.add_argument("--ports", metavar="PORTS", help="Comma-separated ports (default: common ports)")
    parser.add_argument("--web", metavar="URL", help="Base URL to run web checks against")
    parser.add_argument("--xss-param", default="q", help="Query param name to test for reflected XSS")
    parser.add_argument("--sqli-param", default="id", help="Query param name to test for SQL injection")
    parser.add_argument("--json", metavar="PATH", help="Also save results as JSON to this path")

    args = parser.parse_args()

    if not args.network and not args.web:
        parser.print_help()
        sys.exit(1)

    network_result, network_risks, web_result = None, None, None

    if args.network:
        ports = None
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        print(f"[*] Scanning network host: {args.network}")
        network_result = network_scanner.scan_host(args.network, ports=ports)
        network_risks = network_scanner.analyze_risks(network_result)

    if args.web:
        print(f"[*] Running web checks on: {args.web}")
        web_result = web_scanner.scan_web(args.web, xss_param=args.xss_param, sqli_param=args.sqli_param)

    text_report = report.build_text_report(network_result, network_risks, web_result)
    print("\n" + text_report)

    if args.json:
        report.save_json_report(args.json, network_result, network_risks, web_result)
        print(f"\n[*] JSON report saved to {args.json}")


if __name__ == "__main__":
    main()
