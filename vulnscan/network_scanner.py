"""
network_scanner.py
-------------------
A lightweight TCP port scanner with banner grabbing.

"""

import socket
import concurrent.futures
from datetime import datetime

# A small set of common ports and the service usually running on them.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}


def grab_banner(sock):
    """Try to read a short banner/response from an open socket."""
    try:
        sock.settimeout(1.0)
        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip()
    except Exception:
        return ""


def scan_port(host, port, timeout=1.0):
    """Attempt to connect to a single port. Returns a result dict or None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = grab_banner(sock)
                service = COMMON_PORTS.get(port, "unknown")
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                }
    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {host}")
    except Exception:
        pass
    return None


def scan_host(host, ports=None, max_workers=100):
    """
    Scan a host across a list of ports (defaults to COMMON_PORTS).
    Returns a list of dicts describing open ports found.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    start = datetime.now()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])
    duration = (datetime.now() - start).total_seconds()

    return {
        "host": host,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "duration_seconds": round(duration, 2),
    }


def analyze_risks(scan_result):
    """
    Give simple, human-readable risk notes for commonly-risky open services.
    This is intentionally basic/educational, not a full CVE database.
    """
    risky_notes = {
        21: "FTP often transmits credentials in plaintext. Consider SFTP/FTPS.",
        23: "Telnet is unencrypted. Use SSH instead.",
        3389: "RDP exposed to the internet is a common ransomware entry point.",
        3306: "Database port exposed publicly increases attack surface.",
        5432: "Database port exposed publicly increases attack surface.",
    }
    findings = []
    for entry in scan_result["open_ports"]:
        note = risky_notes.get(entry["port"])
        if note:
            findings.append({"port": entry["port"], "risk": note})
    return findings
