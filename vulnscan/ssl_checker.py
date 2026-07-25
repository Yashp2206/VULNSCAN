"""
ssl_checker.py
Checks a host's SSL/TLS certificate: validity, issuer, and expiry.
"""

import ssl
import socket
from datetime import datetime


def check_ssl(host, port=443, timeout=6):
    """
    Connects to host:port over TLS and returns certificate details.
    Returns a dict with keys: valid, issuer, subject, expires, days_left, error
    """
    host = host.replace("http://", "").replace("https://", "").split("/")[0]

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        expires_str = cert.get("notAfter")
        expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.utcnow()).days

        return {
            "valid": True,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
            "subject": subject.get("commonName", "Unknown"),
            "expires": expires_str,
            "days_left": days_left,
            "warning": "Certificate expires soon!" if days_left < 30 else None,
        }

    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificate verification failed: {e}"}
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        return {"valid": False, "error": f"Could not connect: {e}"}
    except Exception as e:
        return {"valid": False, "error": str(e)}
