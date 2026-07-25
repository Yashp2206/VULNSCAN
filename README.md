# VulnScan

A lightweight vulnerability scanning prototype written in Python. It combines
**network scanning** (open ports, service/banner detection, basic risk notes)
and **web application scanning** (missing security headers, reflected XSS
detection, error-based SQL injection detection) into one command-line tool.

## Features

### Network Scanner
- Multi-threaded TCP port scanning
- Service name mapping for common ports
- Banner grabbing for basic service fingerprinting
- Basic risk analysis for potentially exposed services
- Risk notes for services such as Telnet, RDP, and database ports

### Web Vulnerability Scanner
- Security header analysis
- Detects missing security headers such as:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
- Reflected XSS detection using a safe, inert marker payload
- Error-based SQL injection detection using test payloads and common database error signatures

### SSL Certificate Checker
- Checks SSL/TLS certificate information
- Displays certificate issuer and subject
- Checks certificate expiry date
- Shows remaining certificate validity
- Provides warnings for certificates approaching expiry

### Technology Detection
- Detects technology-related information exposed through HTTP response headers
- Helps identify server/framework information revealed by the target

### Web Interface
- Flask-based web interface
- Target URL/host input
- Select individual scanning modules
- Displays scan results in a structured format
- Provides separate sections for network, web, SSL and technology results

### AI Security Recommendations
- Generates security recommendations based on scan results
- Uses Llama AI through Ollama
- Provides an easy-to-understand interpretation of detected security issues
- Helps suggest possible remediation steps

### Reporting
- Generates a readable scan report
- PDF report generation and download
- Report includes network and web scan findings
- AI recommendations can be viewed separately through the web interface

## Installation

```bash
git clone <your-repo-url>
cd vulnscan
pip install -r requirements.txt
```

## Usage

```bash
# Network scan only
python main.py --network scanme.nmap.org

# Network scan with custom ports
python main.py --network 192.168.1.10 --ports 22,80,443,3306

# Web scan only
python main.py --web http://localhost:3000 --xss-param q --sqli-param id

# Both, with JSON output
python main.py --network 192.168.1.10 --web http://192.168.1.10 --json report.json
```

## Example output

```
[ Network Scan ]
Host: scanme.nmap.org
Ports scanned: 13
Open ports:
  - 22/tcp  SSH  | banner: SSH-2.0-OpenSSH_6.6.1p1
  - 80/tcp  HTTP

[ Web Application Scan ]
URL: http://localhost:3000
  Missing security headers:
    - Content-Security-Policy: Mitigates XSS and data injection attacks.
  [!] Possible reflected XSS at: http://localhost:3000/?q=<script>...
```

## Project structure

```
vulnscan/
├── main.py                    # CLI entry point
├── vulnscan/
│   ├── network_scanner.py     # Port scanning + banner grabbing
│   ├── web_scanner.py         # Header checks, XSS/SQLi detection
│   └── report.py              # Text + JSON report generation
├── requirements.txt
└── README.md
```

## How it works (talking points for interviews)

- **Port scanning**: opens raw TCP sockets against a host and uses
  `connect_ex()` to non-blockingly test whether each port accepts
  connections, using a thread pool for speed.
- **Banner grabbing**: after a successful connection, reads the first bytes
  the service sends back — many services (SSH, FTP, HTTP) announce their
  name/version unprompted, which is useful for fingerprinting.
- **Security headers**: modern browsers enforce protections (like blocking
  inline scripts) only if the server explicitly sends headers like
  `Content-Security-Policy`. Missing headers are a common, easy-to-fix
  weakness auditors flag.
- **Reflected XSS detection**: sends a harmless marker string wrapped in a
  `<script>` tag as a query parameter, then checks if the *raw, unescaped*
  tag comes back in the HTML response — a sign user input isn't being
  encoded before being echoed back.
- **SQL injection detection**: sends characters that break out of a typical
  SQL string context (`'`, `"`, `OR '1'='1`) and checks whether the response
  contains known database error message fragments — a classic
  "error-based" detection technique.

## Roadmap / possible extensions

- Add authenticated scanning (session cookies/tokens)
- Add CVE lookups for identified service versions
- Add rate limiting / stealth scan modes
- Add HTML report output
- Add async I/O (`asyncio`) for faster large-range scans

## Disclaimer

This tool is for educational and authorized security testing purposes only.
The author is not responsible for misuse. Always get permission before
testing any system you do not own.
