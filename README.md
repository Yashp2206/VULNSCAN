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

## Project Architecture

```text
                              User
                                |
                +---------------+---------------+
                |                               |
                v                               v
        Command Line Interface             Web Browser
              main.py                         app.py
                |                               |
                +---------------+---------------+
                                |
                                v
                       Scanning Engine
                                |
             +------------------+------------------+
             |                  |                  |
             v                  v                  v
       Network Scanner     Web Scanner       SSL Checker
             |                  |                  |
             |                  |                  |
             +------------------+------------------+
                                |
                                v
                    Technology Detector
                                |
                                v
                         Scan Results
                                |
                    +-----------+-----------+
                    |                       |
                    v                       v
                 report.py             llama_ai.py
                    |                       |
                    v                       v
               PDF Report             Llama / Ollama
                                            |
                                            v
                                  AI Recommendations

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
1.[ Network Scan ]
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
```
2.[ Web Application Scan ]
URL: http://localhost:3000

Status code: 200

Missing security headers:
  - Content-Security-Policy:
    Mitigates XSS and data injection attacks.
  - Strict-Transport-Security:
    Helps enforce HTTPS connections.
  - X-Frame-Options:
    Helps prevent clickjacking attacks.

[!] Possible reflected XSS at:
    http://localhost:3000/?q=<test-payload>

No SQL error signatures detected with test payloads.
```
```
3.[ SSL Certificate Check ]

Issuer: Example Certificate Authority
Subject: example.com
Expires: 2027-05-10
Days left: 289

Certificate status: Valid
```
```
4.[ Technology Detection ]

Detected technology information:
  - Server: Example Web Server
  - X-Powered-By: Example Framework

Technology information is based on
headers exposed by the target web server.
```
```
5.[ AI Security Recommendation ]

Target: http://localhost:3000

Findings:
- Missing Content-Security-Policy header
- Missing X-Frame-Options header
- Possible reflected XSS
```

Recommendations:
1. Implement an appropriate Content-Security-Policy.
2. Configure X-Frame-Options or an equivalent
   frame-ancestors policy.
3. Properly validate and encode user-controlled input.
4. Review the affected parameter and application
   context for potential XSS exposure.

## Roadmap / Possible Extensions

- Add authenticated scanning using session cookies or authentication tokens
- Add CVE lookups for identified service and software versions
- Add rate limiting and configurable scan modes for controlled scanning
- Add HTML report output
- Add asynchronous I/O (`asyncio`) for faster large-range scans
- Add scan history and storage using a database such as SQLite
- Add security scoring to provide an overall risk score for each scan
- Add cookie security analysis (`Secure`, `HttpOnly`, `SameSite`)
- Add advanced SSL/TLS analysis including supported protocols and cipher information
- Improve technology detection and software/version fingerprinting
- Add more vulnerability checks to the web scanner
- Improve AI recommendations with more detailed remediation guidance
- Add user authentication and role-based access to the web interface
- Add Docker support for easier deployment
- Add cloud/VPS deployment for remote scanning and report access

## Disclaimer

This tool is for educational and authorized security testing purposes only.
The author is not responsible for misuse. Always get permission before
testing any system you do not own.
