# Prism — Simple Web Vulnerability Scanner

Prism is a lightweight, beginner-friendly web security checker built with a single Flask backend and one HTML frontend. It performs a focused set of non-intrusive checks and turns the results into clear findings with fix suggestions.

> Only scan targets that you own or have explicit permission to test.

## Features

- Checks common TCP ports: 21, 22, 80, 443, 3306, and 8080
- Audits Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, and X-Content-Type-Options
- Reports Server and X-Powered-By technology banner disclosure
- Detects outdated software versions (Apache, Nginx, PHP, IIS, OpenSSL) against known vulnerable version baselines
- Shows severity, a plain-language explanation, and an actionable fix per finding
- Includes a responsive one-page dashboard with a dark, 3D-glass (glassmorphism) theme

## Project structure

    vulnerability-scanner/
    ├── app.py                 Flask server and scan logic
    ├── requirements.txt       Python dependencies
    ├── README.md              This documentation
    └── templates/
        └── index.html         Full frontend: HTML, CSS, and JavaScript

## Requirements

- Python 3.9 or newer
- Network access to the target
- Permission to scan the target

## Install and run

1. Open a terminal in the project folder.

2. Create a virtual environment (recommended).

   Windows PowerShell:

       python -m venv .venv
       .\.venv\Scripts\Activate.ps1

   macOS/Linux:

       python3 -m venv .venv
       source .venv/bin/activate

3. Install packages:

       pip install -r requirements.txt

4. Start the app:

       python app.py

   If Python uses the python3 command on your computer:

       python3 app.py

5. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## How to use

1. Enter a domain, IP address, or complete HTTP(S) URL, such as:

       example.com
       192.0.2.10
       https://example.com

2. Click **Start Scan**.
3. Review the open ports and findings that appear after the scan completes.
4. Read the **Recommended fix** section in each finding before making configuration changes.

## What the scanner checks

### 1. Common port exposure

The backend makes a TCP connection attempt to each listed port with a 0.5-second timeout.

| Port | Typical service | Why it may need review |
| --- | --- | --- |
| 21 | FTP | Unencrypted file transfer is often unsafe. |
| 22 | SSH | Should be limited to trusted users and networks. |
| 80 | HTTP | Usually should redirect visitors to HTTPS. |
| 443 | HTTPS | Expected for secure web services. |
| 3306 | MySQL | Database ports should rarely be public. |
| 8080 | Alternate HTTP | Often used by development or admin services. |

An open port is not automatically a vulnerability. It means a service accepted a connection and should be intentionally exposed, configured securely, and updated.

### 2. HTTP security headers

The app sends an HTTP GET request to the provided URL and checks these response headers:

| Header | Purpose | Suggested remediation |
| --- | --- | --- |
| Content-Security-Policy | Restricts resources a browser can load. | Start with a restrictive policy such as default-src self, then permit necessary resources. |
| X-Frame-Options | Helps prevent clickjacking through frames. | Set DENY or SAMEORIGIN. |
| Strict-Transport-Security | Instructs browsers to prefer HTTPS. | Use HTTPS and set a suitable max-age. |
| X-Content-Type-Options | Stops MIME type sniffing. | Set nosniff. |

### 3. Server banner disclosure

The scanner reports Server and X-Powered-By headers when present. These can expose implementation details like server or framework versions. This is usually a low-risk informational issue, but removing unneeded details is sensible hardening.

## API reference

The frontend uses a single endpoint: POST /scan.

### Request body

    {
      "target": "example.com"
    }

The target may be a hostname, IP address, or URL.

### Successful response

    {
      "target": "example.com",
      "open_ports": [80, 443],
      "vulnerabilities": [
        {
          "issue": "Missing X-Frame-Options Header",
          "severity": "Medium",
          "description": "Protects pages from clickjacking attacks.",
          "suggestion": "Add X-Frame-Options: DENY or SAMEORIGIN."
        }
      ]
    }

### Invalid request response

    {
      "error": "Please provide a target domain, IP address, or URL."
    }

## How it works

    Browser UI
        │ POST /scan with target
        ▼
    Flask app (app.py)
        ├── Normalizes target into hostname and URL
        ├── Connects to six common TCP ports
        ├── Requests HTTP response headers
        ├── Creates findings and suggestions
        ▼
    JSON response
        ▼
    Browser renders the report

## Technology used

- Backend: Flask, Flask-CORS, Requests, and Python socket
- Frontend: HTML, Tailwind CSS CDN, Google Fonts, and vanilla JavaScript
- Style: dark, glassmorphic "3D glass" theme with ambient gradient blobs and a subtle pointer-driven tilt effect on panels; no animation dependency

## Important limitations

This is an educational basic checker, not a full vulnerability assessment platform.

- It checks only six ports and does not identify services or do deep enumeration.
- Port results can be affected by firewalls, routing, and the scanner location.
- Header checks determine whether a header exists; they do not validate whether its value is correctly configured.
- Missing HSTS can be normal on a plain HTTP endpoint. Configure it only after HTTPS is working.
- Redirects, WAFs, bot protection, and network rules can affect the results.
- A finding is a signal for review, not proof that exploitation is possible.

## Safe and authorized use

Use this tool only for your own applications, lab environments, or systems where you have clear authorization. Do not scan third-party systems without permission. Follow organizational rules, applicable law, and any defined rules of engagement.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| python is not recognized | Install Python and enable Add Python to PATH, or use python3 when it is available. |
| ModuleNotFoundError | Activate the virtual environment, then run pip install -r requirements.txt. |
| Header audit unavailable | Confirm the URL is reachable and supports a normal HTTP or HTTPS request. |
| No open ports found | The six tested ports may be closed, filtered, or inaccessible from your network. |
| UI has no styling | Confirm the browser can access the Tailwind CDN. |

## License

No license is currently specified. Add a license file before distributing this project.
