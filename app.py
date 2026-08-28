import re
import socket
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS


app = Flask(__name__)
CORS(app)

COMMON_PORTS = [21, 22, 80, 443, 3306, 8080]
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "issue": "Missing Content-Security-Policy Header",
        "severity": "Medium",
        "description": "Helps reduce the impact of cross-site scripting and content injection attacks.",
        "suggestion": "Add a restrictive Content-Security-Policy header, for example: default-src 'self'.",
    },
    "X-Frame-Options": {
        "issue": "Missing X-Frame-Options Header",
        "severity": "Medium",
        "description": "Protects pages from being embedded in malicious frames for clickjacking attacks.",
        "suggestion": "Add X-Frame-Options: DENY or SAMEORIGIN in your web server configuration.",
    },
    "Strict-Transport-Security": {
        "issue": "Missing Strict-Transport-Security Header",
        "severity": "Medium",
        "description": "Encourages browsers to use HTTPS for future visits.",
        "suggestion": "Serve the site over HTTPS and add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    },
    "X-Content-Type-Options": {
        "issue": "Missing X-Content-Type-Options Header",
        "severity": "Low",
        "description": "Prevents browsers from MIME-sniffing a response away from its declared content type.",
        "suggestion": "Add X-Content-Type-Options: nosniff in your web server configuration.",
    },
}

# Known outdated software pattern rules and safe version thresholds
OUTDATED_SOFTWARE_PATTERNS = [
    {
        "name": "Apache",
        "pattern": r"Apache/(?P<version>\d+\.\d+(?:\.\d+)?)",
        "min_safe": (2, 4, 50),
        "severity": "High",
        "suggestion": "Upgrade Apache HTTP Server to version 2.4.50 or higher to patch known security vulnerabilities (such as CVE-2021-41773).",
    },
    {
        "name": "Nginx",
        "pattern": r"nginx/(?P<version>\d+\.\d+(?:\.\d+)?)",
        "min_safe": (1, 22, 0),
        "severity": "Medium",
        "suggestion": "Upgrade Nginx to a modern supported release (version 1.22.0 or 1.24+).",
    },
    {
        "name": "PHP",
        "pattern": r"PHP/(?P<version>\d+\.\d+(?:\.\d+)?)",
        "min_safe": (8, 1, 0),
        "severity": "High",
        "suggestion": "Upgrade PHP to a supported version (PHP 8.1 or 8.2+). Older versions (e.g. PHP 5.x, 7.x) are End-of-Life and no longer receive security patches.",
    },
    {
        "name": "Gunicorn",
        "pattern": r"gunicorn/(?P<version>\d+\.\d+(?:\.\d+)?)",
        "min_safe": (20, 0, 0),
        "severity": "Medium",
        "suggestion": "Upgrade Gunicorn to version 20.0.0 or higher.",
    },
    {
        "name": "Tomcat",
        "pattern": r"Tomcat/(?P<version>\d+\.\d+(?:\.\d+)?)",
        "min_safe": (9, 0, 50),
        "severity": "High",
        "suggestion": "Upgrade Apache Tomcat to 9.0.50+ or 10.x to patch known remote code execution vulnerabilities.",
    },
    {
        "name": "Lighttpd",
        "pattern": r"lighttpd/(?P<version>\d+\.\d+(?:\.\d+)?)",
        "min_safe": (1, 4, 60),
        "severity": "Medium",
        "suggestion": "Upgrade Lighttpd to version 1.4.60 or newer.",
    },
    {
        "name": "Microsoft-IIS",
        "pattern": r"Microsoft-IIS/(?P<version>\d+\.\d+)",
        "min_safe": (10, 0),
        "severity": "Medium",
        "suggestion": "Upgrade to Windows Server running Microsoft IIS 10.0 or higher.",
    },
    {
        "name": "OpenSSL",
        "pattern": r"OpenSSL/(?P<version>\d+\.\d+(?:\.\d+)?)",
        "min_safe": (1, 1, 1),
        "severity": "High",
        "suggestion": "Upgrade OpenSSL to 1.1.1w or 3.0+ to protect against known cryptographic vulnerabilities.",
    },
]

# Common outdated version exact string matches for quick detection
KNOWN_OUTDATED_EXACT = {
    "apache/2.4.41": ("Apache 2.4.41", "High", "Upgrade Apache to version 2.4.50 or newer."),
    "apache/2.2.15": ("Apache 2.2.15", "High", "Apache 2.2.x is End-of-Life. Upgrade to 2.4.x."),
    "php/7.4.3": ("PHP 7.4.3", "High", "PHP 7.4 reached End-of-Life in Nov 2022. Upgrade to PHP 8.1+."),
    "php/5.6.40": ("PHP 5.6.40", "High", "PHP 5.6 reached End-of-Life in Dec 2018. Upgrade to PHP 8.1+."),
    "nginx/1.18.0": ("Nginx 1.18.0", "Medium", "Upgrade Nginx to version 1.22.0 or newer."),
    "nginx/1.14.0": ("Nginx 1.14.0", "High", "Upgrade Nginx to version 1.22.0 or newer."),
    "gunicorn/19.9.0": ("Gunicorn 19.9.0", "Medium", "Upgrade Gunicorn to version 20.0.0 or newer."),
}


def parse_version_tuple(version_str):
    """Convert version string like '2.4.41' into integer tuple (2, 4, 41) for comparison."""
    try:
        parts = [int(p) for p in re.findall(r"\d+", version_str)]
        return tuple(parts)
    except Exception:
        return None


def check_outdated_software(headers):
    """Inspect Server and X-Powered-By headers and match against known outdated versions."""
    findings = []
    header_values = [headers.get("Server", ""), headers.get("X-Powered-By", "")]
    combined_str = " ".join([v for v in header_values if v]).lower()

    if not combined_str:
        return findings

    # 1. Exact match check
    for key, (soft_name, severity, suggestion) in KNOWN_OUTDATED_EXACT.items():
        if key in combined_str:
            findings.append({
                "issue": f"Outdated Software Detected ({soft_name})",
                "severity": severity,
                "description": f"The target server reports running {soft_name}, which is an outdated release with known security vulnerabilities.",
                "suggestion": suggestion,
            })

    # 2. Regex pattern & version comparison check
    for rule in OUTDATED_SOFTWARE_PATTERNS:
        match = re.search(rule["pattern"], " ".join([v for v in header_values if v]), re.IGNORECASE)
        if match:
            ver_str = match.group("version")
            ver_tuple = parse_version_tuple(ver_str)
            min_safe = rule["min_safe"]
            soft_name = rule["name"]

            if ver_tuple and ver_tuple < min_safe:
                issue_title = f"Outdated Software Detected ({soft_name} {ver_str})"
                if not any(issue_title in f["issue"] for f in findings):
                    min_safe_str = ".".join(map(str, min_safe))
                    findings.append({
                        "issue": issue_title,
                        "severity": rule["severity"],
                        "description": f"The target server is reporting {soft_name} version {ver_str}, which is below the minimum recommended version ({min_safe_str}) and contains known security vulnerabilities.",
                        "suggestion": rule["suggestion"],
                    })

    return findings


def audit_software_banner(headers):
    """Analyze Server and X-Powered-By headers for version disclosure and version masking."""
    findings = []
    exposed_headers = [h for h in ("Server", "X-Powered-By") if headers.get(h)]
    if not exposed_headers:
        return findings

    header_details = ", ".join(f"{h}: {headers[h]}" for h in exposed_headers)
    combined_val = " ".join([headers[h] for h in exposed_headers])

    # Find explicitly disclosed version numbers (e.g. Apache/2.4.41, gunicorn/19.9.0, PHP/7.4.3)
    version_matches = re.findall(
        r"([a-zA-Z0-9\-_]+)[/\s](\d+\.\d+(?:\.\d+)?(?:[a-z\d\._-]+)?)",
        combined_val,
    )

    if version_matches:
        for soft_name, ver_str in version_matches:
            findings.append({
                "issue": f"Software Version Disclosed ({soft_name} v{ver_str})",
                "severity": "Low",
                "description": f"The server explicitly exposes software name and version in response headers: '{soft_name} {ver_str}' ({header_details}).",
                "suggestion": f"Configure your web server to hide version numbers (e.g. set ServerTokens ProductOnly in Apache or server_tokens off in Nginx).",
            })
    else:
        # Banner is present but version is masked (e.g. Server: ESF or Server: cloudflare)
        findings.append({
            "issue": "Banner Disclosed (Version Masked)",
            "severity": "Info",
            "description": f"The server exposes a banner header ({header_details}), but hides the exact software version number (version masking active).",
            "suggestion": "Hiding the version number is a good security posture. Optionally remove the Server header completely for full anonymity.",
        })

    # Also run outdated version checks
    outdated = check_outdated_software(headers)
    findings.extend(outdated)

    return findings


def normalize_target(target):
    """Return a hostname for sockets and an HTTP(S) URL for header checks."""
    candidate = target.strip()
    parsed = urlparse(candidate if "://" in candidate else f"http://{candidate}")
    if not parsed.hostname:
        raise ValueError("Enter a valid domain, IP address, or URL.")
    return parsed.hostname, parsed.geturl()


def scan_ports(hostname):
    open_ports = []
    for port in COMMON_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if sock.connect_ex((hostname, port)) == 0:
                    open_ports.append(port)
        except (socket.gaierror, OSError):
            continue
    return open_ports


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    if not isinstance(target, str) or not target.strip():
        return jsonify({"error": "Please provide a target domain, IP address, or URL."}), 400

    try:
        hostname, url = normalize_target(target)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    vulnerabilities = []
    open_ports = scan_ports(hostname)

    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "Beginner-Vulnerability-Scanner/1.0"},
        )
        headers = response.headers

        for header, finding in SECURITY_HEADERS.items():
            if header not in headers:
                vulnerabilities.append(finding)

        # Software banner and version audit
        banner_findings = audit_software_banner(headers)
        vulnerabilities.extend(banner_findings)

    except requests.RequestException as error:
        vulnerabilities.append({
            "issue": "Header Audit Unavailable",
            "severity": "Info",
            "description": f"Could not retrieve HTTP headers: {error}",
            "suggestion": "Confirm the target is reachable over HTTP/HTTPS and try again.",
        })

    return jsonify({
        "target": hostname,
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
