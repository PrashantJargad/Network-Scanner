from flask import Flask, render_template, request
import socket
import requests
from concurrent.futures import ThreadPoolExecutor
import nmap
import sys

app = Flask(__name__)


# CONFIG

COMMON_PORTS = [21, 22, 25, 80, 110, 143, 443, 8080]
TIMEOUT = 4
THREADS = 50

PORT_SERVICE = {
    21: "FTP", 22: "SSH", 25: "SMTP",
    80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 8080: "HTTP-ALT"
}


# VALIDATION

def is_valid_target(target):
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False


def resolve_target(target):
    return socket.gethostbyname(target)


# SOCKET SCANNER

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            result = s.connect_ex((ip, port))
            return port if result == 0 else None
    except Exception:
        return None


def scan_ports(ip):
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = executor.map(lambda p: scan_port(ip, p), COMMON_PORTS)
        return [p for p in results if p]


# BANNER GRABBING

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((ip, port))

            if port in (80, 8080):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")

            banner = s.recv(1024).decode(errors="ignore")
            return banner.split("\n")[0] if banner else None
    except Exception:
        return None


# NMAP SCAN

def get_nmap():
    try:
        if sys.platform == "win32":
            return nmap.PortScanner(
                nmap_search_path=("Your Nmap Path",)
            )
        return nmap.PortScanner()  # Linux/Mac: nmap is expected in PATH
    except Exception:
        return None


def nmap_scan(ip, ports):
    nm = get_nmap()
    if not nm or not ports:
        return [], []

    nm.scan(ip, ",".join(map(str, ports)), arguments="-sV -O")

    os_info, services = [], []

    for host in nm.all_hosts():
        if "osmatch" in nm[host]:
            os_info = [o["name"] for o in nm[host]["osmatch"]]

        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                svc = nm[host][proto][port]
                services.append({
                    "port": port,
                    "name": svc.get("name", ""),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", "")
                })

    return os_info, services


# CVE LOOKUP

def lookup_cves(product, version):
    if not product:
        return []

    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": f"{product} {version}", "resultsPerPage": 3}
        res = requests.get(url, params=params, timeout=5).json()

        results = []
        for item in res.get("vulnerabilities", []):
            cve = item["cve"]

            # Extract CVSS base score (try v3.1 → v3.0 → v2 in order)
            score = None
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics:
                    score = metrics[key][0]["cvssData"]["baseScore"]
                    break

            results.append({
                "id": cve["id"],
                "description": cve["descriptions"][0]["value"][:150],  # key was `desc` before — fixed
                "score": score
            })

        return results

    except Exception:
        return []


# VULNERABILITY HINTS

def find_vulns(services):
    vulns = []

    for s in services:
        name = s["name"].lower()

        if name == "ssh":
            vulns.append("SSH brute-force risk")
        elif name == "http":
            vulns.append("Missing security headers")
        elif name in ["pop3", "imap"]:
            vulns.append("Plaintext credentials possible")

    return list(set(vulns))




@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()

        if not is_valid_target(target):
            return render_template("index.html", result={"error": "Invalid target — hostname could not be resolved."})

        try:
            ip = resolve_target(target)
            open_ports = scan_ports(ip)

            port_data = []
            for p in open_ports:
                port_data.append({
                    "port": p,
                    "service": PORT_SERVICE.get(p, "Unknown"),
                    "banner": grab_banner(ip, p)
                })

            os_info, services = nmap_scan(ip, open_ports)

            # Attach CVEs to each detected service
            for s in services:
                s["cves"] = lookup_cves(s["product"], s["version"])

            result = {
                "ip": ip,
                "total_ports": len(COMMON_PORTS),
                "open_ports": port_data,
                "os": os_info,
                "services": services,
                "vulns": find_vulns(services)
            }

        except Exception as e:
            result = {"error": str(e)}

    return render_template("index.html", result=result)



if __name__ == "__main__":
    app.run(debug=True)
