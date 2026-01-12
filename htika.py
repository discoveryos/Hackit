#!/usr/bin/env python3
"""
CVE-2025-66516 Safe Detector
Detects if a remote Apache Tika server is vulnerable to the critical XXE
by checking the version header only (no malicious PDF sent).

Author   : kevin dan mathew 
Date     : Dec 2025
CVE      : CVE-2025-66516 (CVSS 10.0)
Target   : Apache Tika ≤ 3.2.1 / ≤ 1.28.5
Github   : https://github.com/Ashwesker/Blackash-CVE-2025-66516
"""

import sys
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings if testing internal/self-signed instances
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

VULNERABLE_VERSIONS = {
    # tika-core
    "1.", "2.", "3.0", "3.1", "3.2.0", "3.2.1",
    # tika-parsers (older branch)
    "1.13", "1.14", "1.15", "1.16", "1.17", "1.18", "1.19",
    "1.20", "1.21", "1.22", "1.23", "1.24", "1.25", "1.26", "1.27", "1.28.0", "1.28.1", "1.28.2", "1.28.3", "1.28.4", "1.28.5"
}

def banner():
    print(r"""
 ██████╗  ██╗       █████╗   ██████╗ ██╗  ██╗  █████╗  ███████╗ ██╗  ██╗ 
 ██╔══██╗ ██║      ██╔══██╗ ██╔════╝ ██║ ██╔╝ ██╔══██╗ ██╔════╝ ██║  ██║ 
 ██████╔╝ ██║      ███████║ ██║      █████╔╝  ███████║ ███████╗ ███████║ 
 ██╔══██╗ ██║      ██╔══██║ ██║      ██╔═██╗  ██╔══██║ ╚════██║ ██╔══██║ 
 ██████╔╝ ███████╗ ██║  ██║ ╚██████╗ ██║  ██╗ ██║  ██║ ███████║ ██║  ██║ 
 ╚═════╝  ╚══════╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚═╝
         htika — Critical Apache Tika Vulnerability
    """)

def check_tika_version(url, timeout=10):
    try:
        # Most Tika servers expose version on /version or root
        for endpoint in ["/version", "/"]:
            r = requests.get(
                f"{url.rstrip('/')}{endpoint}",
                timeout=timeout,
                verify=False,
                headers={"Accept": "text/plain"}
            )
            if r.status_code == 200:
                version = r.text.strip()
                print(f"[+] Version response from {endpoint}: {version}")
                return version
    except Exception as e:
        print(f"[-] Connection error: {e}")
    return None

def is_vulnerable(version):
    if not version:
        return False
    version = version.lower().replace("apache tika ", "").strip()
    for vuln in VULNERABLE_VERSIONS:
        if version.startswith(vuln):
            return True
    return False

def main():
    banner()
    if len(sys.argv) != 2:
        print("Usage: python3 CVE-2025-66516.py http://target:9998")
        print("Example: python3 CVE-2025-66516.py http://192.168.1.10:9998")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[*] Targeting: {target}\n")

    version = check_tika_version(target)
    if not version:
        print("[-] Could not retrieve Tika version – is it running?")
        sys.exit(1)

    if is_vulnerable(version):
        print("🚨 VULNERABLE to CVE-2025-66516 (CVSS 10.0)!")
        print("   Upgrade to Apache Tika ≥ 3.2.2 immediately")
    else:
        print("✅ SAFE – version is patched or not affected")

if __name__ == "__main__":
    main()
