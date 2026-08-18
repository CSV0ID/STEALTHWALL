"""STEALTHWALL — Live Security Penetration & Attack Simulator.

Simulates realistic attack streams against any local or remote HTTP target
to test real-time detection, graduated response blocking, and live dashboard metrics.
"""

from __future__ import annotations

import random
import sys
import time
from typing import Callable, Dict, List, Optional
import urllib.request
import urllib.error

TOOL_PROFILES = {
    "sqlmap": {
        "ua": "sqlmap/1.8#stable (https://sqlmap.org)",
        "paths": [
            "/items?id=1' AND 1=1--", "/items?id=1' WAITFOR DELAY '0:0:5'--",
            "/items?id=1 UNION SELECT username, password FROM users--",
            "/search?q=lamp' OR '1'='1", "/items?id=1; SELECT PG_SLEEP(5)--"
        ],
        "methods": ["GET"],
        "rate_gap": 0.05,
    },
    "wpscan": {
        "ua": "WPScan v3.8.25 (https://wpscan.com)",
        "paths": [
            "/wp-login.php", "/xmlrpc.php", "/wp-admin/admin-ajax.php",
            "/wp-content/plugins/revslider/", "/wp-config.php.bak",
            "/wp-json/wp/v2/users", "/wp-content/debug.log"
        ],
        "methods": ["GET"],
        "rate_gap": 0.03,
    },
    "nikto": {
        "ua": "Nikto/2.1.6",
        "paths": [
            "/cgi-bin/test-cgi", "/server-status", "/.env", "/.git/config",
            "/admin/config.php", "/phpmyadmin/", "/backup.tar.gz"
        ],
        "methods": ["GET"],
        "rate_gap": 0.02,
    },
    "gobuster": {
        "ua": "gobuster/3.6",
        "paths": [
            "/admin", "/backup", "/secret", "/internal", "/shell",
            "/test", "/console", "/actuator", "/debug", "/server"
        ],
        "methods": ["GET"],
        "rate_gap": 0.01,
    },
    "hydra": {
        "ua": "Hydra/9.5",
        "paths": ["/login", "/api/v1/auth", "/signin"],
        "methods": ["POST"],
        "rate_gap": 0.02,
    },
    "nuclei": {
        "ua": "Nuclei - projectdiscovery",
        "paths": [
            "/${jndi:ldap://127.0.0.1/a}", "/actuator/env",
            "/../../../../../../etc/shadow", "/api/v1/debug"
        ],
        "methods": ["GET"],
        "rate_gap": 0.04,
    },
    "commix": {
        "ua": "commix/v3.8-stable",
        "paths": [
            "/ping?host=127.0.0.1;cat /etc/passwd",
            "/ping?host=127.0.0.1|id|",
            "/ping?host=127.0.0.1$(whoami)"
        ],
        "methods": ["GET"],
        "rate_gap": 0.08,
    },
    "xsstrike": {
        "ua": "XSStrike/3.1.5",
        "paths": [
            "/search?q=<script>alert(1)</script>",
            "/search?q=<svg/onload=confirm(1)>",
            "/profile?name=<img src=x onerror=alert(1)>"
        ],
        "methods": ["GET"],
        "rate_gap": 0.05,
    },
    "low_and_slow": {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0",
        "paths": ["/hidden_1", "/hidden_2", "/hidden_3", "/hidden_4"],
        "methods": ["GET"],
        "rate_gap": 1.2,
    },
}


def run_attack_simulation(target_url: str, tool_name: str = "sqlmap", count: int = 30) -> dict:
    """Send a realistic attack burst against a target URL."""
    profile = TOOL_PROFILES.get(tool_name.lower(), TOOL_PROFILES["sqlmap"])
    ua = profile["ua"]
    paths = profile["paths"]
    base_url = target_url.rstrip("/")

    results = {"sent": 0, "blocked_403": 0, "ok_200": 0, "notfound_404": 0, "errors": 0}

    print(f"Launching simulated '{tool_name}' attack ({count} requests) -> {base_url}")

    for i in range(count):
        sub_path = random.choice(paths)
        url = f"{base_url}{sub_path}" if sub_path.startswith("/") else f"{base_url}/{sub_path}"
        method = random.choice(profile["methods"])

        data = b"user=admin&pass=12345" if method == "POST" else None
        headers = {
            "User-Agent": ua,
            "Accept": "*/*",
            "Host": "target.local",
        }

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                results["sent"] += 1
                if resp.status == 200:
                    results["ok_200"] += 1
        except urllib.error.HTTPError as exc:
            results["sent"] += 1
            if exc.code == 403:
                results["blocked_403"] += 1
            elif exc.code == 404:
                results["notfound_404"] += 1
            else:
                results["errors"] += 1
        except Exception:
            results["errors"] += 1

        time.sleep(profile["rate_gap"])

    print(f"Simulation Complete: {results['sent']} sent, {results['blocked_403']} blocked by StealthWall (403 Forbidden)")
    return results
