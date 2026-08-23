#  Attack Simulation & Penetration Testing Guide

STEALTHWALL includes a built-in attack simulator tool to allow security engineers and developers to test their applications against realistic attack traffic.

---

## 1. Running Simulations via CLI

Use the `stealthwall attack` command:

```bash
# Test against SQLMap (SQL Injection)
stealthwall attack --tool sqlmap --target http://localhost:8000 --count 30

# Test against WPScan (WordPress Vulnerability Scanning)
stealthwall attack --tool wpscan --target http://localhost:8000 --count 30

# Test against Nikto (Server & CGI Scanning)
stealthwall attack --tool nikto --target http://localhost:8000 --count 30

# Test against Gobuster (Directory & Path Fuzzing)
stealthwall attack --tool gobuster --target http://localhost:8000 --count 30

# Test against THC-Hydra (Credential Brute Force)
stealthwall attack --tool hydra --target http://localhost:8000 --count 30

# Test against Nuclei (CVE Exploit Probing)
stealthwall attack --tool nuclei --target http://localhost:8000 --count 30

# Test against Commix (Command Injection)
stealthwall attack --tool commix --target http://localhost:8000 --count 30

# Test against XSStrike (Cross-Site Scripting)
stealthwall attack --tool xsstrike --target http://localhost:8000 --count 30

# Test against Low-and-Slow (Evasive Stealth Scanning)
stealthwall attack --tool low_and_slow --target http://localhost:8000 --count 15
```

---

## 2. Real-Time Verification

While running the simulation in one terminal window, watch the live operations dashboard in another:

```bash
stealthwall dashboard --port 9377
```

You will see:
1. Attack requests appear instantly in the WebSocket stream.
2. The ML model score escalate above `0.85`.
3. The graduated response engine trigger a `temp_block` or `provisional_block`.
4. Subsequent requests from the simulated attacker return `403 Forbidden` immediately.
