# Contributing to STEALTHWALL

Thank you for your interest in contributing to **STEALTHWALL**! As an open-source, self-hosted machine learning Web Application Firewall and Intrusion Prevention System, we welcome contributions from security researchers, ML engineers, and software developers.

---

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment. Please be respectful and constructive in all issue discussions, pull requests, and community interactions.

---

## How Can I Contribute?

### 1. Reporting Bugs
- Check the [GitHub Issues](https://github.com/CSV0ID/STEALTHWALL/issues) tab to see if the issue has already been reported.
- If not, open a new issue detailing your environment, reproduction steps, and logs.

### 2. Suggesting Features & Threat Heuristics
- We welcome proposals for new sliding-window statistical features, 0-day heuristic patterns, and framework integrations.

### 3. Submitting Pull Requests
1. Fork the repository on GitHub.
2. Clone your fork and create a branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Set up your environment and run tests:
   ```bash
   pip install -e .
   pytest tests/
   ```
   Ensure all 40+ unit and parity tests pass with 100% success.
4. Commit with conventional commit messages and submit a PR against `main`.

---

## Technical Standards
- **Latency Budget**: Feature extraction and ONNX inference must execute in under **1.0 millisecond** per request.
- **Bit-Parity**: Python (`middleware.py`) and Node.js (`middleware.js`) must maintain numerical parity down to `1e-7` precision.

---

## Security Vulnerabilities
Please do not open public issues for security vulnerabilities. Review our [SECURITY.md](SECURITY.md) for responsible disclosure.
