#!/usr/bin/env python3
"""STEALTHWALL — Unified Developer CLI

Usage:
    python3 stealthwall_cli.py test              # Run full test suite & parity
    python3 stealthwall_cli.py parity            # Run cross-language parity check
    python3 stealthwall_cli.py status            # Display system status & config
    python3 stealthwall_cli.py generate-data     # Generate benign traffic datasets
    python3 stealthwall_cli.py drift-check       # Run Model1 vs Model2 drift check
    python3 stealthwall_cli.py dashboard [--port 9377] # Start operations dashboard
    python3 stealthwall_cli.py attack [--tool sqlmap] [--target http://127.0.0.1:4488] # Attack simulator
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.defaults import (
    FEATURE_SPEC_VERSION,
    MODEL_SCHEMA_VERSION,
    SIGNATURE_FEATURE_MAX_WEIGHT,
    TIER_LOW_THRESHOLD,
    TIER_MEDIUM_THRESHOLD,
    TIER_HIGH_THRESHOLD,
    TIER_VERY_HIGH_THRESHOLD,
    MAX_BASELINE_SHIFT_PER_HOUR,
    COLD_START_FLOOR_THRESHOLD,
)


def cmd_status(_args):
    print("=" * 60)
    print("STEALTHWALL SYSTEM CONFIGURATION & STATUS")
    print("=" * 60)
    print(f"Feature Spec Version   : v{FEATURE_SPEC_VERSION}")
    print(f"Model Schema Version   : v{MODEL_SCHEMA_VERSION}")
    print(f"Signature Weight Cap   : {SIGNATURE_FEATURE_MAX_WEIGHT * 100:.0f}%")
    print(f"Confidence Tiers       : Low >= {TIER_LOW_THRESHOLD}, Med >= {TIER_MEDIUM_THRESHOLD}, High >= {TIER_HIGH_THRESHOLD}, VHigh >= {TIER_VERY_HIGH_THRESHOLD}")
    print(f"Adaptive Shift Cap     : ±{MAX_BASELINE_SHIFT_PER_HOUR}/hour")
    print(f"Cold-Start Floor       : {COLD_START_FLOOR_THRESHOLD}")
    print("-" * 60)

    # Check artifacts
    coldstart = ROOT / "models" / "coldstart" / "artifacts" / "coldstart.onnx"
    lkg = ROOT / "models" / "coldstart" / "artifacts" / "last_known_good.onnx"
    print(f"Cold-start model exists: {coldstart.exists()} ({coldstart})")
    print(f"Last-known-good exists : {lkg.exists()} ({lkg})")
    print("=" * 60)


def cmd_test(_args):
    print("Running pytest suite...")
    ret = subprocess.run([sys.executable, "-m", "pytest", str(ROOT / "tests"), "-v"], cwd=str(ROOT))
    if ret.returncode != 0:
        sys.exit(ret.returncode)

    print("\nRunning Cross-Language Parity Check...")
    ret_parity = subprocess.run([sys.executable, str(ROOT / "tests" / "parity" / "run_parity.py")], cwd=str(ROOT))
    if ret_parity.returncode != 0:
        sys.exit(ret_parity.returncode)

    print("\nALL TESTS AND PARITY CHECKS PASSED SUCCESSFULLY!")


def cmd_parity(_args):
    ret = subprocess.run([sys.executable, str(ROOT / "tests" / "parity" / "run_parity.py")], cwd=str(ROOT))
    sys.exit(ret.returncode)


def cmd_generate_data(_args):
    gen_script = ROOT / "data" / "benign_traffic" / "generate_benign.py"
    print(f"Generating synthetic benign and hard-negative datasets...")
    ret = subprocess.run([sys.executable, str(gen_script)], cwd=str(ROOT))
    sys.exit(ret.returncode)


def cmd_drift_check(_args):
    drift_script = ROOT / "models" / "adaptive_scoring" / "drift_check.py"
    print("Executing drift check...")
    ret = subprocess.run([sys.executable, str(drift_script)], cwd=str(ROOT))
    sys.exit(ret.returncode)


def cmd_dashboard(args):
    os.environ.setdefault("STEALTHWALL_ALLOW_NO_IPTABLES", "1")
    print(f"Launching StealthWall Operations Dashboard on http://127.0.0.1:{args.port} ...")
    try:
        import uvicorn
        uvicorn.run("dashboard.app:app", host="127.0.0.1", port=args.port, reload=False)
    except ImportError:
        print("uvicorn is required to run the dashboard. Run: pip install uvicorn")
        sys.exit(1)


def cmd_attack(args):
    from data.simulator import run_attack_simulation
    run_attack_simulation(target_url=args.target, tool_name=args.tool, count=args.count)


def main():
    parser = argparse.ArgumentParser(description="StealthWall Developer CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("status", help="Print system status and configuration")
    subparsers.add_parser("test", help="Run full pytest test suite and parity checks")
    subparsers.add_parser("parity", help="Run Node.js vs Python feature parity assertion")
    subparsers.add_parser("generate-data", help="Generate synthetic benign traffic dataset")
    subparsers.add_parser("drift-check", help="Run Model 1 vs Model 2 drift detection")

    dash_parser = subparsers.add_parser("dashboard", help="Start operations dashboard")
    dash_parser.add_argument("--port", type=int, default=9377, help="Port to listen on (default: 9377)")

    atk_parser = subparsers.add_parser("attack", help="Simulate an attack burst against a target")
    atk_parser.add_argument("--tool", type=str, default="sqlmap", help="Tool to simulate: sqlmap, wpscan, nikto, gobuster, hydra, nuclei, commix, xsstrike, low_and_slow")
    atk_parser.add_argument("--target", type=str, default="http://127.0.0.1:4488", help="Target URL (default: http://127.0.0.1:4488)")
    atk_parser.add_argument("--count", type=int, default=25, help="Number of simulated requests to send (default: 25)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "status": cmd_status,
        "test": cmd_test,
        "parity": cmd_parity,
        "generate-data": cmd_generate_data,
        "drift-check": cmd_drift_check,
        "dashboard": cmd_dashboard,
        "attack": cmd_attack,
    }

    cmd_fn = commands.get(args.command)
    if cmd_fn:
        cmd_fn(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
