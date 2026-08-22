"""Unit tests for Attack Simulator."""

import pytest
from data.simulator import TOOL_PROFILES, run_attack_simulation


def test_tool_profiles_completeness():
    required_tools = ["sqlmap", "wpscan", "nikto", "gobuster", "hydra", "nuclei", "commix", "xsstrike", "low_and_slow"]
    for tool in required_tools:
        assert tool in TOOL_PROFILES
        assert len(TOOL_PROFILES[tool]["paths"]) > 0
        assert "ua" in TOOL_PROFILES[tool]
